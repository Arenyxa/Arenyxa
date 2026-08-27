from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.security.models import TrustDomain


class AuditFailurePolicy(str, Enum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPERATIONAL = "fail_operational"


class AuditMode(str, Enum):
    NORMAL = "normal"
    DEGRADED = "degraded"
    RECOVERY = "recovery"


@dataclass(slots=True)
class AuditEvent:
    id: str
    actor: str
    action: str
    resource: str
    decision: str
    trust_domain: TrustDomain
    device: str = ""
    time: str = field(default_factory=utc_now)
    correlation_id: str = ""
    reason: str = ""
    integrity_metadata: dict[str, str] = field(default_factory=dict)


class AuditLog:
    """Tamper-evident audit chain with explicit fail-closed/fail-operational recovery semantics.

    The primary chain is never modified or truncated after an integrity failure.  In
    ``fail_operational`` mode new security events are written to a separate recovery chain so
    operations can continue while preserving forensic evidence that the primary chain failed.
    """

    ALGORITHM = "sha256-chain-v1"
    MAX_LINE_BYTES = 1024 * 1024
    MAX_EMERGENCY_EVENTS = 10_000

    def __init__(
        self,
        path: Path | None = None,
        *,
        failure_policy: AuditFailurePolicy | str = AuditFailurePolicy.FAIL_CLOSED,
        recovery_path: Path | None = None,
    ) -> None:
        self.path = None if path is None else Path(path)
        self.failure_policy = AuditFailurePolicy(str(getattr(failure_policy, "value", failure_policy)).casefold())
        self.recovery_path = (
            None
            if self.path is None
            else Path(recovery_path) if recovery_path is not None else self.path.with_name(self.path.stem + ".recovery.jsonl")
        )
        self._lock = threading.Lock()
        self._memory: list[dict[str, Any]] = []
        self._emergency_memory: list[dict[str, Any]] = []
        self._last_hash = ""
        self._recovery_last_hash = ""
        self._integrity_error = ""
        self._recovery_error = ""
        self._mode = AuditMode.NORMAL
        self._recovery_marker_written = False
        if self.path is not None:
            valid, last_hash, reason = self._scan_path(self.path)
            if valid:
                self._last_hash = last_hash
            else:
                self._integrity_error = reason
                self._mode = AuditMode.DEGRADED
            if self.recovery_path is not None:
                recovery_valid, recovery_hash, recovery_reason = self._scan_path(self.recovery_path)
                if recovery_valid:
                    self._recovery_last_hash = recovery_hash
                    self._recovery_marker_written = bool(recovery_hash)
                else:
                    self._recovery_error = recovery_reason

    @staticmethod
    def _canonical_without_event_hash(payload: Mapping[str, Any]) -> bytes:
        row = dict(payload)
        metadata = dict(row.get("integrity_metadata") or {})
        metadata.pop("event_hash", None)
        row["integrity_metadata"] = metadata
        return json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    @classmethod
    def _hash(cls, payload: Mapping[str, Any]) -> str:
        return hashlib.sha256(cls._canonical_without_event_hash(payload)).hexdigest()

    @classmethod
    def _verify_row(cls, row: Mapping[str, Any], previous: str, index: int) -> tuple[bool, str, str]:
        metadata = dict(row.get("integrity_metadata") or {})
        if metadata.get("algorithm") != cls.ALGORITHM:
            return False, previous, f"row {index} algorithm mismatch"
        if str(metadata.get("previous_hash") or "") != previous:
            return False, previous, f"row {index} previous hash mismatch"
        expected = str(metadata.get("event_hash") or "")
        actual = cls._hash(row)
        if not expected or expected != actual:
            return False, previous, f"row {index} event hash mismatch"
        return True, expected, "ok"

    @classmethod
    def _scan_path(cls, path: Path) -> tuple[bool, str, str]:
        if not path.exists():
            return True, "", "empty"
        previous = ""
        index = 0
        try:
            with path.open("rb") as stream:
                while True:
                    raw = stream.readline(cls.MAX_LINE_BYTES + 1)
                    if not raw:
                        break
                    if len(raw) > cls.MAX_LINE_BYTES:
                        return False, previous, f"row {index} exceeds maximum audit line size"
                    if not raw.strip():
                        return False, previous, f"row {index} is blank"
                    try:
                        value = json.loads(raw.decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        return False, previous, f"row {index} is invalid: {type(exc).__name__}: {exc}"
                    if not isinstance(value, dict):
                        return False, previous, f"row {index} is not an object"
                    valid, previous, reason = cls._verify_row(value, previous, index)
                    if not valid:
                        return False, previous, reason
                    index += 1
        except (OSError, TypeError, ValueError) as exc:
            return False, previous, f"audit verification failed: {type(exc).__name__}: {exc}"
        return True, previous, "empty" if index == 0 else "ok"

    def _scan_file(self) -> tuple[bool, str, str]:
        if self.path is None:
            return True, "", "empty"
        return self._scan_path(self.path)

    @classmethod
    def _encoded_row(cls, event: AuditEvent, *, previous_hash: str, channel: str, primary_error: str = "") -> tuple[bytes, str]:
        event.integrity_metadata = {
            "algorithm": cls.ALGORITHM,
            "previous_hash": previous_hash,
            "channel": channel,
        }
        if primary_error:
            event.integrity_metadata["primary_integrity_error"] = primary_error[:512]
        payload = asdict(event)
        event_hash = cls._hash(payload)
        event.integrity_metadata["event_hash"] = event_hash
        row = asdict(event)
        encoded = (json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str) + "\n").encode("utf-8")
        if len(encoded) > cls.MAX_LINE_BYTES:
            raise ArenyxaError("AUDIT_EVENT_TOO_LARGE", "security audit event exceeds maximum line size", domain="SECURITY")
        return encoded, event_hash

    @staticmethod
    def _durable_append(path: Path, encoded: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())

    def _append_primary_locked(self, event: AuditEvent) -> AuditEvent:
        encoded, event_hash = self._encoded_row(event, previous_hash=self._last_hash, channel="primary")
        if self.path is None:
            self._memory.append(asdict(event))
        else:
            self._durable_append(self.path, encoded)
        self._last_hash = event_hash
        self._mode = AuditMode.NORMAL
        return event

    def _append_emergency_locked(self, event: AuditEvent, error: BaseException) -> AuditEvent:
        row = asdict(event)
        metadata = dict(row.get("integrity_metadata") or {})
        metadata.update({
            "channel": "emergency-memory",
            "durability_error": f"{type(error).__name__}: {error}"[:512],
            "primary_integrity_error": self._integrity_error[:512],
        })
        row["integrity_metadata"] = metadata
        if len(self._emergency_memory) >= self.MAX_EMERGENCY_EVENTS:
            raise ArenyxaError(
                "AUDIT_EMERGENCY_BUFFER_FULL",
                "all durable audit sinks are unavailable and the emergency buffer is full",
                domain="SECURITY",
                context={
                    "primary_error": self._integrity_error[:512],
                    "recovery_error": self._recovery_error[:512],
                    "buffered_events": len(self._emergency_memory),
                },
            ) from error
        self._emergency_memory.append(row)
        self._mode = AuditMode.DEGRADED
        return event

    def _append_recovery_locked(self, event: AuditEvent) -> AuditEvent:
        if self.recovery_path is None:
            return self._append_emergency_locked(event, RuntimeError("recovery audit path is unavailable"))
        if not self._recovery_marker_written:
            marker = AuditEvent(
                id=new_id("audit"),
                actor="arenyxa.audit",
                action="audit.degraded",
                resource=str(self.path or "memory"),
                decision="recovery",
                trust_domain=TrustDomain.ENTERPRISE,
                reason=self._integrity_error or "primary audit sink unavailable",
            )
            marker_encoded, marker_hash = self._encoded_row(
                marker,
                previous_hash=self._recovery_last_hash,
                channel="recovery",
                primary_error=self._integrity_error,
            )
            self._durable_append(self.recovery_path, marker_encoded)
            self._recovery_last_hash = marker_hash
            self._recovery_marker_written = True
        encoded, event_hash = self._encoded_row(
            event,
            previous_hash=self._recovery_last_hash,
            channel="recovery",
            primary_error=self._integrity_error,
        )
        self._durable_append(self.recovery_path, encoded)
        self._recovery_last_hash = event_hash
        self._recovery_error = ""
        self._mode = AuditMode.RECOVERY
        return event

    def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            if self._integrity_error:
                if self.failure_policy is AuditFailurePolicy.FAIL_CLOSED:
                    raise ArenyxaError(
                        "AUDIT_INTEGRITY_BROKEN",
                        "security audit log integrity is broken; refusing to append a new chain",
                        domain="SECURITY",
                        context={"reason": self._integrity_error},
                    )
                try:
                    return self._append_recovery_locked(event)
                except OSError as exc:
                    self._recovery_error = f"{type(exc).__name__}: {exc}"
                    return self._append_emergency_locked(event, exc)
            try:
                return self._append_primary_locked(event)
            except OSError as exc:
                self._integrity_error = f"primary audit append failed: {type(exc).__name__}: {exc}"
                self._mode = AuditMode.DEGRADED
                if self.failure_policy is AuditFailurePolicy.FAIL_CLOSED:
                    raise ArenyxaError(
                        "AUDIT_APPEND_FAILED",
                        "security audit persistence failed",
                        domain="SECURITY",
                        context={"reason": self._integrity_error},
                    ) from exc
                try:
                    return self._append_recovery_locked(event)
                except OSError as recovery_exc:
                    self._recovery_error = f"{type(recovery_exc).__name__}: {recovery_exc}"
                    return self._append_emergency_locked(event, recovery_exc)

    def emit(
        self,
        *,
        actor: str,
        action: str,
        resource: str,
        decision: str,
        trust_domain: TrustDomain,
        device: str = "",
        correlation_id: str = "",
        reason: str = "",
    ) -> AuditEvent:
        return self.record(
            AuditEvent(
                id=new_id("audit"),
                actor=str(actor)[:256],
                action=str(action)[:256],
                resource=str(resource)[:4096],
                decision=str(decision)[:64],
                trust_domain=trust_domain,
                device=str(device)[:256],
                correlation_id=str(correlation_id)[:256],
                reason=str(reason)[:512],
            )
        )

    def verify(self) -> tuple[bool, str]:
        if self.path is None:
            previous = ""
            try:
                rows = list(self._memory)
                for index, row in enumerate(rows):
                    valid, previous, reason = self._verify_row(row, previous, index)
                    if not valid:
                        return False, reason
            except (TypeError, ValueError) as exc:
                return False, f"audit verification failed: {type(exc).__name__}: {exc}"
            return True, "ok" if rows else "empty"

        valid, last_hash, reason = self._scan_file()
        with self._lock:
            if valid:
                self._last_hash = last_hash
                self._integrity_error = ""
                if self._mode is AuditMode.DEGRADED and not self._recovery_error:
                    self._mode = AuditMode.RECOVERY if self._recovery_marker_written else AuditMode.NORMAL
            else:
                self._integrity_error = reason
                if self._mode is AuditMode.NORMAL:
                    self._mode = AuditMode.DEGRADED
        return valid, reason

    def recovery_verify(self) -> tuple[bool, str]:
        if self.recovery_path is None:
            return (not self._emergency_memory, "memory-only" if self._emergency_memory else "empty")
        valid, last_hash, reason = self._scan_path(self.recovery_path)
        with self._lock:
            if valid:
                self._recovery_last_hash = last_hash
                self._recovery_error = ""
            else:
                self._recovery_error = reason
        return valid, reason

    def status(self) -> dict[str, Any]:
        recovery_valid, recovery_reason = self.recovery_verify()
        return {
            "mode": self._mode.value,
            "failure_policy": self.failure_policy.value,
            "primary_integrity_error": self._integrity_error,
            "primary_appendable": not bool(self._integrity_error),
            "recovery_path": "" if self.recovery_path is None else str(self.recovery_path),
            "recovery_valid": bool(recovery_valid),
            "recovery_reason": recovery_reason,
            "recovery_error": self._recovery_error,
            "emergency_memory_events": len(self._emergency_memory),
            "operational_appendable": self.appendable,
        }

    @property
    def appendable(self) -> bool:
        if not self._integrity_error:
            return True
        return self.failure_policy is AuditFailurePolicy.FAIL_OPERATIONAL

    @property
    def integrity_error(self) -> str:
        return self._integrity_error

    @property
    def mode(self) -> AuditMode:
        return self._mode
