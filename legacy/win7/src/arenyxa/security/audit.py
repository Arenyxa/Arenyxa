from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import asdict, field
from pathlib import Path
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.security.models import TrustDomain


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
    









    ALGORITHM = "sha256-chain-v1"
    MAX_LINE_BYTES = 1024 * 1024

    def __init__(self, path: Path | None = None) -> None:
        self.path = None if path is None else Path(path)
        self._lock = threading.Lock()
        self._memory: list[dict[str, Any]] = []
        self._last_hash = ""
        self._integrity_error = ""
        if self.path is not None:
            valid, last_hash, reason = self._scan_file()
            if valid:
                self._last_hash = last_hash
            else:
                self._integrity_error = reason

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

    def _scan_file(self) -> tuple[bool, str, str]:
        if self.path is None or not self.path.exists():
            return True, "", "empty"
        previous = ""
        index = 0
        try:
            with self.path.open("rb") as stream:
                while True:
                    raw = stream.readline(self.MAX_LINE_BYTES + 1)
                    if not raw:
                        break
                    if len(raw) > self.MAX_LINE_BYTES:
                        return False, previous, f"row {index} exceeds maximum audit line size"
                    if not raw.strip():
                        return False, previous, f"row {index} is blank"
                    try:
                        value = json.loads(raw.decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        return False, previous, f"row {index} is invalid: {type(exc).__name__}: {exc}"
                    if not isinstance(value, dict):
                        return False, previous, f"row {index} is not an object"
                    valid, previous, reason = self._verify_row(value, previous, index)
                    if not valid:
                        return False, previous, reason
                    index += 1
        except (OSError, TypeError, ValueError) as exc:
            return False, previous, f"audit verification failed: {type(exc).__name__}: {exc}"
        return True, previous, "empty" if index == 0 else "ok"

    def record(self, event: AuditEvent) -> AuditEvent:
        with self._lock:
            if self._integrity_error:
                raise ArenyxaError(
                    "AUDIT_INTEGRITY_BROKEN",
                    "security audit log integrity is broken; refusing to append a new chain",
                    domain="SECURITY",
                    context={"reason": self._integrity_error},
                )
            event.integrity_metadata = {
                "algorithm": self.ALGORITHM,
                "previous_hash": self._last_hash,
            }
            payload = asdict(event)
            event_hash = self._hash(payload)
            event.integrity_metadata["event_hash"] = event_hash
            row = asdict(event)
            if self.path is None:
                self._memory.append(row)
            else:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                encoded = (
                    json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str) + "\n"
                ).encode("utf-8")
                with self.path.open("ab") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            self._last_hash = event_hash
            return event

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
            else:
                self._integrity_error = reason
        return valid, reason

    @property
    def appendable(self) -> bool:
        return not bool(self._integrity_error)

    @property
    def integrity_error(self) -> str:
        return self._integrity_error
