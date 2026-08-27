from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
from contextlib import contextmanager
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arenyxa import __compat_version__
from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Task, new_id, utc_now
from arenyxa.enterprise.governance import EnterpriseGovernanceService
from arenyxa.enterprise.runtime_storage import DistributedRuntimeStorageBackend, storage_backend_for
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.application.runner import RunOrchestrator

DISTRIBUTED_SCHEMA = "arenyxa.enterprise-distributed/v1"
CURRENT_PROTOCOL = 2
MIN_COMPATIBLE_PROTOCOL = 1
MAX_JOB_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_CHECKPOINT_BYTES = 128 * 1024
MAX_RESOURCE_DECLARATION_BYTES = 64 * 1024
MAX_JOBS = 100_000
MAX_WORKERS = 4096
MAX_CHALLENGES = 4096
MAX_WORKER_SESSIONS = 4096
MAX_WORKER_SLOTS = 64
MAX_JOB_EVENTS_PER_JOB = 128
MAX_EVENT_DETAILS_BYTES = 16 * 1024
DEFAULT_LEASE_SECONDS = 60
MAX_LEASE_SECONDS = 15 * 60
WORKER_SESSION_TTL_SECONDS = 15 * 60
CHALLENGE_TTL_SECONDS = 120

LOGGER = logging.getLogger(__name__)


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE_DISTRIBUTED", context=context)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _bounded_json(value: Mapping[str, Any], max_bytes: int, label: str) -> tuple[str, str]:
    if not isinstance(value, Mapping):
        raise _fail("DISTRIBUTED_PAYLOAD_INVALID", f"{label} must be a JSON object")
    raw = _canonical(dict(value))
    if len(raw) > max_bytes:
        raise _fail("DISTRIBUTED_PAYLOAD_TOO_LARGE", f"{label} exceeds the safety limit", bytes=len(raw), limit=max_bytes)
    return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()


def _load_json(text: str, max_bytes: int, label: str) -> dict[str, Any]:
    raw = str(text).encode("utf-8")
    if len(raw) > max_bytes:
        raise _fail("DISTRIBUTED_STATE_CORRUPT", f"{label} exceeds the safety limit")
    def no_duplicates(pairs):
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _fail("DISTRIBUTED_STATE_CORRUPT", f"{label} cannot be decoded") from exc
    if not isinstance(value, dict):
        raise _fail("DISTRIBUTED_STATE_CORRUPT", f"{label} must be an object")
    return value


def _clean_token(value: str, label: str, max_len: int = 160) -> str:
    text = str(value).strip()
    if (
        not text
        or len(text) > max_len
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in text)
    ):
        raise _fail("DISTRIBUTED_IDENTIFIER_INVALID", f"{label} is invalid")
    return text


def _b64u_decode(value: str, *, expected: int | None = None, max_bytes: int = 512) -> bytes:
    text = str(value).strip()
    if not text or "=" in text or len(text) > max_bytes * 2:
        raise _fail("DISTRIBUTED_KEY_INVALID", "base64url value is invalid")
    try:
        data = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    except Exception as exc:
        raise _fail("DISTRIBUTED_KEY_INVALID", "base64url value cannot be decoded") from exc
    if len(data) > max_bytes:
        raise _fail("DISTRIBUTED_KEY_INVALID", "decoded value exceeds safety limit")
    canonical = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    if not hmac.compare_digest(canonical, text):
        raise _fail("DISTRIBUTED_KEY_INVALID", "base64url value is not canonical")
    if expected is not None and len(data) != expected:
        raise _fail("DISTRIBUTED_KEY_INVALID", "decoded value has an unexpected length")
    return data


def negotiate_protocol(peer_min: int, peer_max: int) -> int:
    low = max(MIN_COMPATIBLE_PROTOCOL, int(peer_min))
    high = min(CURRENT_PROTOCOL, int(peer_max))
    if low > high:
        raise _fail(
            "PROTOCOL_INCOMPATIBLE",
            "No compatible Arenyxa Enterprise protocol version is available",
            server_min=MIN_COMPATIBLE_PROTOCOL,
            server_max=CURRENT_PROTOCOL,
            peer_min=int(peer_min),
            peer_max=int(peer_max),
        )
    return high


def verify_enterprise_server_identity(artifact: Mapping[str, Any], expected_root_fingerprint: str, peer_cert_der: bytes) -> dict[str, Any]:
    
    required = {
        "schema", "enterprise_id", "server_id", "tls_certificate_sha256", "protocol_min",
        "protocol_max", "issued_at", "expires_at", "root_public_key", "root_fingerprint", "signature",
    }
    if set(artifact) != required or artifact.get("schema") != "arenyxa.enterprise-server-identity/v1":
        raise _fail("SERVER_IDENTITY_INVALID", "Enterprise Server identity schema is invalid")
    expected_fp = str(expected_root_fingerprint).strip().casefold()
    actual_fp = str(artifact.get("root_fingerprint", "")).strip().casefold()
    if len(expected_fp) != 64 or not hmac.compare_digest(expected_fp, actual_fp):
        raise _fail("SERVER_IDENTITY_UNTRUSTED", "Enterprise Server Root fingerprint does not match the expected Enterprise")
    public_raw = _b64u_decode(str(artifact.get("root_public_key", "")), expected=32)
    if not hmac.compare_digest(hashlib.sha256(public_raw).hexdigest(), actual_fp):
        raise _fail("SERVER_IDENTITY_UNTRUSTED", "Enterprise Server Root fingerprint/public key binding is invalid")
    cert_hash = hashlib.sha256(bytes(peer_cert_der)).hexdigest()
    if not hmac.compare_digest(cert_hash, str(artifact.get("tls_certificate_sha256", "")).casefold()):
        raise _fail("SERVER_TLS_BINDING_INVALID", "Enterprise Server identity is not bound to this TLS certificate")
    try:
        issued = datetime.fromisoformat(str(artifact.get("issued_at", "")).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(artifact.get("expires_at", "")).replace("Z", "+00:00"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise _fail("SERVER_IDENTITY_TIME_INVALID", "Enterprise Server identity time fields are invalid") from exc
    if issued.tzinfo is None or expires.tzinfo is None:
        raise _fail("SERVER_IDENTITY_TIME_INVALID", "Enterprise Server identity time fields require a timezone")
    issued = issued.astimezone(timezone.utc)
    expires = expires.astimezone(timezone.utc)
    now = datetime.now(timezone.utc)
    if issued > now + timedelta(minutes=5) or expires <= issued or (expires - issued) > timedelta(days=8):
        raise _fail("SERVER_IDENTITY_TIME_INVALID", "Enterprise Server identity validity window is invalid")
    if expires <= now:
        raise _fail("SERVER_IDENTITY_EXPIRED", "Enterprise Server identity has expired")
    negotiate_protocol(int(artifact.get("protocol_min", 0)), int(artifact.get("protocol_max", 0)))
    signed = {key: value for key, value in artifact.items() if key not in {"signature", "root_public_key", "root_fingerprint"}}
    signature = _b64u_decode(str(artifact.get("signature", "")), expected=64)
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, _canonical(signed))
    except InvalidSignature as exc:
        raise _fail("SERVER_IDENTITY_SIGNATURE_INVALID", "Enterprise Server identity signature is invalid") from exc
    return dict(artifact)


@dataclass(frozen=True, slots=True)
class DistributedLease:
    job_id: str
    worker_id: str
    lease_token: str
    lease_expires_at: float
    kind: str
    payload: dict[str, Any]
    resource_id: str
    permission: str
    attempt: int
    max_attempts: int
    side_effect_mode: str
    checkpoint: dict[str, Any]
    checkpoint_seq: int
    protocol_version: int


class _NoopLock:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class DurableDistributedQueue:
    





    def __init__(
        self, path: Path | str, *, storage_backend: DistributedRuntimeStorageBackend | None = None
    ) -> None:
        self.path = path
        self._storage = storage_backend or storage_backend_for(path)
        if not self._storage.capabilities.external_server:
            Path(str(path)).parent.mkdir(parents=True, exist_ok=True)
                                                                                                  
                                                                                                
                                                                           
        self._lock = _NoopLock() if self._storage.capabilities.multi_host_writers else threading.Lock()
        self._expiry_scan_lock = threading.Lock()
        self._expiry_scan_interval_seconds = 0.5
        self._last_expiry_scan_monotonic = 0.0
        self._health_lock = threading.Lock()
        self._health_integrity_checked_at = 0.0
        self._health_integrity_result: tuple[bool, str] = (False, "not_checked")
        self._health_event_count_checked_at = 0.0
        self._health_event_count = 0
        self.initialize()

    @contextmanager
    def _connection(self):
        with self._storage.connection() as connection:
            yield connection

    @contextmanager
    def _connect(self):
        with self._connection() as connection:
            yield connection

    def initialize(self) -> None:
        with self._lock:
            self._storage.initialize_schema(DISTRIBUTED_SCHEMA, CURRENT_PROTOCOL, MIN_COMPATIBLE_PROTOCOL)
        self._last_reconciliation = self.reconcile_durable_state()
        self._last_reconciliation["expired_leases_recovered"] = self.recover_expired_leases()

    @property
    def storage_capabilities(self) -> dict[str, Any]:
        return self._storage.capabilities.as_dict()

    def _record_event_locked(
        self, connection: Any, job_id: str, event_type: str,
        from_state: str, to_state: str, *, worker_id: str = "", code: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        event = _clean_token(event_type, "event type", 96)
        detail_json, _ = _bounded_json(details or {}, MAX_EVENT_DETAILS_BYTES, "distributed event details")
        connection.execute(
            """INSERT INTO distributed_job_events(
                job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
            ) VALUES(?,?,?,?,?,?,?,?)""",
            (str(job_id), event, str(from_state), str(to_state), str(worker_id), str(code)[:128], detail_json, utc_now()),
        )
                                                                                                 
                                                                                                    
        connection.execute(
            """DELETE FROM distributed_job_events WHERE job_id=? AND event_id NOT IN (
                SELECT event_id FROM distributed_job_events WHERE job_id=? ORDER BY event_id DESC LIMIT ?
            )""",
            (str(job_id), str(job_id), MAX_JOB_EVENTS_PER_JOB),
        )

    @staticmethod
    def _recovery_target(row: Mapping[str, Any], *, exhausted_code: str) -> tuple[str, str]:
        if str(row["side_effect_mode"]) == "non_idempotent" and str(row["side_effect_state"]) == "started":
            return "review_required", "LEASE_STATE_LOST_AFTER_SIDE_EFFECT_START"
        if int(row["attempt"]) < int(row["max_attempts"]):
            return "queued", "LEASE_STATE_RECONCILED"
        return "failed", exhausted_code

    def reconcile_durable_state(self) -> dict[str, int]:
        






        summary = {"worker_counters_repaired": 0, "leases_recovered": 0}
        current_wall = time.time()
        with self._lock, self._connection() as connection:
            self._begin(connection)
            invalid = connection.execute(
                self._storage.invalid_lease_candidates_sql(),
                (current_wall + MAX_LEASE_SECONDS + 60.0,),
            ).fetchall()
            for row in invalid:
                target, code = self._recovery_target(row, exhausted_code="LEASE_STATE_INVALID_MAX_ATTEMPTS")
                previous = str(row["state"])
                connection.execute(
                    """UPDATE distributed_jobs SET state=?,lease_worker_id='',lease_token_sha256='',
                       lease_expires_at=0,error_code=?,updated_at=? WHERE job_id=?""",
                    (target, code, utc_now(), str(row["job_id"])),
                )
                self._record_event_locked(
                    connection, str(row["job_id"]), "lease_reconciled", previous, target,
                    worker_id=str(row["lease_worker_id"]), code=code,
                )
                summary["leases_recovered"] += 1
                                                                                               
                                                                                                
                                                 
            active_by_worker = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    """SELECT lease_worker_id,count(*) FROM distributed_jobs
                       WHERE state IN ('leased','running') AND lease_worker_id<>''
                       GROUP BY lease_worker_id"""
                ).fetchall()
            }
            workers = connection.execute("SELECT worker_id,active_leases FROM distributed_workers").fetchall()
            for worker in workers:
                worker_id = str(worker["worker_id"])
                actual = active_by_worker.get(worker_id, 0)
                if actual != int(worker["active_leases"]):
                    connection.execute(
                        "UPDATE distributed_workers SET active_leases=?,updated_at=? WHERE worker_id=?",
                        (actual, utc_now(), worker_id),
                    )
                    summary["worker_counters_repaired"] += 1
            connection.commit()
        self._last_reconciliation = dict(summary)
        return summary

    def job_events(self, job_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
        cap = max(1, min(MAX_JOB_EVENTS_PER_JOB, int(limit)))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM distributed_job_events WHERE job_id=? ORDER BY event_id DESC LIMIT ?",
                (str(job_id), cap),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            events.append({
                "event_id": int(row["event_id"]), "job_id": str(row["job_id"]),
                "event_type": str(row["event_type"]), "from_state": str(row["from_state"]),
                "to_state": str(row["to_state"]), "worker_id": str(row["worker_id"]),
                "code": str(row["code"]),
                "details": _load_json(str(row["details_json"]), MAX_EVENT_DETAILS_BYTES, "distributed event details"),
                "created_at": str(row["created_at"]),
            })
        return events

    def integrity_check(self) -> tuple[bool, str]:
        return self._storage.integrity_check()

    def _begin(self, connection: Any) -> None:
        self._storage.begin_write(connection)

    def _job_count_guard(self, connection: Any) -> None:
        count = int(connection.execute("SELECT count(*) FROM distributed_jobs").fetchone()[0])
        if count >= MAX_JOBS:
            raise _fail("DISTRIBUTED_QUEUE_FULL", "Distributed job queue reached its configured safety bound")

    def job_for_idempotency(self, key: str) -> dict[str, Any] | None:
        token = _clean_token(key, "idempotency key", 192)
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM distributed_jobs WHERE idempotency_key=?", (token,)).fetchone()
            return None if row is None else self._job_row(row)

    def enqueue(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        resource_id: str,
        permission: str,
        idempotency_key: str,
        side_effect_mode: str = "idempotent",
        max_attempts: int = 3,
        priority: int = 0,
        protocol_version: int = CURRENT_PROTOCOL,
    ) -> str:
        kind_id = _clean_token(kind, "job kind")
        resource = _clean_token(resource_id, "resource id", 256)
        capability = _clean_token(permission, "permission", 128)
        idem = _clean_token(idempotency_key, "idempotency key", 192)
        mode = str(side_effect_mode).strip().casefold()
        if mode not in {"idempotent", "non_idempotent"}:
            raise _fail("DISTRIBUTED_SIDE_EFFECT_MODE_INVALID", "side_effect_mode must be idempotent or non_idempotent")
        attempts = max(1, min(20, int(max_attempts)))
        protocol = int(protocol_version)
        if protocol < MIN_COMPATIBLE_PROTOCOL or protocol > CURRENT_PROTOCOL:
            raise _fail("PROTOCOL_INCOMPATIBLE", "Job protocol version is outside the supported window")
        payload_json, payload_sha = _bounded_json(payload, MAX_JOB_PAYLOAD_BYTES, "job payload")
        job_id = new_id("job")
        now = utc_now()
        with self._lock, self._connection() as connection:
            self._begin(connection)
            existing = connection.execute(
                "SELECT job_id,kind,payload_sha256,resource_id,permission FROM distributed_jobs WHERE idempotency_key=?",
                (idem,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["kind"]) == kind_id
                    and str(existing["payload_sha256"]) == payload_sha
                    and str(existing["resource_id"]) == resource
                    and str(existing["permission"]) == capability
                ):
                    connection.commit()
                    return str(existing["job_id"])
                connection.rollback()
                raise _fail("DISTRIBUTED_IDEMPOTENCY_COLLISION", "Idempotency key was already used for a different job")
            self._job_count_guard(connection)
            connection.execute(
                """INSERT INTO distributed_jobs(
                    job_id,kind,state,payload_json,payload_sha256,resource_id,permission,idempotency_key,
                    side_effect_mode,side_effect_state,attempt,max_attempts,protocol_version,priority,
                    checkpoint_json,result_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, kind_id, "queued", payload_json, payload_sha, resource, capability, idem,
                    mode, "none", 0, attempts, protocol, max(-1000, min(1000, int(priority))),
                    "{}", "{}", now, now,
                ),
            )
            self._record_event_locked(connection, job_id, "enqueued", "", "queued", details={
                "kind": kind_id, "side_effect_mode": mode, "protocol_version": protocol,
            })
            connection.commit()
        return job_id

    def _worker_row(self, row: Any) -> dict[str, Any]:
        resources = _load_json(str(row["resources_json"]), MAX_RESOURCE_DECLARATION_BYTES, "worker resources")
        return {
            "worker_id": str(row["worker_id"]), "display_name": str(row["display_name"]),
            "public_key": str(row["public_key"]), "protocol_min": int(row["protocol_min"]),
            "protocol_max": int(row["protocol_max"]), "negotiated_protocol": int(row["negotiated_protocol"]),
            "app_compat_version": str(row["app_compat_version"]), "resources": resources,
            "max_slots": int(row["max_slots"]), "active_leases": int(row["active_leases"]),
            "state": str(row["state"]), "heartbeat_at": float(row["heartbeat_at"]),
            "created_at": str(row["created_at"]), "updated_at": str(row["updated_at"]),
            "revoked_at": str(row["revoked_at"]),
        }

    def register_worker(
        self,
        worker_id: str,
        public_key_b64: str,
        resources: Mapping[str, Any],
        *,
        display_name: str = "",
        protocol_min: int = MIN_COMPATIBLE_PROTOCOL,
        protocol_max: int = CURRENT_PROTOCOL,
        app_compat_version: str = __compat_version__,
        max_slots: int = 1,
    ) -> dict[str, Any]:
        worker = _clean_token(worker_id, "worker id")
        _b64u_decode(public_key_b64, expected=32)
        negotiated = negotiate_protocol(protocol_min, protocol_max)
        resources_json, _ = _bounded_json(resources, MAX_RESOURCE_DECLARATION_BYTES, "worker resource declaration")
        slots = max(1, min(MAX_WORKER_SLOTS, int(max_slots)))
        now_iso = utc_now()
        now = time.time()
        with self._lock, self._connection() as connection:
            self._begin(connection)
            existing = connection.execute("SELECT * FROM distributed_workers WHERE worker_id=?", (worker,)).fetchone()
            if existing is None:
                count = int(connection.execute("SELECT count(*) FROM distributed_workers").fetchone()[0])
                if count >= MAX_WORKERS:
                    connection.rollback()
                    raise _fail("DISTRIBUTED_WORKER_LIMIT", "Worker registry reached its safety bound")
                connection.execute(
                    """INSERT INTO distributed_workers(
                        worker_id,display_name,public_key,protocol_min,protocol_max,negotiated_protocol,
                        app_compat_version,resources_json,max_slots,active_leases,state,created_at,updated_at,heartbeat_at,revoked_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        worker, str(display_name).strip()[:160] or worker, str(public_key_b64), int(protocol_min),
                        int(protocol_max), negotiated, str(app_compat_version)[:64], resources_json, slots, 0,
                        "active", now_iso, now_iso, now, "",
                    ),
                )
            else:
                if str(existing["state"]) == "revoked":
                    connection.rollback()
                    raise _fail("WORKER_REVOKED", "Revoked worker identity cannot re-register without administrator recovery")
                if not hmac.compare_digest(str(existing["public_key"]), str(public_key_b64)):
                    connection.rollback()
                    raise _fail("WORKER_IDENTITY_MISMATCH", "Worker ID is already bound to another public key")
                connection.execute(
                    """UPDATE distributed_workers SET display_name=?,protocol_min=?,protocol_max=?,negotiated_protocol=?,
                       app_compat_version=?,resources_json=?,max_slots=?,updated_at=?,heartbeat_at=? WHERE worker_id=?""",
                    (
                        str(display_name).strip()[:160] or worker, int(protocol_min), int(protocol_max), negotiated,
                        str(app_compat_version)[:64], resources_json, slots, now_iso, now, worker,
                    ),
                )
            row = connection.execute("SELECT * FROM distributed_workers WHERE worker_id=?", (worker,)).fetchone()
            connection.commit()
        assert row is not None
        return self._worker_row(row)

    def worker(self, worker_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM distributed_workers WHERE worker_id=?", (str(worker_id),)).fetchone()
            return None if row is None else self._worker_row(row)

    def list_workers(self, limit: int = 500) -> list[dict[str, Any]]:
        cap = max(1, min(2000, int(limit)))
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM distributed_workers ORDER BY updated_at DESC LIMIT ?", (cap,)).fetchall()
        return [self._worker_row(row) for row in rows]

    def heartbeat(self, worker_id: str, *, resources: Mapping[str, Any] | None = None) -> None:
        now = time.time()
        now_iso = utc_now()
        resources_json = None
        if resources is not None:
            resources_json, _ = _bounded_json(resources, MAX_RESOURCE_DECLARATION_BYTES, "worker resource declaration")
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = connection.execute("SELECT state FROM distributed_workers WHERE worker_id=?", (str(worker_id),)).fetchone()
            if row is None:
                connection.rollback()
                raise _fail("WORKER_UNKNOWN", "Worker is not registered")
            if str(row["state"]) == "revoked":
                connection.rollback()
                raise _fail("WORKER_REVOKED", "Worker is revoked")
            if resources_json is None:
                connection.execute("UPDATE distributed_workers SET heartbeat_at=?,updated_at=? WHERE worker_id=?", (now, now_iso, str(worker_id)))
            else:
                connection.execute(
                    "UPDATE distributed_workers SET heartbeat_at=?,updated_at=?,resources_json=? WHERE worker_id=?",
                    (now, now_iso, resources_json, str(worker_id)),
                )
            connection.commit()

    def set_worker_drain(self, worker_id: str, drain: bool = True) -> None:
        target = "draining" if drain else "active"
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = connection.execute("SELECT state FROM distributed_workers WHERE worker_id=?", (str(worker_id),)).fetchone()
            if row is None:
                connection.rollback()
                raise _fail("WORKER_UNKNOWN", "Worker is not registered")
            if str(row["state"]) == "revoked":
                connection.rollback()
                raise _fail("WORKER_REVOKED", "Revoked worker cannot be undrained")
            connection.execute("UPDATE distributed_workers SET state=?,updated_at=? WHERE worker_id=?", (target, utc_now(), str(worker_id)))
            connection.commit()

    def revoke_worker(self, worker_id: str) -> int:
        worker = str(worker_id)
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = connection.execute("SELECT state FROM distributed_workers WHERE worker_id=?", (worker,)).fetchone()
            if row is None:
                connection.rollback()
                raise _fail("WORKER_UNKNOWN", "Worker is not registered")
            connection.execute(
                "UPDATE distributed_workers SET state='revoked',revoked_at=?,updated_at=?,active_leases=0 WHERE worker_id=?",
                (utc_now(), utc_now(), worker),
            )
            affected = self._recover_worker_jobs_locked(connection, worker, "WORKER_REVOKED")
            connection.commit()
            return affected

    def _recover_worker_jobs_locked(self, connection: Any, worker_id: str, error_code: str) -> int:
        rows = connection.execute(
            """SELECT job_id,state,side_effect_mode,side_effect_state,attempt,max_attempts
               FROM distributed_jobs WHERE lease_worker_id=? AND state IN ('leased','running')""",
            (worker_id,),
        ).fetchall()
        for row in rows:
            mode = str(row["side_effect_mode"])
            effect = str(row["side_effect_state"])
            attempt = int(row["attempt"])
            max_attempts = int(row["max_attempts"])
            if mode == "non_idempotent" and effect == "started":
                state = "review_required"
            elif attempt < max_attempts:
                state = "queued"
            else:
                state = "failed"
            previous = str(row["state"])
            connection.execute(
                """UPDATE distributed_jobs SET state=?,lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                   error_code=?,updated_at=? WHERE job_id=?""",
                (state, error_code, utc_now(), str(row["job_id"])),
            )
            self._record_event_locked(
                connection, str(row["job_id"]), "worker_lease_recovered", previous, state,
                worker_id=str(worker_id), code=str(error_code),
            )
        return len(rows)

    def recover_expired_leases(self, now: float | None = None) -> int:
        current = time.time() if now is None else float(now)
        with self._lock, self._connection() as connection:
            self._begin(connection)
            rows = connection.execute(
                self._storage.expired_lease_candidates_sql(),
                (current,),
            ).fetchall()
            affected = 0
            recovered_by_worker: dict[str, int] = {}
            for row in rows:
                worker = str(row["lease_worker_id"])
                mode = str(row["side_effect_mode"])
                effect = str(row["side_effect_state"])
                if mode == "non_idempotent" and effect == "started":
                    state = "review_required"
                    code = "LEASE_LOST_AFTER_SIDE_EFFECT_START"
                elif int(row["attempt"]) < int(row["max_attempts"]):
                    state = "queued"
                    code = "LEASE_EXPIRED_REQUEUED"
                else:
                    state = "failed"
                    code = "LEASE_EXPIRED_MAX_ATTEMPTS"
                previous = str(row["state"])
                connection.execute(
                    """UPDATE distributed_jobs SET state=?,lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                       error_code=?,updated_at=? WHERE job_id=?""",
                    (state, code, utc_now(), str(row["job_id"])),
                )
                self._record_event_locked(
                    connection, str(row["job_id"]), "lease_expired", previous, state,
                    worker_id=worker, code=code,
                )
                recovered_by_worker[worker] = recovered_by_worker.get(worker, 0) + 1
                affected += 1
            for worker, recovered in recovered_by_worker.items():
                connection.execute(
                    "UPDATE distributed_workers SET active_leases=max(0,active_leases-?),updated_at=? WHERE worker_id=?",
                    (recovered, utc_now(), worker),
                )
            connection.commit()
                                                                                                  
                                                                                           
        if now is None:
            self._last_expiry_scan_monotonic = time.monotonic()
        return affected

    def _recover_expired_leases_if_due(self) -> int:
        
        now = time.monotonic()
        if now - self._last_expiry_scan_monotonic < self._expiry_scan_interval_seconds:
            return 0
        if not self._expiry_scan_lock.acquire(blocking=False):
            return 0
        try:
            now = time.monotonic()
            if now - self._last_expiry_scan_monotonic < self._expiry_scan_interval_seconds:
                return 0
            return self.recover_expired_leases()
        finally:
            self._expiry_scan_lock.release()

    def lease_next(self, worker_id: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> DistributedLease | None:
        worker = str(worker_id)
        duration = max(15, min(MAX_LEASE_SECONDS, int(lease_seconds)))
        self._recover_expired_leases_if_due()
        with self._lock, self._connection() as connection:
            self._begin(connection)
            worker_row = connection.execute(self._storage.worker_for_lease_sql(), (worker,)).fetchone()
            if worker_row is None:
                connection.rollback()
                raise _fail("WORKER_UNKNOWN", "Worker is not registered")
            if str(worker_row["state"]) != "active":
                connection.rollback()
                if str(worker_row["state"]) == "revoked":
                    raise _fail("WORKER_REVOKED", "Worker is revoked")
                return None
            if int(worker_row["active_leases"]) >= int(worker_row["max_slots"]):
                connection.rollback()
                return None
            protocol_min = int(worker_row["protocol_min"])
            protocol_max = int(worker_row["protocol_max"])
            row = connection.execute(
                self._storage.lease_candidate_sql(),
                (protocol_min, protocol_max),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            token = secrets.token_urlsafe(32)
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            expires = time.time() + duration
            job_id = str(row["job_id"])
            attempt = int(row["attempt"]) + 1
            updated_at = utc_now()
            cursor = connection.execute(
                """UPDATE distributed_jobs SET state='leased',attempt=attempt+1,lease_worker_id=?,lease_token_sha256=?,
                   lease_expires_at=?,error_code='',updated_at=? WHERE job_id=? AND state='queued'""",
                (worker, digest, expires, updated_at, job_id),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                return None
            slot_cursor = connection.execute(
                self._storage.claim_worker_slot_sql(),
                (time.time(), updated_at, worker),
            )
            if slot_cursor.rowcount != 1:
                connection.rollback()
                return None
            self._record_event_locked(
                connection, job_id, "leased", "queued", "leased", worker_id=worker,
                details={"attempt": attempt, "lease_seconds": duration},
            )
            connection.commit()
        return DistributedLease(
            job_id=job_id,
            worker_id=worker,
            lease_token=token,
            lease_expires_at=expires,
            kind=str(row["kind"]),
            payload=_load_json(str(row["payload_json"]), MAX_JOB_PAYLOAD_BYTES, "job payload"),
            resource_id=str(row["resource_id"]),
            permission=str(row["permission"]),
            attempt=attempt,
            max_attempts=int(row["max_attempts"]),
            side_effect_mode=str(row["side_effect_mode"]),
            checkpoint=_load_json(str(row["checkpoint_json"]), MAX_CHECKPOINT_BYTES, "job checkpoint"),
            checkpoint_seq=int(row["checkpoint_seq"]),
            protocol_version=int(row["protocol_version"]),
        )

    def _require_lease_locked(
        self, connection: Any, job_id: str, worker_id: str, lease_token: str,
    ) -> Any:
        row = connection.execute("SELECT * FROM distributed_jobs WHERE job_id=?", (str(job_id),)).fetchone()
        if row is None:
            raise _fail("DISTRIBUTED_JOB_UNKNOWN", "Distributed job does not exist")
        if str(row["state"]) not in {"leased", "running"} or str(row["lease_worker_id"]) != str(worker_id):
            raise _fail("DISTRIBUTED_LEASE_STALE", "Distributed job lease is no longer owned by this worker")
        expected = str(row["lease_token_sha256"])
        actual = hashlib.sha256(str(lease_token).encode("utf-8")).hexdigest()
        if not expected or not hmac.compare_digest(expected, actual):
            raise _fail("DISTRIBUTED_LEASE_STALE", "Distributed job lease token is invalid")
        if float(row["lease_expires_at"]) <= time.time():
            raise _fail("DISTRIBUTED_LEASE_EXPIRED", "Distributed job lease has expired")
        return row

    def start_job(self, job_id: str, worker_id: str, lease_token: str) -> None:
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token)
            previous = str(row["state"])
            if previous != "running":
                connection.execute("UPDATE distributed_jobs SET state='running',updated_at=? WHERE job_id=?", (utc_now(), str(job_id)))
                self._record_event_locked(connection, str(job_id), "started", previous, "running", worker_id=str(worker_id))
            connection.commit()

    def renew_lease(self, job_id: str, worker_id: str, lease_token: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> float:
        duration = max(15, min(MAX_LEASE_SECONDS, int(lease_seconds)))
        expires = time.time() + duration
        with self._lock, self._connection() as connection:
            self._begin(connection)
            self._require_lease_locked(connection, job_id, worker_id, lease_token)
            connection.execute(
                "UPDATE distributed_jobs SET lease_expires_at=?,updated_at=? WHERE job_id=?",
                (expires, utc_now(), str(job_id)),
            )
            connection.execute(
                "UPDATE distributed_workers SET heartbeat_at=?,updated_at=? WHERE worker_id=?",
                (time.time(), utc_now(), str(worker_id)),
            )
            connection.commit()
        return expires

    def checkpoint(self, job_id: str, worker_id: str, lease_token: str, checkpoint: Mapping[str, Any]) -> int:
        payload_json, _ = _bounded_json(checkpoint, MAX_CHECKPOINT_BYTES, "job checkpoint")
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token)
            sequence = int(row["checkpoint_seq"]) + 1
            connection.execute(
                "UPDATE distributed_jobs SET checkpoint_json=?,checkpoint_seq=?,updated_at=? WHERE job_id=?",
                (payload_json, sequence, utc_now(), str(job_id)),
            )
            connection.commit()
            return sequence

    def mark_side_effect_started(self, job_id: str, worker_id: str, lease_token: str) -> None:
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token)
            if str(row["side_effect_mode"]) == "non_idempotent" and str(row["side_effect_state"]) != "started":
                connection.execute(
                    "UPDATE distributed_jobs SET side_effect_state='started',updated_at=? WHERE job_id=?",
                    (utc_now(), str(job_id)),
                )
                self._record_event_locked(
                    connection, str(job_id), "side_effect_started", str(row["state"]), str(row["state"]),
                    worker_id=str(worker_id), code="NON_IDEMPOTENT_FENCE",
                )
            connection.commit()

    def complete(self, job_id: str, worker_id: str, lease_token: str, result: Mapping[str, Any]) -> None:
        result_json, result_sha = _bounded_json(result, MAX_RESULT_BYTES, "job result")
        token_sha = hashlib.sha256(str(lease_token).encode("utf-8")).hexdigest()
        with self._lock, self._connection() as connection:
            self._begin(connection)
            existing = connection.execute("SELECT * FROM distributed_jobs WHERE job_id=?", (str(job_id),)).fetchone()
            if existing is None:
                connection.rollback()
                raise _fail("DISTRIBUTED_JOB_UNKNOWN", "Distributed job does not exist")
            if str(existing["state"]) == "completed":
                                                                                                  
                                                                                             
                                                                                                   
                if (
                    str(existing["terminal_worker_id"]) == str(worker_id)
                    and hmac.compare_digest(str(existing["terminal_lease_token_sha256"]), token_sha)
                    and hmac.compare_digest(str(existing["result_sha256"]), result_sha)
                ):
                    connection.commit()
                    return
                connection.rollback()
                raise _fail(
                    "DISTRIBUTED_TERMINAL_CONFLICT",
                    "Completed job terminal receipt does not match the presented Worker/lease/result",
                )
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token)
            previous = str(row["state"])
            effect = "completed" if str(row["side_effect_state"]) == "started" else str(row["side_effect_state"])
            terminal_at = utc_now()
            connection.execute(
                """UPDATE distributed_jobs SET state='completed',result_json=?,result_sha256=?,side_effect_state=?,
                   terminal_worker_id=?,terminal_lease_token_sha256=?,terminal_at=?,lease_worker_id='',
                   lease_token_sha256='',lease_expires_at=0,error_code='',updated_at=? WHERE job_id=?""",
                (result_json, result_sha, effect, str(worker_id), token_sha, terminal_at, terminal_at, str(job_id)),
            )
            connection.execute(
                "UPDATE distributed_workers SET active_leases=max(0,active_leases-1),heartbeat_at=?,updated_at=? WHERE worker_id=?",
                (time.time(), utc_now(), str(worker_id)),
            )
            self._record_event_locked(
                connection, str(job_id), "completed", previous, "completed", worker_id=str(worker_id),
                details={"result_sha256": result_sha},
            )
            connection.commit()

    def fail(
        self, job_id: str, worker_id: str, lease_token: str, error_code: str,
        *, retryable: bool = True,
    ) -> str:
        code = _clean_token(error_code or "WORKER_EXECUTION_FAILED", "error code", 128)
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token)
            mode = str(row["side_effect_mode"])
            effect = str(row["side_effect_state"])
            attempt = int(row["attempt"])
            max_attempts = int(row["max_attempts"])
            if mode == "non_idempotent" and effect == "started":
                state = "review_required"
            elif bool(retryable) and attempt < max_attempts:
                state = "queued"
            else:
                state = "failed"
            previous = str(row["state"])
            connection.execute(
                """UPDATE distributed_jobs SET state=?,lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                   error_code=?,updated_at=? WHERE job_id=?""",
                (state, code, utc_now(), str(job_id)),
            )
            self._record_event_locked(
                connection, str(job_id), "execution_failed", previous, state, worker_id=str(worker_id), code=code,
                details={"retryable": bool(retryable), "attempt": attempt, "max_attempts": max_attempts},
            )
            connection.execute(
                "UPDATE distributed_workers SET active_leases=max(0,active_leases-1),heartbeat_at=?,updated_at=? WHERE worker_id=?",
                (time.time(), utc_now(), str(worker_id)),
            )
            connection.commit()
            return state

    def retry_review_required(self, job_id: str) -> None:
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = connection.execute("SELECT state,side_effect_state FROM distributed_jobs WHERE job_id=?", (str(job_id),)).fetchone()
            if row is None:
                connection.rollback()
                raise _fail("DISTRIBUTED_JOB_UNKNOWN", "Distributed job does not exist")
            if str(row["state"]) != "review_required":
                connection.rollback()
                raise _fail("DISTRIBUTED_JOB_STATE", "Only review-required jobs can be explicitly retried")
            connection.execute(
                "UPDATE distributed_jobs SET state='queued',side_effect_state='none',error_code='OPERATOR_RETRY_APPROVED',updated_at=? WHERE job_id=?",
                (utc_now(), str(job_id)),
            )
            self._record_event_locked(
                connection, str(job_id), "operator_retry", "review_required", "queued", code="OPERATOR_RETRY_APPROVED",
            )
            connection.commit()

    def _job_row(self, row: Any) -> dict[str, Any]:
        return {
            "job_id": str(row["job_id"]), "kind": str(row["kind"]), "state": str(row["state"]),
            "payload_sha256": str(row["payload_sha256"]), "resource_id": str(row["resource_id"]),
            "permission": str(row["permission"]), "idempotency_key": str(row["idempotency_key"]),
            "side_effect_mode": str(row["side_effect_mode"]), "side_effect_state": str(row["side_effect_state"]),
            "attempt": int(row["attempt"]), "max_attempts": int(row["max_attempts"]),
            "protocol_version": int(row["protocol_version"]), "priority": int(row["priority"]),
            "lease_worker_id": str(row["lease_worker_id"]), "lease_expires_at": float(row["lease_expires_at"]),
            "checkpoint": _load_json(str(row["checkpoint_json"]), MAX_CHECKPOINT_BYTES, "job checkpoint"),
            "checkpoint_seq": int(row["checkpoint_seq"]),
            "result": _load_json(str(row["result_json"]), MAX_RESULT_BYTES, "job result"),
            "result_sha256": str(row["result_sha256"]),
            "terminal_worker_id": str(row["terminal_worker_id"]),
            "terminal_at": str(row["terminal_at"]),
            "error_code": str(row["error_code"]), "created_at": str(row["created_at"]), "updated_at": str(row["updated_at"]),
        }

    def job(self, job_id: str, *, include_payload: bool = False) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM distributed_jobs WHERE job_id=?", (str(job_id),)).fetchone()
        if row is None:
            return None
        item = self._job_row(row)
        if include_payload:
            item["payload"] = _load_json(str(row["payload_json"]), MAX_JOB_PAYLOAD_BYTES, "job payload")
        return item

    def list_jobs(self, *, state: str = "", limit: int = 500) -> list[dict[str, Any]]:
        cap = max(1, min(2000, int(limit)))
        with self._connection() as connection:
            if state:
                rows = connection.execute(
                    "SELECT * FROM distributed_jobs WHERE state=? ORDER BY created_at DESC LIMIT ?", (str(state), cap)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM distributed_jobs ORDER BY created_at DESC LIMIT ?", (cap,)).fetchall()
        return [self._job_row(row) for row in rows]

    def health(self) -> dict[str, Any]:
                                                                                               
                                                                                               
                                                                                                 
                                       
        now_mono = time.monotonic()
        with self._health_lock:
            if (
                self._health_integrity_checked_at == 0.0
                or now_mono - self._health_integrity_checked_at >= 30.0
            ):
                self._health_integrity_result = self.integrity_check()
                self._health_integrity_checked_at = now_mono
            valid, detail = self._health_integrity_result
                                                                                               
                                                                                              
                                                                                              
                                                                  
            if (
                self._health_event_count_checked_at == 0.0
                or now_mono - self._health_event_count_checked_at >= 30.0
            ):
                with self._connection() as event_connection:
                    self._health_event_count = int(
                        event_connection.execute("SELECT count(*) FROM distributed_job_events").fetchone()[0]
                    )
                self._health_event_count_checked_at = now_mono
            event_count = self._health_event_count
        with self._connection() as connection:
                                                                                              
            job_rows = connection.execute(
                """SELECT state,count(*) AS state_count,
                   sum(CASE WHEN
                       (state IN ('leased','running') AND
                        (lease_worker_id='' OR lease_token_sha256='' OR lease_expires_at<=0)) OR
                       (state NOT IN ('leased','running') AND
                        (lease_worker_id<>'' OR lease_token_sha256<>'' OR lease_expires_at<>0))
                       THEN 1 ELSE 0 END) AS inconsistent_count,
                   sum(CASE WHEN state='completed' AND
                       (result_sha256='' OR terminal_worker_id='' OR
                        terminal_lease_token_sha256='' OR terminal_at='')
                       THEN 1 ELSE 0 END) AS unreceipted_count
                   FROM distributed_jobs GROUP BY state"""
            ).fetchall()
            states = {str(row["state"]): int(row["state_count"]) for row in job_rows}
            inconsistent_leases = sum(int(row["inconsistent_count"] or 0) for row in job_rows)
            unreceipted_completed = sum(int(row["unreceipted_count"] or 0) for row in job_rows)
            worker_states = {str(row[0]): int(row[1]) for row in connection.execute(
                "SELECT state,count(*) FROM distributed_workers GROUP BY state"
            ).fetchall()}
        return {
            "schema": DISTRIBUTED_SCHEMA,
            "protocol_current": CURRENT_PROTOCOL,
            "protocol_min": MIN_COMPATIBLE_PROTOCOL,
            "database_integrity": "ok" if valid else detail,
            "last_reconciliation": dict(getattr(self, "_last_reconciliation", {})),
            "state_invariants": {
                "inconsistent_lease_rows": inconsistent_leases,
                "unreceipted_completed_jobs": unreceipted_completed,
                "journal_events": event_count,
            },
            "jobs": states,
            "workers": worker_states,
        }


class EnterpriseServerRuntime:
    





    def __init__(
        self,
        identity: LocalEnterpriseIdentityService,
        governance: EnterpriseGovernanceService,
        data_root: Path,
        *,
        distributed_storage_target: Path | str | None = None,
    ) -> None:
        self.identity = identity
        self.governance = governance
        target = distributed_storage_target or (Path(data_root) / "enterprise" / "distributed.sqlite")
        self.queue = DurableDistributedQueue(target)
        self._lock = threading.Lock()
        self._challenges: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._service_lock = threading.Lock()
        self._service_lease = ""
        self._service_stop = threading.Event()
        self._service_thread = None
        self._service_ttl_seconds = 24 * 60 * 60

    def build_server_identity(self, tls_certificate_der: bytes, *, server_id: str = "", ttl_seconds: int = 24 * 60 * 60) -> dict[str, Any]:
        
        self.identity.require("enterprise.server.manage", "enterprise:server")
        self.identity.require_recent_step_up()
        cert = bytes(tls_certificate_der)
        if not cert or len(cert) > 256 * 1024:
            raise _fail("SERVER_TLS_CERT_INVALID", "Enterprise Server TLS certificate is empty or oversized")
        root = self.identity.root_public_identity()
        now = datetime.now(timezone.utc)
        payload = {
            "schema": "arenyxa.enterprise-server-identity/v1",
            "enterprise_id": str(root["enterprise_id"]),
            "server_id": _clean_token(server_id or new_id("server"), "server id"),
            "tls_certificate_sha256": hashlib.sha256(cert).hexdigest(),
            "protocol_min": MIN_COMPATIBLE_PROTOCOL,
            "protocol_max": CURRENT_PROTOCOL,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=max(300, min(7 * 24 * 60 * 60, int(ttl_seconds))))).isoformat(),
        }
        proof = self.identity.sign_enterprise_artifact(
            _canonical(payload), capability="enterprise.server.manage", resource="enterprise:server", step_up=False,
        )
        return {**payload, "root_public_key": proof["root_public_key"], "root_fingerprint": proof["root_fingerprint"], "signature": proof["signature"]}

    def activate_service(self, ttl_seconds: int = 24 * 60 * 60) -> str:
        
        ttl = max(300, min(24 * 60 * 60, int(ttl_seconds)))
        with self._service_lock:
            if self._service_lease:
                return self._service_lease
            lease = self.identity.issue_service_lease(
                "enterprise-server",
                ("governance", "enrollment", "server"),
                (
                    ("enterprise.server.manage", "enterprise:server"),
                    ("enterprise.worker.manage", "enterprise:workers"),
                    ("enterprise.remote_ops", "enterprise:distributed"),
                ),
                ttl_seconds=ttl,
            )
            self._service_lease = lease
            self._service_ttl_seconds = ttl
            self._service_stop.clear()
            thread = threading.Thread(
                target=self._service_lease_maintenance,
                name="arenyxa-enterprise-server-authority", daemon=True,
            )
            self._service_thread = thread
            thread.start()
            return lease

    def _service_lease_maintenance(self) -> None:
        while not self._service_stop.wait(max(60.0, min(3600.0, self._service_ttl_seconds / 3.0))):
            with self._service_lock:
                token = self._service_lease
                ttl = self._service_ttl_seconds
            if not token:
                return
            try:
                self.identity.renew_service_lease(token, "server", ttl_seconds=ttl)
            except Exception:
                                                                                                
                                                                                                    
                                                                                   
                LOGGER.exception("Enterprise Server service-lease renewal failed")

    def deactivate_service(self, reason: str = "SERVER_STOP") -> None:
        with self._service_lock:
            token = self._service_lease
            thread = self._service_thread
            self._service_lease = ""
            self._service_thread = None
            self._service_stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3.0)
        if token:
            self.identity.revoke_service_lease(token, reason=reason)

    def build_service_server_identity(
        self, tls_certificate_der: bytes, *, server_id: str, ttl_seconds: int = 6 * 60 * 60,
    ) -> dict[str, Any]:
        
        with self._service_lock:
            lease = self._service_lease
        if not lease:
            raise _fail("SERVER_SERVICE_INACTIVE", "Enterprise Server service authority is not active")
        cert = bytes(tls_certificate_der)
        if not cert or len(cert) > 256 * 1024:
            raise _fail("SERVER_TLS_CERT_INVALID", "Enterprise Server TLS certificate is empty or oversized")
        now = datetime.now(timezone.utc)
        payload = {
            "schema": "arenyxa.enterprise-server-identity/v1",
            "enterprise_id": "",
            "server_id": _clean_token(server_id, "server id"),
            "tls_certificate_sha256": hashlib.sha256(cert).hexdigest(),
            "protocol_min": MIN_COMPATIBLE_PROTOCOL,
            "protocol_max": CURRENT_PROTOCOL,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=max(300, min(7 * 24 * 60 * 60, int(ttl_seconds))))).isoformat(),
        }
                                                                                                    
                                                                  
        root = self.identity.root_public_identity()
        payload["enterprise_id"] = str(root["enterprise_id"])
        proof = self.identity.service_sign_enterprise_artifact(lease, "server", _canonical(payload))
        return {**payload, "root_public_key": proof["root_public_key"], "root_fingerprint": proof["root_fingerprint"], "signature": proof["signature"]}

    def register_worker(
        self, worker_id: str, public_key: str, resources: Mapping[str, Any], *, display_name: str = "",
        protocol_min: int = MIN_COMPATIBLE_PROTOCOL, protocol_max: int = CURRENT_PROTOCOL,
        app_compat_version: str = __compat_version__, max_slots: int = 1,
    ) -> dict[str, Any]:
        self.identity.require("enterprise.worker.manage", "enterprise:workers")
        self.identity.require_recent_step_up()                                                                                  
        return self.queue.register_worker(
            worker_id, public_key, resources, display_name=display_name, protocol_min=protocol_min,
            protocol_max=protocol_max, app_compat_version=app_compat_version, max_slots=max_slots,
        )

    def submit_task(
        self,
        task: Task,
        *,
        resource_id: str,
        permission: str,
        idempotency_key: str,
        approval_id: str = "",
        quota_metric: str = "",
        quota_amount: int = 0,
        side_effect_mode: str = "idempotent",
        max_attempts: int = 3,
        priority: int = 0,
    ) -> str:
        errors = task.validate()
        if errors:
            raise _fail("DISTRIBUTED_TASK_INVALID", "; ".join(errors[:8]))
        idem = _clean_token(idempotency_key, "idempotency key", 192)
        existing = self.queue.job_for_idempotency(idem)
        payload = {"task": task.to_dict(), "task_snapshot_sha256": task.snapshot_hash()}
        payload_json, payload_sha = _bounded_json(payload, MAX_JOB_PAYLOAD_BYTES, "job payload")
        if existing is not None:
            if existing["kind"] != "task.run" or existing["resource_id"] != resource_id or existing["permission"] != permission:
                raise _fail("DISTRIBUTED_IDEMPOTENCY_COLLISION", "Idempotency key is already bound to another operation")
                                                                             
            with self.queue._connect() as connection:
                row = connection.execute("SELECT payload_sha256 FROM distributed_jobs WHERE job_id=?", (existing["job_id"],)).fetchone()
            if row is None or not hmac.compare_digest(str(row[0]), payload_sha):
                raise _fail("DISTRIBUTED_IDEMPOTENCY_COLLISION", "Idempotency key payload does not match the original job")
            return str(existing["job_id"])
        decision = self.governance.authorize_operation(
            permission, resource_id, approval_id=approval_id, quota_metric=quota_metric, quota_amount=quota_amount,
        )
        try:
            return self.queue.enqueue(
                "task.run", json.loads(payload_json), resource_id=resource_id, permission=permission,
                idempotency_key=idem, side_effect_mode=side_effect_mode, max_attempts=max_attempts,
                priority=priority, protocol_version=CURRENT_PROTOCOL,
            )
        except Exception:
            reserved = int(decision.get("quota_reserved", 0))
            if quota_metric and quota_amount > 0 and reserved:
                try:
                    self.governance.release_for_operation(resource_id, permission, quota_metric, quota_amount)
                except Exception:
                                                                                                               
                    LOGGER.exception("Enterprise distributed enqueue failed and quota compensation also failed")
            raise

    def create_worker_challenge(self, worker_id: str) -> dict[str, Any]:
        worker = self.queue.worker(worker_id)
        if worker is None:
            raise _fail("WORKER_UNKNOWN", "Worker is not registered")
        if worker["state"] == "revoked":
            raise _fail("WORKER_REVOKED", "Worker is revoked")
        challenge_id = new_id("worker-challenge")
        nonce = secrets.token_bytes(32)
        expires = time.time() + CHALLENGE_TTL_SECONDS
        with self._lock:
            self._cleanup_auth_locked()
            if len(self._challenges) >= MAX_CHALLENGES:
                oldest = min(self._challenges.items(), key=lambda item: float(item[1]["created_at"]))[0]
                self._challenges.pop(oldest, None)
            self._challenges[challenge_id] = {
                "worker_id": str(worker_id), "nonce": nonce, "expires_at": expires, "created_at": time.time(),
                "protocol": int(worker["negotiated_protocol"]),
            }
        return {
            "schema": "arenyxa.enterprise-worker-challenge/v1",
            "challenge_id": challenge_id,
            "worker_id": str(worker_id),
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
            "expires_at": expires,
            "protocol": int(worker["negotiated_protocol"]),
        }

    @staticmethod
    def _challenge_message(challenge: Mapping[str, Any]) -> bytes:
        return _canonical({
            "schema": "arenyxa.enterprise-worker-challenge/v1",
            "challenge_id": str(challenge["challenge_id"]),
            "worker_id": str(challenge["worker_id"]),
            "nonce": str(challenge["nonce"]),
            "expires_at": float(challenge["expires_at"]),
            "protocol": int(challenge["protocol"]),
        })

    def authenticate_worker(self, challenge: Mapping[str, Any], signature_b64: str) -> dict[str, Any]:
        challenge_id = str(challenge.get("challenge_id", ""))
        with self._lock:
            self._cleanup_auth_locked()
            state = self._challenges.pop(challenge_id, None)
        if state is None:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge is missing, expired, or already consumed")
        if float(state["expires_at"]) <= time.time() or str(state["worker_id"]) != str(challenge.get("worker_id", "")):
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge binding is invalid")
        if str(challenge.get("schema", "")) != "arenyxa.enterprise-worker-challenge/v1":
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge schema is invalid")
        expected_nonce = base64.urlsafe_b64encode(bytes(state["nonce"])).decode("ascii").rstrip("=")
        if not hmac.compare_digest(expected_nonce, str(challenge.get("nonce", ""))):
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge nonce does not match")
        if int(challenge.get("protocol", -1)) != int(state["protocol"]):
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge protocol binding does not match")
        try:
            presented_expiry = float(challenge.get("expires_at", 0.0))
        except (TypeError, ValueError) as exc:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge expiry is invalid") from exc
        if abs(presented_expiry - float(state["expires_at"])) > 1e-6:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge expiry binding does not match")
        worker = self.queue.worker(str(state["worker_id"]))
        if worker is None or worker["state"] == "revoked":
            raise _fail("WORKER_REVOKED", "Worker identity is unavailable")
        public_raw = _b64u_decode(str(worker["public_key"]), expected=32)
        signature = _b64u_decode(signature_b64, expected=64)
        try:
            Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, self._challenge_message(challenge))
        except InvalidSignature as exc:
            raise _fail("WORKER_PROOF_INVALID", "Worker private-key proof failed") from exc
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        created_at = time.time()
        expires_at = created_at + WORKER_SESSION_TTL_SECONDS
        with self._lock:
            self._cleanup_auth_locked()
            if len(self._sessions) >= MAX_WORKER_SESSIONS:
                oldest = min(self._sessions.items(), key=lambda item: float(item[1]["created_at"]))[0]
                self._sessions.pop(oldest, None)
            self._sessions[digest] = {
                "worker_id": str(worker["worker_id"]), "protocol": int(worker["negotiated_protocol"]),
                "created_at": created_at, "expires_at": expires_at,
            }
        return {
            "schema": "arenyxa.enterprise-worker-session/v1", "session_token": token,
            "worker_id": str(worker["worker_id"]), "protocol": int(worker["negotiated_protocol"]),
            "expires_at": expires_at,
        }

    def _cleanup_auth_locked(self) -> None:
        now = time.time()
        self._challenges = {key: value for key, value in self._challenges.items() if float(value["expires_at"]) > now}
        self._sessions = {key: value for key, value in self._sessions.items() if float(value["expires_at"]) > now}

    def _worker_session(self, token: str) -> dict[str, Any]:
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        with self._lock:
            self._cleanup_auth_locked()
            session = self._sessions.get(digest)
            if session is None:
                raise _fail("WORKER_SESSION_INVALID", "Worker session is invalid or expired")
            return dict(session)

    def lease(self, session_token: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> DistributedLease | None:
        session = self._worker_session(session_token)
        return self.queue.lease_next(str(session["worker_id"]), lease_seconds=lease_seconds)

    def heartbeat_worker(self, session_token: str, resources: Mapping[str, Any] | None = None) -> None:
        session = self._worker_session(session_token)
        self.queue.heartbeat(str(session["worker_id"]), resources=resources)

    def checkpoint_worker(self, session_token: str, job_id: str, lease_token: str, checkpoint: Mapping[str, Any]) -> int:
        session = self._worker_session(session_token)
        return self.queue.checkpoint(job_id, str(session["worker_id"]), lease_token, checkpoint)

    def start_worker_job(self, session_token: str, job_id: str, lease_token: str) -> None:
        session = self._worker_session(session_token)
        self.queue.start_job(job_id, str(session["worker_id"]), lease_token)

    def renew_worker_lease(self, session_token: str, job_id: str, lease_token: str, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> float:
        session = self._worker_session(session_token)
        return self.queue.renew_lease(job_id, str(session["worker_id"]), lease_token, lease_seconds=lease_seconds)

    def mark_worker_side_effect_started(self, session_token: str, job_id: str, lease_token: str) -> None:
        session = self._worker_session(session_token)
        self.queue.mark_side_effect_started(job_id, str(session["worker_id"]), lease_token)

    def complete_worker_job(self, session_token: str, job_id: str, lease_token: str, result: Mapping[str, Any]) -> None:
        session = self._worker_session(session_token)
        self.queue.complete(job_id, str(session["worker_id"]), lease_token, result)

    def fail_worker_job(self, session_token: str, job_id: str, lease_token: str, error_code: str, retryable: bool = True) -> str:
        session = self._worker_session(session_token)
        return self.queue.fail(job_id, str(session["worker_id"]), lease_token, error_code, retryable=retryable)

    def set_worker_drain(self, worker_id: str, drain: bool = True) -> None:
        self.identity.require("enterprise.worker.manage", "enterprise:workers")
        self.queue.set_worker_drain(worker_id, drain)

    def revoke_worker(self, worker_id: str) -> int:
        self.identity.require("enterprise.worker.manage", "enterprise:workers")
        self.identity.require_recent_step_up()
        return self.queue.revoke_worker(worker_id)

    def retry_review_required(self, job_id: str) -> None:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        self.identity.require_recent_step_up()
        self.queue.retry_review_required(job_id)

    def remote_ops_snapshot(self) -> dict[str, Any]:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        return {
            "queue": self.queue.health(),
            "workers": self.queue.list_workers(limit=1000),
            "jobs": self.queue.list_jobs(limit=1000),
        }


class EnterpriseWorkerRuntime:
    

    def __init__(self, runner: RunOrchestrator, worker_id: str) -> None:
        self.runner = runner
        self.worker_id = _clean_token(worker_id, "worker id")

    @staticmethod
    def task_from_payload(payload: Mapping[str, Any]) -> Task:
        raw = payload.get("task")
        if not isinstance(raw, dict):
            raise _fail("DISTRIBUTED_TASK_INVALID", "Distributed task payload is missing")
                                                                                               
                                                        
        from arenyxa.infrastructure.database import SQLiteStore
        task = SQLiteStore._task_from_dict(dict(raw))
        expected = str(payload.get("task_snapshot_sha256", ""))
        if not expected or not hmac.compare_digest(expected, task.snapshot_hash()):
            raise _fail("DISTRIBUTED_TASK_INTEGRITY", "Distributed task snapshot hash does not match")
        return task

    def execute_lease(self, queue: DurableDistributedQueue, lease: DistributedLease) -> dict[str, Any]:
        if lease.worker_id != self.worker_id:
            raise _fail("DISTRIBUTED_LEASE_STALE", "Lease belongs to another worker")
        if lease.kind != "task.run":
            raise _fail("DISTRIBUTED_JOB_KIND_UNSUPPORTED", "Worker cannot execute this distributed job kind")
        task = self.task_from_payload(lease.payload)
                                                                                              
                                                                                               
                                                                                              
                                                                             
        try:
            self.runner.store.save_task(task)
        except Exception as exc:
            try:
                queue.fail(lease.job_id, self.worker_id, lease.lease_token, "WORKER_TASK_PERSIST_FAILED", retryable=True)
            except Exception:
                LOGGER.exception("Worker Task snapshot persistence failed and distributed lease failure could not be recorded")
            raise _fail("WORKER_TASK_PERSIST_FAILED", "Worker could not persist the distributed Task snapshot") from exc
        queue.start_job(lease.job_id, self.worker_id, lease.lease_token)
        if lease.side_effect_mode == "non_idempotent":
                                                                                                   
                                                                                                 
            queue.mark_side_effect_started(lease.job_id, self.worker_id, lease.lease_token)

        stop_keepalive = threading.Event()
        lease_lost = threading.Event()
        handle_ref: list[Any] = []
        expiry_lock = threading.Lock()
                                                                                                
                                                                                               
                                                                                                  
                             
        confirmed_deadline_mono = [time.monotonic() + 10.0]

        def cancel_for_lease_loss() -> None:
            lease_lost.set()
            if handle_ref:
                try:
                    handle_ref[0].cancel()
                except Exception:
                    LOGGER.exception("Distributed lease was lost and local Run cancellation failed")

        def keepalive() -> None:
                                                                                                    
                                                                                                     
                                                                                                      
                                                                                                  
                                                                                
            wait_for = 0.0
            while not stop_keepalive.wait(wait_for):
                try:
                    queue.renew_lease(lease.job_id, self.worker_id, lease.lease_token)
                    with expiry_lock:
                        confirmed_deadline_mono[0] = time.monotonic() + DEFAULT_LEASE_SECONDS
                    wait_for = max(2.0, min(20.0, DEFAULT_LEASE_SECONDS / 3.0))
                    continue
                except ArenyxaError as exc:
                    if exc.code in {"DISTRIBUTED_LEASE_STALE", "DISTRIBUTED_LEASE_EXPIRED"}:
                        cancel_for_lease_loss()
                        return
                    LOGGER.warning("Distributed lease keepalive failed: %s", exc)
                except Exception as exc:
                    text = str(exc)
                    if "DISTRIBUTED_LEASE_STALE" in text or "DISTRIBUTED_LEASE_EXPIRED" in text:
                        cancel_for_lease_loss()
                        return
                                                                                                    
                                                                                                 
                                                                                                     
                    LOGGER.warning("Distributed lease keepalive transport failure: %s", exc)
                with expiry_lock:
                    expired = time.monotonic() >= confirmed_deadline_mono[0]
                if expired:
                    cancel_for_lease_loss()
                    return
                wait_for = 2.0

        def progress(run: Any) -> None:
            if lease_lost.is_set():
                return
            try:
                queue.checkpoint(lease.job_id, self.worker_id, lease.lease_token, {
                    "run_id": str(run.id), "stage": str(run.stage),
                    "completed_units": int(run.completed_units), "total_units": run.total_units,
                    "status": str(run.status.value),
                })
            except ArenyxaError as exc:
                if exc.code in {"DISTRIBUTED_LEASE_STALE", "DISTRIBUTED_LEASE_EXPIRED"}:
                    cancel_for_lease_loss()
                    return
                raise

        handle = None
        keepalive_thread = threading.Thread(
            target=keepalive, name=f"arenyxa-lease-keepalive-{lease.job_id[-16:]}", daemon=True,
        )
        try:
            handle = self.runner.submit(task, on_progress=progress)
            handle_ref.append(handle)
            keepalive_thread.start()
            run = handle.future.result()
            if lease_lost.is_set():
                raise _fail("DISTRIBUTED_LEASE_LOST", "Distributed lease was lost while the local Run was executing")
            result = {
                "run_id": run.id, "status": run.status.value, "stage": run.stage,
                "success_count": run.success_count, "failure_count": run.failure_count,
                "result_count": run.result_count, "error_code": run.error_code or "",
            }
            if run.status.value == "completed":
                queue.complete(lease.job_id, self.worker_id, lease.lease_token, result)
                return result
            state = queue.fail(
                lease.job_id, self.worker_id, lease.lease_token,
                run.error_code or "RUN_FAILED", retryable=lease.side_effect_mode == "idempotent",
            )
            result["distributed_state"] = state
            return result
        except ArenyxaError:
            raise
        except Exception as exc:
            if lease_lost.is_set():
                raise _fail("DISTRIBUTED_LEASE_LOST", "Distributed lease was lost while the local Run was executing") from exc
            try:
                queue.fail(
                    lease.job_id, self.worker_id, lease.lease_token,
                    "WORKER_EXECUTION_EXCEPTION", retryable=lease.side_effect_mode == "idempotent",
                )
            except Exception:
                LOGGER.exception("Distributed worker execution failed and job failure persistence also failed")
            raise _fail("WORKER_EXECUTION_EXCEPTION", "Distributed worker execution failed") from exc
        finally:
            stop_keepalive.set()
            if keepalive_thread.is_alive():
                keepalive_thread.join(timeout=3.0)
