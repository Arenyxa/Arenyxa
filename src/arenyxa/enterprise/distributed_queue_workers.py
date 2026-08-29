"""Worker registry and lease recovery mixin for DurableDistributedQueue.

This module keeps worker lifecycle code out of distributed_queue.py so queue core,
worker registry, and lease execution paths remain independently reviewable.
"""
from __future__ import annotations

import hmac
import time
from typing import Any, Mapping

from arenyxa import __compat_version__
from arenyxa.domain.models import utc_now
from arenyxa.security.worker_identity import ED25519, normalize_algorithm, validate_public_key
from arenyxa.enterprise.distributed_protocol import (
    CURRENT_PROTOCOL,
    MIN_COMPATIBLE_PROTOCOL,
    MAX_RESOURCE_DECLARATION_BYTES,
    MAX_WORKERS,
    MAX_WORKER_SLOTS,
    _fail,
    _bounded_json,
    _load_json,
    _clean_token,
    negotiate_protocol,
)

MAX_WORKER_IDENTITY_METADATA_BYTES = 16 * 1024


class DistributedQueueWorkerMixin:
    """Worker registry, heartbeat, revocation, and expired-lease recovery."""

    def _worker_row(self, row: Any) -> dict[str, Any]:
        resources = _load_json(str(row["resources_json"]), MAX_RESOURCE_DECLARATION_BYTES, "worker resources")
        max_slots = int(row["max_slots"])
        recommended = int(self._storage.capabilities.recommended_worker_slots or 0)
        advisory = ""
        if recommended > 0 and max_slots > recommended:
            advisory = (
                "Configured worker slots exceed the storage backend tail-latency recommendation; "
                "use PostgreSQL for sustained high-concurrency execution."
            )
        identity_algorithm = normalize_algorithm(str(row["identity_algorithm"]) if "identity_algorithm" in row.keys() else ED25519)
        identity_metadata = _load_json(
            str(row["identity_metadata_json"]) if "identity_metadata_json" in row.keys() else "{}",
            MAX_WORKER_IDENTITY_METADATA_BYTES,
            "worker identity metadata",
        )
        return {
            "worker_id": str(row["worker_id"]), "display_name": str(row["display_name"]),
            "public_key": str(row["public_key"]), "identity_algorithm": identity_algorithm,
            "identity_metadata": identity_metadata, "protocol_min": int(row["protocol_min"]),
            "protocol_max": int(row["protocol_max"]), "negotiated_protocol": int(row["negotiated_protocol"]),
            "app_compat_version": str(row["app_compat_version"]), "resources": resources,
            "max_slots": max_slots, "active_leases": int(row["active_leases"]),
            "state": str(row["state"]), "heartbeat_at": float(row["heartbeat_at"]),
            "created_at": str(row["created_at"]), "updated_at": str(row["updated_at"]),
            "revoked_at": str(row["revoked_at"]), "concurrency_advisory": advisory,
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
        identity_algorithm: str = ED25519,
        identity_metadata: Mapping[str, Any] | None = None,
        enforce_capacity: bool = False,
    ) -> dict[str, Any]:
        worker = _clean_token(worker_id, "worker id")
        algorithm = normalize_algorithm(identity_algorithm)
        validate_public_key(algorithm, public_key_b64)
        negotiated = negotiate_protocol(protocol_min, protocol_max)
        resources_json, _ = _bounded_json(resources, MAX_RESOURCE_DECLARATION_BYTES, "worker resource declaration")
        identity_metadata_json, _ = _bounded_json(
            dict(identity_metadata or {}), MAX_WORKER_IDENTITY_METADATA_BYTES, "worker identity metadata"
        )
        slots = max(1, min(MAX_WORKER_SLOTS, int(max_slots)))
        now_iso = utc_now()
        now = self._clock.stable_epoch()
        with self._lock, self._connection() as connection:
            self._begin(connection)
            existing = connection.execute("SELECT * FROM distributed_workers WHERE worker_id=?", (worker,)).fetchone()
            if enforce_capacity and not self._storage.capabilities.multi_host_writers:
                configured = int(connection.execute(
                    "SELECT coalesce(sum(max_slots),0) FROM distributed_workers WHERE state<>'revoked' AND worker_id<>?",
                    (worker,),
                ).fetchone()[0] or 0)
                proposed = configured + slots
                cutover = max(1, int(self._storage.capabilities.high_concurrency_cutover_slots or 16))
                if proposed >= cutover:
                    connection.rollback()
                    raise _fail(
                        "SQLITE_DISTRIBUTED_CAPACITY_EXCEEDED",
                        "SQLite Enterprise Worker capacity reached the fail-closed concurrency boundary; use PostgreSQL",
                        configured_slots=configured, requested_slots=slots, cutover_slots=cutover,
                    )
            if existing is None:
                count = int(connection.execute("SELECT count(*) FROM distributed_workers").fetchone()[0])
                if count >= MAX_WORKERS:
                    connection.rollback()
                    raise _fail("DISTRIBUTED_WORKER_LIMIT", "Worker registry reached its safety bound")
                connection.execute(
                    """INSERT INTO distributed_workers(
                        worker_id,display_name,public_key,identity_algorithm,identity_metadata_json,protocol_min,protocol_max,negotiated_protocol,
                        app_compat_version,resources_json,max_slots,active_leases,state,created_at,updated_at,heartbeat_at,revoked_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        worker, str(display_name).strip()[:160] or worker, str(public_key_b64), algorithm, identity_metadata_json,
                        int(protocol_min), int(protocol_max), negotiated, str(app_compat_version)[:64], resources_json, slots, 0,
                        "active", now_iso, now_iso, now, "",
                    ),
                )
            else:
                if str(existing["state"]) == "revoked":
                    connection.rollback()
                    raise _fail("WORKER_REVOKED", "Revoked worker identity cannot re-register without administrator recovery")
                existing_algorithm = normalize_algorithm(
                    str(existing["identity_algorithm"]) if "identity_algorithm" in existing.keys() else ED25519
                )
                if (
                    not hmac.compare_digest(str(existing["public_key"]), str(public_key_b64))
                    or not hmac.compare_digest(existing_algorithm, algorithm)
                ):
                    connection.rollback()
                    raise _fail("WORKER_IDENTITY_MISMATCH", "Worker ID is already bound to another public key or identity algorithm")
                connection.execute(
                    """UPDATE distributed_workers SET display_name=?,identity_metadata_json=?,protocol_min=?,protocol_max=?,negotiated_protocol=?,
                       app_compat_version=?,resources_json=?,max_slots=?,updated_at=?,heartbeat_at=? WHERE worker_id=?""",
                    (
                        str(display_name).strip()[:160] or worker, identity_metadata_json, int(protocol_min), int(protocol_max), negotiated,
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
        now = self._clock.stable_epoch()
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

    def recover_stale_worker_leases(self, now: float | None = None) -> int:
        """Recover active leases whose Worker heartbeat has disappeared before lease expiry.

        Fencing tokens prevent a stale Worker from completing after reassignment. Non-idempotent
        work that may have started is never automatically re-executed and enters review_required.
        """
        current = self._clock.stable_epoch() if now is None else float(now)
        cutoff = current - float(self._worker_heartbeat_timeout_seconds)
        with self._lock, self._connection() as connection:
            self._begin(connection)
            rows = connection.execute(
                """SELECT j.job_id,j.state,j.lease_worker_id,j.lease_token_sha256,j.lease_expires_at,
                          j.side_effect_mode,j.side_effect_state,j.attempt,j.max_attempts,w.heartbeat_at
                   FROM distributed_jobs j JOIN distributed_workers w ON w.worker_id=j.lease_worker_id
                   WHERE j.state IN ('leased','running') AND j.lease_worker_id<>''
                     AND w.heartbeat_at>0 AND w.heartbeat_at<=? AND j.lease_expires_at>?""",
                (cutoff, current),
            ).fetchall()
            affected = 0
            recovered_by_worker: dict[str, int] = {}
            for row in rows:
                worker = str(row["lease_worker_id"])
                if str(row["side_effect_mode"]) == "non_idempotent" and str(row["side_effect_state"]) == "started":
                    target = "review_required"
                    code = "WORKER_HEARTBEAT_LOST_AFTER_SIDE_EFFECT_START"
                elif int(row["attempt"]) < int(row["max_attempts"]):
                    target = "queued"
                    code = "WORKER_HEARTBEAT_LOST_REQUEUED"
                else:
                    target = "failed"
                    code = "WORKER_HEARTBEAT_LOST_MAX_ATTEMPTS"
                previous = str(row["state"])
                cursor = connection.execute(
                    """UPDATE distributed_jobs SET state=?,lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                       error_code=?,updated_at=? WHERE job_id=? AND state=? AND lease_worker_id=?
                       AND lease_token_sha256=? AND lease_expires_at>?
                       AND EXISTS (
                           SELECT 1 FROM distributed_workers w
                           WHERE w.worker_id=? AND w.heartbeat_at=?
                             AND w.heartbeat_at>0 AND w.heartbeat_at<=?
                       )""",
                    (
                        target, code, utc_now(), str(row["job_id"]), previous, worker,
                        str(row["lease_token_sha256"]), current, worker,
                        float(row["heartbeat_at"]), cutoff,
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                self._record_event_locked(
                    connection, str(row["job_id"]), "worker_heartbeat_lost", previous, target,
                    worker_id=worker, code=code,
                    details={"heartbeat_timeout_seconds": self._worker_heartbeat_timeout_seconds},
                )
                recovered_by_worker[worker] = recovered_by_worker.get(worker, 0) + 1
                affected += 1
            for worker, recovered in recovered_by_worker.items():
                connection.execute(
                    "UPDATE distributed_workers SET active_leases=max(0,active_leases-?),updated_at=? WHERE worker_id=?",
                    (recovered, utc_now(), worker),
                )
            connection.commit()
        return affected

    def recover_expired_leases(self, now: float | None = None) -> int:
        current = self._clock.stable_epoch() if now is None else float(now)
        recovery_cutoff = current - (self._lease_grace_seconds if now is None else 0.0)
        with self._lock, self._connection() as connection:
            self._begin(connection)
            rows = connection.execute(
                self._storage.expired_lease_candidates_sql(),
                (recovery_cutoff,),
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
                cursor = connection.execute(
                    """UPDATE distributed_jobs SET state=?,lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                       error_code=?,updated_at=? WHERE job_id=? AND state=? AND lease_worker_id=?
                       AND lease_token_sha256=? AND lease_expires_at>0 AND lease_expires_at<=?""",
                    (
                        state, code, utc_now(), str(row["job_id"]), previous, worker,
                        str(row["lease_token_sha256"]), recovery_cutoff,
                    ),
                )
                if cursor.rowcount != 1:
                    # Another writer renewed/completed the lease after candidate discovery.
                    # Never decrement worker counters or emit a false recovery event.
                    continue
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
            heartbeat_recovered = self.recover_stale_worker_leases()
            return heartbeat_recovered + self.recover_expired_leases()
        finally:
            self._expiry_scan_lock.release()
