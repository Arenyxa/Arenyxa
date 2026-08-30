from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
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
from arenyxa.security.worker_identity import ED25519, normalize_algorithm, validate_public_key
from arenyxa.observability.trace_context import persisted_trace_fields
from arenyxa.infrastructure.timebase import PROCESS_CLOCK, StableEpochClock
from arenyxa.enterprise.distributed_rows import distributed_job_row
from arenyxa.enterprise.distributed_health import DistributedQueueHealthMixin
from arenyxa.enterprise.distributed_queue_workers import DistributedQueueWorkerMixin

LOGGER = logging.getLogger(__name__)

from arenyxa.enterprise.distributed_protocol import (
    DISTRIBUTED_SCHEMA,
    CURRENT_PROTOCOL,
    MIN_COMPATIBLE_PROTOCOL,
    MAX_JOB_PAYLOAD_BYTES,
    MAX_RESULT_BYTES,
    MAX_CHECKPOINT_BYTES,
    MAX_RESOURCE_DECLARATION_BYTES,
    MAX_JOBS,
    MAX_WORKERS,
    MAX_CHALLENGES,
    MAX_WORKER_SESSIONS,
    MAX_WORKER_SLOTS,
    MAX_JOB_EVENTS_PER_JOB,
    MAX_EVENT_DETAILS_BYTES,
    DEFAULT_LEASE_SECONDS,
    MAX_LEASE_SECONDS,
    WORKER_SESSION_TTL_SECONDS,
    CHALLENGE_TTL_SECONDS,
    _JOB_STATES,
    _ALLOWED_JOB_TRANSITIONS,
    _fail,
    _canonical,
    _bounded_json,
    _load_json,
    _clean_token,
    _b64u_decode,
    negotiate_protocol,
    verify_enterprise_server_identity,
    DistributedLease,
    _NoopLock,
)

class DurableDistributedQueue(DistributedQueueWorkerMixin, DistributedQueueHealthMixin):

    def __init__(
        self, path: Path | str, *, storage_backend: DistributedRuntimeStorageBackend | None = None,
        clock: StableEpochClock | None = None, lease_grace_seconds: float = 5.0,
    ) -> None:
        self.path = path
        self._clock = clock or PROCESS_CLOCK
        self._lease_grace_seconds = max(0.0, min(120.0, float(lease_grace_seconds)))
        self._storage = storage_backend or storage_backend_for(path)
        if not self._storage.capabilities.external_server:
            Path(str(path)).parent.mkdir(parents=True, exist_ok=True)

        self._lock = _NoopLock() if self._storage.capabilities.multi_host_writers else threading.Lock()
        self._expiry_scan_lock = threading.Lock()
        # External PostgreSQL queues are shared by many independent clients.
        # A 0.5s scan interval makes every client periodically run two
        # recovery transactions during a short burst, competing with the hot
        # lease path.  Explicit recovery remains available; the background
        # safety sweep is still frequent enough for the 45s heartbeat window.
        self._expiry_scan_interval_seconds = 5.0 if self._storage.capabilities.external_server else 0.5
        self._last_expiry_scan_monotonic = 0.0
        self._worker_heartbeat_timeout_seconds = max(10.0, min(45.0, float(DEFAULT_LEASE_SECONDS) * 0.75))
        self._health_lock = threading.Lock()
        self._health_integrity_checked_at = 0.0
        self._health_integrity_result: tuple[bool, str] = (False, "not_checked")
        self._health_event_count_checked_at = 0.0
        self._health_event_count = 0
        self._storage_circuit_lock = threading.Lock()
        self._storage_circuit_failures = 0
        self._storage_circuit_open_until = 0.0
        self._storage_circuit_last_error = ""
        self._storage_circuit_threshold = 3
        self._storage_circuit_cooldown_seconds = 2.0
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
        self._idempotency_backfill_complete = False
        try:
            self._backfill_idempotency_tombstones()
            self._idempotency_backfill_complete = True
        except Exception:
            LOGGER.exception(
                "Idempotency tombstone backfill failed; destructive terminal retention is disabled"
            )
        self._last_reconciliation = self.reconcile_durable_state()
        self._last_reconciliation["stale_worker_leases_recovered"] = self.recover_stale_worker_leases()
        self._last_reconciliation["expired_leases_recovered"] = self.recover_expired_leases()

    @property
    def storage_capabilities(self) -> dict[str, Any]:
        return self._storage.capabilities.as_dict()

    def _record_event_locked(
        self, connection: Any, job_id: str, event_type: str,
        from_state: str, to_state: str, *, worker_id: str = "", code: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> None:
        source = str(from_state)
        target = str(to_state)
        if target not in _JOB_STATES or (source and source not in _JOB_STATES):
            raise _fail("DISTRIBUTED_STATE_UNKNOWN", "Distributed job event contains an unknown state", from_state=source, to_state=target)
        if (source, target) not in _ALLOWED_JOB_TRANSITIONS:
            raise _fail("DISTRIBUTED_STATE_TRANSITION_INVALID", "Distributed job state transition is not permitted", from_state=source, to_state=target, event_type=str(event_type))
        event = _clean_token(event_type, "event type", 96)
        detail_json, _ = _bounded_json(details or {}, MAX_EVENT_DETAILS_BYTES, "distributed event details")
        self._storage.record_event(
            connection,
            (str(job_id), event, str(from_state), str(to_state), str(worker_id), str(code)[:128], detail_json, utc_now()),
            MAX_JOB_EVENTS_PER_JOB,
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
        with self._lock, self._connection() as connection:
            self._begin(connection)
            current_wall = self._lease_now(connection)
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
                if target in {"completed", "failed", "cancelled", "review_required"}:
                    terminal_row = connection.execute(
                        "SELECT * FROM distributed_jobs WHERE job_id=?", (str(row["job_id"]),)
                    ).fetchone()
                    if terminal_row is not None:
                        self._fence_terminal_from_row_locked(connection, terminal_row, target)
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

    def invariant_violations(self) -> list[str]:
        """Return durable queue invariant violations without mutating state.

        This is intentionally cheap enough for CI/fault-injection checkpoints and explicit
        health diagnostics, but is not run on every hot-path transition.
        """
        violations: list[str] = []
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT job_id,state,lease_worker_id,lease_token_sha256,lease_expires_at "
                "FROM distributed_jobs"
            ).fetchall()
            for row in rows:
                state = str(row["state"])
                has_lease = bool(str(row["lease_worker_id"])) or bool(str(row["lease_token_sha256"])) or float(row["lease_expires_at"]) > 0
                if state in {"leased", "running"} and not (
                    str(row["lease_worker_id"]) and str(row["lease_token_sha256"]) and float(row["lease_expires_at"]) > 0
                ):
                    violations.append(f"job:{row['job_id']}:active-state-missing-lease")
                elif state not in {"leased", "running"} and has_lease:
                    violations.append(f"job:{row['job_id']}:inactive-state-retains-lease")
            actual = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT lease_worker_id,count(*) FROM distributed_jobs "
                    "WHERE state IN ('leased','running') AND lease_worker_id<>'' GROUP BY lease_worker_id"
                ).fetchall()
            }
            workers = connection.execute(
                "SELECT worker_id,active_leases,max_slots FROM distributed_workers"
            ).fetchall()
            for worker in workers:
                worker_id = str(worker["worker_id"])
                reported = int(worker["active_leases"])
                expected = actual.get(worker_id, 0)
                if reported != expected:
                    violations.append(f"worker:{worker_id}:active-leases:{reported}!={expected}")
                if reported < 0 or reported > int(worker["max_slots"]):
                    violations.append(f"worker:{worker_id}:slot-bound:{reported}")
        return violations

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

    def close(self) -> None:
        """Release storage resources such as a PostgreSQL connection pool."""
        self._storage.close()

    def _begin(self, connection: Any) -> None:
        self._storage.begin_write(connection)

    def _lease_now(self, connection: Any) -> float:
        return float(self._storage.authoritative_lease_epoch(connection, self._clock))

    def _job_count_guard(self, connection: Any) -> None:
        count = int(connection.execute("SELECT count(*) FROM distributed_jobs").fetchone()[0])
        if count >= MAX_JOBS and self._idempotency_backfill_complete:
            self._retain_terminal_jobs_locked(
                connection,
                max_terminal=max(0, MAX_JOBS // 2),
                max_idempotent_tombstones=MAX_JOBS,
            )
            count = int(connection.execute("SELECT count(*) FROM distributed_jobs").fetchone()[0])
        if count >= MAX_JOBS:
            raise _fail("DISTRIBUTED_QUEUE_FULL", "Distributed job queue reached its configured safety bound")

    def _upsert_idempotency_locked(
        self,
        connection: Any,
        *,
        idempotency_key: str,
        job_id: str,
        kind: str,
        payload_sha256: str,
        resource_id: str,
        permission: str,
        side_effect_mode: str,
        terminal_state: str,
        created_at: str,
        terminal_at: str,
    ) -> None:
        updated_at = utc_now()
        existing = self._lookup_idempotency_locked(connection, idempotency_key)
        expected = (
            str(job_id),
            str(kind),
            str(payload_sha256),
            str(resource_id),
            str(permission),
            str(side_effect_mode),
        )
        if existing is not None:
            actual = (
                str(existing["job_id"]),
                str(existing["kind"]),
                str(existing["payload_sha256"]),
                str(existing["resource_id"]),
                str(existing["permission"]),
                str(existing["side_effect_mode"]),
            )
            if actual != expected:
                raise _fail(
                    "DISTRIBUTED_IDEMPOTENCY_COLLISION",
                    "Durable idempotency fence conflicts with the terminal job binding",
                    idempotency_key=idempotency_key,
                    job_id=job_id,
                )
        cursor = connection.execute(
            """INSERT INTO distributed_job_idempotency(
                idempotency_key,job_id,kind,payload_sha256,resource_id,permission,
                side_effect_mode,terminal_state,created_at,terminal_at,updated_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(idempotency_key) DO UPDATE SET
                terminal_state=excluded.terminal_state,
                terminal_at=excluded.terminal_at,
                updated_at=excluded.updated_at
            WHERE distributed_job_idempotency.job_id=excluded.job_id
              AND distributed_job_idempotency.kind=excluded.kind
              AND distributed_job_idempotency.payload_sha256=excluded.payload_sha256
              AND distributed_job_idempotency.resource_id=excluded.resource_id
              AND distributed_job_idempotency.permission=excluded.permission
              AND distributed_job_idempotency.side_effect_mode=excluded.side_effect_mode""",
            (
                idempotency_key,
                job_id,
                kind,
                payload_sha256,
                resource_id,
                permission,
                side_effect_mode,
                terminal_state,
                created_at,
                terminal_at or updated_at,
                updated_at,
            ),
        )
        if int(cursor.rowcount) != 1:
            raise _fail(
                "DISTRIBUTED_IDEMPOTENCY_COLLISION",
                "Durable idempotency fence could not be established exactly",
                idempotency_key=idempotency_key,
                job_id=job_id,
            )

    @staticmethod
    def _lookup_idempotency_locked(connection: Any, key: str) -> Any | None:
        return connection.execute(
            "SELECT * FROM distributed_job_idempotency WHERE idempotency_key=?", (key,)
        ).fetchone()

    def _fence_terminal_from_row_locked(
        self, connection: Any, row: Any, terminal_state: str
    ) -> None:
        state = str(terminal_state)
        if state not in {"completed", "failed", "cancelled", "review_required"}:
            return
        terminal_at = str(row["terminal_at"] or row["updated_at"] or row["created_at"])
        self._upsert_idempotency_locked(
            connection,
            idempotency_key=str(row["idempotency_key"]),
            job_id=str(row["job_id"]),
            kind=str(row["kind"]),
            payload_sha256=str(row["payload_sha256"]),
            resource_id=str(row["resource_id"]),
            permission=str(row["permission"]),
            side_effect_mode=str(row["side_effect_mode"]),
            terminal_state=state,
            created_at=str(row["created_at"]),
            terminal_at=terminal_at,
        )

    def _backfill_idempotency_tombstones(self) -> int:
        states = ("completed", "failed", "cancelled", "review_required")
        placeholders = ",".join("?" for _ in states)
        inserted = 0
        while True:
            with self._lock, self._connection() as connection:
                self._begin(connection)
                rows = connection.execute(
                    f"""SELECT j.* FROM distributed_jobs AS j
                        WHERE j.state IN ({placeholders})
                          AND NOT EXISTS (
                              SELECT 1 FROM distributed_job_idempotency AS i
                              WHERE i.idempotency_key=j.idempotency_key
                          )
                        ORDER BY j.created_at ASC LIMIT ?""",
                    (*states, 200),
                ).fetchall()
                for row in rows:
                    self._fence_terminal_from_row_locked(connection, row, str(row["state"]))
                connection.commit()
            inserted += len(rows)
            if len(rows) < 200:
                return inserted

    @staticmethod
    def _retention_counts_locked(connection: Any) -> tuple[int, int, int]:
        jobs = int(connection.execute("SELECT count(*) FROM distributed_jobs").fetchone()[0])
        idempotent = int(
            connection.execute(
                "SELECT count(*) FROM distributed_job_idempotency WHERE side_effect_mode='idempotent'"
            ).fetchone()[0]
        )
        non_idempotent = int(
            connection.execute(
                "SELECT count(*) FROM distributed_job_idempotency WHERE side_effect_mode='non_idempotent'"
            ).fetchone()[0]
        )
        return jobs, idempotent, non_idempotent

    def _prune_idempotent_tombstones_locked(self, connection: Any, limit: int) -> int:
        cap = max(0, int(limit))
        total = int(
            connection.execute(
                "SELECT count(*) FROM distributed_job_idempotency WHERE side_effect_mode='idempotent'"
            ).fetchone()[0]
        )
        excess = max(0, total - cap)
        if excess == 0:
            return 0
        rows = connection.execute(
            """SELECT i.idempotency_key FROM distributed_job_idempotency AS i
               LEFT JOIN distributed_jobs AS j ON j.job_id=i.job_id
               WHERE i.side_effect_mode='idempotent' AND j.job_id IS NULL
               ORDER BY COALESCE(NULLIF(i.terminal_at,''),i.created_at) ASC LIMIT ?""",
            (excess,),
        ).fetchall()
        deleted = 0
        for row in rows:
            cursor = connection.execute(
                "DELETE FROM distributed_job_idempotency "
                "WHERE idempotency_key=? AND side_effect_mode='idempotent'",
                (str(row["idempotency_key"]),),
            )
            deleted += max(0, int(cursor.rowcount))
        return deleted

    def _retain_terminal_jobs_locked(
        self,
        connection: Any,
        *,
        max_terminal: int,
        max_idempotent_tombstones: int,
    ) -> dict[str, int | bool]:
        terminal_limit = max(0, int(max_terminal))
        terminal_count = int(
            connection.execute(
                "SELECT count(*) FROM distributed_jobs "
                "WHERE state IN ('completed','failed','cancelled')"
            ).fetchone()[0]
        )
        excess = max(0, terminal_count - terminal_limit)
        rows = connection.execute(
            """SELECT * FROM distributed_jobs
               WHERE state IN ('completed','failed','cancelled')
               ORDER BY COALESCE(NULLIF(terminal_at,''),updated_at,created_at) ASC LIMIT ?""",
            (excess,),
        ).fetchall() if excess else []
        jobs_pruned = 0
        for row in rows:
            self._fence_terminal_from_row_locked(connection, row, str(row["state"]))
            cursor = connection.execute(
                "DELETE FROM distributed_jobs WHERE job_id=? "
                "AND state IN ('completed','failed','cancelled')",
                (str(row["job_id"]),),
            )
            jobs_pruned += max(0, int(cursor.rowcount))
        tombstones_pruned = self._prune_idempotent_tombstones_locked(
            connection, max_idempotent_tombstones
        )
        jobs, idempotent, non_idempotent = self._retention_counts_locked(connection)
        return {
            "jobs_pruned": jobs_pruned,
            "idempotent_tombstones_pruned": tombstones_pruned,
            "jobs_remaining": jobs,
            "idempotent_tombstones_remaining": idempotent,
            "non_idempotent_tombstones_remaining": non_idempotent,
            "pruning_disabled": False,
        }

    def retain_terminal_jobs(
        self,
        max_terminal: int | None = None,
        *,
        max_idempotent_tombstones: int | None = None,
    ) -> dict[str, int | bool]:
        terminal_limit = max(0, MAX_JOBS // 2) if max_terminal is None else max(0, int(max_terminal))
        tombstone_limit = (
            MAX_JOBS
            if max_idempotent_tombstones is None
            else max(0, int(max_idempotent_tombstones))
        )
        with self._lock, self._connection() as connection:
            if not self._idempotency_backfill_complete:
                jobs, idempotent, non_idempotent = self._retention_counts_locked(connection)
                return {
                    "jobs_pruned": 0,
                    "idempotent_tombstones_pruned": 0,
                    "jobs_remaining": jobs,
                    "idempotent_tombstones_remaining": idempotent,
                    "non_idempotent_tombstones_remaining": non_idempotent,
                    "pruning_disabled": True,
                }
            self._begin(connection)
            report = self._retain_terminal_jobs_locked(
                connection,
                max_terminal=terminal_limit,
                max_idempotent_tombstones=tombstone_limit,
            )
            connection.commit()
        if report["jobs_pruned"] or report["idempotent_tombstones_pruned"]:
            LOGGER.info("Distributed queue retention maintenance: %s", report)
        return report

    def job_for_idempotency(self, key: str) -> dict[str, Any] | None:
        token = _clean_token(key, "idempotency key", 192)
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM distributed_jobs WHERE idempotency_key=?", (token,)).fetchone()
            if row is not None:
                return distributed_job_row(row)
            tombstone = self._lookup_idempotency_locked(connection, token)
            if tombstone is None:
                return None
            return {
                "job_id": str(tombstone["job_id"]),
                "kind": str(tombstone["kind"]),
                "state": str(tombstone["terminal_state"]),
                "payload_sha256": str(tombstone["payload_sha256"]),
                "resource_id": str(tombstone["resource_id"]),
                "permission": str(tombstone["permission"]),
                "idempotency_key": token,
                "side_effect_mode": str(tombstone["side_effect_mode"]),
                "created_at": str(tombstone["created_at"]),
                "terminal_at": str(tombstone["terminal_at"]),
                "updated_at": str(tombstone["updated_at"]),
            }

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
        traceparent: str = "",
        tracestate: str = "",
        idempotency_prefix: str = "",
        idempotency_prefix_limit: int | None = None,
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
        job_traceparent, job_tracestate = persisted_trace_fields(traceparent, tracestate)
        job_id = new_id("job")
        now = utc_now()
        with self._lock, self._connection() as connection:
            self._begin(connection)
            tombstone = self._lookup_idempotency_locked(connection, idem)
            if tombstone is not None:
                if (
                    str(tombstone["kind"]) == kind_id
                    and hmac.compare_digest(str(tombstone["payload_sha256"]), payload_sha)
                    and str(tombstone["resource_id"]) == resource
                    and str(tombstone["permission"]) == capability
                    and str(tombstone["side_effect_mode"]) == mode
                ):
                    connection.commit()
                    return str(tombstone["job_id"])
                connection.rollback()
                raise _fail(
                    "DISTRIBUTED_IDEMPOTENCY_COLLISION",
                    "Idempotency key was already used for a different retained operation",
                )
            existing = connection.execute(
                "SELECT job_id,kind,payload_sha256,resource_id,permission,side_effect_mode "
                "FROM distributed_jobs WHERE idempotency_key=?",
                (idem,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["kind"]) == kind_id
                    and str(existing["payload_sha256"]) == payload_sha
                    and str(existing["resource_id"]) == resource
                    and str(existing["permission"]) == capability
                    and str(existing["side_effect_mode"]) == mode
                ):
                    connection.commit()
                    return str(existing["job_id"])
                connection.rollback()
                raise _fail("DISTRIBUTED_IDEMPOTENCY_COLLISION", "Idempotency key was already used for a different job")
            if idempotency_prefix_limit is not None:
                prefix = _clean_token(idempotency_prefix, "idempotency prefix", 192)
                limit = max(1, min(MAX_JOBS, int(idempotency_prefix_limit)))
                prefix_count = int(connection.execute(
                    """SELECT count(*) FROM (
                           SELECT idempotency_key FROM distributed_jobs
                           WHERE substr(idempotency_key,1,?)=?
                           UNION
                           SELECT idempotency_key FROM distributed_job_idempotency
                           WHERE substr(idempotency_key,1,?)=?
                       ) AS retained_keys""",
                    (len(prefix), prefix, len(prefix), prefix),
                ).fetchone()[0])
                if prefix_count >= limit:
                    connection.rollback()
                    raise _fail(
                        "DISTRIBUTED_PREFIX_LIMIT",
                        "Distributed job namespace reached its configured safety bound",
                        idempotency_prefix=prefix, limit=limit,
                    )
            self._job_count_guard(connection)
            connection.execute(
                """INSERT INTO distributed_jobs(
                    job_id,kind,state,payload_json,payload_sha256,traceparent,tracestate,resource_id,permission,idempotency_key,
                    side_effect_mode,side_effect_state,attempt,max_attempts,protocol_version,priority,
                    checkpoint_json,result_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, kind_id, "queued", payload_json, payload_sha, job_traceparent, job_tracestate, resource, capability, idem,
                    mode, "none", 0, attempts, protocol, max(-1000, min(1000, int(priority))),
                    "{}", "{}", now, now,
                ),
            )
            self._record_event_locked(connection, job_id, "enqueued", "", "queued", details={
                "kind": kind_id, "side_effect_mode": mode, "protocol_version": protocol,
                "trace_id": job_traceparent.split("-")[1],
            })
            connection.commit()
        return job_id

    def _storage_circuit_preflight(self) -> None:
        now = time.monotonic()
        with self._storage_circuit_lock:
            if self._storage_circuit_open_until > now:
                raise _fail(
                    "DISTRIBUTED_STORAGE_CIRCUIT_OPEN",
                    "Distributed storage circuit breaker is open; leasing is temporarily paused",
                    retry_after_seconds=round(self._storage_circuit_open_until - now, 3),
                    last_error=self._storage_circuit_last_error[:192],
                )
            if self._storage_circuit_open_until:
                # Half-open: allow one probe and clear the elapsed open deadline.
                self._storage_circuit_open_until = 0.0

    def _storage_circuit_success(self) -> None:
        with self._storage_circuit_lock:
            self._storage_circuit_failures = 0
            self._storage_circuit_open_until = 0.0
            self._storage_circuit_last_error = ""

    def _storage_circuit_failure(self, exc: BaseException) -> ArenyxaError:
        now = time.monotonic()
        with self._storage_circuit_lock:
            self._storage_circuit_failures += 1
            self._storage_circuit_last_error = f"{type(exc).__name__}: {exc}"[:256]
            opened = self._storage_circuit_failures >= self._storage_circuit_threshold
            if opened:
                self._storage_circuit_open_until = now + self._storage_circuit_cooldown_seconds
        return _fail(
            "DISTRIBUTED_STORAGE_CIRCUIT_OPEN" if opened else "DISTRIBUTED_STORAGE_BACKPRESSURE",
            "Distributed storage is unavailable or backpressured; queue state is not empty by implication",
            failures=self._storage_circuit_failures,
            retry_after_seconds=self._storage_circuit_cooldown_seconds if opened else 0.5,
            backend=self._storage.capabilities.backend,
        )

    def storage_circuit_snapshot(self) -> dict[str, Any]:
        now = time.monotonic()
        with self._storage_circuit_lock:
            return {
                "state": "open" if self._storage_circuit_open_until > now else ("half_open" if self._storage_circuit_failures else "closed"),
                "consecutive_failures": self._storage_circuit_failures,
                "retry_after_seconds": max(0.0, round(self._storage_circuit_open_until - now, 3)),
                "last_error": self._storage_circuit_last_error[:256],
            }

    def lease_next(self, worker_id: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> DistributedLease | None:
        self._storage_circuit_preflight()
        try:
            lease = self._lease_next_storage(worker_id, lease_seconds=lease_seconds)
        except (sqlite3.OperationalError, TimeoutError, OSError) as exc:
            raise self._storage_circuit_failure(exc) from exc
        self._storage_circuit_success()
        return lease

    @staticmethod
    def _lease_from_row(row: Any, worker: str, token: str, expires: float, attempt: int) -> DistributedLease:
        return DistributedLease(
            job_id=str(row["job_id"]),
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
            traceparent=str(row["traceparent"]) if "traceparent" in row.keys() else "",
            tracestate=str(row["tracestate"]) if "tracestate" in row.keys() else "",
        )

    def _lease_next_storage(self, worker_id: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> DistributedLease | None:
        worker = str(worker_id)
        duration = max(15, min(MAX_LEASE_SECONDS, int(lease_seconds)))
        self._recover_expired_leases_if_due()

        # PostgreSQL can perform admission, candidate selection, lease fencing,
        # and the audit event as one atomic server-side statement.  A missing
        # row falls through to the portable path so unknown/revoked workers and
        # empty queues retain their precise error semantics.
        fast_sql = self._storage.lease_next_fast_sql()
        if fast_sql is not None:
            token = secrets.token_urlsafe(32)
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            now = utc_now()
            detail_created = utc_now()
            expires = 0.0
            with self._storage.lease_admission_guard():
                with self._lock, self._connection() as connection:
                    lease_now = self._lease_now(connection)
                    expires = lease_now + duration
                    expiry_parameter = self._storage.fast_lease_expiry_parameter(lease_now, duration)
                    row = connection.execute(
                        fast_sql,
                        (
                            worker,
                            lease_now,
                            now,
                            worker,
                            worker,
                            digest,
                            expiry_parameter,
                            now,
                            worker,
                            "",
                            duration,
                            detail_created,
                            MAX_JOB_EVENTS_PER_JOB - 1,
                        ),
                    ).fetchone()
            if row is not None:
                expires = self._storage.fast_lease_expiry_from_row(row, expires)
                return self._lease_from_row(row, worker, token, expires, int(row["attempt"]))

        with self._lock, self._connection() as connection:
            self._begin(connection)
            lease_now = self._lease_now(connection)
            atomic_slot_sql = self._storage.claim_worker_slot_for_lease_sql()
            if atomic_slot_sql is not None:
                worker_row = connection.execute(
                    atomic_slot_sql, (lease_now, utc_now(), worker)
                ).fetchone()
                if worker_row is None:
                    state_row = connection.execute(
                        "SELECT state FROM distributed_workers WHERE worker_id=?", (worker,)
                    ).fetchone()
                    connection.rollback()
                    if state_row is None:
                        raise _fail("WORKER_UNKNOWN", "Worker is not registered")
                    if str(state_row["state"]) == "revoked":
                        raise _fail("WORKER_REVOKED", "Worker is revoked")
                    return None
                protocol_min = int(worker_row["protocol_min"])
                protocol_max = int(worker_row["protocol_max"])
                slot_claimed = True
            else:
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
                slot_claimed = False
            row = connection.execute(
                self._storage.lease_candidate_sql(),
                (protocol_min, protocol_max),
            ).fetchone()
            if row is None:
                if slot_claimed:
                    connection.rollback()
                else:
                    connection.commit()
                return None
            token = secrets.token_urlsafe(32)
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            lease_now = self._lease_now(connection)
            expires = lease_now + duration
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
            if not slot_claimed:
                slot_cursor = connection.execute(
                    self._storage.claim_worker_slot_sql(),
                    (lease_now, updated_at, worker),
                )
                if slot_cursor.rowcount != 1:
                    connection.rollback()
                    return None
            self._record_event_locked(
                connection, job_id, "leased", "queued", "leased", worker_id=worker,
                details={"attempt": attempt, "lease_seconds": duration, "clock": "storage-authoritative-epoch"},
            )
            connection.commit()
        return self._lease_from_row(row, worker, token, expires, attempt)

    def lease_many(
        self, worker_id: str, *, max_items: int = 8, lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> list[DistributedLease]:
        self._storage_circuit_preflight()
        try:
            leases = self._lease_many_storage(worker_id, max_items=max_items, lease_seconds=lease_seconds)
        except (sqlite3.OperationalError, TimeoutError, OSError) as exc:
            raise self._storage_circuit_failure(exc) from exc
        self._storage_circuit_success()
        return leases

    def _lease_many_storage(
        self, worker_id: str, *, max_items: int = 8, lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> list[DistributedLease]:
        worker = str(worker_id)
        limit = max(1, min(MAX_WORKER_SLOTS, int(max_items)))
        duration = max(15, min(MAX_LEASE_SECONDS, int(lease_seconds)))
        self._recover_expired_leases_if_due()
        leases: list[DistributedLease] = []
        with self._lock, self._connection() as connection:
            self._begin(connection)
            worker_row = connection.execute(self._storage.worker_for_lease_sql(), (worker,)).fetchone()
            if worker_row is None:
                connection.rollback()
                raise _fail("WORKER_UNKNOWN", "Worker is not registered")
            state = str(worker_row["state"])
            if state != "active":
                connection.rollback()
                if state == "revoked":
                    raise _fail("WORKER_REVOKED", "Worker is revoked")
                return []
            active_leases = int(worker_row["active_leases"])
            max_slots = int(worker_row["max_slots"])
            available = max(0, min(limit, max_slots - active_leases))
            if available <= 0:
                connection.rollback()
                return []
            protocol_min = int(worker_row["protocol_min"])
            protocol_max = int(worker_row["protocol_max"])
            for _index in range(available):
                row = connection.execute(
                    self._storage.lease_candidate_sql(),
                    (protocol_min, protocol_max),
                ).fetchone()
                if row is None:
                    break
                token = secrets.token_urlsafe(32)
                digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
                lease_now = self._lease_now(connection)
                expires = lease_now + duration
                job_id = str(row["job_id"])
                attempt = int(row["attempt"]) + 1
                updated_at = utc_now()
                cursor = connection.execute(
                    """UPDATE distributed_jobs SET state='leased',attempt=attempt+1,lease_worker_id=?,lease_token_sha256=?,
                       lease_expires_at=?,error_code='',updated_at=? WHERE job_id=? AND state='queued'""",
                    (worker, digest, expires, updated_at, job_id),
                )
                if cursor.rowcount != 1:
                    continue
                slot_cursor = connection.execute(
                    self._storage.claim_worker_slot_sql(),
                    (lease_now, updated_at, worker),
                )
                if slot_cursor.rowcount != 1:
                    connection.rollback()
                    return []
                self._record_event_locked(
                    connection, job_id, "leased", "queued", "leased", worker_id=worker,
                    details={"attempt": attempt, "lease_seconds": duration, "batch": True, "clock": "storage-authoritative-epoch"},
                )
                leases.append(DistributedLease(
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
                    traceparent=str(row["traceparent"]) if "traceparent" in row.keys() else "",
                    tracestate=str(row["tracestate"]) if "tracestate" in row.keys() else "",
                ))
            connection.commit()
        return leases

    def _require_lease_locked(
        self, connection: Any, job_id: str, worker_id: str, lease_token: str, *, row: Any | None = None,
    ) -> Any:
        if row is None:
            row = connection.execute(self._storage.lease_for_update_sql(), (str(job_id),)).fetchone()
        if row is None:
            raise _fail("DISTRIBUTED_JOB_UNKNOWN", "Distributed job does not exist")
        if str(row["state"]) not in {"leased", "running"} or str(row["lease_worker_id"]) != str(worker_id):
            raise _fail("DISTRIBUTED_LEASE_STALE", "Distributed job lease is no longer owned by this worker")
        expected = str(row["lease_token_sha256"])
        actual = hashlib.sha256(str(lease_token).encode("utf-8")).hexdigest()
        if not expected or not hmac.compare_digest(expected, actual):
            raise _fail("DISTRIBUTED_LEASE_STALE", "Distributed job lease token is invalid")
        now = self._lease_now(connection)
        expires = float(row["lease_expires_at"])
        if expires <= now:
            raise _fail(
                "DISTRIBUTED_LEASE_EXPIRED",
                "Distributed job lease has expired",
                job_id=str(job_id),
                worker_id=str(worker_id),
                lease_expires_at=expires,
                clock_authoritative_epoch=now,
                lease_remaining_seconds=expires - now,
            )
        if expires > now + MAX_LEASE_SECONDS + 60.0:
            raise _fail(
                "DISTRIBUTED_LEASE_TIME_INVALID",
                "Distributed job lease expiry is implausibly far in the future",
                lease_expires_at=expires, now=now, max_lease_seconds=MAX_LEASE_SECONDS,
            )
        return row

    def start_job(self, job_id: str, worker_id: str, lease_token: str) -> None:
        with self._lock, self._connection() as connection:
            fast_sql = self._storage.start_job_fast_sql()
            if fast_sql is not None:
                token_sha = hashlib.sha256(str(lease_token).encode("utf-8")).hexdigest()
                now = self._lease_now(connection)
                updated_at = utc_now()
                cursor = connection.execute(
                    fast_sql,
                    (
                        str(job_id), str(worker_id), token_sha, now, updated_at,
                        str(worker_id), "", "{}", utc_now(), MAX_JOB_EVENTS_PER_JOB - 1,
                    ),
                )
                if cursor.fetchone() is not None:
                    return
            self._begin(connection)
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token)
            previous = str(row["state"])
            if previous != "running":
                connection.execute("UPDATE distributed_jobs SET state='running',updated_at=? WHERE job_id=?", (utc_now(), str(job_id)))
                self._record_event_locked(connection, str(job_id), "started", previous, "running", worker_id=str(worker_id))
            connection.commit()

    def renew_lease(self, job_id: str, worker_id: str, lease_token: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> float:
        duration = max(15, min(MAX_LEASE_SECONDS, int(lease_seconds)))
        with self._lock, self._connection() as connection:
            self._begin(connection)
            self._require_lease_locked(connection, job_id, worker_id, lease_token)
            lease_now = self._lease_now(connection)
            expires = lease_now + duration
            connection.execute(
                "UPDATE distributed_jobs SET lease_expires_at=?,updated_at=? WHERE job_id=?",
                (expires, utc_now(), str(job_id)),
            )
            connection.execute(
                "UPDATE distributed_workers SET heartbeat_at=?,updated_at=? WHERE worker_id=?",
                (lease_now, utc_now(), str(worker_id)),
            )
            connection.commit()
        return expires

    def handover_lease(
        self, job_id: str, worker_id: str, lease_token: str, *, reason: str = "WORKER_HANDOVER"
    ) -> str:
        """Release a live lease under fencing, preserving non-idempotent review semantics."""
        code = _clean_token(reason or "WORKER_HANDOVER", "handover reason", 128)
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token)
            previous = str(row["state"])
            if str(row["side_effect_mode"]) == "non_idempotent" and str(row["side_effect_state"]) == "started":
                target = "review_required"
                code = "HANDOVER_AFTER_SIDE_EFFECT_START"
            elif int(row["attempt"]) < int(row["max_attempts"]):
                target = "queued"
            else:
                target = "failed"
                code = "HANDOVER_MAX_ATTEMPTS"
            connection.execute(
                """UPDATE distributed_jobs SET state=?,lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                   error_code=?,updated_at=? WHERE job_id=?""",
                (target, code, utc_now(), str(job_id)),
            )
            lease_now = self._lease_now(connection)
            connection.execute(
                "UPDATE distributed_workers SET active_leases=max(0,active_leases-1),heartbeat_at=?,updated_at=? WHERE worker_id=?",
                (lease_now, utc_now(), str(worker_id)),
            )
            self._record_event_locked(
                connection, str(job_id), "lease_handover", previous, target, worker_id=str(worker_id), code=code,
                details={"review_required": target == "review_required"},
            )
            if target in {"failed", "review_required"}:
                terminal_row = connection.execute(
                    "SELECT * FROM distributed_jobs WHERE job_id=?", (str(job_id),)
                ).fetchone()
                if terminal_row is not None:
                    self._fence_terminal_from_row_locked(connection, terminal_row, target)
            connection.commit()
            return target

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
            if str(row["side_effect_mode"]) == "non_idempotent":
                if str(row["side_effect_state"]) == "started":
                    connection.rollback()
                    raise _fail(
                        "DISTRIBUTED_SIDE_EFFECT_ALREADY_STARTED",
                        "Non-idempotent side effect is already fenced; automatic re-execution is forbidden",
                        job_id=str(job_id), worker_id=str(worker_id),
                    )
                cursor = connection.execute(
                    "UPDATE distributed_jobs SET side_effect_state='started',updated_at=? "
                    "WHERE job_id=? AND side_effect_state<>'started' AND lease_worker_id=? AND lease_token_sha256=?",
                    (utc_now(), str(job_id), str(worker_id), hashlib.sha256(str(lease_token).encode("utf-8")).hexdigest()),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise _fail(
                        "DISTRIBUTED_SIDE_EFFECT_FENCE_CONFLICT",
                        "Non-idempotent side-effect fence changed concurrently", job_id=str(job_id),
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
            fast_sql = self._storage.complete_fast_sql()
            if fast_sql is not None:
                now = self._lease_now(connection)
                terminal_at = utc_now()
                details_json, _ = _bounded_json({"result_sha256": result_sha}, MAX_EVENT_DETAILS_BYTES, "distributed event details")
                cursor = connection.execute(
                    fast_sql,
                    (
                        str(job_id), str(worker_id), token_sha, now,
                        terminal_at, terminal_at, result_json, result_sha, str(worker_id), token_sha,
                        now, utc_now(), str(worker_id),
                        str(worker_id), "", details_json, utc_now(), MAX_JOB_EVENTS_PER_JOB - 1,
                    ),
                )
                if cursor.fetchone() is not None:
                    return
            self._begin(connection)
            existing = connection.execute(self._storage.lease_for_update_sql(), (str(job_id),)).fetchone()
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
            row = self._require_lease_locked(connection, job_id, worker_id, lease_token, row=existing)
            previous = str(row["state"])
            effect = "completed" if str(row["side_effect_state"]) == "started" else str(row["side_effect_state"])
            terminal_at = utc_now()
            cursor = connection.execute(
                """UPDATE distributed_jobs SET state='completed',result_json=?,result_sha256=?,side_effect_state=?,
                   terminal_worker_id=?,terminal_lease_token_sha256=?,terminal_at=?,lease_worker_id='',
                   lease_token_sha256='',lease_expires_at=0,error_code='',updated_at=?
                   WHERE job_id=? AND state IN ('leased','running') AND lease_worker_id=? AND lease_token_sha256=?""",
                (result_json, result_sha, effect, str(worker_id), token_sha, terminal_at, terminal_at, str(job_id), str(worker_id), token_sha),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise _fail("DISTRIBUTED_TERMINAL_CONFLICT", "Distributed job completion lost its fenced lease")
            lease_now = self._lease_now(connection)
            connection.execute(
                "UPDATE distributed_workers SET active_leases=max(0,active_leases-1),heartbeat_at=?,updated_at=? WHERE worker_id=?",
                (lease_now, utc_now(), str(worker_id)),
            )
            self._record_event_locked(
                connection, str(job_id), "completed", previous, "completed", worker_id=str(worker_id),
                details={"result_sha256": result_sha},
            )
            terminal_row = connection.execute(
                "SELECT * FROM distributed_jobs WHERE job_id=?", (str(job_id),)
            ).fetchone()
            if terminal_row is not None:
                self._fence_terminal_from_row_locked(connection, terminal_row, "completed")
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
            lease_now = self._lease_now(connection)
            connection.execute(
                "UPDATE distributed_workers SET active_leases=max(0,active_leases-1),heartbeat_at=?,updated_at=? WHERE worker_id=?",
                (lease_now, utc_now(), str(worker_id)),
            )
            if state in {"failed", "review_required"}:
                terminal_row = connection.execute(
                    "SELECT * FROM distributed_jobs WHERE job_id=?", (str(job_id),)
                ).fetchone()
                if terminal_row is not None:
                    self._fence_terminal_from_row_locked(connection, terminal_row, state)
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

    def job(self, job_id: str, *, include_payload: bool = False) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM distributed_jobs WHERE job_id=?", (str(job_id),)).fetchone()
        if row is None:
            return None
        item = distributed_job_row(row)
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
        return [distributed_job_row(row) for row in rows]

    def count_jobs_by_idempotency_prefix(self, prefix: str, *, state: str = "") -> int:
        """Count jobs in a durable idempotency namespace without exposing payloads."""
        token = _clean_token(prefix, "idempotency prefix", 192)
        with self._connection() as connection:
            if state:
                row = connection.execute(
                    "SELECT count(*) FROM distributed_jobs WHERE substr(idempotency_key,1,?)=? AND state=?",
                    (len(token), token, str(state)),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT count(*) FROM distributed_jobs WHERE substr(idempotency_key,1,?)=?",
                    (len(token), token),
                ).fetchone()
        return 0 if row is None else int(row[0] or 0)

    def list_jobs_by_idempotency_prefix(
        self, prefix: str, *, state: str = "", limit: int = 500
    ) -> list[dict[str, Any]]:
        """List jobs belonging to one bounded distributed-work namespace."""
        token = _clean_token(prefix, "idempotency prefix", 192)
        cap = max(1, min(5000, int(limit)))
        with self._connection() as connection:
            if state:
                rows = connection.execute(
                    "SELECT * FROM distributed_jobs WHERE substr(idempotency_key,1,?)=? AND state=? "
                    "ORDER BY created_at ASC LIMIT ?",
                    (len(token), token, str(state), cap),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM distributed_jobs WHERE substr(idempotency_key,1,?)=? "
                    "ORDER BY created_at ASC LIMIT ?",
                    (len(token), token, cap),
                ).fetchall()
        return [distributed_job_row(row) for row in rows]
