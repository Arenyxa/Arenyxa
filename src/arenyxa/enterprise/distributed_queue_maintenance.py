from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any, Mapping

from arenyxa.domain.models import utc_now
from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed_rows import distributed_job_row
from arenyxa.enterprise.distributed_protocol import MAX_LEASE_SECONDS, _clean_token, _fail

LOGGER = logging.getLogger(__name__)


class DistributedQueueMaintenanceMixin:
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
