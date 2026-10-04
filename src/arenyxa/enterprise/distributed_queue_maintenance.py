"""Durable lease-clock anchoring and bounded terminal-history maintenance."""
from __future__ import annotations

import json
from typing import Any

from arenyxa.enterprise.distributed_protocol import _clean_token, _fail
from arenyxa.enterprise.distributed_rows import distributed_job_row


class DistributedQueueMaintenanceMixin:
    """Keep time authority, worker lock helpers and terminal fences coherent."""

    def job_for_idempotency(self, key: str) -> dict[str, Any] | None:
        token = _clean_token(key, "idempotency key", 192)
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM distributed_jobs WHERE idempotency_key=?", (token,)).fetchone()
            if row is not None:
                return distributed_job_row(row)
            row = connection.execute("SELECT * FROM distributed_job_idempotency WHERE idempotency_key=?", (token,)).fetchone()
            if row is None:
                return None
            result = {key: row[key] for key in row.keys() if key != "terminal_receipt"}
            result["state"] = str(row["terminal_state"])
            result["history_pruned"] = True
            return result

    def _initialize_lease_clock(self) -> None:
        if self._storage.capabilities.external_server:
            return
        with self._lock, self._connection() as connection:
            self._begin(connection)
            row = connection.execute("SELECT value FROM distributed_meta WHERE key='lease_clock_anchor'").fetchone()
            domain = self._boot_clock_domain()
            mono = self._clock.monotonic()
            anchor = None if row is None else json.loads(str(row[0]))
            if anchor is not None and anchor["domain"] == domain and mono >= float(anchor["monotonic"]):
                self._clock = self._clock.anchored(float(anchor["epoch"]), float(anchor["monotonic"]))
            else:
                if anchor is not None or connection.execute(
                    "SELECT 1 FROM distributed_jobs WHERE state IN ('leased','running') LIMIT 1"
                ).fetchone() is not None:
                    # A boot change or unanchored legacy lease has no trusted
                    # monotonic domain. Expiry
                    # recovery preserves started non-idempotent effects for review.
                    connection.execute("UPDATE distributed_jobs SET lease_expires_at=1 WHERE state IN ('leased','running')")
                value = json.dumps({"domain": domain, "monotonic": mono, "epoch": self._clock.stable_epoch()})
                connection.execute("INSERT INTO distributed_meta(key,value) VALUES('lease_clock_anchor',?) "
                                   "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (value,))
            connection.commit()

    def _now(self, connection: Any | None = None) -> float:
        if connection is not None:
            return self._storage.current_epoch(connection, self._clock)
        if not self._storage.capabilities.external_server:
            return self._clock.stable_epoch()
        with self._connection() as current:
            return self._storage.current_epoch(current, self._clock)

    def _lock_worker(self, connection: Any, worker_id: str) -> Any:
        return connection.execute(self._storage.worker_for_lease_sql(), (str(worker_id),)).fetchone()

    def _lock_all_workers(self, connection: Any) -> None:
        # Recovery may affect multiple workers. Consistent ordering prevents
        # it from creating a cycle with a worker-bound transition.
        connection.execute(self._storage.lock_workers_sql()).fetchall()

    @staticmethod
    def _same_job_identity(first: Any, second: Any) -> bool:
        return all(str(first[key]) == str(second[key]) for key in
                   ("job_id", "kind", "payload_sha256", "resource_id", "permission", "side_effect_mode"))

    def _store_terminal_fence(self, connection: Any, row: Any) -> None:
        existing = connection.execute("SELECT * FROM distributed_job_idempotency WHERE idempotency_key=?",
                                      (str(row["idempotency_key"]),)).fetchone()
        if existing is not None and not self._same_job_identity(existing, row):
            raise _fail("DISTRIBUTED_IDEMPOTENCY_COLLISION", "Terminal idempotency fence conflicts with its original job")
        connection.execute(
            """INSERT INTO distributed_job_idempotency(
                idempotency_key,job_id,kind,payload_sha256,resource_id,permission,side_effect_mode,
                terminal_state,created_at,terminal_at,updated_at,terminal_receipt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(idempotency_key) DO UPDATE SET terminal_state=excluded.terminal_state,
                    terminal_at=excluded.terminal_at,updated_at=excluded.updated_at,terminal_receipt=excluded.terminal_receipt""",
            tuple(str(row[key]) for key in ("idempotency_key", "job_id", "kind", "payload_sha256", "resource_id", "permission", "side_effect_mode"))
            + (str(row["state"]), str(row["created_at"]), str(row["terminal_at"] or row["updated_at"]), str(row["updated_at"]),
               json.dumps([str(row["terminal_worker_id"]), str(row["terminal_lease_token_sha256"]), str(row["result_sha256"])])),
        )

    def _retain_terminal_locked(self, connection: Any, max_terminal: int, max_idempotent_tombstones: int) -> dict[str, Any]:
        report = {"jobs_pruned": 0, "idempotent_tombstones_pruned": 0,
                  "pruning_disabled": not self._idempotency_backfill_complete}
        if self._idempotency_backfill_complete:
            rows = connection.execute(
                "SELECT * FROM distributed_jobs WHERE state IN ('completed','failed','cancelled') "
                "ORDER BY updated_at DESC,job_id DESC"
            ).fetchall()
            for row in rows[max(0, int(max_terminal)):]:
                self._store_terminal_fence(connection, row)
                cursor = connection.execute("DELETE FROM distributed_jobs WHERE job_id=? AND state IN ('completed','failed','cancelled')",
                                            (str(row["job_id"]),))
                report["jobs_pruned"] += cursor.rowcount
            fences = connection.execute(
                "SELECT idempotency_key FROM distributed_job_idempotency WHERE side_effect_mode='idempotent' "
                "ORDER BY terminal_at DESC,idempotency_key DESC"
            ).fetchall()
            for fence in fences[max(0, int(max_idempotent_tombstones)):]:
                cursor = connection.execute(
                    "DELETE FROM distributed_job_idempotency WHERE idempotency_key=? AND side_effect_mode='idempotent' "
                    "AND NOT EXISTS (SELECT 1 FROM distributed_jobs WHERE distributed_jobs.idempotency_key=distributed_job_idempotency.idempotency_key)",
                    (str(fence[0]),),
                )
                report["idempotent_tombstones_pruned"] += cursor.rowcount
        report["jobs_remaining"] = int(connection.execute("SELECT count(*) FROM distributed_jobs").fetchone()[0])
        for mode in ("idempotent", "non_idempotent"):
            report[mode + "_tombstones_remaining"] = int(connection.execute(
                "SELECT count(*) FROM distributed_job_idempotency WHERE side_effect_mode=?", (mode,)).fetchone()[0])
        return report

    def retain_terminal_jobs(self, *, max_terminal: int = 10_000, max_idempotent_tombstones: int = 100_000) -> dict[str, Any]:
        """Bound completed history; non-idempotent fences and review jobs never expire."""
        with self._lock, self._connection() as connection:
            self._begin(connection)
            self._lock_all_workers(connection)
            report = self._retain_terminal_locked(connection, max_terminal, max_idempotent_tombstones)
            connection.commit()
            return report
