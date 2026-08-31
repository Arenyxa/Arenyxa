from __future__ import annotations
"""Health/readiness projection for the durable distributed runtime.

Kept outside the queue mutation engine so operational diagnostics can evolve without
expanding the lease/state-machine module.
"""

import time
from typing import Any

from arenyxa.enterprise.distributed_protocol import (
    CURRENT_PROTOCOL,
    DISTRIBUTED_SCHEMA,
    MAX_LEASE_SECONDS,
    MIN_COMPATIBLE_PROTOCOL,
)
from arenyxa.enterprise.storage_capacity import assess_storage_capacity


class DistributedQueueHealthMixin:
    """Read-only health projection shared by distributed queue backends."""

    def storage_metrics(self) -> dict[str, Any]:
        """Return backend pool/connection metrics without making health collection fatal."""
        metrics = getattr(self._storage, "pool_metrics", None)
        if not callable(metrics):
            return {"backend": self._storage.capabilities.backend}
        try:
            return dict(metrics())
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as exc:
            return {
                "backend": self._storage.capabilities.backend,
                "metrics_error": f"{type(exc).__name__}: {exc}"[:256],
            }

    def clock_snapshot(self) -> dict[str, float]:
        """Expose stable/wall clock drift for lease diagnostics and NTP/suspend analysis."""
        snapshot = self._clock.snapshot()
        return {
            "stable_epoch": snapshot.stable_epoch,
            "wall_epoch": snapshot.wall_epoch,
            "monotonic": snapshot.monotonic,
            "wall_drift_seconds": snapshot.wall_drift_seconds,
            "lease_grace_seconds": self._lease_grace_seconds,
        }

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
            authoritative_now = self._lease_now(connection)
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
                       THEN 1 ELSE 0 END) AS unreceipted_count,
                   sum(CASE WHEN state IN ('leased','running') AND lease_expires_at>?
                       THEN 1 ELSE 0 END) AS implausible_future_count
                   FROM distributed_jobs GROUP BY state""",
                (authoritative_now + MAX_LEASE_SECONDS + 60.0,),
            ).fetchall()
            states = {str(row["state"]): int(row["state_count"]) for row in job_rows}
            inconsistent_leases = sum(int(row["inconsistent_count"] or 0) for row in job_rows)
            unreceipted_completed = sum(int(row["unreceipted_count"] or 0) for row in job_rows)
            implausible_future_leases = sum(int(row["implausible_future_count"] or 0) for row in job_rows)
            worker_states = {
                str(row[0]): int(row[1])
                for row in connection.execute(
                    "SELECT state,count(*) FROM distributed_workers GROUP BY state"
                ).fetchall()
            }
            worker_capacity = connection.execute(
                "SELECT count(*) AS worker_count, "
                "coalesce(sum(max_slots),0) AS total_worker_slots, "
                "coalesce(sum(active_leases),0) AS active_leases "
                "FROM distributed_workers WHERE state<>'revoked'"
            ).fetchone()
            worker_count = 0 if worker_capacity is None else int(worker_capacity["worker_count"] or 0)
            total_worker_slots = 0 if worker_capacity is None else int(worker_capacity["total_worker_slots"] or 0)
            active_leases = 0 if worker_capacity is None else int(worker_capacity["active_leases"] or 0)
        capacity = assess_storage_capacity(
            self._storage.capabilities,
            worker_count=worker_count,
            total_worker_slots=total_worker_slots,
            active_leases=active_leases,
        )
        return {
            "schema": DISTRIBUTED_SCHEMA,
            "protocol_current": CURRENT_PROTOCOL,
            "protocol_min": MIN_COMPATIBLE_PROTOCOL,
            "database_integrity": "ok" if valid else detail,
            "last_reconciliation": dict(getattr(self, "_last_reconciliation", {})),
            "state_invariants": {
                "inconsistent_lease_rows": inconsistent_leases,
                "unreceipted_completed_jobs": unreceipted_completed,
                "implausible_future_leases": implausible_future_leases,
                "journal_events": event_count,
            },
            "jobs": states,
            "workers": worker_states,
            "storage": self.storage_capabilities,
            "storage_circuit": self.storage_circuit_snapshot() if hasattr(self, "storage_circuit_snapshot") else {"state": "unknown"},
            "worker_heartbeat_timeout_seconds": float(getattr(self, "_worker_heartbeat_timeout_seconds", 0.0)),
            "capacity": capacity.as_dict(),
            "deployment_profile": {
                "mode": "multi-host" if self._storage.capabilities.multi_host_writers else "embedded-single-host",
                "server_scale_backend": self._storage.capabilities.backend,
                "multi_host_writers": self._storage.capabilities.multi_host_writers,
                "row_lock_skip_locked": self._storage.capabilities.row_lock_skip_locked,
                "guidance": (
                    "PostgreSQL runtime is suitable for concurrent multi-host Server/Worker deployment"
                    if self._storage.capabilities.multi_host_writers
                    else "SQLite runtime is durable single-host mode with serialized writers; keep Worker slots near the reported recommendation and use PostgreSQL for sustained high-concurrency or multi-host deployment"
                ),
                "recommended_worker_slots": int(self._storage.capabilities.recommended_worker_slots or 0),
                "recommended_total_worker_slots": int(self._storage.capabilities.recommended_total_worker_slots or 0),
                "high_concurrency_cutover_slots": int(self._storage.capabilities.high_concurrency_cutover_slots or 0),
                "recommended_parallel_writers": int(self._storage.capabilities.recommended_parallel_writers or 0),
                "write_model": self._storage.capabilities.write_model,
                "capacity_severity": capacity.severity,
                "postgresql_recommended": capacity.postgresql_recommended,
            },
        }
