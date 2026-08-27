from __future__ import annotations

from typing import Any

from arenyxa.compat import dataclass
from arenyxa.enterprise.runtime_storage import RuntimeStorageCapabilities


@dataclass(frozen=True, slots=True)
class StorageCapacityAssessment:
    backend: str
    severity: str
    worker_count: int
    total_worker_slots: int
    active_leases: int
    recommended_total_worker_slots: int
    high_concurrency_cutover_slots: int
    oversubscription_ratio: float
    postgresql_recommended: bool
    code: str
    guidance: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "severity": self.severity,
            "worker_count": self.worker_count,
            "total_worker_slots": self.total_worker_slots,
            "active_leases": self.active_leases,
            "recommended_total_worker_slots": self.recommended_total_worker_slots,
            "high_concurrency_cutover_slots": self.high_concurrency_cutover_slots,
            "oversubscription_ratio": round(self.oversubscription_ratio, 3),
            "postgresql_recommended": self.postgresql_recommended,
            "code": self.code,
            "guidance": self.guidance,
        }


def assess_storage_capacity(
    capabilities: RuntimeStorageCapabilities,
    *,
    worker_count: int,
    total_worker_slots: int,
    active_leases: int = 0,
) -> StorageCapacityAssessment:
    """Assess distributed-runtime concurrency against the persistence backend contract.

    SQLite remains the durable single-host backend. The assessment does not weaken its
    durability PRAGMAs to chase benchmark numbers; instead it exposes sustained writer
    pressure and recommends PostgreSQL before serialized WAL contention becomes a
    tail-latency problem.
    """

    workers = max(0, int(worker_count))
    slots = max(0, int(total_worker_slots))
    active = max(0, int(active_leases))
    recommended = max(
        1,
        int(
            capabilities.recommended_total_worker_slots
            or capabilities.recommended_worker_slots
            or 1
        ),
    )
    cutover = max(
        recommended + 1,
        int(capabilities.high_concurrency_cutover_slots or recommended * 2),
    )
    ratio = float(slots) / float(recommended) if recommended else 0.0

    if capabilities.multi_host_writers:
        severity = "healthy" if slots <= recommended else "warning"
        code = "STORAGE_CAPACITY_HEALTHY" if severity == "healthy" else "STORAGE_CAPACITY_ADVISORY"
        guidance = (
            "PostgreSQL concurrent-writer storage is active. Monitor database connection, lock, and latency telemetry."
            if severity == "healthy"
            else "Configured Worker capacity exceeds the backend advisory target; validate PostgreSQL pool and server sizing."
        )
        return StorageCapacityAssessment(
            backend=capabilities.backend,
            severity=severity,
            worker_count=workers,
            total_worker_slots=slots,
            active_leases=active,
            recommended_total_worker_slots=recommended,
            high_concurrency_cutover_slots=cutover,
            oversubscription_ratio=ratio,
            postgresql_recommended=False,
            code=code,
            guidance=guidance,
        )

    high_worker_fanout = workers >= int(capabilities.high_concurrency_cutover_workers or 16)
    postgresql_recommended = slots >= cutover or high_worker_fanout
    if postgresql_recommended:
        severity = "critical"
        code = "SQLITE_HIGH_CONCURRENCY_CUTOVER"
        guidance = (
            "SQLite is operating beyond the durable single-host concurrency envelope. "
            "Move the Enterprise distributed runtime to PostgreSQL for sustained high-concurrency execution; "
            "do not reduce SQLite durability settings merely to improve benchmark tail latency."
        )
    elif slots > recommended or workers > max(4, recommended):
        severity = "warning"
        code = "SQLITE_SERIALIZED_WRITER_PRESSURE"
        guidance = (
            "SQLite serialized WAL writer pressure is elevated. Keep Worker capacity near the backend recommendation "
            "or migrate to PostgreSQL before increasing concurrency further."
        )
    else:
        severity = "healthy"
        code = "STORAGE_CAPACITY_HEALTHY"
        guidance = "SQLite capacity is within the durable single-host concurrency recommendation."

    return StorageCapacityAssessment(
        backend=capabilities.backend,
        severity=severity,
        worker_count=workers,
        total_worker_slots=slots,
        active_leases=active,
        recommended_total_worker_slots=recommended,
        high_concurrency_cutover_slots=cutover,
        oversubscription_ratio=ratio,
        postgresql_recommended=postgresql_recommended,
        code=code,
        guidance=guidance,
    )
