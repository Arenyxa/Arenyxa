from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class FleetTelemetry:
    backend: str
    database_integrity: str
    worker_count: int
    healthy_workers: int
    stale_workers: int
    total_slots: int
    active_slots: int
    slot_utilization: float
    job_count: int
    queued_jobs: int
    leased_jobs: int
    terminal_jobs: int
    failed_jobs: int
    retry_pressure: int
    invariant_violations: int
    capacity_severity: str
    postgresql_recommended: bool
    severity: str
    warnings: list[str]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class FleetTelemetryAnalyzer:
    STALE_HEARTBEAT_SECONDS = 120.0

    def analyze(self, snapshot: dict[str, Any], *, now: datetime | None = None) -> FleetTelemetry:
        queue = dict(snapshot.get("queue") or {})
        workers = [dict(item) for item in list(snapshot.get("workers") or []) if isinstance(item, dict)]
        jobs = [dict(item) for item in list(snapshot.get("jobs") or []) if isinstance(item, dict)]
        now_value = now or datetime.now(timezone.utc)
        stale = 0
        healthy = 0
        total_slots = 0
        active_slots = 0
        warnings: list[str] = []
        for worker in workers:
            max_slots = max(0, int(worker.get("max_slots") or 0))
            active = max(0, int(worker.get("active_leases") or 0))
            total_slots += max_slots
            active_slots += min(active, max_slots) if max_slots else active
            state = str(worker.get("state") or "").casefold()
            age = self._heartbeat_age(worker.get("heartbeat_at"), now_value)
            if age is not None and age > self.STALE_HEARTBEAT_SECONDS:
                stale += 1
            elif state not in {"offline", "disabled", "revoked", "failed"}:
                healthy += 1
        states: dict[str, int] = {}
        retry_pressure = 0
        for job in jobs:
            state = str(job.get("state") or "unknown").casefold()
            states[state] = states.get(state, 0) + 1
            attempt = max(0, int(job.get("attempt") or 0))
            if attempt > 1 and state not in {"completed", "cancelled"}:
                retry_pressure += attempt - 1
        invariants = dict(queue.get("state_invariants") or {})
        violation_count = self._count_violations(invariants)
        capabilities = dict(queue.get("storage_capabilities") or queue.get("storage") or {})
        capacity = dict(queue.get("capacity") or {})
        backend = str(capabilities.get("backend") or capacity.get("backend") or "unknown")
        integrity = str(queue.get("database_integrity") or "unknown")
        queued = sum(states.get(name, 0) for name in ("queued", "pending", "reclaimable"))
        leased = sum(states.get(name, 0) for name in ("leased", "running", "assigned"))
        terminal = sum(states.get(name, 0) for name in ("completed", "failed", "cancelled"))
        failed = states.get("failed", 0)
        utilization = round(active_slots / max(1, total_slots), 4)
        if violation_count:
            warnings.append(f"Distributed state invariants report {violation_count} violations")
        if integrity.casefold() not in {"ok", "pass", "healthy"}:
            warnings.append(f"Storage integrity is {integrity}")
        if stale:
            warnings.append(f"{stale} workers have stale heartbeats")
        if queued > max(20, total_slots * 4) and total_slots:
            warnings.append("Queued work materially exceeds current worker-slot capacity")
        if retry_pressure > max(10, len(jobs) // 10):
            warnings.append("Distributed retry pressure is elevated")
        recommended_slots = max(0, int(capabilities.get("recommended_worker_slots") or 0))
        capacity_severity = str(capacity.get("severity") or "unknown").casefold()
        postgresql_recommended = bool(capacity.get("postgresql_recommended"))
        if postgresql_recommended:
            warnings.append(
                str(capacity.get("guidance") or "SQLite high-concurrency capacity exceeded; migrate the distributed runtime to PostgreSQL")
            )
        elif backend.casefold().startswith("sqlite") and (
            len(workers) > 1 or (recommended_slots > 0 and total_slots > recommended_slots)
        ):
            warnings.append(
                "SQLite backend is under serialized-writer pressure; reduce Worker slots to the backend recommendation or use PostgreSQL"
            )
        if utilization > 0.95 and queued:
            warnings.append("Worker slots are saturated while jobs remain queued")
        severity = "critical" if violation_count or integrity.casefold() in {"corrupt", "failed", "invalid"} else "warning" if warnings else "healthy"
        return FleetTelemetry(
            backend=backend,
            database_integrity=integrity,
            worker_count=len(workers),
            healthy_workers=healthy,
            stale_workers=stale,
            total_slots=total_slots,
            active_slots=active_slots,
            slot_utilization=utilization,
            job_count=len(jobs),
            queued_jobs=queued,
            leased_jobs=leased,
            terminal_jobs=terminal,
            failed_jobs=failed,
            retry_pressure=retry_pressure,
            invariant_violations=violation_count,
            capacity_severity=capacity_severity,
            postgresql_recommended=postgresql_recommended,
            severity=severity,
            warnings=warnings,
        )

    @classmethod
    def _count_violations(cls, value: Any) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return max(0, int(value))
        if isinstance(value, dict):
            return sum(cls._count_violations(item) for item in value.values())
        if isinstance(value, list):
            return sum(cls._count_violations(item) for item in value)
        return 0

    @staticmethod
    def _heartbeat_age(value: Any, now: datetime) -> float | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, (now - parsed.astimezone(timezone.utc)).total_seconds())
