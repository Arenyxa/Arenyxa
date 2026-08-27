from __future__ import annotations

from dataclasses import asdict, field
from arenyxa.compat import dataclass
from datetime import datetime
from arenyxa.compat import UTC
from typing import Any

from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.domain.models import utc_now


@dataclass(slots=True)
class RuntimeHealthSnapshot:
    generated_at: str = field(default_factory=utc_now)
    recovery: dict[str, Any] = field(default_factory=dict)
    runner: dict[str, Any] = field(default_factory=dict)
    scheduler: dict[str, Any] = field(default_factory=dict)
    capture: dict[str, Any] = field(default_factory=dict)
    workers: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RuntimeHealthService:
    






    def __init__(self, context: Any) -> None:
        self.context = context

    @staticmethod
    def _parse_datetime(value: object) -> datetime | None:
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(str(value))
        except (TypeError, ValueError, OverflowError):
            return None
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)

    def snapshot(self) -> RuntimeHealthSnapshot:
        audit = RuntimeRecoveryService(self.context.store).audit()
        scheduler_rows = self.context.scheduler.snapshot()
        now = datetime.now(UTC)
        overdue = 0
        for row in scheduler_rows:
            due = self._parse_datetime(row.get("next_run_at"))
            if row.get("enabled") and not row.get("running") and due is not None and due < now:
                overdue += 1

        capture_session = self.context.capture.session
        capture = {
            "active": bool(
                capture_session is not None
                and capture_session.state.value in {"preparing", "capturing", "paused", "finalizing"}
            ),
            "id": None if capture_session is None else capture_session.id,
            "state": None if capture_session is None else capture_session.state.value,
            "events": 0 if capture_session is None else int(capture_session.event_count),
            "dropped": 0 if capture_session is None else int(capture_session.dropped_events),
        }

        worker_error: str | None = None
        try:
            workers = self.context.nextgen.workers.list()
            worker_summary = {
                "configured": len(workers),
                "enabled": sum(1 for item in workers if item.enabled),
                "items": [
                    {
                        "id": item.id,
                        "name": item.name,
                        "base_url": item.base_url,
                        "enabled": bool(item.enabled),
                        "weight": int(item.weight),
                    }
                    for item in workers
                ],
            }
        except Exception as exc:                                                         
            worker_error = f"{type(exc).__name__}: {exc}"[:500]
            worker_summary = {"configured": 0, "enabled": 0, "items": []}
        worker_summary["error"] = worker_error

        scheduler = {
            "configured": len(scheduler_rows),
            "enabled": sum(1 for row in scheduler_rows if row.get("enabled")),
            "running": sum(1 for row in scheduler_rows if row.get("running")),
            "pending_callbacks": sum(1 for row in scheduler_rows if row.get("callback_pending")),
            "overdue": overdue,
            "items": scheduler_rows,
        }

        return RuntimeHealthSnapshot(
            recovery=audit.to_dict(),
            runner=self.context.runner.concurrency_snapshot(),
            scheduler=scheduler,
            capture=capture,
            workers=worker_summary,
        )

    def probe_workers(self) -> list[dict[str, Any]]:
        return self.context.nextgen.workers.health_all(max_workers=4)
