from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any

from arenyxa.enterprise.fleet_telemetry import FleetTelemetryAnalyzer


@dataclass(slots=True)
class FleetTelemetryPoint:
    sampled_at: float
    severity: str
    total_workers: int
    healthy_workers: int
    stale_workers: int
    total_slots: int
    active_slots: int
    slot_utilization: float
    queued_jobs: int
    running_jobs: int
    failed_jobs: int
    retry_pressure: int
    invariant_violations: int


@dataclass(slots=True)
class FleetChangeEvent:
    sampled_at: float
    kind: str
    severity: str
    message: str
    data: dict[str, Any]


class FleetLiveTelemetry:
    MAX_POINTS = 3600
    MAX_EVENTS = 2000

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._points: deque[FleetTelemetryPoint] = deque(maxlen=self.MAX_POINTS)
        self._events: deque[FleetChangeEvent] = deque(maxlen=self.MAX_EVENTS)
        self._previous: dict[str, Any] | None = None
        self._analyzer = FleetTelemetryAnalyzer()

    def ingest(self, snapshot: dict[str, Any], *, sampled_at: float | None = None) -> dict[str, Any]:
        stamp = time.time() if sampled_at is None else float(sampled_at)
        telemetry = self._analyzer.analyze(snapshot)
        point = FleetTelemetryPoint(
            sampled_at=stamp,
            severity=str(telemetry.severity),
            total_workers=int(telemetry.worker_count),
            healthy_workers=int(telemetry.healthy_workers),
            stale_workers=int(telemetry.stale_workers),
            total_slots=int(telemetry.total_slots),
            active_slots=int(telemetry.active_slots),
            slot_utilization=float(telemetry.slot_utilization),
            queued_jobs=int(telemetry.queued_jobs),
            running_jobs=int(telemetry.leased_jobs),
            failed_jobs=int(telemetry.failed_jobs),
            retry_pressure=int(telemetry.retry_pressure),
            invariant_violations=int(telemetry.invariant_violations),
        )
        current = asdict(point)
        with self._lock:
            previous = self._previous
            self._points.append(point)
            for event in self._changes(previous, current, stamp):
                self._events.append(event)
            self._previous = current
        return self.snapshot()

    def snapshot(self, *, tail_points: int = 300, tail_events: int = 200) -> dict[str, Any]:
        points_limit = max(1, min(int(tail_points), self.MAX_POINTS))
        events_limit = max(1, min(int(tail_events), self.MAX_EVENTS))
        with self._lock:
            points = list(self._points)[-points_limit:]
            events = list(self._events)[-events_limit:]
        latest = asdict(points[-1]) if points else {}
        return {
            "latest": latest,
            "points": [asdict(item) for item in points],
            "events": [asdict(item) for item in events],
            "sample_count": len(points),
        }

    def clear(self) -> None:
        with self._lock:
            self._points.clear()
            self._events.clear()
            self._previous = None

    @staticmethod
    def _changes(previous: dict[str, Any] | None, current: dict[str, Any], stamp: float) -> list[FleetChangeEvent]:
        if previous is None:
            return [FleetChangeEvent(stamp, "baseline", "info", "Fleet telemetry baseline established", {})]
        events: list[FleetChangeEvent] = []
        checks = (
            ("stale_workers", "stale-workers", "warning"),
            ("failed_jobs", "failed-jobs", "error"),
            ("invariant_violations", "invariant-violations", "critical"),
            ("retry_pressure", "retry-pressure", "warning"),
            ("queued_jobs", "queue-depth", "info"),
        )
        for key, kind, severity in checks:
            before = int(previous.get(key) or 0)
            after = int(current.get(key) or 0)
            if before == after:
                continue
            direction = "increased" if after > before else "decreased"
            events.append(FleetChangeEvent(stamp, kind, severity if after > before else "info", f"{key} {direction}: {before} → {after}", {"before": before, "after": after}))
        before_severity = str(previous.get("severity") or "")
        after_severity = str(current.get("severity") or "")
        if before_severity != after_severity:
            events.append(FleetChangeEvent(stamp, "severity", after_severity or "info", f"Fleet severity changed: {before_severity or '-'} → {after_severity or '-'}", {}))
        return events
