from __future__ import annotations

"""Bounded in-process performance telemetry for Arenyxa Phase 6.

This module deliberately avoids a dependency on the GUI, database, or network stack.  Hot
paths can record timings/counters in constant bounded memory while control-plane and diagnostic
surfaces consume immutable snapshots.  No telemetry path is allowed to grow without bound.
"""

import math
import threading
import time
from collections import Counter, deque
from contextlib import contextmanager
from typing import Any, Iterator

from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now


@dataclass(frozen=True, slots=True)
class LatencySummary:
    name: str
    count: int
    min_ms: float
    max_ms: float
    mean_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "count": self.count,
            "min_ms": self.min_ms,
            "max_ms": self.max_ms,
            "mean_ms": self.mean_ms,
            "p50_ms": self.p50_ms,
            "p95_ms": self.p95_ms,
            "p99_ms": self.p99_ms,
        }


class PerformanceTelemetry:
    """Thread-safe, bounded latency/counter/gauge telemetry.

    Latency series retain only the newest ``max_samples_per_metric`` values.  Counter and gauge
    names are also bounded so attacker-controlled labels cannot turn diagnostics into a memory
    leak.  Unknown metric names are normalized and rejected once the metric budget is exhausted.
    """

    def __init__(self, *, max_metrics: int = 128, max_samples_per_metric: int = 2048) -> None:
        self.max_metrics = max(8, min(2048, int(max_metrics)))
        self.max_samples_per_metric = max(32, min(32768, int(max_samples_per_metric)))
        self._latencies: dict[str, deque[float]] = {}
        self._counters: Counter[str] = Counter()
        self._gauges: dict[str, float] = {}
        self._dropped_metric_names = 0
        self._lock = threading.RLock()

    @staticmethod
    def _name(value: str) -> str:
        text = str(value or "metric").strip().lower().replace(" ", "_")
        cleaned = "".join(ch for ch in text if ch.isalnum() or ch in "._:-")[:96]
        return cleaned or "metric"

    def _accept_name_locked(self, name: str) -> bool:
        known = name in self._latencies or name in self._counters or name in self._gauges
        if known:
            return True
        known_names = set(self._latencies) | set(self._counters) | set(self._gauges)
        if len(known_names) >= self.max_metrics:
            self._dropped_metric_names += 1
            return False
        return True

    def record_latency(self, name: str, milliseconds: float) -> None:
        metric = self._name(name)
        try:
            value = float(milliseconds)
        except (TypeError, ValueError, OverflowError):
            return
        if not math.isfinite(value) or value < 0:
            return
        value = min(value, 24.0 * 60.0 * 60.0 * 1000.0)
        with self._lock:
            if not self._accept_name_locked(metric):
                return
            series = self._latencies.get(metric)
            if series is None:
                series = deque(maxlen=self.max_samples_per_metric)
                self._latencies[metric] = series
            series.append(value)

    def increment(self, name: str, amount: int = 1) -> None:
        metric = self._name(name)
        try:
            value = int(amount)
        except (TypeError, ValueError, OverflowError):
            return
        with self._lock:
            if not self._accept_name_locked(metric):
                return
            self._counters[metric] += value

    def gauge(self, name: str, value: float) -> None:
        metric = self._name(name)
        try:
            numeric = float(value)
        except (TypeError, ValueError, OverflowError):
            return
        if not math.isfinite(numeric):
            return
        with self._lock:
            if not self._accept_name_locked(metric):
                return
            self._gauges[metric] = numeric

    @contextmanager
    def measure(self, name: str) -> Iterator[None]:
        started = time.perf_counter()
        try:
            yield
        finally:
            self.record_latency(name, (time.perf_counter() - started) * 1000.0)

    @staticmethod
    def _percentile(sorted_values: list[float], fraction: float) -> float:
        if not sorted_values:
            return 0.0
        if len(sorted_values) == 1:
            return sorted_values[0]
        position = (len(sorted_values) - 1) * fraction
        lower = int(math.floor(position))
        upper = int(math.ceil(position))
        if lower == upper:
            return sorted_values[lower]
        weight = position - lower
        return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight

    def latency_summary(self, name: str) -> LatencySummary:
        metric = self._name(name)
        with self._lock:
            values = list(self._latencies.get(metric, ()))
        if not values:
            return LatencySummary(metric, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        ordered = sorted(values)
        count = len(ordered)
        return LatencySummary(
            metric,
            count,
            round(ordered[0], 3),
            round(ordered[-1], 3),
            round(sum(ordered) / count, 3),
            round(self._percentile(ordered, 0.50), 3),
            round(self._percentile(ordered, 0.95), 3),
            round(self._percentile(ordered, 0.99), 3),
        )

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            latency_names = tuple(sorted(self._latencies))
            counters = dict(sorted(self._counters.items()))
            gauges = dict(sorted(self._gauges.items()))
            dropped = self._dropped_metric_names
        return {
            "schema": "arenyxa.performance-telemetry/v1",
            "generated_at": utc_now(),
            "bounded": True,
            "max_metrics": self.max_metrics,
            "max_samples_per_metric": self.max_samples_per_metric,
            "dropped_metric_names": dropped,
            "latencies": {name: self.latency_summary(name).to_dict() for name in latency_names},
            "counters": counters,
            "gauges": gauges,
        }
