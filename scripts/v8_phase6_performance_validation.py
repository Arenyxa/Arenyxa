from __future__ import annotations

"""Current-host Phase-6 microbaseline for bounded telemetry and proxy persistence.

This is not a WAN, Npcap, Windows-Service, or PostgreSQL production benchmark.  It validates the
new Phase-6 hot-path primitives on the host where the source gate executes and records explicit
scope so the result cannot be mistaken for external certification.
"""

import argparse
import json
import platform
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa import __version__  # noqa: E402
from arenyxa.application.performance_telemetry import PerformanceTelemetry  # noqa: E402
from arenyxa.application.resilience_drills import ResilienceDrillService  # noqa: E402
from arenyxa.domain.models import utc_now  # noqa: E402
from arenyxa.infrastructure.capture.proxy_models import ProxyFlow  # noqa: E402
from arenyxa.infrastructure.capture.proxy_persistence import ProxyPersistencePipeline  # noqa: E402


class _MemorySink:
    def __init__(self) -> None:
        self.count = 0
        self._lock = threading.Lock()

    def store(self, *args: Any) -> None:
        _flow = args[-1]
        with self._lock:
            self.count += 1


def _telemetry_baseline(samples: int = 100_000) -> dict[str, Any]:
    telemetry = PerformanceTelemetry(max_metrics=32, max_samples_per_metric=4096)
    started = time.perf_counter()
    for index in range(samples):
        telemetry.record_latency("phase6.hotpath", float(index % 1000) / 10.0)
        if index % 10 == 0:
            telemetry.increment("phase6.events")
    elapsed = max(1e-9, time.perf_counter() - started)
    snapshot = telemetry.snapshot()
    summary = snapshot["latencies"]["phase6.hotpath"]
    return {
        "samples_submitted": samples,
        "samples_retained": summary["count"],
        "max_samples": snapshot["max_samples_per_metric"],
        "elapsed_seconds": round(elapsed, 6),
        "operations_per_second": round(samples / elapsed, 2),
        "p50_ms": summary["p50_ms"],
        "p95_ms": summary["p95_ms"],
        "p99_ms": summary["p99_ms"],
        "bounded": summary["count"] <= snapshot["max_samples_per_metric"],
    }


def _proxy_persistence_baseline(flows: int = 5_000) -> dict[str, Any]:
    history = _MemorySink()
    archive = _MemorySink()
    pipeline = ProxyPersistencePipeline(history, archive, capacity=256)
    started = time.perf_counter()
    try:
        for sequence in range(flows):
            flow = ProxyFlow(
                id=f"bench-{sequence}",
                sequence=sequence,
                started_at=utc_now(),
                client="127.0.0.1",
                scheme="http",
                method="GET",
                host="benchmark.invalid",
                port=80,
                target="/",
                completed_at=utc_now(),
            )
            pipeline.enqueue("bench", flow)
        drained = pipeline.flush(30.0)
        elapsed = max(1e-9, time.perf_counter() - started)
        status = pipeline.status()
    finally:
        closed = pipeline.close(30.0)
    return {
        "flows": flows,
        "elapsed_seconds": round(elapsed, 6),
        "flows_per_second": round(flows / elapsed, 2),
        "history_rows": history.count,
        "archive_rows": archive.count,
        "drained": bool(drained),
        "closed": bool(closed),
        "capacity": status["capacity"],
        "max_queue_depth": status["max_queue_depth"],
        "sync_fallbacks": status["sync_fallbacks"],
        "history_failures": status["history_failures"],
        "archive_failures": status["archive_failures"],
        "bounded": status["max_queue_depth"] <= status["capacity"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="V8_PHASE6_PERFORMANCE_REPORT.json")
    args = parser.parse_args()

    telemetry = _telemetry_baseline()
    proxy = _proxy_persistence_baseline()
    sqlite_drill = ResilienceDrillService._sqlite_lock_backpressure()
    pressure_drill = ResilienceDrillService._resource_pressure_degradation()

    checks = {
        "telemetry_bounded": bool(telemetry["bounded"]),
        "telemetry_rate": float(telemetry["operations_per_second"]) >= 10_000.0,
        "proxy_bounded": bool(proxy["bounded"]),
        "proxy_complete": bool(proxy["drained"] and proxy["closed"] and proxy["history_rows"] == proxy["flows"] and proxy["archive_rows"] == proxy["flows"]),
        "proxy_no_sink_failures": int(proxy["history_failures"]) == 0 and int(proxy["archive_failures"]) == 0,
        "proxy_rate": float(proxy["flows_per_second"]) >= 500.0,
        "sqlite_contention_bounded": bool(sqlite_drill[0]),
        "resource_pressure_recovers": bool(pressure_drill[0]),
    }
    passed = all(checks.values())
    payload = {
        "schema": "arenyxa.v8-phase6-performance/v1",
        "generated_at": utc_now(),
        "version": __version__,
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "scope": "current-host in-process Phase-6 microbaseline; not Windows/Npcap/WAN/PostgreSQL production certification",
        "telemetry": telemetry,
        "proxy_persistence": proxy,
        "sqlite_contention": {"passed": sqlite_drill[0], "detail": sqlite_drill[1], "metrics": sqlite_drill[2]},
        "resource_pressure": {"passed": pressure_drill[0], "detail": pressure_drill[1], "metrics": pressure_drill[2]},
        "checks": checks,
        "passed": passed,
    }
    target = ROOT / args.output
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
