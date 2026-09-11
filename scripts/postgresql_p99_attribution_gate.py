"""Diagnostic-only PostgreSQL P99 gate with full client-pool prewarm.

This module intentionally leaves the production runtime and release gate unchanged.
It substitutes a queue class only while invoking the existing run_gate() function so
we can isolate whether lazy pool growth from min_size=4 to max_size=8 is inflating
first-run tail latency.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from arenyxa.enterprise.distributed import DurableDistributedQueue
from scripts import postgresql_32_worker_gate as base_gate


def _prewarm_client_pool(
    queue: DurableDistributedQueue, *, timeout_seconds: float = 15.0
) -> None:
    """Force one bounded client pool to reach pool_max before timed work begins."""
    metrics = queue.storage_metrics()
    target = max(1, int(metrics.get("pool_max", 1) or 1))
    ready = threading.Barrier(target + 1)
    release = threading.Event()

    def hold_connection() -> None:
        with queue._connection():
            try:
                ready.wait(timeout=timeout_seconds)
                release.wait(timeout=timeout_seconds)
            except threading.BrokenBarrierError as exc:
                raise RuntimeError("PostgreSQL client-pool prewarm barrier failed") from exc

    with ThreadPoolExecutor(max_workers=target, thread_name_prefix="arenyxa-pg-prewarm") as executor:
        futures = [executor.submit(hold_connection) for _ in range(target)]
        try:
            ready.wait(timeout=timeout_seconds)
        except threading.BrokenBarrierError as exc:
            raise RuntimeError("PostgreSQL client pool did not reach configured capacity") from exc
        finally:
            release.set()
        for future in futures:
            future.result(timeout=timeout_seconds)

    warmed = queue.storage_metrics()
    pool_size = int(warmed.get("pool_size", 0) or 0)
    if pool_size < target:
        raise RuntimeError(
            f"PostgreSQL client pool prewarm incomplete: pool_size={pool_size}, pool_max={target}"
        )


class _FullyPrewarmedClientQueue(DurableDistributedQueue):
    _instance_lock = threading.Lock()
    _instance_count = 0

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        with type(self)._instance_lock:
            type(self)._instance_count += 1
            ordinal = type(self)._instance_count
        # run_gate() creates the coordinator first, then the 16 timed client queues.
        # Keep the coordinator unchanged so the A/B variable is client-pool prewarm only.
        if ordinal > 1:
            _prewarm_client_pool(self)


def run_attribution_gate(
    dsn: str, *, workers: int = 64, concurrency: int = 128,
    jobs: int = 1024, p99_budget_ms: float = 500.0,
) -> dict[str, Any]:
    original_queue = base_gate.DurableDistributedQueue
    _FullyPrewarmedClientQueue._instance_count = 0
    base_gate.DurableDistributedQueue = _FullyPrewarmedClientQueue
    try:
        result = base_gate.run_gate(
            dsn,
            workers=workers,
            concurrency=concurrency,
            jobs=jobs,
            p99_budget_ms=p99_budget_ms,
        )
    finally:
        base_gate.DurableDistributedQueue = original_queue
    result["diagnostic"] = {
        "mode": "full-client-pool-prewarm",
        "production_runtime_modified": False,
        "release_gate_modified": False,
    }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Arenyxa PostgreSQL P99 full-pool-prewarm attribution gate")
    parser.add_argument("--dsn", default=os.environ.get("ARENYXA_POSTGRES_TEST_DSN", ""))
    parser.add_argument("--jobs", type=int, default=1024)
    parser.add_argument("--p99-ms", type=float, default=500.0)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    if not str(args.dsn).strip():
        parser.error("--dsn or ARENYXA_POSTGRES_TEST_DSN is required")
    result = run_attribution_gate(
        str(args.dsn), jobs=max(256, int(args.jobs)), p99_budget_ms=max(1.0, float(args.p99_ms))
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return 0 if bool(result.get("passed")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
