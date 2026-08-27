from __future__ import annotations

import base64
import os
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed import DurableDistributedQueue

SERVER_PERFORMANCE_SCHEMA = "arenyxa.enterprise-server-performance/v1"


def _public_key() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return float(ordered[index])


def _fd_count() -> int | None:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return None


@dataclass(frozen=True, slots=True)
class ServerConcurrencyLevel:
    workers: int
    jobs: int
    enqueue_ops_per_second: float
    execute_ops_per_second: float
    enqueue_p95_ms: float
    execute_p95_ms: float
    execute_p99_ms: float
    max_execute_ms: float
    errors: int
    completed: int
    thread_delta: int
    fd_delta: int | None
    invariants: dict[str, int]

    @property
    def stable(self) -> bool:
        return (
            self.errors == 0
            and self.completed == self.jobs
            and all(int(value) == 0 for value in self.invariants.values())
            and self.thread_delta <= 2
            and (self.fd_delta is None or self.fd_delta <= 4)
        )

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["stable"] = self.stable
        for key in ("enqueue_ops_per_second", "execute_ops_per_second", "enqueue_p95_ms", "execute_p95_ms", "execute_p99_ms", "max_execute_ms"):
            value[key] = round(float(value[key]), 3)
        return value


@dataclass(frozen=True, slots=True)
class ServerPerformanceReport:
    started_at_epoch: float
    duration_seconds: float
    levels: list[ServerConcurrencyLevel]
    recommended_workers: int
    peak_execute_ops_per_second: float

    @property
    def stable(self) -> bool:
        return bool(self.levels) and all(level.stable for level in self.levels)

    def to_dict(self) -> dict[str, Any]:
        baseline = min((item.execute_p99_ms for item in self.levels if item.workers <= 4), default=0.0)
        highest = max(self.levels, key=lambda item: item.workers, default=None)
        highest_p99 = 0.0 if highest is None else float(highest.execute_p99_ms)
        amplification = highest_p99 / max(1.0, baseline) if highest is not None else 0.0
        postgresql_recommended = bool(
            highest is not None
            and highest.workers >= 16
            and (highest_p99 >= 250.0 or amplification >= 8.0)
        )
        return {
            "schema": SERVER_PERFORMANCE_SCHEMA,
            "started_at_epoch": self.started_at_epoch,
            "duration_seconds": round(self.duration_seconds, 3),
            "stable": self.stable,
            "storage_backend": "sqlite-single-host",
            "recommended_workers": self.recommended_workers,
            "peak_execute_ops_per_second": round(self.peak_execute_ops_per_second, 3),
            "tail_latency": {
                "baseline_p99_ms": round(baseline, 3),
                "highest_concurrency_p99_ms": round(highest_p99, 3),
                "amplification": round(amplification, 3),
                "postgresql_recommended": postgresql_recommended,
                "guidance": (
                    "Use PostgreSQL for sustained high-concurrency Enterprise execution; SQLite remains the durable single-host backend."
                    if postgresql_recommended
                    else "SQLite tail latency remains within the current benchmark advisory envelope."
                ),
            },
            "levels": [item.to_dict() for item in self.levels],
        }


class ServerConcurrencyValidator:
    def __init__(self, *, jobs_per_level: int = 192, worker_levels: Iterable[int] = (1, 2, 4, 8, 16, 32)) -> None:
        self.jobs_per_level = max(64, min(4096, int(jobs_per_level)))
        normalized = sorted({max(1, min(64, int(value))) for value in worker_levels})
        self.worker_levels = tuple(normalized or [1])

    def run(self) -> ServerPerformanceReport:
        started_epoch = time.time()
        started = time.monotonic()
        levels: list[ServerConcurrencyLevel] = []
        for workers in self.worker_levels:
            levels.append(self._run_level(workers))
        stable_levels = [item for item in levels if item.stable]
        if stable_levels:
            peak = max(stable_levels, key=lambda item: item.execute_ops_per_second)
            peak_ops = peak.execute_ops_per_second
            minimum_p95 = min(item.execute_p95_ms for item in stable_levels)
            latency_ceiling = max(100.0, minimum_p95 * 4.0)
            efficient = [
                item for item in stable_levels
                if item.execute_ops_per_second >= peak_ops * 0.85 and item.execute_p95_ms <= latency_ceiling
            ]
            selected = max(efficient or stable_levels, key=lambda item: (item.execute_ops_per_second / (1.0 + item.execute_p95_ms / 100.0), -item.workers))
            recommended = selected.workers
        else:
            recommended = 1
            peak_ops = 0.0
        return ServerPerformanceReport(started_epoch, time.monotonic() - started, levels, recommended, peak_ops)

    def _run_level(self, workers: int) -> ServerConcurrencyLevel:
        before_threads = threading.active_count()
        before_fds = _fd_count()
        errors: list[str] = []
        error_lock = threading.Lock()
        enqueue_latencies: list[float] = []
        execute_latencies: list[float] = []
        latency_lock = threading.Lock()
        completed = 0
        completed_lock = threading.Lock()
        with tempfile.TemporaryDirectory(prefix=f"arenyxa-server-perf-{workers}-") as raw:
            queue = DurableDistributedQueue(Path(raw) / "distributed.sqlite")
            for index in range(workers):
                queue.register_worker(f"perf-worker-{index}", _public_key(), {"slots": 1}, max_slots=1)

            enqueue_started = time.perf_counter()

            def enqueue(index: int) -> None:
                began = time.perf_counter()
                try:
                    queue.enqueue(
                        "task.run",
                        {"task": {"name": f"server-perf-{index}"}, "index": index},
                        resource_id="server-performance",
                        permission="workflow.execute",
                        idempotency_key=f"server-performance-{workers}-{index}",
                        side_effect_mode="idempotent",
                    )
                except (ArenyxaError, OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
                    with error_lock:
                        errors.append(f"enqueue:{type(exc).__name__}:{exc}")
                    return
                with latency_lock:
                    enqueue_latencies.append((time.perf_counter() - began) * 1000.0)

            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="arenyxa-server-enqueue") as executor:
                futures = [executor.submit(enqueue, index) for index in range(self.jobs_per_level)]
                for future in as_completed(futures):
                    future.result()
            enqueue_duration = max(0.000001, time.perf_counter() - enqueue_started)

            execute_started = time.perf_counter()

            def consume(worker_index: int) -> None:
                nonlocal completed
                worker_id = f"perf-worker-{worker_index}"
                idle_rounds = 0
                while True:
                    began = time.perf_counter()
                    try:
                        lease = queue.lease_next(worker_id, lease_seconds=60)
                        if lease is None:
                            with completed_lock:
                                done = completed >= self.jobs_per_level
                            if done:
                                return
                            idle_rounds += 1
                            if idle_rounds >= 500:
                                raise RuntimeError("worker made no leasing progress")
                            time.sleep(0.001)
                            continue
                        idle_rounds = 0
                        queue.start_job(lease.job_id, worker_id, lease.lease_token)
                        queue.checkpoint(lease.job_id, worker_id, lease.lease_token, {"worker": worker_index})
                        queue.complete(lease.job_id, worker_id, lease.lease_token, {"ok": True, "worker": worker_index})
                        elapsed = (time.perf_counter() - began) * 1000.0
                        with latency_lock:
                            execute_latencies.append(elapsed)
                        with completed_lock:
                            completed += 1
                    except (ArenyxaError, OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
                        with error_lock:
                            errors.append(f"execute:{type(exc).__name__}:{exc}")
                        return

            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="arenyxa-server-execute") as executor:
                futures = [executor.submit(consume, index) for index in range(workers)]
                for future in as_completed(futures):
                    future.result()
            execute_duration = max(0.000001, time.perf_counter() - execute_started)
            health = queue.health()
            invariant_state = dict(health.get("state_invariants") or {})
            invariants = {
                "inconsistent_lease_rows": int(invariant_state.get("inconsistent_lease_rows", 0)),
                "unreceipted_completed_jobs": int(invariant_state.get("unreceipted_completed_jobs", 0)),
                "implausible_future_leases": int(invariant_state.get("implausible_future_leases", 0)),
                "active_jobs_remaining": sum(int((health.get("jobs") or {}).get(state, 0)) for state in ("queued", "leased", "running")),
            }

        time.sleep(0.01)
        after_threads = threading.active_count()
        after_fds = _fd_count()
        fd_delta = None if before_fds is None or after_fds is None else max(0, after_fds - before_fds)
        return ServerConcurrencyLevel(
            workers=workers,
            jobs=self.jobs_per_level,
            enqueue_ops_per_second=self.jobs_per_level / enqueue_duration,
            execute_ops_per_second=completed / execute_duration,
            enqueue_p95_ms=_percentile(enqueue_latencies, 0.95),
            execute_p95_ms=_percentile(execute_latencies, 0.95),
            execute_p99_ms=_percentile(execute_latencies, 0.99),
            max_execute_ms=max(execute_latencies, default=0.0),
            errors=len(errors),
            completed=completed,
            thread_delta=max(0, after_threads - before_threads),
            fd_delta=fd_delta,
            invariants=invariants,
        )
