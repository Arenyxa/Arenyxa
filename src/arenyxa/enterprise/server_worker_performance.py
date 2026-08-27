from __future__ import annotations

import base64
import os
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed import DurableDistributedQueue


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


@dataclass(slots=True)
class WorkerSlotLevel:
    slots: int
    jobs: int
    throughput_jobs_per_second: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    errors: int
    completed: int
    thread_delta: int
    fd_delta: int | None
    invariants: dict[str, int]
    stable: bool


@dataclass(slots=True)
class WorkerSlotPerformanceReport:
    schema: str
    stable: bool
    storage_backend: str
    recommended_slots: int
    peak_throughput_jobs_per_second: float
    levels: list[WorkerSlotLevel]

    def to_dict(self) -> dict[str, Any]:
        baseline = min((float(level.p99_ms) for level in self.levels if level.slots <= 4), default=0.0)
        highest = max(self.levels, key=lambda level: level.slots, default=None)
        highest_p99 = 0.0 if highest is None else float(highest.p99_ms)
        amplification = highest_p99 / max(1.0, baseline) if highest is not None else 0.0
        postgresql_recommended = bool(
            highest is not None
            and highest.slots >= 16
            and (highest_p99 >= 250.0 or amplification >= 8.0)
        )
        return {
            "schema": self.schema,
            "stable": self.stable,
            "storage_backend": self.storage_backend,
            "recommended_slots": self.recommended_slots,
            "peak_throughput_jobs_per_second": round(self.peak_throughput_jobs_per_second, 3),
            "tail_latency": {
                "baseline_p99_ms": round(baseline, 3),
                "highest_concurrency_p99_ms": round(highest_p99, 3),
                "amplification": round(amplification, 3),
                "postgresql_recommended": postgresql_recommended,
            },
            "levels": [asdict(level) for level in self.levels],
        }


class WorkerSlotConcurrencyValidator:
    def __init__(self, *, jobs_per_level: int = 192, slot_levels: Iterable[int] = (1, 2, 4, 8, 16, 32)) -> None:
        self.jobs_per_level = max(64, min(2048, int(jobs_per_level)))
        normalized = sorted({max(1, min(64, int(value))) for value in slot_levels})
        self.slot_levels = tuple(normalized or [1])

    def run(self) -> WorkerSlotPerformanceReport:
        levels = [self._run_level(slots) for slots in self.slot_levels]
        stable_levels = [level for level in levels if level.stable]
        if stable_levels:
            peak_level = max(stable_levels, key=lambda item: item.throughput_jobs_per_second)
            peak = peak_level.throughput_jobs_per_second
            baseline_p95 = max(1.0, stable_levels[0].p95_ms)
            # SQLite can gain throughput from more slots while quietly multiplying tail
            # latency. A single-host recommendation must therefore prefer a real
            # throughput/latency sweet spot rather than the largest thread count.
            latency_ceiling = min(75.0, max(25.0, baseline_p95 * 4.0))
            efficient = [
                item for item in stable_levels
                if item.throughput_jobs_per_second >= peak * 0.70
                and item.p95_ms <= latency_ceiling
            ]
            if efficient:
                recommended = max(
                    efficient,
                    key=lambda item: (item.throughput_jobs_per_second, -item.p95_ms, -item.slots),
                ).slots
            else:
                recommended = max(
                    stable_levels,
                    key=lambda item: (
                        item.throughput_jobs_per_second
                        / ((1.0 + item.p95_ms / baseline_p95) ** 0.5)
                    ),
                ).slots
        else:
            peak = 0.0
            recommended = 1
        return WorkerSlotPerformanceReport(
            schema="arenyxa.enterprise-worker-slot-performance/v1",
            stable=bool(levels) and all(level.stable for level in levels),
            storage_backend="sqlite-single-host",
            recommended_slots=recommended,
            peak_throughput_jobs_per_second=peak,
            levels=levels,
        )

    def _run_level(self, slots: int) -> WorkerSlotLevel:
        before_threads = threading.active_count()
        before_fds = _fd_count()
        latencies: list[float] = []
        errors: list[str] = []
        state_lock = threading.Lock()
        completed = 0
        with tempfile.TemporaryDirectory(prefix=f"arenyxa-worker-slots-{slots}-") as raw:
            queue = DurableDistributedQueue(Path(raw) / "distributed.sqlite")
            worker_id = "slot-worker"
            queue.register_worker(worker_id, _public_key(), {"slots": slots}, max_slots=slots)
            for index in range(self.jobs_per_level):
                queue.enqueue(
                    "task.run", {"task": {"index": index}}, resource_id="worker-slot-performance",
                    permission="workflow.execute", idempotency_key=f"slot-{slots}-{index}", side_effect_mode="idempotent",
                )

            def execute(lease) -> None:
                nonlocal completed
                began = time.perf_counter()
                try:
                    queue.start_job(lease.job_id, worker_id, lease.lease_token)
                    if int(lease.attempt) % 4 == 0:
                        queue.checkpoint(lease.job_id, worker_id, lease.lease_token, {"slot_level": slots})
                    queue.complete(lease.job_id, worker_id, lease.lease_token, {"status": "completed"})
                    elapsed = (time.perf_counter() - began) * 1000.0
                    with state_lock:
                        completed += 1
                        latencies.append(elapsed)
                except (ArenyxaError, OSError, sqlite3.Error, ValueError, RuntimeError) as exc:
                    with state_lock:
                        errors.append(f"{type(exc).__name__}: {exc}")

            started = time.perf_counter()
            active: set[Future] = set()
            with ThreadPoolExecutor(max_workers=slots, thread_name_prefix="arenyxa-slot-perf") as executor:
                idle = 0
                while completed < self.jobs_per_level:
                    available = max(0, slots - len(active))
                    if available:
                        leases = queue.lease_many(worker_id, max_items=available, lease_seconds=60)
                        for lease in leases:
                            active.add(executor.submit(execute, lease))
                    if active:
                        done, active = wait(active, timeout=0.2, return_when=FIRST_COMPLETED)
                        for future in done:
                            future.result()
                        idle = 0
                    else:
                        idle += 1
                        if idle > 1000:
                            errors.append("worker slot validator made no progress")
                            break
                        time.sleep(0.001)
                    if errors:
                        break
            duration = max(0.000001, time.perf_counter() - started)
            health = queue.health()
            state = dict(health.get("state_invariants") or {})
            invariants = {
                "inconsistent_lease_rows": int(state.get("inconsistent_lease_rows", 0)),
                "unreceipted_completed_jobs": int(state.get("unreceipted_completed_jobs", 0)),
                "implausible_future_leases": int(state.get("implausible_future_leases", 0)),
                "active_jobs_remaining": sum(int((health.get("jobs") or {}).get(name, 0)) for name in ("queued", "leased", "running")),
            }
        time.sleep(0.01)
        after_threads = threading.active_count()
        after_fds = _fd_count()
        fd_delta = None if before_fds is None or after_fds is None else max(0, after_fds - before_fds)
        stable = (
            not errors and completed == self.jobs_per_level and all(value == 0 for value in invariants.values())
            and max(0, after_threads - before_threads) <= 2 and (fd_delta is None or fd_delta <= 4)
        )
        return WorkerSlotLevel(
            slots=slots,
            jobs=self.jobs_per_level,
            throughput_jobs_per_second=round(completed / duration, 3),
            p95_ms=round(_percentile(latencies, 0.95), 3),
            p99_ms=round(_percentile(latencies, 0.99), 3),
            max_ms=round(max(latencies, default=0.0), 3),
            errors=len(errors),
            completed=completed,
            thread_delta=max(0, after_threads - before_threads),
            fd_delta=fd_delta,
            invariants=invariants,
            stable=stable,
        )
