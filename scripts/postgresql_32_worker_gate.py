from __future__ import annotations
import logging

import argparse
import base64
import json
import os
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.enterprise.distributed import DurableDistributedQueue


def _public_key() -> str:
    key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def _close(queue: DurableDistributedQueue) -> None:
    try:
        queue.close()
    except Exception:
        logging.getLogger(__name__).debug("Suppressed non-fatal exception", exc_info=True)


def _postgres_fencing_probe(
    coordinator: DurableDistributedQueue,
    clients: list[DurableDistributedQueue],
    worker_ids: list[str],
    run_id: str,
) -> dict[str, Any]:
    if len(worker_ids) < 2:
        return {"passed": False, "detail": "at least two workers are required for lease-fencing probe"}
    job_id = coordinator.enqueue(
        "benchmark.fencing", {"probe": True},
        resource_id="benchmark:postgresql-fencing",
        permission="workflow.execute",
        idempotency_key=f"{run_id}-fencing",
        max_attempts=3,
    )
    first_queue = clients[0]
    second_queue = clients[1 % len(clients)]
    first_worker, second_worker = worker_ids[0], worker_ids[1]
    first = first_queue.lease_next(first_worker, lease_seconds=15)
    if first is None or first.job_id != job_id:
        return {"passed": False, "detail": "first worker could not lease fencing probe"}
    first_queue.start_job(job_id, first_worker, first.lease_token)
    recovered = coordinator.recover_expired_leases(now=first.lease_expires_at + 1.0)
    state_after_recovery = coordinator.job(job_id)
    second = second_queue.lease_next(second_worker, lease_seconds=60)

    if recovered < 1:
        return {
            "passed": False,
            "detail": "expired lease recovery returned zero",
            "recovered": recovered,
            "job_id": job_id,
            "state_after_recovery": state_after_recovery,
            "second_job_id": None if second is None else second.job_id,
        }

    if second is None:
        return {
            "passed": False,
            "detail": "recovered fencing job could not be leased by second worker",
            "recovered": recovered,
            "job_id": job_id,
            "state_after_recovery": state_after_recovery,
            "second_worker": second_worker,
        }

    if second.job_id != job_id:
        return {
            "passed": False,
            "detail": "second worker leased a different job after fencing recovery",
            "recovered": recovered,
            "job_id": job_id,
            "state_after_recovery": state_after_recovery,
            "second_job_id": second.job_id,
        }

    stale_rejected = False
    try:
        first_queue.complete(job_id, first_worker, first.lease_token, {"winner": "stale"})
    except Exception:
        stale_rejected = True
    if not stale_rejected:
        return {"passed": False, "detail": "stale worker completed after lease reassignment"}

    second_queue.start_job(job_id, second_worker, second.lease_token)
    result = {"winner": "fresh"}
    second_queue.complete(job_id, second_worker, second.lease_token, result)
    # Lost terminal ACK replay must be idempotent, while a conflicting replay must fail closed.
    second_queue.complete(job_id, second_worker, second.lease_token, result)
    conflict_rejected = False
    try:
        second_queue.complete(job_id, second_worker, second.lease_token, {"winner": "conflict"})
    except Exception:
        conflict_rejected = True
    final = coordinator.job(job_id)
    return {
        "passed": bool(stale_rejected and conflict_rejected and final and final.get("state") == "completed"),
        "stale_completion_rejected": stale_rejected,
        "conflicting_terminal_replay_rejected": conflict_rejected,
        "exact_terminal_replay_idempotent": True,
        "final_state": None if final is None else final.get("state"),
    }


def run_gate(
    dsn: str, *, workers: int, jobs: int, p99_budget_ms: float, concurrency: int | None = None
) -> dict[str, Any]:
    coordinator = DurableDistributedQueue(dsn)
    public = _public_key()
    concurrency = max(workers, int(concurrency or workers))
    slots_per_worker = max(1, (concurrency + workers - 1) // workers)
    run_id = f"pgpool-{workers}w-{concurrency}c-{time.time_ns()}"
    worker_ids = [f"{run_id}-worker-{index:02d}" for index in range(workers)]
    for worker_id in worker_ids:
        coordinator.register_worker(worker_id, public, {"benchmark": True}, max_slots=slots_per_worker)

    # Use multiple independent queue clients/pools so the gate exercises PostgreSQL row-lock
    # semantics across client boundaries instead of only many threads on one Python object.
    client_count = max(2, min(concurrency, 16))
    clients = [DurableDistributedQueue(dsn) for _ in range(client_count)]
    job_ids = [
        coordinator.enqueue(
            "benchmark.noop", {"sequence": index},
            resource_id="benchmark:postgresql-32-worker",
            permission="workflow.execute",
            idempotency_key=f"{run_id}-job-{index:05d}",
            max_attempts=1,
        )
        for index in range(jobs)
    ]
    latencies_ms: list[float] = []
    errors: list[str] = []
    completed = 0
    state_lock = threading.Lock()
    began = time.perf_counter()

    def work(index: int) -> None:
        worker_id = worker_ids[index % len(worker_ids)]
        nonlocal completed
        queue = clients[index % len(clients)]
        empty_rounds = 0
        while True:
            with state_lock:
                if completed >= jobs or errors:
                    return
            operation_start = time.perf_counter()
            try:
                lease = queue.lease_next(worker_id, lease_seconds=60)
                if lease is None:
                    empty_rounds += 1
                    if empty_rounds > 500:
                        with state_lock:
                            errors.append(f"{worker_id}: lease starvation")
                        return
                    time.sleep(0.002)
                    continue
                empty_rounds = 0
                queue.start_job(lease.job_id, worker_id, lease.lease_token)
                queue.complete(lease.job_id, worker_id, lease.lease_token, {"status": "ok"})
            except (OSError, RuntimeError, ValueError) as exc:
                with state_lock:
                    errors.append(f"{worker_id}: {type(exc).__name__}: {exc}")
                return
            elapsed = (time.perf_counter() - operation_start) * 1000.0
            with state_lock:
                latencies_ms.append(elapsed)
                completed += 1

    try:
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="arenyxa-pg-pool") as executor:
            futures = [executor.submit(work, index) for index in range(concurrency)]
            for future in futures:
                future.result(timeout=180)

        duration = time.perf_counter() - began
        states = [coordinator.job(job_id) for job_id in job_ids]
        non_completed = sum(1 for row in states if row is None or row.get("state") != "completed")
        p99 = _percentile(latencies_ms, 0.99)
        fencing = _postgres_fencing_probe(coordinator, clients, worker_ids, run_id)
        health = coordinator.health()
        invariants = dict(health.get("state_invariants") or {})
        invariant_keys = ("inconsistent_lease_rows", "unreceipted_completed_jobs", "implausible_future_leases")
        invariants_clean = all(int(invariants.get(key, 1)) == 0 for key in invariant_keys)
        active_leases = int((health.get("capacity") or {}).get("active_leases", 0))
        pool_metrics = [queue.storage_metrics() for queue in [coordinator, *clients]]
        max_pool_size = max((int(row.get("pool_size", 0) or 0) for row in pool_metrics), default=0)
        total_pool_size = sum(int(row.get("pool_size", 0) or 0) for row in pool_metrics)
        connection_storm_free = all(
            int(row.get("pool_size", 0) or 0) <= int(row.get("pool_max", 64) or 64)
            and int(row.get("acquisition_failures", 0) or 0) == 0
            for row in pool_metrics
            if row.get("backend") == "postgresql"
        )
        result = {
            "schema": "arenyxa.postgresql-pool-concurrency-gate/v2",
            "workers": workers,
            "concurrency": concurrency,
            "slots_per_worker": slots_per_worker,
            "independent_clients": client_count,
            "jobs": jobs,
            "completed": completed,
            "errors": errors,
            "non_completed": non_completed,
            "duration_seconds": round(duration, 3),
            "throughput_jobs_per_second": round(completed / max(duration, 1e-9), 3),
            "latency_ms": {
                "mean": round(statistics.fmean(latencies_ms), 3) if latencies_ms else 0.0,
                "p50": round(_percentile(latencies_ms, 0.50), 3),
                "p95": round(_percentile(latencies_ms, 0.95), 3),
                "p99": round(p99, 3),
                "max": round(max(latencies_ms), 3) if latencies_ms else 0.0,
                "budget_p99": float(p99_budget_ms),
            },
            "fencing_probe": fencing,
            "state_invariants": {key: int(invariants.get(key, 0)) for key in invariant_keys},
            "active_leases_after": active_leases,
            "pool": {
                "instances": len(pool_metrics),
                "max_pool_size_observed": max_pool_size,
                "total_pool_size_observed": total_pool_size,
                "connection_storm_free": connection_storm_free,
                "metrics": pool_metrics,
            },
            "passed": (
                not errors
                and completed == jobs
                and non_completed == 0
                and p99 <= p99_budget_ms
                and bool(fencing.get("passed"))
                and invariants_clean
                and active_leases == 0
                and connection_storm_free
            ),
            "storage": coordinator.storage_capabilities,
        }
        return result
    finally:
        for queue in clients:
            _close(queue)
        _close(coordinator)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Release-blocking PostgreSQL 32-Worker tail-latency and fencing gate.")
    parser.add_argument("--dsn", default=os.environ.get("ARENYXA_POSTGRES_TEST_DSN", ""))
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--concurrency", type=int, default=None)
    parser.add_argument("--jobs", type=int, default=512)
    parser.add_argument("--p99-ms", type=float, default=float(os.environ.get("ARENYXA_POSTGRES_32W_P99_MS", "350")))
    parser.add_argument("--report", type=Path, default=None)
    args = parser.parse_args(argv)
    if not str(args.dsn).strip():
        parser.error("--dsn or ARENYXA_POSTGRES_TEST_DSN is required")
    result = run_gate(
        str(args.dsn),
        workers=max(2, args.workers),
        concurrency=None if args.concurrency is None else max(2, args.concurrency),
        jobs=max(64, args.jobs),
        p99_budget_ms=max(1.0, args.p99_ms),
    )
    encoded = json.dumps(result, sort_keys=True)
    print(encoded)
    if args.report is not None:
        args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
