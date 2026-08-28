from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed import DurableDistributedQueue

_GATE_OPERATION_ERRORS = (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, KeyError)


def _public_key() -> str:
    key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return ordered[index]


def _close(queue: DurableDistributedQueue) -> None:
    try:
        queue.close()
    except Exception:
        logging.getLogger(__name__).debug("Suppressed non-fatal exception", exc_info=True)


def _database_lease_diagnostic(
    queue: DurableDistributedQueue, job_id: str, lease_token: str
) -> dict[str, Any]:
    with queue._connection() as connection:
        row = connection.execute(
            "SELECT state,lease_expires_at,lease_worker_id,lease_token_sha256 "
            "FROM distributed_jobs WHERE job_id=?",
            (str(job_id),),
        ).fetchone()
    if row is None:
        return {
            "database_job_state": None,
            "database_lease_expires_at": None,
            "database_lease_worker_id": None,
            "database_lease_token_present": False,
            "database_lease_token_hash_state": "job_missing",
        }
    stored_digest = str(row["lease_token_sha256"])
    presented_digest = hashlib.sha256(str(lease_token).encode("utf-8")).hexdigest()
    return {
        "database_job_state": str(row["state"]),
        "database_lease_expires_at": float(row["lease_expires_at"]),
        "database_lease_worker_id": str(row["lease_worker_id"]),
        "database_lease_token_present": bool(stored_digest),
        "database_lease_token_hash_state": (
            "matches_presented" if stored_digest and stored_digest == presented_digest
            else "different_or_cleared"
        ),
    }


def _lease_failure_diagnostic(
    queue: DurableDistributedQueue,
    worker_id: str,
    phase: str,
    exc: BaseException,
    lease: Any | None,
    timing: dict[str, float | None],
) -> dict[str, Any]:
    failure = queue._clock.snapshot()
    lease_expires_at = None if lease is None else float(lease.lease_expires_at)
    lease_token = "" if lease is None else str(lease.lease_token)
    job_id = None if lease is None else str(lease.job_id)
    database = (
        {
            "database_job_state": None,
            "database_lease_expires_at": None,
            "database_lease_worker_id": None,
            "database_lease_token_present": False,
            "database_lease_token_hash_state": "lease_not_returned",
        }
        if job_id is None
        else _database_lease_diagnostic(queue, job_id, lease_token)
    )
    pool = queue.storage_metrics()
    finished_perf = timing.get("lease_next_finished_perf") or time.perf_counter()
    started_perf = timing.get("lease_next_started_perf") or finished_perf
    returned_stable = timing.get("lease_next_finished_stable")
    finished_wall = timing.get("lease_next_finished_wall")
    if phase in {"lease_next", "fencing_lease_next"}:
        returned_stable = returned_stable or failure.stable_epoch
        finished_wall = finished_wall or failure.wall_epoch
    start_stable = timing.get("start_job_started_stable")
    return {
        "phase": str(phase),
        "worker_id": str(worker_id),
        "job_id": job_id,
        "error_type": type(exc).__name__,
        "error_code": exc.code if isinstance(exc, ArenyxaError) else type(exc).__name__,
        "error_message": str(exc),
        "lease_expires_at": lease_expires_at,
        "lease_next_started_perf": timing.get("lease_next_started_perf"),
        "lease_next_finished_perf": finished_perf,
        "lease_next_elapsed_ms": round((finished_perf - started_perf) * 1000.0, 3),
        "lease_next_started_wall": timing.get("lease_next_started_wall"),
        "lease_next_finished_wall": finished_wall,
        "lease_next_started_stable": timing.get("lease_next_started_stable"),
        "lease_next_finished_stable": returned_stable,
        "start_job_started_wall": timing.get("start_job_started_wall"),
        "start_job_started_stable": start_stable,
        "failure_wall": failure.wall_epoch,
        "failure_stable": failure.stable_epoch,
        "lease_remaining_at_return_seconds": (
            None if lease_expires_at is None or returned_stable is None
            else lease_expires_at - returned_stable
        ),
        "lease_remaining_at_start_job_seconds": (
            None if lease_expires_at is None or start_stable is None
            else lease_expires_at - start_stable
        ),
        "lease_remaining_at_failure_seconds": (
            None if lease_expires_at is None else lease_expires_at - failure.stable_epoch
        ),
        "clock_stable_epoch": failure.stable_epoch,
        "clock_wall_epoch": failure.wall_epoch,
        "clock_monotonic": failure.monotonic,
        "clock_wall_drift_seconds": failure.wall_drift_seconds,
        "pool_size": int(pool.get("pool_size", 0) or 0),
        "pool_available": int(pool.get("pool_available", 0) or 0),
        "requests_waiting": int(pool.get("requests_waiting", 0) or 0),
        "requests_wait_ms": float(pool.get("requests_wait_ms", 0.0) or 0.0),
        "acquisition_failures": int(pool.get("acquisition_failures", 0) or 0),
        **database,
    }


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
    lease_started = first_queue._clock.snapshot()
    timing: dict[str, float | None] = {
        "lease_next_started_perf": time.perf_counter(),
        "lease_next_started_wall": lease_started.wall_epoch,
        "lease_next_started_stable": lease_started.stable_epoch,
    }
    try:
        first = first_queue.lease_next(first_worker, lease_seconds=15)
    except _GATE_OPERATION_ERRORS as exc:
        return {
            "passed": False,
            "detail": "first worker lease request failed",
            **_lease_failure_diagnostic(
                first_queue, first_worker, "fencing_lease_next", exc, None, timing
            ),
        }
    lease_finished = first_queue._clock.snapshot()
    timing.update({
        "lease_next_finished_perf": time.perf_counter(),
        "lease_next_finished_wall": lease_finished.wall_epoch,
        "lease_next_finished_stable": lease_finished.stable_epoch,
    })
    if first is None or first.job_id != job_id:
        return {"passed": False, "detail": "first worker could not lease fencing probe"}
    start_snapshot = first_queue._clock.snapshot()
    timing.update({
        "start_job_started_wall": start_snapshot.wall_epoch,
        "start_job_started_stable": start_snapshot.stable_epoch,
    })
    try:
        first_queue.start_job(job_id, first_worker, first.lease_token)
    except _GATE_OPERATION_ERRORS as exc:
        return {
            "passed": False,
            "detail": "first fencing lease expired before start_job",
            **_lease_failure_diagnostic(
                first_queue, first_worker, "fencing_start_job", exc, first, timing
            ),
        }

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
    stale_error_code = ""
    try:
        first_queue.complete(job_id, first_worker, first.lease_token, {"winner": "stale"})
    except ArenyxaError as exc:
        stale_error_code = str(exc.code)
        stale_rejected = stale_error_code == "DISTRIBUTED_LEASE_STALE"
    if not stale_rejected:
        return {
            "passed": False,
            "detail": "stale worker completion was not rejected by the lease-token fence",
            "stale_error_code": stale_error_code,
        }

    second_queue.start_job(job_id, second_worker, second.lease_token)
    result = {"winner": "fresh"}
    second_queue.complete(job_id, second_worker, second.lease_token, result)
    # Lost terminal ACK replay must be idempotent, while a conflicting replay must fail closed.
    second_queue.complete(job_id, second_worker, second.lease_token, result)
    conflict_rejected = False
    conflict_error_code = ""
    try:
        second_queue.complete(job_id, second_worker, second.lease_token, {"winner": "conflict"})
    except ArenyxaError as exc:
        conflict_error_code = str(exc.code)
        conflict_rejected = conflict_error_code == "DISTRIBUTED_TERMINAL_CONFLICT"
    final = coordinator.job(job_id)
    return {
        "passed": bool(stale_rejected and conflict_rejected and final and final.get("state") == "completed"),
        "stale_completion_rejected": stale_rejected,
        "stale_completion_error_code": stale_error_code,
        "conflicting_terminal_replay_rejected": conflict_rejected,
        "conflicting_terminal_replay_error_code": conflict_error_code,
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
    errors: list[dict[str, Any]] = []
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
            phase = "lease_next"
            lease = None
            lease_started = queue._clock.snapshot()
            timing: dict[str, float | None] = {
                "lease_next_started_perf": operation_start,
                "lease_next_started_wall": lease_started.wall_epoch,
                "lease_next_started_stable": lease_started.stable_epoch,
            }
            try:
                lease = queue.lease_next(worker_id, lease_seconds=60)
                lease_finished = queue._clock.snapshot()
                timing.update({
                    "lease_next_finished_perf": time.perf_counter(),
                    "lease_next_finished_wall": lease_finished.wall_epoch,
                    "lease_next_finished_stable": lease_finished.stable_epoch,
                })
                if lease is None:
                    empty_rounds += 1
                    if empty_rounds > 500:
                        with state_lock:
                            errors.append(_lease_failure_diagnostic(
                                queue,
                                worker_id,
                                phase,
                                ArenyxaError(
                                    "DISTRIBUTED_LEASE_STARVATION",
                                    "Worker could not obtain a lease within the bounded gate retry window",
                                    domain="ENTERPRISE_DISTRIBUTED",
                                ),
                                None,
                                timing,
                            ))
                        return
                    time.sleep(0.002)
                    continue
                empty_rounds = 0
                phase = "start_job"
                start_snapshot = queue._clock.snapshot()
                timing.update({
                    "start_job_started_wall": start_snapshot.wall_epoch,
                    "start_job_started_stable": start_snapshot.stable_epoch,
                })
                queue.start_job(lease.job_id, worker_id, lease.lease_token)
                phase = "complete"
                queue.complete(lease.job_id, worker_id, lease.lease_token, {"status": "ok"})
            except _GATE_OPERATION_ERRORS as exc:
                with state_lock:
                    errors.append(
                        _lease_failure_diagnostic(queue, worker_id, phase, exc, lease, timing)
                    )
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
            "schema": "arenyxa.postgresql-pool-concurrency-gate/v3",
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
