from __future__ import annotations

import base64
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.enterprise.distributed import DurableDistributedQueue, MAX_LEASE_SECONDS


def _public_key() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _queue(tmp_path: Path, workers: int = 2) -> DurableDistributedQueue:
    queue = DurableDistributedQueue(tmp_path / "fault-matrix.sqlite")
    for index in range(workers):
        queue.register_worker(f"worker-{index}", _public_key(), {"slots": 1}, max_slots=1)
    return queue


def _job(queue: DurableDistributedQueue, key: str = "fault-job", *, side_effect_mode: str = "idempotent") -> str:
    return queue.enqueue(
        "task.run", {"task": {"name": key}}, resource_id="resource-fault",
        permission="workflow.execute", idempotency_key=key, side_effect_mode=side_effect_mode,
        max_attempts=4,
    )


def test_stale_worker_cannot_complete_after_lease_recovery_and_reassignment(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = _job(queue)
    first = queue.lease_next("worker-0", lease_seconds=15)
    assert first is not None
    queue.start_job(job, "worker-0", first.lease_token)
    assert queue.recover_expired_leases(now=first.lease_expires_at + 1) == 1
    second = queue.lease_next("worker-1", lease_seconds=15)
    assert second is not None and second.job_id == job

    with pytest.raises(Exception) as stale:
        queue.complete(job, "worker-0", first.lease_token, {"winner": "old"})
    assert getattr(stale.value, "code", "") == "DISTRIBUTED_LEASE_STALE"

    queue.start_job(job, "worker-1", second.lease_token)
    queue.complete(job, "worker-1", second.lease_token, {"winner": "new"})
    state = queue.job(job)
    assert state is not None and state["state"] == "completed"
    assert state["result"] == {"winner": "new"}
    assert state["terminal_worker_id"] == "worker-1"


def test_simultaneous_workers_cannot_double_lease_one_job(tmp_path: Path) -> None:
    queue = _queue(tmp_path, workers=8)
    job = _job(queue, "single-owner")

    def attempt(index: int):
        return queue.lease_next(f"worker-{index}", lease_seconds=30)

    with ThreadPoolExecutor(max_workers=8) as executor:
        leases = list(executor.map(attempt, range(8)))
    winners = [lease for lease in leases if lease is not None]
    assert len(winners) == 1
    assert winners[0].job_id == job
    state = queue.job(job)
    assert state is not None and state["state"] == "leased"
    assert state["lease_worker_id"] == winners[0].worker_id


def test_atomic_worker_admission_rolls_back_empty_poll_and_preserves_fencing(tmp_path: Path, monkeypatch) -> None:
    queue = _queue(tmp_path, workers=1)
    atomic_sql = (
        "UPDATE distributed_workers SET active_leases=active_leases+1,heartbeat_at=?,updated_at=? "
        "WHERE worker_id=? AND state='active' AND active_leases<max_slots "
        "RETURNING protocol_min,protocol_max"
    )
    monkeypatch.setattr(queue._storage, "claim_worker_slot_for_lease_sql", lambda: atomic_sql)

    assert queue.lease_next("worker-0") is None
    worker = queue.worker("worker-0")
    assert worker is not None and worker["active_leases"] == 0

    job = _job(queue, "atomic-admission")
    lease = queue.lease_next("worker-0")
    assert lease is not None and lease.job_id == job
    queue.start_job(job, "worker-0", lease.lease_token)
    queue.complete(job, "worker-0", lease.lease_token, {"status": "completed"})
    assert queue.job(job)["state"] == "completed"


def test_runtime_clock_rollback_like_future_lease_fails_closed_and_health_surfaces_it(tmp_path: Path) -> None:
    queue = _queue(tmp_path, workers=1)
    job = _job(queue, "clock-rollback")
    lease = queue.lease_next("worker-0", lease_seconds=30)
    assert lease is not None
    db = tmp_path / "fault-matrix.sqlite"
    with closing(sqlite3.connect(db)) as connection:
        connection.execute(
            "UPDATE distributed_jobs SET lease_expires_at=lease_expires_at+? WHERE job_id=?",
            (MAX_LEASE_SECONDS + 600, job),
        )
        connection.commit()

    health = queue.health()
    assert health["state_invariants"]["implausible_future_leases"] == 1
    with pytest.raises(Exception) as invalid:
        queue.start_job(job, "worker-0", lease.lease_token)
    assert getattr(invalid.value, "code", "") == "DISTRIBUTED_LEASE_TIME_INVALID"

    repaired = queue.reconcile_durable_state()
    assert repaired["leases_recovered"] == 1
    assert queue.health()["state_invariants"]["implausible_future_leases"] == 0
    assert queue.job(job)["state"] == "queued"


def test_non_idempotent_job_with_started_side_effect_never_auto_replays_after_worker_loss(tmp_path: Path) -> None:
    queue = _queue(tmp_path, workers=1)
    job = _job(queue, "non-idempotent-fault", side_effect_mode="non_idempotent")
    lease = queue.lease_next("worker-0", lease_seconds=15)
    assert lease is not None
    queue.start_job(job, "worker-0", lease.lease_token)
    queue.mark_side_effect_started(job, "worker-0", lease.lease_token)
    assert queue.recover_expired_leases(now=lease.lease_expires_at + 1) == 1
    state = queue.job(job)
    assert state is not None and state["state"] == "review_required"
    assert queue.lease_next("worker-0") is None


def test_corrupt_active_lease_binding_is_reconciled_before_it_can_be_reused(tmp_path: Path) -> None:
    queue = _queue(tmp_path, workers=1)
    job = _job(queue, "corrupt-lease")
    lease = queue.lease_next("worker-0")
    assert lease is not None
    db = tmp_path / "fault-matrix.sqlite"
    with closing(sqlite3.connect(db)) as connection:
        connection.execute("UPDATE distributed_jobs SET lease_token_sha256='' WHERE job_id=?", (job,))
        connection.commit()
    summary = queue.reconcile_durable_state()
    assert summary["leases_recovered"] == 1
    state = queue.job(job)
    assert state is not None and state["state"] == "queued"
    assert state["lease_worker_id"] == ""
    assert queue.worker("worker-0")["active_leases"] == 0
