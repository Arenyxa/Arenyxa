from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.enterprise.distributed import DurableDistributedQueue


def _worker_key() -> tuple[Ed25519PrivateKey, str]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, base64.urlsafe_b64encode(public).decode("ascii").rstrip("=")


def _leased_queue(tmp_path: Path, *, side_effect_mode: str = "idempotent"):
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite")
    _private, public = _worker_key()
    queue.register_worker("worker-a", public, {"slots": 1}, max_slots=1)
    job = queue.enqueue(
        "task.run", {"task": {"name": "state-test"}}, resource_id="resource-a",
        permission="workflow.execute", idempotency_key="state-test", side_effect_mode=side_effect_mode,
    )
    lease = queue.lease_next("worker-a")
    assert lease is not None
    queue.start_job(job, "worker-a", lease.lease_token)
    return queue, job, lease


def test_completion_terminal_receipt_is_idempotent_but_conflicts_fail_closed(tmp_path: Path) -> None:
    queue, job, lease = _leased_queue(tmp_path)
    result = {"run_id": "run-a", "status": "completed", "result_count": 7}
    queue.complete(job, "worker-a", lease.lease_token, result)

                                                                                                             
    queue.complete(job, "worker-a", lease.lease_token, result)
    state = queue.job(job)
    assert state is not None
    assert state["state"] == "completed"
    assert state["result"] == result
    assert state["result_sha256"] == hashlib.sha256(
        b'{"result_count":7,"run_id":"run-a","status":"completed"}'
    ).hexdigest()
    assert state["terminal_worker_id"] == "worker-a"
    assert state["terminal_at"]

    with pytest.raises(Exception) as changed_result:
        queue.complete(job, "worker-a", lease.lease_token, {**result, "result_count": 8})
    assert getattr(changed_result.value, "code", "") == "DISTRIBUTED_TERMINAL_CONFLICT"

    with pytest.raises(Exception) as changed_token:
        queue.complete(job, "worker-a", lease.lease_token + "tamper", result)
    assert getattr(changed_token.value, "code", "") == "DISTRIBUTED_TERMINAL_CONFLICT"


def test_transition_journal_survives_restart_and_does_not_duplicate_terminal_ack(tmp_path: Path) -> None:
    queue, job, lease = _leased_queue(tmp_path)
    queue.complete(job, "worker-a", lease.lease_token, {"status": "completed"})
    queue.complete(job, "worker-a", lease.lease_token, {"status": "completed"})

    reopened = DurableDistributedQueue(tmp_path / "distributed.sqlite")
    events = list(reversed(reopened.job_events(job)))
    event_types = [item["event_type"] for item in events]
    assert event_types[:4] == ["enqueued", "leased", "started", "completed"]
    assert event_types.count("completed") == 1
    assert events[-1]["from_state"] == "running"
    assert events[-1]["to_state"] == "completed"
    assert events[-1]["details"]["result_sha256"] == reopened.job(job)["result_sha256"]


def test_restart_reconciles_derived_worker_lease_counter(tmp_path: Path) -> None:
    queue, job, lease = _leased_queue(tmp_path)
    db = tmp_path / "distributed.sqlite"
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE distributed_workers SET active_leases=99 WHERE worker_id='worker-a'")
        connection.commit()

    reopened = DurableDistributedQueue(db)
    worker = reopened.worker("worker-a")
    assert worker is not None and worker["active_leases"] == 1
    assert reopened.job(job)["state"] == "running"
    assert reopened.health()["last_reconciliation"]["worker_counters_repaired"] == 1


def test_restart_fences_non_idempotent_orphan_lease_to_review_required(tmp_path: Path) -> None:
    queue, job, lease = _leased_queue(tmp_path, side_effect_mode="non_idempotent")
    queue.mark_side_effect_started(job, "worker-a", lease.lease_token)
    db = tmp_path / "distributed.sqlite"

                                                                                                  
                                                                                            
    with sqlite3.connect(db) as connection:
        connection.execute("DELETE FROM distributed_workers WHERE worker_id='worker-a'")
        connection.commit()

    reopened = DurableDistributedQueue(db)
    state = reopened.job(job)
    assert state is not None
    assert state["state"] == "review_required"
    assert state["error_code"] == "LEASE_STATE_LOST_AFTER_SIDE_EFFECT_START"
    events = reopened.job_events(job)
    assert events[0]["event_type"] == "lease_reconciled"
    assert events[0]["to_state"] == "review_required"
    assert reopened.health()["last_reconciliation"]["leases_recovered"] == 1


def test_restart_requeues_idempotent_orphan_lease_with_attempt_budget(tmp_path: Path) -> None:
    queue, job, _lease = _leased_queue(tmp_path)
    db = tmp_path / "distributed.sqlite"
    with sqlite3.connect(db) as connection:
        connection.execute("DELETE FROM distributed_workers WHERE worker_id='worker-a'")
        connection.commit()

    reopened = DurableDistributedQueue(db)
    state = reopened.job(job)
    assert state is not None
    assert state["state"] == "queued"
    assert state["error_code"] == "LEASE_STATE_RECONCILED"


def test_restart_recovers_expired_persisted_lease_before_first_poll(tmp_path: Path) -> None:
    queue, job, _lease = _leased_queue(tmp_path)
    db = tmp_path / "distributed.sqlite"
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE distributed_jobs SET lease_expires_at=1 WHERE job_id=?", (job,))
        connection.commit()

    reopened = DurableDistributedQueue(db)
    state = reopened.job(job)
    assert state is not None and state["state"] == "queued"
    assert state["error_code"] == "LEASE_EXPIRED_REQUEUED"
    assert reopened.health()["last_reconciliation"]["expired_leases_recovered"] == 1
    assert reopened.health()["state_invariants"]["inconsistent_lease_rows"] == 0


def test_restart_rejects_implausibly_far_future_lease_as_clock_or_state_corruption(tmp_path: Path) -> None:
    queue, job, _lease = _leased_queue(tmp_path, side_effect_mode="non_idempotent")
    db = tmp_path / "distributed.sqlite"
                                                                                              
                                                                                                  
    with sqlite3.connect(db) as connection:
        connection.execute(
            "UPDATE distributed_jobs SET lease_expires_at=lease_expires_at+864000,side_effect_state='started' WHERE job_id=?",
            (job,),
        )
        connection.commit()

    reopened = DurableDistributedQueue(db)
    state = reopened.job(job)
    assert state is not None and state["state"] == "review_required"
    assert state["error_code"] == "LEASE_STATE_LOST_AFTER_SIDE_EFFECT_START"
    assert reopened.health()["state_invariants"]["inconsistent_lease_rows"] == 0
