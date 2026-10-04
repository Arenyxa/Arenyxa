from __future__ import annotations

import base64
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Task, RequestSpec
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise.distributed_runtime import EnterpriseServerRuntime
from arenyxa.enterprise import distributed_queue as queue_module
from arenyxa.infrastructure.timebase import StableEpochClock


def _enqueue(queue, key, *, mode="idempotent"):
    return queue.enqueue("task.run", {"task": key}, resource_id="resource", permission="workflow.execute",
                         idempotency_key=key, side_effect_mode=mode)


def _worker(queue, name="worker"):
    return queue.register_worker(name, base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="),
                                 {"slots": 4}, max_slots=4)


def test_runtime_replay_rejects_changed_side_effect_contract(tmp_path):
    queue = DurableDistributedQueue(tmp_path / "runtime.sqlite")
    task = Task("task", [RequestSpec("https://example.test/")])
    queue.enqueue("task.run", {"task": task.to_dict(), "task_snapshot_sha256": task.snapshot_hash()},
                  resource_id="resource", permission="workflow.execute", idempotency_key="same")
    runtime = object.__new__(EnterpriseServerRuntime)
    runtime.queue = queue
    with pytest.raises(ArenyxaError) as error:
        runtime.submit_task(task, resource_id="resource", permission="workflow.execute", idempotency_key="same",
                            side_effect_mode="non_idempotent")
    assert error.value.code == "DISTRIBUTED_IDEMPOTENCY_COLLISION"


def test_sqlite_boot_change_fences_started_non_idempotent_work(tmp_path, monkeypatch):
    monkeypatch.setattr(queue_module, "boot_clock_domain", lambda: "boot-one")
    path = tmp_path / "boot.sqlite"
    first = DurableDistributedQueue(path)
    _worker(first)
    job = _enqueue(first, "boot", mode="non_idempotent")
    lease = first.lease_next("worker")
    first.start_job(job, "worker", lease.lease_token)
    first.mark_side_effect_started(job, "worker", lease.lease_token)
    monkeypatch.setattr(queue_module, "boot_clock_domain", lambda: "boot-two")
    second = DurableDistributedQueue(path)
    assert second.job(job)["state"] == "review_required"
    with pytest.raises(ArenyxaError):
        first.complete(job, "worker", lease.lease_token, {})
    assert second.worker("worker")["active_leases"] == 0


def test_terminal_receipt_survives_history_pruning(tmp_path):
    queue = DurableDistributedQueue(tmp_path / "receipt.sqlite")
    _worker(queue)
    job = _enqueue(queue, "receipt", mode="non_idempotent")
    lease = queue.lease_next("worker")
    queue.complete(job, "worker", lease.lease_token, {"ok": True})
    assert queue.retain_terminal_jobs(max_terminal=0)["jobs_pruned"] == 1
    queue.complete(job, "worker", lease.lease_token, {"ok": True})
    with pytest.raises(ArenyxaError) as error:
        queue.complete(job, "worker", lease.lease_token, {"ok": False})
    assert error.value.code == "DISTRIBUTED_TERMINAL_CONFLICT"


@pytest.fixture
def retained_postgres_dsn():
    dsn = os.environ.get("ARENYXA_POSTGRES_TEST_DSN", "")
    if not dsn:
        pytest.skip("Dedicated PostgreSQL DSN is not configured")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    schema = "arenyxa_v01_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    print("retained_postgresql_schema=" + schema)
    # Intentionally retain the complete test schema; never DROP or terminate backends.
    return make_conninfo(dsn, options=f"-c search_path={schema}")


def test_postgres_clock_authority_covers_fast_and_portable_paths(retained_postgres_dsn):
    import psycopg
    q = DurableDistributedQueue(retained_postgres_dsn, clock=StableEpochClock(wall=lambda: 1.0))
    skewed = DurableDistributedQueue(retained_postgres_dsn, clock=StableEpochClock(wall=lambda: 1e12))
    try:
        _worker(q)
        job = _enqueue(q, "clock")
        lease = q.lease_next("worker", lease_seconds=30)
        with psycopg.connect(retained_postgres_dsn) as c:
            now = float(c.execute("SELECT EXTRACT(EPOCH FROM clock_timestamp())").fetchone()[0])
        assert now + 28 < lease.lease_expires_at < now + 31
        skewed.start_job(job, "worker", lease.lease_token)
        expires = skewed.renew_lease(job, "worker", lease.lease_token, lease_seconds=30)
        assert now + 28 < expires < now + 32
        skewed.heartbeat("worker")
        assert now - 1 < skewed.worker("worker")["heartbeat_at"] < now + 3
        assert skewed.recover_expired_leases() == 0
        assert q.health()["state_invariants"]["implausible_future_leases"] == 0
        skewed.complete(job, "worker", lease.lease_token, {"ok": True})
        assert skewed.retain_terminal_jobs(max_terminal=0)["jobs_pruned"] == 1
        q.complete(job, "worker", lease.lease_token, {"ok": True})
        assert _enqueue(q, "clock") == job
        for index in range(2):
            _enqueue(q, "batch-" + str(index))
        leases = skewed.lease_many("worker", max_items=2, lease_seconds=30)
        assert len(leases) == 2
        for item in leases:
            assert now + 28 < item.lease_expires_at < now + 35
            q.complete(item.job_id, "worker", item.lease_token, {})
        assert q.invariant_violations() == []
    finally:
        skewed.close()
        q.close()


def test_postgres_completion_validates_expiry_after_worker_lock_wait(retained_postgres_dsn):
    import psycopg
    q = DurableDistributedQueue(retained_postgres_dsn, lease_grace_seconds=0)
    try:
        _worker(q)
        job = _enqueue(q, "waiting")
        lease = q.lease_next("worker")
        q.start_job(job, "worker", lease.lease_token)
        with psycopg.connect(retained_postgres_dsn, autocommit=True) as c:
            c.execute("UPDATE distributed_jobs SET lease_expires_at=EXTRACT(EPOCH FROM clock_timestamp())+0.5 WHERE job_id=%s", (job,))
        with ThreadPoolExecutor(max_workers=1) as executor:
            with psycopg.connect(retained_postgres_dsn) as blocker:
                blocker.execute("SELECT worker_id FROM distributed_workers WHERE worker_id='worker' FOR UPDATE")
                future = executor.submit(q.complete, job, "worker", lease.lease_token, {})
                time.sleep(0.7)
                assert not future.done()
                blocker.commit()
            with pytest.raises(ArenyxaError) as error:
                future.result(timeout=5)
            assert error.value.code == "DISTRIBUTED_LEASE_EXPIRED"
        assert q.job(job)["state"] == "running"
        assert q.recover_expired_leases() == 1
        assert q.invariant_violations() == []
    finally:
        q.close()


def test_postgres_completion_wins_before_revocation(retained_postgres_dsn):
    q = DurableDistributedQueue(retained_postgres_dsn)
    try:
        _worker(q)
        job = _enqueue(q, "complete-first")
        lease = q.lease_next("worker")
        q.complete(job, "worker", lease.lease_token, {})
        assert q.revoke_worker("worker") == 0
        q.complete(job, "worker", lease.lease_token, {})  # terminal receipt remains replayable
        assert q.job(job)["state"] == "completed"
        assert q.worker("worker")["state"] == "revoked"
        assert q.invariant_violations() == []
    finally:
        q.close()


def test_postgres_concurrent_same_key_returns_one_job(retained_postgres_dsn):
    first = DurableDistributedQueue(retained_postgres_dsn)
    second = DurableDistributedQueue(retained_postgres_dsn)
    barrier = threading.Barrier(2)
    def submit(q):
        barrier.wait(timeout=5)
        return _enqueue(q, "same-key")
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            one = executor.submit(submit, first)
            two = executor.submit(submit, second)
            assert one.result(timeout=5) == two.result(timeout=5)
        assert len(first.list_jobs()) == 1
    finally:
        first.close()
        second.close()
