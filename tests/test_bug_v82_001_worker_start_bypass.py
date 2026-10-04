"""BUG-V82-001: EnterpriseWorkerRuntime must fail the lease when start_job raises.

Migrated from audit_out_v82/repro/test_worker_start_bypass.py with inverted
runtime assertion: production path must now mirror JobLifecycle recovery.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from arenyxa.enterprise.distributed_protocol import DistributedLease
from arenyxa.enterprise.distributed_runtime import EnterpriseWorkerRuntime
from arenyxa.enterprise.job_lifecycle import JobLifecycle


class _TrackingQueue:
    """Minimal FakeQueue: lease already held; start_job can boom; fail is recorded."""

    def __init__(self, *, boom_start: bool = False) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.boom_start = boom_start
        self.leased_jobs: dict[str, dict[str, Any]] = {
            "job_bypass": {
                "state": "leased",
                "worker_id": "w-runtime",
                "lease_token": "tok_bypass",
            }
        }

    def start_job(self, job_id: str, worker_id: str, lease_token: str) -> None:
        self.calls.append(("start_job", (job_id, worker_id, lease_token)))
        if self.boom_start:
            raise RuntimeError("injected start_job failure")
        job = self.leased_jobs.get(job_id)
        if job is not None:
            job["state"] = "running"

    def fail(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        error_code: str,
        *,
        retryable: bool = True,
    ) -> str:
        self.calls.append(("fail", (job_id, worker_id, lease_token, error_code, retryable)))
        job = self.leased_jobs.get(job_id)
        if job is not None:
            job["state"] = "queued"
            job["lease_token"] = ""
        return "queued"

    def complete(self, job_id: str, worker_id: str, lease_token: str, result: Mapping[str, Any]) -> None:
        self.calls.append(("complete", (job_id, worker_id, lease_token, dict(result))))
        job = self.leased_jobs.get(job_id)
        if job is not None:
            job["state"] = "completed"

    def renew_lease(self, *a, **k):
        raise AssertionError("renew should not run if start_job failed")

    def checkpoint(self, *a, **k):
        raise AssertionError("checkpoint should not run if start_job failed")

    def mark_side_effect_started(self, *a, **k):
        raise AssertionError("side effect should not run if start_job failed")

    def lease_next(self, worker_id: str, *, lease_seconds: int = 60):
        self.calls.append(("lease_next", (worker_id, lease_seconds)))
        return SimpleNamespace(
            job_id="job_bypass",
            lease_token="tok_bypass",
            lease_expires_at=9_999_999_999.0,
            kind="benchmark.noop",
            payload={},
            attempt=1,
            max_attempts=3,
        )


def _lease() -> DistributedLease:
    return DistributedLease(
        job_id="job_bypass",
        worker_id="w-runtime",
        lease_token="tok_bypass",
        lease_expires_at=9_999_999_999.0,
        kind="task.run",
        payload={"task": {"id": "t1"}},
        resource_id="r1",
        permission="p1",
        attempt=1,
        max_attempts=3,
        side_effect_mode="idempotent",
        checkpoint={},
        checkpoint_seq=0,
        protocol_version=1,
        traceparent="",
        tracestate="",
    )


def test_joblifecycle_releases_on_start_fail() -> None:
    q = _TrackingQueue(boom_start=True)
    life = JobLifecycle(q)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="injected start_job failure"):
        life.acquire_job("w-runtime")
    assert [c[0] for c in q.calls] == ["lease_next", "start_job", "fail"]
    assert q.calls[2][1][3] == "JOB_START_FAILED"
    assert q.calls[2][1][4] is True
    assert q.leased_jobs["job_bypass"]["state"] == "queued"


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_enterprise_worker_runtime_start_fail_releases_lease(cleanup_fails: bool) -> None:
    """Production path must fail(..., JOB_START_FAILED) when start_job raises."""
    q = _TrackingQueue(boom_start=True)
    if cleanup_fails:
        original_fail = q.fail

        def fail_then_raise(*args, **kwargs):
            original_fail(*args, **kwargs)
            raise OSError("cleanup unavailable")

        q.fail = fail_then_raise

    class _Runner:
        store = SimpleNamespace(save_task=lambda task: None)

    runtime = EnterpriseWorkerRuntime(_Runner(), "w-runtime")  # type: ignore[arg-type]
    lease = _lease()

    class _Task:
        def snapshot_hash(self) -> str:
            return "deadbeef"

    runtime.task_from_payload = lambda payload: _Task()  # type: ignore[method-assign]
    runtime.runner.store.save_task = lambda task: None

    with pytest.raises(RuntimeError, match="injected start_job failure"):
        runtime._execute_lease_inner(q, lease)  # type: ignore[arg-type]

    names = [c[0] for c in q.calls]
    assert names == ["start_job", "fail"], f"unexpected call sequence: {q.calls}"
    assert q.calls[1][1][3] == "JOB_START_FAILED"
    assert q.calls[1][1][4] is True
    assert q.leased_jobs["job_bypass"]["state"] == "queued"
