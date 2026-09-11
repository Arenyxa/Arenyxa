from __future__ import annotations

from types import SimpleNamespace

import pytest

from arenyxa.enterprise.job_lifecycle import ClaimedJob, JobLifecycle


class _FakeQueue:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.lease = SimpleNamespace(
            job_id="job_1",
            lease_token="tok_a",
            lease_expires_at=1.0,
            kind="benchmark.noop",
            payload={"k": 1},
            attempt=1,
            max_attempts=3,
        )

    def lease_next(self, worker_id: str, *, lease_seconds: int = 60):
        self.calls.append(("lease_next", (worker_id, lease_seconds)))
        return self.lease

    def start_job(self, job_id: str, worker_id: str, lease_token: str) -> None:
        self.calls.append(("start_job", (job_id, worker_id, lease_token)))

    def complete(self, job_id: str, worker_id: str, lease_token: str, result) -> None:
        self.calls.append(("complete", (job_id, worker_id, lease_token, dict(result))))

    def fail(self, job_id: str, worker_id: str, lease_token: str, error_code: str, *, retryable: bool = True) -> str:
        self.calls.append(("fail", (job_id, worker_id, lease_token, error_code, retryable)))
        return "queued"

    def recover_expired_leases(self, now: float | None = None) -> int:
        self.calls.append(("recover", (now,)))
        return 0


def test_claimed_job_has_no_connection() -> None:
    job = ClaimedJob("j", "w", "t", 1.0, "k", {}, 1, 1)
    assert not hasattr(job, "_connection")
    with pytest.raises(RuntimeError, match="does not own"):
        job.connection()


def test_acquire_releases_before_return_and_complete_is_separate_call() -> None:
    queue = _FakeQueue()
    life = JobLifecycle(queue)  # type: ignore[arg-type]
    claimed = life.acquire_job("w1")
    assert claimed is not None
    assert claimed.job_id == "job_1"
    assert [name for name, _ in queue.calls] == ["lease_next", "start_job"]
    life.recover_expired_leases()
    life.complete_job(claimed, {"ok": True})
    assert [name for name, _ in queue.calls] == ["lease_next", "start_job", "recover", "complete"]


def test_acquire_job_start_failure_fails_lease_then_reraises() -> None:
    queue = _FakeQueue()

    def boom(job_id: str, worker_id: str, lease_token: str) -> None:
        queue.calls.append(("start_job", (job_id, worker_id, lease_token)))
        raise RuntimeError("injected start_job failure")

    queue.start_job = boom  # type: ignore[method-assign]
    life = JobLifecycle(queue)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="injected start_job failure"):
        life.acquire_job("w1")
    assert [name for name, _ in queue.calls] == ["lease_next", "start_job", "fail"]
    fail_call = queue.calls[-1]
    assert fail_call[1][:4] == ("job_1", "w1", "tok_a", "JOB_START_FAILED")
    assert fail_call[1][4] is True
