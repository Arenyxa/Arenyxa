from __future__ import annotations

import threading
from pathlib import Path

import pytest

from arenyxa.application.job_system import JobSystem
from arenyxa.bootstrap import bootstrap
from arenyxa.domain.errors import ArenyxaError


@pytest.fixture()
def context(tmp_path: Path):
    value = bootstrap(tmp_path / "runtime", start_scheduler=False)
    try:
        yield value
    finally:
        value.shutdown(reason="test_cleanup", timeout=5.0)


def _submit(jobs: JobSystem, context, operation, *, kind: str):
    assert context.local_control_session is not None
    return jobs.submit(
        kind,
        operation,
        session=context.local_control_session,
        capability="logs.read",
        resource=f"job:{kind}",
        surface="test",
        timeout_seconds=5.0,
    )


def test_submit_executor_handoff_and_registry_publication_are_atomic_with_shutdown(
    context, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shutdown must never snapshot between executor handoff and future/token publication."""
    jobs = JobSystem(context.store, context.security, max_workers=1, queue_capacity=1)
    real_submit = jobs._executor.submit
    handoff_entered = threading.Event()
    allow_handoff = threading.Event()
    operation_started = threading.Event()
    submit_result: dict[str, object] = {}
    shutdown_result: dict[str, object] = {}

    def blocking_submit(*args, **kwargs):
        handoff_entered.set()
        assert allow_handoff.wait(2.0)
        return real_submit(*args, **kwargs)

    def cooperative(execution):
        operation_started.set()
        assert execution._cancelled.wait(2.0)
        execution.check_cancelled()

    monkeypatch.setattr(jobs._executor, "submit", blocking_submit)

    def submitter() -> None:
        try:
            submit_result["row"] = _submit(jobs, context, cooperative, kind="handoff-race")
        except BaseException as exc:  # pragma: no cover - asserted below
            submit_result["error"] = exc

    def stopper() -> None:
        shutdown_result["value"] = jobs.shutdown(wait=True, timeout=1.0)

    submit_thread = threading.Thread(target=submitter, name="test-job-submit")
    shutdown_thread = threading.Thread(target=stopper, name="test-job-shutdown")
    try:
        submit_thread.start()
        assert handoff_entered.wait(1.0)
        shutdown_thread.start()

        # submit() is inside the JobSystem handoff critical section.  Let it
        # publish both registries before shutdown can take its snapshot.
        allow_handoff.set()
        submit_thread.join(2.0)
        shutdown_thread.join(2.0)

        assert not submit_thread.is_alive()
        assert not shutdown_thread.is_alive()
        assert "error" not in submit_result
        assert shutdown_result["value"] is True
        assert jobs.shutdown_snapshot()["active_futures"] == 0
        # Either shutdown cancels the Future while still queued, or the worker
        # starts and observes the cooperative cancellation event.  Both are
        # valid; the invariant is that no active Future remains when shutdown
        # reports success.
        if operation_started.is_set():
            row = submit_result["row"]
            terminal = jobs.store.get_platform_job(row["id"])
            assert terminal is not None
            assert terminal["state"] == "cancelled"
    finally:
        allow_handoff.set()
        jobs.shutdown(wait=True, timeout=1.0)


def test_shutdown_during_pre_handoff_submit_rejects_job_before_executor_ownership(
    context, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An admit already in persistence must not hand work to an executor after shutdown wins."""
    jobs = JobSystem(context.store, context.security, max_workers=1, queue_capacity=1)
    real_create = jobs.store.create_platform_job
    persistence_entered = threading.Event()
    allow_persistence = threading.Event()
    operation_started = threading.Event()
    submit_result: dict[str, object] = {}

    def blocking_create(payload):
        persistence_entered.set()
        assert allow_persistence.wait(2.0)
        return real_create(payload)

    def should_not_run(_execution):
        operation_started.set()
        return {"unexpected": True}

    monkeypatch.setattr(jobs.store, "create_platform_job", blocking_create)

    def submitter() -> None:
        try:
            submit_result["row"] = _submit(jobs, context, should_not_run, kind="pre-handoff-race")
        except BaseException as exc:  # pragma: no cover - asserted below
            submit_result["error"] = exc

    submit_thread = threading.Thread(target=submitter, name="test-job-pre-handoff")
    try:
        submit_thread.start()
        assert persistence_entered.wait(1.0)

        # No executor handoff or registry publication has occurred yet.
        assert jobs.shutdown(wait=True, timeout=1.0) is True
        allow_persistence.set()
        submit_thread.join(2.0)

        assert not submit_thread.is_alive()
        error = submit_result.get("error")
        assert isinstance(error, ArenyxaError)
        assert error.code == "JOB_SYSTEM_STOPPING"
        assert not operation_started.is_set()
        assert jobs.shutdown_snapshot()["active_futures"] == 0
    finally:
        allow_persistence.set()
        jobs.shutdown(wait=True, timeout=1.0)


def test_submit_after_shutdown_raises_stopping(context) -> None:
    jobs = JobSystem(context.store, context.security, max_workers=1, queue_capacity=1)
    assert jobs.shutdown(wait=True, timeout=1.0) is True

    with pytest.raises(ArenyxaError) as captured:
        _submit(jobs, context, lambda execution: execution.check_cancelled(), kind="after-shutdown")

    assert captured.value.code == "JOB_SYSTEM_STOPPING"


def test_persistence_failure_returns_job_slot_before_future_ownership(
    context, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A persistence failure before executor handoff must not permanently consume capacity."""
    jobs = JobSystem(context.store, context.security, max_workers=1, queue_capacity=1)
    real_create = jobs.store.create_platform_job
    release_operations = threading.Event()

    def fail_create(_payload):
        raise OSError("simulated platform-job persistence failure")

    def blocking_operation(execution):
        assert release_operations.wait(2.0)
        execution.check_cancelled()
        return {"ok": True}

    try:
        monkeypatch.setattr(jobs.store, "create_platform_job", fail_create)
        with pytest.raises(OSError, match="simulated platform-job persistence failure"):
            _submit(jobs, context, blocking_operation, kind="persistence-failure")

        # Restore persistence and consume the full advertised capacity.  With
        # max_workers=1 and queue_capacity=1 both submissions must be admitted:
        # one running and one queued.  A leaked semaphore permit makes the
        # second submission incorrectly fail with JOB_BACKPRESSURE.
        monkeypatch.setattr(jobs.store, "create_platform_job", real_create)
        first = _submit(jobs, context, blocking_operation, kind="capacity-after-failure-1")
        second = _submit(jobs, context, blocking_operation, kind="capacity-after-failure-2")

        assert first["id"] != second["id"]
    finally:
        release_operations.set()
        jobs.shutdown(wait=True, timeout=2.0)
