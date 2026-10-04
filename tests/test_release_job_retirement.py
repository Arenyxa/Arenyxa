from __future__ import annotations

import threading
from types import SimpleNamespace

from arenyxa.application.job_system import JobSystem


def _jobs(store):
    security = SimpleNamespace(require=lambda *args, **kwargs: None,
                               audit=SimpleNamespace(emit=lambda **kwargs: None))
    return JobSystem(store, security, max_workers=1, queue_capacity=1)


def _submit(jobs, operation, kind="test"):
    return jobs.submit(kind, operation, session=None, capability="logs.read", resource="job:test", surface="test")


def test_shutdown_retains_and_retries_failed_queued_retirement(store, monkeypatch):
    jobs = _jobs(store)
    started, release, failing, failed = (threading.Event() for _ in range(4))
    failing.set()

    def running(context):
        started.set()
        assert release.wait(2.0)
        context.check_cancelled()

    _submit(jobs, running, "running")
    assert started.wait(1.0)
    queued = _submit(jobs, lambda context: None, "queued")
    update = store.update_platform_job

    def flaky(job_id, **values):
        if job_id == queued["id"] and values.get("state") == "cancelled" and failing.is_set():
            failed.set()
            raise OSError("transient queued retirement persistence failure")
        return update(job_id, **values)

    monkeypatch.setattr(store, "update_platform_job", flaky)
    try:
        jobs.begin_shutdown()
        assert failed.wait(1.0)
        release.set()
        assert jobs.shutdown(timeout=0.1) is False
        assert store.get_platform_job(queued["id"])["state"] == "queued"
        assert jobs.shutdown_snapshot()["active_futures"] >= 1
        failing.clear()
        assert jobs.shutdown(timeout=1.0) is True
        assert store.get_platform_job(queued["id"])["state"] == "cancelled"
        assert jobs.shutdown_snapshot()["active_futures"] == 0
        assert jobs._slots.acquire(blocking=False)
        assert jobs._slots.acquire(blocking=False)
        assert not jobs._slots.acquire(blocking=False)
        jobs._slots.release()
        jobs._slots.release()
    finally:
        failing.clear()
        release.set()
        jobs.shutdown(timeout=1.0)


def test_drain_includes_retirement_callback_tail(store, monkeypatch):
    jobs = _jobs(store)
    operation_release, entered, release = (threading.Event() for _ in range(3))
    original = jobs._metric_increment

    def metric(name, amount=1):
        if name == "job.retired":
            entered.set()
            assert release.wait(2.0)
        original(name, amount)

    monkeypatch.setattr(jobs, "_metric_increment", metric)
    try:
        _submit(jobs, lambda context: operation_release.wait(1.0))
        operation_release.set()
        assert entered.wait(1.0)
        assert jobs.drain(timeout=0.02, include_submissions=True) is False
        assert jobs.shutdown_snapshot()["active_futures"] == 1
    finally:
        operation_release.set()
        release.set()
        assert jobs.shutdown(timeout=1.0)


def test_cancel_acknowledgement_cannot_be_overwritten_by_late_run_start(store, monkeypatch):
    jobs = _jobs(store)
    starting, allow_start, start_written, cancel_called, cancel_written, allow_cancel_return, finish = (
        threading.Event() for _ in range(7)
    )
    update = store.update_platform_job
    response = []

    def controlled_update(job_id, **values):
        if values.get("message") == "Running":
            starting.set()
            assert allow_start.wait(2.0)
            result = update(job_id, **values)
            start_written.set()
            return result
        if values.get("message") == "Cancellation requested":
            result = update(job_id, **values)
            cancel_written.set()
            assert allow_cancel_return.wait(2.0)
            return result
        if values.get("state") == "cancelled":
            assert finish.wait(2.0)
        return update(job_id, **values)

    monkeypatch.setattr(store, "update_platform_job", controlled_update)
    row = _submit(jobs, lambda context: finish.wait(2.0))
    assert starting.wait(1.0)

    def cancel():
        cancel_called.set()
        response.append(jobs.cancel(row["id"], session=None, surface="test"))

    thread = threading.Thread(target=cancel)
    try:
        thread.start()
        assert cancel_called.wait(1.0)
        # Give the old unsynchronized cancellation write the opportunity to
        # finish; a serialized implementation waits for the running write.
        cancel_written.wait(0.05)
        allow_start.set()
        assert start_written.wait(1.0)
        allow_cancel_return.set()
        thread.join(1.0)
        assert not thread.is_alive()
        assert response[0]["message"] == "Cancellation requested"
    finally:
        allow_start.set()
        allow_cancel_return.set()
        finish.set()
        thread.join(1.0)
        assert jobs.shutdown(timeout=1.0)
