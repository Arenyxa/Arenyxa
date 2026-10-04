from __future__ import annotations

import threading

import pytest

from arenyxa.application.job_system import JobCancelled, JobTimedOut
from arenyxa.application.runner import RunOrchestrator
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, Task
from test_release_job_retirement import _jobs, _submit
from test_runner_scheduler_shutdown_contract import _HeldFetcher


@pytest.mark.parametrize("outcome", ["succeeded", "cancelled", "failed", "timed_out"])
@pytest.mark.parametrize("failure_mode", ["exception", "rejected", "committed_exception"])
def test_job_terminal_intent_survives_storage_failure(store, monkeypatch, outcome, failure_mode):
    jobs = _jobs(store)
    entered, release, failed, fault = (threading.Event() for _ in range(4))
    fault.set()
    calls = []
    writes = []
    audits = []
    monkeypatch.setattr(jobs.security.audit, "emit", lambda **values: audits.append(values))
    original = store.update_platform_job

    def operation(context):
        calls.append(context.job_id)
        entered.set()
        assert release.wait(2.0)
        if outcome == "cancelled":
            raise JobCancelled("requested cancellation")
        if outcome == "timed_out":
            raise JobTimedOut("execution budget expired")
        if outcome == "failed":
            raise ValueError("operation failed")
        return {"result": 42}

    def update(job_id, **values):
        if values.get("state") in {"succeeded", "cancelled", "failed", "timed_out"}:
            writes.append(dict(values))
            if fault.is_set():
                failed.set()
                if failure_mode == "rejected":
                    return False
                if failure_mode == "committed_exception":
                    original(job_id, **values)
                raise OSError("terminal write unavailable")
        return original(job_id, **values)

    monkeypatch.setattr(store, "update_platform_job", update)
    row = _submit(jobs, operation)
    try:
        assert entered.wait(1.0)
        release.set()
        assert failed.wait(1.0)
        assert jobs.shutdown(timeout=0.15) is False
        assert jobs.shutdown_snapshot()["active_futures"] == 1
        assert store.get_platform_job(row["id"])["state"] == (outcome if failure_mode == "committed_exception" else "running")
        assert len(calls) == 1
        assert len(audits) == 1
        first_intent = writes[0]
        fault.clear()
        assert jobs.shutdown(timeout=1.0) is True
        saved = store.get_platform_job(row["id"])
        assert saved["state"] == outcome
        assert saved["finished_at"] == first_intent["finished_at"]
        assert all(values == first_intent for values in writes)
        if outcome == "succeeded":
            assert saved["result"] == {"result": 42}
        assert len(calls) == 1
        assert len(audits) == 1
        assert jobs.shutdown_snapshot()["active_futures"] == 0
    finally:
        fault.clear()
        release.set()
        jobs.shutdown(timeout=1.0)


@pytest.mark.parametrize("interrupt", [False, True])
def test_job_escaped_execution_failure_still_owns_terminal_write(store, monkeypatch, interrupt):
    jobs = _jobs(store)
    entered, release, fault = (threading.Event() for _ in range(3))
    fault.set()
    original_update = store.update_platform_job

    def update(job_id, **values):
        if values.get("state") == "running":
            entered.set()
            assert release.wait(2.0)
            raise SystemExit("worker interrupted") if interrupt else OSError("start write failed")
        if values.get("state") == "failed" and fault.is_set():
            raise OSError("terminal write unavailable")
        return original_update(job_id, **values)

    monkeypatch.setattr(store, "update_platform_job", update)
    row = _submit(jobs, lambda context: pytest.fail("operation must not run"))
    try:
        assert entered.wait(1.0)
        release.set()
        assert jobs.shutdown(timeout=0.15) is False
        assert jobs.shutdown_snapshot()["active_futures"] == 1
        fault.clear()
        assert jobs.shutdown(timeout=1.0) is True
        assert store.get_platform_job(row["id"])["state"] == "failed"
    finally:
        fault.clear()
        release.set()
        jobs.shutdown(timeout=1.0)


def test_runner_escaped_execution_failure_still_owns_terminal_write(store, monkeypatch):
    runner = RunOrchestrator(store, max_workers=1, request_workers=1)
    runner.fetcher.close()
    fetcher = _HeldFetcher()
    runner.fetcher = fetcher
    entered, release, fault = (threading.Event() for _ in range(3))
    fault.set()
    original_save = store.save_run

    def execute(*args, **kwargs):
        entered.set()
        assert release.wait(2.0)
        raise SystemExit("worker interrupted")

    def save(run):
        if run.status == RunStatus.FAILED and fault.is_set():
            raise OSError("terminal write unavailable")
        return original_save(run)

    monkeypatch.setattr(runner, "_execute", execute)
    monkeypatch.setattr(store, "save_run", save)
    task = Task("escaped worker", [RequestSpec("https://example.test/")], status=TaskStatus.READY)
    store.save_task(task)
    handle = runner.submit(task)
    try:
        assert entered.wait(1.0)
        release.set()
        with pytest.raises(SystemExit):
            handle.future.result(timeout=1.0)
        assert runner.shutdown(timeout=0.15) is False
        assert fetcher.closed == 0
        assert runner.shutdown_snapshot()["active_runs"] == 1
        fault.clear()
        assert runner.shutdown(timeout=1.0) is True
        assert store.get_run(handle.run.id)["status"] == "failed"
        assert fetcher.closed == 1
    finally:
        fault.clear()
        release.set()
        runner.shutdown(timeout=1.0)


@pytest.mark.parametrize("outcome", [RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.CANCELLED])
def test_runner_terminal_intent_survives_storage_failure(store, monkeypatch, outcome):
    runner = RunOrchestrator(store, max_workers=1, request_workers=1)
    runner.fetcher.close()
    fetcher = _HeldFetcher()
    runner.fetcher = fetcher
    fault, attempted = threading.Event(), threading.Event()
    fault.set()
    original_save, original_fetch = store.save_run, fetcher.fetch
    writes, calls = [], []

    def fetch(spec, token, on_attempt=None):
        calls.append(spec.url)
        response = original_fetch(spec, token, on_attempt)
        if outcome == RunStatus.FAILED or spec.url.endswith("/fail"):
            raise ArenyxaError("FETCH_FAILED", "controlled request failure", domain="HTTP")
        return response

    def save(run):
        if run.status in {RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.CANCELLED}:
            writes.append((run.status, run.error_code, run.finished_at))
            if fault.is_set():
                attempted.set()
                raise OSError("terminal write unavailable")
        return original_save(run)

    monkeypatch.setattr(fetcher, "fetch", fetch)
    monkeypatch.setattr(store, "save_run", save)
    requests = [RequestSpec("https://example.test/ok")]
    if outcome == RunStatus.PARTIAL:
        requests.append(RequestSpec("https://example.test/fail"))
    task = Task("terminal ownership", requests, status=TaskStatus.READY)
    store.save_task(task)
    handle = runner.submit(task)
    try:
        assert fetcher.started.wait(1.0)
        if outcome == RunStatus.CANCELLED:
            handle.cancel()
        fetcher.release.set()
        handle.future.result(timeout=2.0)
        assert attempted.wait(1.0)
        assert runner.shutdown(timeout=0.15) is False
        assert fetcher.closed == 0
        assert runner.shutdown_snapshot()["active_runs"] == 1
        assert store.get_run(handle.run.id)["status"] == "running"
        first_intent = writes[0]
        calls_before = list(calls)
        fault.clear()
        assert runner.shutdown(timeout=1.0) is True
        saved = store.get_run(handle.run.id)
        assert saved["status"] == outcome.value
        assert saved["finished_at"] == first_intent[2]
        assert all(values == first_intent for values in writes)
        assert calls == calls_before
        assert fetcher.closed == 1
        assert runner.shutdown_snapshot()["active_runs"] == 0
    finally:
        fault.clear()
        fetcher.release.set()
        runner.shutdown(timeout=1.0)
