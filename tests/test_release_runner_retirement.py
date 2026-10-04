from __future__ import annotations

import threading

from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.models import RequestSpec, Task
from test_runner_scheduler_shutdown_contract import _start_run


def test_runner_retains_failed_queued_persistence_until_retry(store, monkeypatch):
    runner, fetcher, first = _start_run(store)
    task = Task("queued", [RequestSpec("https://example.test/queued")], status=TaskStatus.READY)
    store.save_task(task)
    queued = runner.submit(task)
    failure, attempted = threading.Event(), threading.Event()
    failure.set()
    original = store.save_run

    def save(run):
        if run.id == queued.run.id and run.status == RunStatus.CANCELLED and failure.is_set():
            attempted.set()
            raise OSError("transient queued run persistence failure")
        return original(run)

    monkeypatch.setattr(store, "save_run", save)
    try:
        runner.begin_shutdown()
        assert attempted.wait(1.0)
        fetcher.release.set()
        first.future.result(timeout=1.0)
        assert runner.shutdown(timeout=0.1) is False
        assert fetcher.closed == 0
        assert queued.run.status == RunStatus.CANCELLED
        assert store.get_run(queued.run.id)["status"] == RunStatus.QUEUED.value
        assert runner.shutdown_snapshot()["active_runs"] >= 1
        failure.clear()
        assert runner.shutdown(timeout=1.0) is True
        assert fetcher.closed == 1
        assert store.get_run(queued.run.id)["status"] == RunStatus.CANCELLED.value
        assert runner.shutdown_snapshot()["active_runs"] == 0
    finally:
        failure.clear()
        fetcher.release.set()
        runner.shutdown(timeout=1.0)
