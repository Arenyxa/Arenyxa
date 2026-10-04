from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta

import pytest

from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.scheduler import ScheduleRule, SchedulerService
from arenyxa.compat import UTC
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, RequestSpec, Task


class _HeldFetcher:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()
        self.closed = 0

    def fetch(self, spec, _token, on_attempt=None):
        self.started.set()
        assert self.release.wait(2.0)
        return FetchResponse(
            url=spec.url, final_url=spec.url, status=200,
            headers={"Content-Type": "text/plain"}, body=b"ok",
            elapsed_ms=0.0, encoding="utf-8", content_type="text/plain",
        )

    def close(self) -> None:
        self.closed += 1


def _start_run(store):
    runner = RunOrchestrator(store, max_workers=1, request_workers=1)
    fetcher = _HeldFetcher()
    runner.fetcher = fetcher
    task = Task("held-run", [RequestSpec("https://example.test/")], status=TaskStatus.READY)
    store.save_task(task)
    handle = runner.submit(task)
    assert fetcher.started.wait(1.0)
    return runner, fetcher, handle


def test_nonblocking_runner_shutdown_preserves_fetcher_until_retry_drains(store) -> None:
    runner, fetcher, handle = _start_run(store)
    try:
        before = time.monotonic()
        result = runner.shutdown(wait=False, timeout=0.05)
        assert fetcher.closed == 0
        assert result is False
        assert time.monotonic() - before < 0.25
    finally:
        fetcher.release.set()
        handle.future.result(timeout=2.0)
        runner.shutdown(wait=True, timeout=1.0)
    assert fetcher.closed == 1
    assert runner.shutdown(wait=True, timeout=1.0) is True
    assert fetcher.closed == 1


def test_runner_drain_waits_for_run_retirement_after_future_is_done(store, monkeypatch) -> None:
    runner, fetcher, handle = _start_run(store)
    retiring = threading.Event()
    release_retirement = threading.Event()
    original = runner._on_run_done

    def held_retirement(*args):
        retiring.set()
        assert release_retirement.wait(2.0)
        original(*args)

    monkeypatch.setattr(runner, "_on_run_done", held_retirement)
    fetcher.release.set()
    assert retiring.wait(1.0)
    assert handle.future.done()
    try:
        assert runner.shutdown(wait=True, timeout=0.03) is False
        assert fetcher.closed == 0
        assert runner.shutdown_snapshot()["active_runs"] == 1
    finally:
        release_retirement.set()
        runner.shutdown(wait=True, timeout=1.0)
    assert fetcher.closed == 1


def test_runner_queued_cancellation_persistence_cannot_block_shutdown_caller(store, monkeypatch) -> None:
    runner, fetcher, first = _start_run(store)
    task = Task("queued-run", [RequestSpec("https://second.example/")], status=TaskStatus.READY)
    store.save_task(task)
    second = runner.submit(task)
    persisting = threading.Event()
    release_persistence = threading.Event()
    original = store.save_run

    def slow_cancel_persistence(run):
        if run.id == second.run.id and run.status == RunStatus.CANCELLED:
            persisting.set()
            release_persistence.wait(0.5)
        return original(run)

    monkeypatch.setattr(store, "save_run", slow_cancel_persistence)
    before = time.monotonic()
    try:
        assert runner.shutdown(wait=True, timeout=0.03) is False
        assert time.monotonic() - before < 0.25
        assert persisting.is_set()
        assert fetcher.closed == 0
        assert runner.shutdown_snapshot()["active_runs"] >= 1
    finally:
        release_persistence.set()
        fetcher.release.set()
        first.future.result(timeout=2.0)
        runner.shutdown(wait=True, timeout=1.0)


def test_runner_shutdown_owns_inflight_authorization_before_executor_handoff(store) -> None:
    authorizing = threading.Event()
    release = threading.Event()
    errors = []

    class HeldAuthorization:
        def authorize_if_bound(self, *_args, **_kwargs):
            authorizing.set()
            assert release.wait(2.0)

    runner = RunOrchestrator(store, enterprise_operations=HeldAuthorization())
    fetcher = _HeldFetcher()
    runner.fetcher = fetcher
    task = Task("authorizing", [RequestSpec("https://example.test/")], status=TaskStatus.READY)

    def submit():
        try:
            runner.submit(task)
        except ArenyxaError as exc:
            errors.append(exc.code)

    submitter = threading.Thread(target=submit)
    submitter.start()
    assert authorizing.wait(1.0)
    try:
        assert runner.shutdown(wait=True, timeout=0.03) is False
        assert fetcher.closed == 0
    finally:
        release.set()
        submitter.join(1.0)
        runner.shutdown(wait=True, timeout=1.0)
    assert not submitter.is_alive()
    assert errors == ["RUNNER_SHUTDOWN"]
    assert fetcher.closed == 1


def test_runner_transport_close_failure_can_be_retried_without_reopening_intake(store) -> None:
    runner = RunOrchestrator(store)

    class RetryCloseFetcher:
        attempts = 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("temporary transport cleanup failure")

    runner.fetcher = RetryCloseFetcher()
    assert runner.shutdown(timeout=1.0) is False
    assert runner.shutdown_snapshot()["accepting"] is False
    assert runner.shutdown(timeout=1.0) is True
    assert runner.shutdown(timeout=1.0) is True
    assert runner.fetcher.attempts == 2


def test_scheduler_drain_waits_for_callback_retirement_after_future_is_done(monkeypatch) -> None:
    scheduler = SchedulerService(max_callback_workers=1)
    entered = threading.Event()
    release = threading.Event()
    retiring = threading.Event()
    release_retirement = threading.Event()
    original = scheduler._callback_done

    def callback():
        entered.set()
        assert release.wait(2.0)

    def held_retirement(*args):
        retiring.set()
        assert release_retirement.wait(2.0)
        original(*args)

    monkeypatch.setattr(scheduler, "_callback_done", held_retirement)
    scheduler.add("held", ScheduleRule(timezone="UTC"), callback,
                  next_run=datetime.now(UTC) - timedelta(seconds=1))
    scheduler.start()
    assert entered.wait(1.0)
    release.set()
    assert retiring.wait(1.0)
    try:
        assert scheduler.stop(timeout=0.03) is False
        assert scheduler.shutdown_snapshot()["running_callbacks"] == 1
    finally:
        release.set()
        release_retirement.set()
        scheduler.stop()
    assert scheduler.stop(timeout=1.0) is True


def test_stopped_scheduler_cannot_reenable_a_definition() -> None:
    scheduler = SchedulerService()
    scheduler.add("later", ScheduleRule(timezone="UTC"), lambda: None, enabled=False)
    scheduler.stop()
    with pytest.raises(RuntimeError, match="停止"):
        scheduler.set_enabled("later", True)


def test_scheduler_callback_can_request_stop_without_waiting_for_itself() -> None:
    scheduler = SchedulerService(max_callback_workers=1)
    returned = threading.Event()
    results = []

    def callback():
        results.append(scheduler.stop())
        returned.set()

    scheduler.add("self-stop", ScheduleRule(timezone="UTC"), callback,
                  next_run=datetime.now(UTC) - timedelta(seconds=1))
    scheduler.start()
    try:
        assert returned.wait(1.0)
        assert results == [False]
    finally:
        scheduler.stop()
