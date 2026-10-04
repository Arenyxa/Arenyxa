from __future__ import annotations

import logging
import threading
import time
from types import SimpleNamespace

import pytest

from arenyxa.app import _make_runtime_finalizer
from arenyxa.infrastructure.shutdown import DependencyShutdownCoordinator, ShutdownDeadline
from arenyxa.presentation.main_window_lifecycle import MainWindowLifecycleMixin


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
def test_job_submission_interrupt_releases_capacity_and_preserves_exception(store, monkeypatch, interrupt):
    from arenyxa.application.job_system import JobSystem

    security = SimpleNamespace(require=lambda *args, **kwargs: None)
    jobs = JobSystem(store, security, max_workers=1, queue_capacity=1)
    error = interrupt("interrupted before executor handoff")

    def stop(*args, **kwargs):
        raise error

    monkeypatch.setattr(jobs._executor, "submit", stop)
    try:
        with pytest.raises(interrupt) as caught:
            jobs.submit("interrupt", lambda context: None, session=None,
                        capability="logs.read", resource="job:interrupt", surface="test")
        assert caught.value is error
        assert jobs.shutdown_snapshot()["pending_submissions"] == 0
        row = store.list_platform_jobs()[0]
        assert row["state"] == "failed" and row["error_code"] == "JOB_SUBMIT_FAILED"
        assert jobs._slots.acquire(blocking=False)
        assert jobs._slots.acquire(blocking=False)
        assert not jobs._slots.acquire(blocking=False)
        jobs._slots.release()
        jobs._slots.release()
    finally:
        assert jobs.shutdown(timeout=1.0)


def test_job_shutdown_distinguishes_executor_drain_from_pending_storage_admission(store, monkeypatch):
    from arenyxa.application.job_system import JobSystem
    from arenyxa.domain.errors import ArenyxaError
    security = SimpleNamespace(require=lambda *args, **kwargs: None, audit=SimpleNamespace(emit=lambda **kwargs: None))
    jobs = JobSystem(store, security, max_workers=1, queue_capacity=1)
    entered, release = threading.Event(), threading.Event()
    original_create = store.create_platform_job
    errors = []

    def create(row):
        entered.set()
        assert release.wait(2.0)
        original_create(row)

    def submit():
        try:
            jobs.submit("pending-storage", lambda context: None, session=None,
                        capability="logs.read", resource="job:pending", surface="test")
        except ArenyxaError as exc:
            errors.append(exc.code)

    monkeypatch.setattr(store, "create_platform_job", create)
    thread = threading.Thread(target=submit)
    try:
        thread.start()
        assert entered.wait(1.0)
        assert jobs.shutdown(timeout=0.01) is True
        assert jobs.shutdown_snapshot()["pending_submissions"] == 1
        assert jobs.drain(timeout=0.01, include_submissions=True) is False
    finally:
        release.set()
        thread.join(2.0)
        assert jobs.drain(timeout=1.0, include_submissions=True) is True
    assert errors == ["JOB_SYSTEM_STOPPING"]
    assert store.list_platform_jobs()[0]["state"] == "cancelled"


def test_job_drain_tracks_authorization_before_capacity_handoff(store):
    from arenyxa.application.job_system import JobSystem
    from arenyxa.domain.errors import ArenyxaError
    entered, release = threading.Event(), threading.Event()
    errors = []

    def authorize(*args, **kwargs):
        entered.set()
        assert release.wait(2.0)

    jobs = JobSystem(store, SimpleNamespace(require=authorize), max_workers=1, queue_capacity=1)

    def submit():
        try:
            jobs.submit("authorization", lambda context: None, session=None,
                        capability="logs.read", resource="job:authorize", surface="test")
        except ArenyxaError as exc:
            errors.append(exc.code)

    thread = threading.Thread(target=submit)
    try:
        thread.start()
        assert entered.wait(1.0)
        assert jobs.shutdown(timeout=0.01) is True
        assert jobs.drain(timeout=0.01, include_submissions=True) is False
    finally:
        release.set()
        thread.join(1.0)
        assert jobs.drain(timeout=1.0, include_submissions=True) is True
    assert errors == ["JOB_SYSTEM_STOPPING"]


def test_job_executor_cleanup_failure_can_be_retried(store, monkeypatch):
    from arenyxa.application.job_system import JobSystem
    jobs = JobSystem(store, SimpleNamespace(), max_workers=1, queue_capacity=1)
    original = jobs._executor.shutdown
    calls = []

    def shutdown(**kwargs):
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("transient executor cleanup failure")
        return original(**kwargs)

    monkeypatch.setattr(jobs._executor, "shutdown", shutdown)
    try:
        assert jobs.shutdown(timeout=0.1) is False
        assert jobs.shutdown(timeout=0.1) is True
    finally:
        original(wait=True)


def test_job_shutdown_deadline_includes_slow_queued_cancellation_persistence(store, monkeypatch):
    from arenyxa.application.job_system import JobSystem
    security = SimpleNamespace(require=lambda *args, **kwargs: None, audit=SimpleNamespace(emit=lambda **kwargs: None))
    jobs = JobSystem(store, security, max_workers=1, queue_capacity=1)
    started, release, persisting, finish_persistence = (threading.Event() for _ in range(4))

    def operation(context):
        started.set()
        assert release.wait(2.0)
        context.check_cancelled()

    def submit(kind):
        return jobs.submit(kind, operation, session=None, capability="logs.read", resource="job:cancel", surface="test")

    submit("running")
    assert started.wait(1.0)
    queued = submit("queued")
    original_update = store.update_platform_job

    def update(job_id, **kwargs):
        if job_id == queued["id"] and kwargs.get("state") == "cancelled":
            persisting.set()
            finish_persistence.wait(0.5)
        return original_update(job_id, **kwargs)

    monkeypatch.setattr(store, "update_platform_job", update)
    try:
        before = time.monotonic()
        assert jobs.shutdown(timeout=0.02) is False
        assert time.monotonic() - before < 0.25
        assert persisting.wait(1.0)
        assert jobs.shutdown_snapshot()["active_futures"] >= 1
    finally:
        finish_persistence.set()
        release.set()
        assert jobs.shutdown(timeout=1.0) is True


def test_proxy_close_retains_history_until_slow_stop_owner_finishes(tmp_path, monkeypatch):
    from arenyxa.infrastructure.capture.proxy import InterceptingProxy
    proxy = InterceptingProxy(tmp_path / "proxy")
    stopping, release = threading.Event(), threading.Event()

    class Server:
        def shutdown(self):
            stopping.set()
            assert release.wait(0.5)

        def server_close(self):
            return None

    with proxy._lock:
        proxy._server = Server()
    try:
        before = time.monotonic()
        assert proxy.close(timeout=0.02) is False
        assert time.monotonic() - before < 0.25
        assert stopping.wait(1.0)
        assert proxy._closed is False
    finally:
        release.set()
        assert proxy.close(timeout=2.0) is True


def test_runner_shutdown_budget_includes_pre_handoff_run_persistence(store, monkeypatch):
    from arenyxa.application.runner import RunOrchestrator
    from arenyxa.domain.enums import TaskStatus
    from arenyxa.domain.errors import ArenyxaError
    from arenyxa.domain.models import RequestSpec, Task
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    task = Task("persisting", [RequestSpec("https://example.test/")], status=TaskStatus.READY)
    store.save_task(task)
    entered, release = threading.Event(), threading.Event()
    original = store.save_run
    errors = []

    def save(run):
        entered.set()
        release.wait(0.5)
        original(run)

    def submit():
        try:
            runner.submit(task)
        except ArenyxaError as exc:
            errors.append(exc.code)

    monkeypatch.setattr(store, "save_run", save)
    monkeypatch.setattr(runner, "_execute", lambda task, run, *args, **kwargs: run)
    thread = threading.Thread(target=submit)
    try:
        thread.start()
        assert entered.wait(1.0)
        before = time.monotonic()
        assert runner.shutdown(timeout=0.02) is False
        assert time.monotonic() - before < 0.25
    finally:
        release.set()
        thread.join(1.0)
        assert runner.shutdown(timeout=1.0) is True
    assert errors == ["RUNNER_SHUTDOWN"]


@pytest.mark.parametrize("first_result", [False, RuntimeError("cleanup failed")])
def test_finalizer_preserves_marker_and_data_root_until_retry_completes(tmp_path, monkeypatch, first_result):
    from arenyxa.presentation import background
    marker = tmp_path / "crash.marker"
    marker.write_text("running", encoding="utf-8")
    released = []
    outcomes = [first_result, True]

    def shutdown():
        outcome = outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(background, "begin_background_shutdown", lambda timeout_ms: True)
    finalize = _make_runtime_finalizer(SimpleNamespace(shutdown=shutdown), marker,
                                       SimpleNamespace(release=lambda: released.append(True)))
    assert finalize() is False
    assert marker.exists()
    assert released == []
    assert finalize() is True
    assert not marker.exists()
    assert released == [True]
    assert finalize() is True
    assert released == [True]


def test_finalizer_does_not_close_context_while_ui_owners_are_active(tmp_path, monkeypatch):
    from arenyxa.presentation import background
    marker = tmp_path / "crash.marker"
    marker.write_text("running", encoding="utf-8")
    closed = []
    monkeypatch.setattr(background, "begin_background_shutdown", lambda timeout_ms: False)
    finalize = _make_runtime_finalizer(SimpleNamespace(shutdown=lambda: closed.append(True)), marker,
                                       SimpleNamespace(release=lambda: closed.append("lease")))
    assert finalize() is False
    assert closed == []
    assert marker.exists()


def test_denied_startup_preserves_ownership_when_context_cleanup_is_incomplete(tmp_path, monkeypatch):
    from arenyxa.app import _enforce_registered_root_startup
    from arenyxa.presentation import root_owner_gate
    marker = tmp_path / "crash.marker"
    marker.write_text("starting", encoding="utf-8")
    released = []
    context = SimpleNamespace(root_workstation_registered=True, shutdown=lambda: False)
    monkeypatch.setattr(root_owner_gate, "enforce_root_owner_startup_gate", lambda context: False)
    assert _enforce_registered_root_startup(
        context=context, startup_splash=None, startup_settings=None, system_reduce_motion=False,
        arguments=None, runtime=None, launch_geometry=None,
        data_root_lease=SimpleNamespace(release=lambda: released.append(True)), crash_marker=marker,
    ) == (False, None)
    assert marker.exists()
    assert released == []


def test_close_event_preserves_window_and_marker_when_context_is_incomplete(tmp_path, monkeypatch):
    from arenyxa.presentation import main_window_lifecycle as lifecycle
    marker = tmp_path / "crash.marker"
    marker.write_text("running", encoding="utf-8")
    events = []
    window = SimpleNamespace(
        context=SimpleNamespace(runner=SimpleNamespace(active_handles=lambda: []), shutdown=lambda: False),
        _repair_exit_requested=False, _route_generation=0, _status_generation=0,
        save_window_state=lambda: None, tray=None,
        taskbar_progress=SimpleNamespace(clear=lambda: None, close=lambda: None), crash_marker=marker,
        show_status=lambda *args: None,
    )
    monkeypatch.setattr(lifecycle, "begin_background_shutdown", lambda timeout_ms: True)
    event = SimpleNamespace(ignore=lambda: events.append("ignore"), accept=lambda: events.append("accept"))
    MainWindowLifecycleMixin.closeEvent(window, event)
    assert events == ["ignore"]
    assert marker.exists()


def test_deadline_exhaustion_blocks_dependent_cleanup_and_retry_skips_completed_steps(monkeypatch):
    from arenyxa.infrastructure import shutdown as shutdown_module
    now = [100.0]
    monkeypatch.setattr(shutdown_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    calls = []
    completed = set()
    coordinator = DependencyShutdownCoordinator(logging.getLogger(__name__),
        deadline=ShutdownDeadline.from_timeout(0.02), completed=completed)
    coordinator.add("intake", lambda: calls.append("intake"))
    coordinator.add("owner", lambda: now.__setitem__(0, now[0] + 0.025), after=("intake",))
    coordinator.add("storage", lambda: calls.append("storage"), after=("owner",))
    assert coordinator.run() == ("owner", "storage")
    assert calls == ["intake"]
    retry = DependencyShutdownCoordinator(logging.getLogger(__name__), completed=completed)
    retry.add("intake", lambda: calls.append("intake"))
    retry.add("owner", lambda: True, after=("intake",))
    retry.add("storage", lambda: calls.append("storage"), after=("owner",))
    assert retry.run() == ()
    assert calls == ["intake", "storage"]
