from __future__ import annotations

import threading
import time
from concurrent.futures import Future
from pathlib import Path

import pytest

from arenyxa.application.runner import RunOrchestrator
from arenyxa.domain.enums import TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, RequestSpec, Run, Task
from arenyxa.infrastructure.http_client import CancellationToken
from arenyxa.infrastructure.shutdown import DependencyShutdownCoordinator, ShutdownDeadline


class _CooperativeFetcher:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.stopped = threading.Event()

    def fetch(self, spec, token, on_attempt=None):
        if on_attempt:
            on_attempt(0)
        self.started.set()
        try:
            while True:
                token.checkpoint()
                time.sleep(0.005)
        finally:
            self.stopped.set()

    def close(self) -> None:
        return None


class _NonCooperativeFetcher:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def fetch(self, spec, token, on_attempt=None):
        del token
        if on_attempt:
            on_attempt(0)
        self.started.set()
        self.release.wait(2.0)
        return FetchResponse(
            url=spec.url,
            final_url=spec.url,
            status=200,
            headers={"Content-Type": "text/plain"},
            body=b"ok",
            elapsed_ms=0.0,
            encoding="utf-8",
            content_type="text/plain",
        )

    def close(self) -> None:
        return None


def _task(url: str = "https://example.test/") -> Task:
    return Task("p1-shutdown", [RequestSpec(url)], status=TaskStatus.READY)


def test_runner_begin_shutdown_stops_new_runs_and_drains_cooperative_request_futures(store) -> None:
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    fetcher = _CooperativeFetcher()
    runner.fetcher = fetcher
    task = _task()
    store.save_task(task)
    handle = runner.submit(task)
    assert fetcher.started.wait(1.0)

    runner.begin_shutdown()
    with pytest.raises(ArenyxaError) as captured:
        runner.submit(_task("https://other.example/"))
    assert captured.value.code == "RUNNER_SHUTDOWN"

    assert runner.drain(timeout=1.0) is True
    assert fetcher.stopped.is_set()
    assert handle.future.done()
    assert runner.shutdown(wait=True, timeout=1.0) is True
    snapshot = runner.shutdown_snapshot()
    assert snapshot["active_runs"] == 0
    assert snapshot["pending_request_futures"] == 0
    assert snapshot["accepting"] is False


def test_runner_bounded_shutdown_reports_noncooperative_request_without_false_success(store) -> None:
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    fetcher = _NonCooperativeFetcher()
    runner.fetcher = fetcher
    task = _task()
    store.save_task(task)
    handle = runner.submit(task)
    assert fetcher.started.wait(1.0)

    started = time.monotonic()
    try:
        completed = runner.shutdown(wait=True, timeout=0.05)
        elapsed = time.monotonic() - started
        assert completed is False
        assert elapsed < 0.25
        assert handle.future.done() is False
        snapshot = runner.shutdown_snapshot()
        assert snapshot["active_runs"] >= 1 or snapshot["pending_request_futures"] >= 1
    finally:
        fetcher.release.set()
        assert runner.drain(timeout=1.0) is True
        assert runner.shutdown(wait=True, timeout=1.0) is True


def test_runner_shutdown_cancels_queued_run_without_treating_running_future_as_cancelled(store) -> None:
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    fetcher = _NonCooperativeFetcher()
    runner.fetcher = fetcher
    first_task = _task("https://one.example/")
    second_task = _task("https://two.example/")
    store.save_task(first_task)
    store.save_task(second_task)
    first = runner.submit(first_task)
    assert fetcher.started.wait(1.0)
    second = runner.submit(second_task)

    try:
        runner.begin_shutdown()
        deadline = time.monotonic() + 1.0
        while not second.future.done() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert second.future.cancelled()
        assert not first.future.cancelled()
        assert runner.drain(timeout=0.03) is False
    finally:
        fetcher.release.set()
        assert runner.drain(timeout=1.0) is True
        assert runner.shutdown(wait=True, timeout=1.0) is True


def test_shutdown_coordinator_records_reason_phase_timing_and_false_step(caplog) -> None:
    import logging

    deadline = ShutdownDeadline.from_timeout(1.0)
    coordinator = DependencyShutdownCoordinator(
        logging.getLogger("test.p1.shutdown"), reason="repair", deadline=deadline
    )
    coordinator.add("intake", lambda: True)
    coordinator.add("blocker", lambda: False, after=("intake",))
    with caplog.at_level(logging.INFO, logger="test.p1.shutdown"):
        failures = coordinator.run()
    assert failures == ("blocker",)
    text = "\n".join(record.getMessage() for record in caplog.records)
    assert "reason=repair" in text
    assert "phase=intake" in text
    assert "elapsed_ms=" in text
    assert "phase=blocker" in text


def test_repair_handoff_dynamically_commits_worker_and_closes_top_level_shell(
    tmp_path,
    monkeypatch,
) -> None:
    from types import SimpleNamespace

    from arenyxa import repair as repair_module
    from arenyxa.presentation import main_window_operations as operations_module
    from arenyxa.presentation.main_window_operations import MainWindowOperationsMixin

    events: list[object] = []

    class Context:
        def prepare_for_repair_shutdown(self, timeout: float) -> bool:
            events.append(("prepare", timeout))
            return True

        def mark_repair_handoff_committed(self) -> None:
            events.append("committed")

        def mark_repair_shutdown_failed(self) -> None:
            events.append("failed")

    class Window(MainWindowOperationsMixin):
        def __init__(self) -> None:
            self.context = Context()
            self._repair_exit_requested = False
            self.shellCloseRequested = SimpleNamespace(emit=lambda: events.append("shell-close"))

        def close(self) -> bool:
            events.append("window-close")
            return True

        def show_status(self, message: str, duration: int = 5000) -> None:
            events.append((message, duration))

        def setEnabled(self, enabled: bool) -> None:
            events.append(("enabled", enabled))

    plan_path = tmp_path / "repair-plan.json"
    plan_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(operations_module, "begin_background_shutdown", lambda timeout_ms: True)
    monkeypatch.setattr(
        repair_module,
        "launch_repair_worker",
        lambda path: events.append(("worker", Path(path))),
    )
    window = Window()

    assert window.handoff_repair(plan_path) is True
    assert events == [
        ("prepare", 8.0),
        ("worker", plan_path),
        "committed",
        "window-close",
        "shell-close",
    ]
    assert window._repair_exit_requested is True


def test_navigation_state_is_normalized_without_changing_authorization(tmp_path) -> None:
    from arenyxa.config import AppSettings
    from arenyxa.infrastructure.atomic_io import atomic_write_json

    path = tmp_path / "settings.json"
    atomic_write_json(
        path,
        {
            "developer_mode": False,
            "developer_nav_expanded": True,
            "experience_profile": "personal",
        },
    )
    settings = AppSettings.load(path)
    assert settings.developer_mode is False
    assert settings.developer_nav_expanded is False
    assert settings.experience_profile == "personal"


def test_job_system_shutdown_is_bounded_and_rejects_new_work(tmp_path) -> None:
    from arenyxa.application.job_system import JobSystem
    from arenyxa.bootstrap import bootstrap

    context = bootstrap(tmp_path / "job-runtime", start_scheduler=False)
    assert context.local_control_session is not None
    blocker_started = threading.Event()
    blocker_release = threading.Event()

    def noncooperative(_execution):
        blocker_started.set()
        blocker_release.wait(2.0)
        return {"released": True}

    jobs = JobSystem(context.store, context.security, max_workers=1, queue_capacity=1)
    try:
        jobs.submit(
            "p1-noncooperative",
            noncooperative,
            session=context.local_control_session,
            capability="logs.read",
            resource="job:p1-noncooperative",
            surface="test",
            timeout_seconds=5.0,
        )
        assert blocker_started.wait(1.0)

        started = time.monotonic()
        assert jobs.shutdown(wait=True, timeout=0.05) is False
        assert time.monotonic() - started < 0.25
        snapshot = jobs.shutdown_snapshot()
        assert snapshot["accepting"] is False
        assert snapshot["running_futures"] == 1

        with pytest.raises(ArenyxaError) as captured:
            jobs.submit(
                "p1-after-shutdown",
                lambda execution: execution.check_cancelled(),
                session=context.local_control_session,
                capability="logs.read",
                resource="job:p1-after-shutdown",
                surface="test",
                timeout_seconds=5.0,
            )
        assert captured.value.code == "JOB_SYSTEM_STOPPING"
    finally:
        blocker_release.set()
        assert jobs.drain(timeout=1.0) is True
        assert jobs.shutdown(wait=True, timeout=1.0) is True
        assert context.shutdown(reason="test_cleanup", timeout=5.0) is True


def test_scheduler_shutdown_is_bounded_and_stops_new_schedule_intake() -> None:
    from datetime import datetime, timedelta

    from arenyxa.application.scheduler import ScheduleRule, SchedulerService
    from arenyxa.compat import UTC

    started = threading.Event()
    release = threading.Event()

    def noncooperative_callback() -> None:
        started.set()
        release.wait(2.0)

    scheduler = SchedulerService(max_callback_workers=1)
    scheduler.add(
        "p1-blocking-schedule",
        ScheduleRule(kind="interval", interval_minutes=1, timezone="UTC"),
        noncooperative_callback,
        next_run=datetime.now(UTC) - timedelta(seconds=1),
    )
    scheduler.start()
    assert started.wait(1.0)
    try:
        before = time.monotonic()
        assert scheduler.stop(timeout=0.05) is False
        assert time.monotonic() - before < 0.25
        assert scheduler.shutdown_snapshot()["running_callbacks"] == 1
        with pytest.raises(RuntimeError, match="停止"):
            scheduler.add(
                "p1-after-stop",
                ScheduleRule(kind="interval", interval_minutes=1, timezone="UTC"),
                lambda: None,
            )
    finally:
        release.set()
        assert scheduler.drain(timeout=1.0) is True
        assert scheduler.stop(timeout=1.0) is True


def test_new_orchestrator_instance_has_fresh_shutdown_and_cancellation_state(store) -> None:
    first = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    assert first.shutdown(wait=True, timeout=1.0) is True
    assert first.shutdown_snapshot()["accepting"] is False

    second = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    fetcher = _CooperativeFetcher()
    second.fetcher = fetcher
    task = _task("https://fresh-instance.example/")
    store.save_task(task)
    handle = second.submit(task)
    assert fetcher.started.wait(1.0)
    assert second.shutdown_snapshot()["accepting"] is True
    try:
        assert handle.token.cancelled is False
        second.begin_shutdown()
        assert handle.token.cancelled is True
        assert second.drain(timeout=1.0) is True
        assert second.shutdown(wait=True, timeout=1.0) is True
    finally:
        if not handle.future.done():
            second.begin_shutdown()
            second.drain(timeout=1.0)
            second.shutdown(wait=True, timeout=1.0)


def test_request_executor_handoff_and_registry_publication_are_atomic_with_shutdown(
    store, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shutdown cannot snapshot between request executor handoff and registry publication."""
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    task = _task()
    run = Run(task_id=task.id, task_snapshot=task.to_dict(), total_units=1)
    token = CancellationToken()
    handoff_entered = threading.Event()
    allow_handoff = threading.Event()
    request_future: Future[object] = Future()
    admit_result: dict[str, object] = {}

    def blocking_submit(*_args, **_kwargs):
        handoff_entered.set()
        assert allow_handoff.wait(2.0)
        return request_future

    monkeypatch.setattr(runner.request_executor, "submit", blocking_submit)

    def admit() -> None:
        try:
            admit_result["value"] = runner._admit_request(
                run=run,
                task=task,
                token=token,
                index=0,
                spec=task.requests[0],
                host="example.test",
            )
        except BaseException as exc:  # pragma: no cover - asserted below
            admit_result["error"] = exc

    admit_thread = threading.Thread(target=admit, name="test-request-admit")
    shutdown_thread = threading.Thread(target=runner.begin_shutdown, name="test-runner-shutdown")
    try:
        admit_thread.start()
        assert handoff_entered.wait(1.0)
        shutdown_thread.start()

        # _admit_request still owns runner._lock while the executor handoff is
        # paused, so begin_shutdown cannot snapshot until publication occurs.
        allow_handoff.set()
        admit_thread.join(2.0)
        shutdown_thread.join(2.0)

        assert not admit_thread.is_alive()
        assert not shutdown_thread.is_alive()
        assert "error" not in admit_result
        assert request_future.cancelled()
        assert runner.shutdown_snapshot()["pending_request_futures"] == 0
    finally:
        allow_handoff.set()
        request_future.cancel()
        runner.shutdown(wait=True, timeout=1.0)
