from __future__ import annotations

import json
import importlib
import logging
import os
import threading
from types import SimpleNamespace

import pytest

from arenyxa.bootstrap import ApplicationContext, bootstrap
from arenyxa.application.command_runtime import CommandRuntimeError
from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION
from arenyxa.domain.enums import RunStatus
from arenyxa.domain.models import RequestSpec, Run, Task
from arenyxa.infrastructure.capture.proxy import InterceptingProxy
from arenyxa.infrastructure.capture.proxy_models import ProxySettings
from arenyxa.infrastructure.shutdown import DependencyShutdownCoordinator
from arenyxa.infrastructure.shutdown import ShutdownDeadline
from arenyxa.presentation import main_window_operations as operations_module
from arenyxa.presentation.main_window_operations import MainWindowOperationsMixin
from arenyxa import repair_executor
from arenyxa.repair_common import _repair_marker_path, _write_repair_marker
from arenyxa.repair_common import installation_root, source_mode
from arenyxa.repair_models import RepairCategory, RepairPlan


class _RepairContextHarness:
    def __init__(self, prepare_result: bool = True) -> None:
        self.prepare_result = prepare_result
        self.failed_transitions = 0
        self.committed_transitions = 0

    def prepare_for_repair_shutdown(self, timeout: float) -> bool:
        del timeout
        return self.prepare_result

    def mark_repair_shutdown_failed(self) -> None:
        self.failed_transitions += 1

    def mark_repair_handoff_committed(self) -> None:
        self.committed_transitions += 1


class _RepairWindowHarness(MainWindowOperationsMixin):
    def __init__(self, context: _RepairContextHarness) -> None:
        self.context = context
        self.enabled = True
        self.repair_exit_requested = False
        self.statuses: list[str] = []

    def setEnabled(self, enabled: bool) -> None:
        self.enabled = bool(enabled)

    def show_status(self, message: str, duration: int = 5000) -> None:
        del duration
        self.statuses.append(message)

    def request_repair_exit(self) -> None:
        self.repair_exit_requested = True


def test_ax_lc_003_failed_prerequisite_blocks_dependent_shutdown_step() -> None:
    calls: list[str] = []
    coordinator = DependencyShutdownCoordinator(
        logging.getLogger("test.ax_lc_003"),
        reason="test-prerequisite-failure",
    )
    coordinator.add("prerequisite", lambda: False)
    coordinator.add("dependent", lambda: calls.append("dependent"), after=("prerequisite",))

    failures = coordinator.run()

    assert calls == []
    assert failures == ("prerequisite", "dependent")


def test_ax_lc_004_incomplete_application_shutdown_can_be_retried(monkeypatch) -> None:
    context = object.__new__(ApplicationContext)
    object.__setattr__(context, "_shutdown", False)
    object.__setattr__(context, "_shutdown_result", None)
    object.__setattr__(context, "_shutdown_reason", "unspecified")
    object.__setattr__(context, "_repair_prepared", False)
    object.__setattr__(context, "_shutdown_lock", threading.Lock())
    coordinator_calls: list[str] = []

    monkeypatch.setattr(
        ApplicationContext,
        "_prepare_execution_shutdown",
        lambda self, *, reason, deadline: True,
    )

    def fake_coordinator(self, *, reason, deadline):
        coordinator_calls.append(reason)
        failures = ("transient_owner",) if len(coordinator_calls) == 1 else ()
        return SimpleNamespace(run=lambda: failures)

    monkeypatch.setattr(ApplicationContext, "_shutdown_coordinator", fake_coordinator)

    assert context.shutdown(reason="user_exit", timeout=0.1) is False
    assert context.shutdown(reason="user_exit", timeout=0.1) is True
    assert coordinator_calls == ["user_exit", "user_exit"]


def test_ax_lc_005_proxy_close_reports_active_client_timeout(tmp_path, monkeypatch) -> None:
    proxy = InterceptingProxy(
        tmp_path / "proxy-active-client",
        ProxySettings(tls_interception=False),
    )
    client = object()
    monkeypatch.setattr(proxy, "stop", lambda: None)
    with proxy._client_condition:
        proxy._active_clients.add(client)  # type: ignore[arg-type]

    try:
        assert proxy.close() is False
        assert proxy._closed is False
    finally:
        with proxy._client_condition:
            proxy._active_clients.clear()
        proxy.close()


def test_ax_lc_005_proxy_close_reports_persistence_refusal_and_context_propagates_it(
    tmp_path,
    monkeypatch,
) -> None:
    proxy = InterceptingProxy(
        tmp_path / "proxy-persistence-refusal",
        ProxySettings(tls_interception=False),
    )
    monkeypatch.setattr(proxy, "stop", lambda: None)
    with monkeypatch.context() as scoped:
        scoped.setattr(proxy.persistence, "close", lambda timeout: False)
        assert proxy.close() is False
        assert proxy._closed is False

    context = object.__new__(ApplicationContext)
    object.__setattr__(context, "proxy_engine", SimpleNamespace(close=lambda: False))
    object.__setattr__(context, "store", SimpleNamespace(optimize=lambda: None))
    actions = context._shutdown_actions(ShutdownDeadline.from_timeout(0.1))
    assert actions["proxy"]() is False
    assert proxy.close() is True


def test_ax_lc_001_repair_preparation_timeout_crosses_irreversible_boundary(
    tmp_path,
    monkeypatch,
) -> None:
    context = bootstrap(tmp_path / "repair-timeout", safe_mode=True, start_scheduler=False)
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(context.scheduler, "drain", lambda timeout: False)
            assert context.prepare_for_repair_shutdown(timeout=0.5) is False
        assert context.repair_shutdown_state.value == "failed_quiesced"
    finally:
        context.shutdown(reason="repair", timeout=5.0)


@pytest.mark.parametrize(
    ("context_ready", "background_ready"),
    [(False, True), (True, False)],
)
def test_ax_lc_001_008_post_boundary_preparation_failure_enters_terminal_ui(
    monkeypatch,
    context_ready: bool,
    background_ready: bool,
) -> None:
    context = _RepairContextHarness(prepare_result=context_ready)
    window = _RepairWindowHarness(context)
    monkeypatch.setattr(
        operations_module,
        "begin_background_shutdown",
        lambda timeout_ms: background_ready,
    )

    assert window.prepare_for_repair_shutdown() is False
    assert context.failed_transitions == 1
    assert window.enabled is False
    assert window.repair_exit_requested is True


def test_ax_lc_006_worker_launch_failure_enters_terminal_ui_before_propagating(
    tmp_path,
    monkeypatch,
) -> None:
    from arenyxa import repair as repair_module

    context = _RepairContextHarness()
    window = _RepairWindowHarness(context)
    plan_path = tmp_path / "repair-plan.json"
    plan_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(operations_module, "begin_background_shutdown", lambda timeout_ms: True)

    def fail_launch(_plan_path) -> None:
        raise RuntimeError("injected worker launch failure")

    monkeypatch.setattr(repair_module, "launch_repair_worker", fail_launch)

    with pytest.raises(RuntimeError, match="injected worker launch failure"):
        window.handoff_repair(plan_path)

    assert context.failed_transitions == 1
    assert context.committed_transitions == 0
    assert window.enabled is False
    assert window.repair_exit_requested is True


def test_ax_lc_007_repair_engine_exception_is_terminal_and_auditable(
    tmp_path,
    monkeypatch,
) -> None:
    data_root = tmp_path / "data"
    plan_path = data_root / "repair" / "pending_repair_plan.json"
    plan = RepairPlan(
        install_root=str(installation_root()),
        data_root=str(data_root),
        categories=[RepairCategory.OTHER.value],
        relaunch=False,
        source_mode=source_mode(),
    )
    plan.save(plan_path)
    _write_repair_marker(data_root, os.getpid(), "ax-lc-007", "active")
    monkeypatch.setattr(repair_executor.time, "sleep", lambda seconds: None)

    def fail_engine(_engine) -> None:
        raise RuntimeError("injected repair engine failure")

    monkeypatch.setattr(repair_executor.RepairEngine, "run", fail_engine)

    assert repair_executor.run_repair_worker(plan_path) == 1
    assert plan_path.exists() is False
    assert _repair_marker_path(data_root).exists() is False
    report = json.loads(
        (data_root / "repair" / "last_repair_report.json").read_text(encoding="utf-8")
    )
    assert report["success"] is False
    assert any("injected repair engine failure" in item for item in report["unresolved"])


def test_ax_lc_002_bootstrap_rolls_back_pre_context_execution_owners(
    tmp_path,
    monkeypatch,
) -> None:
    bootstrap_module = importlib.import_module("arenyxa.bootstrap")
    observed: dict[str, object] = {}
    original_job_services = bootstrap_module._create_platform_job_services
    original_scheduler = bootstrap_module.SchedulerService
    original_runner = bootstrap_module.RunOrchestrator
    original_async_runner = bootstrap_module.AsyncRunOrchestrator

    def capture_job_services(*args, **kwargs):
        session, jobs = original_job_services(*args, **kwargs)
        observed["jobs"] = jobs
        return session, jobs

    def capture_scheduler(*args, **kwargs):
        scheduler = original_scheduler(*args, **kwargs)
        observed["scheduler"] = scheduler
        return scheduler

    def capture_runner(*args, **kwargs):
        runner = original_runner(*args, **kwargs)
        observed["runner"] = runner
        return runner

    def capture_async_runner(*args, **kwargs):
        runner = original_async_runner(*args, **kwargs)
        observed["runner"] = runner
        return runner

    monkeypatch.setattr(bootstrap_module, "_create_platform_job_services", capture_job_services)
    monkeypatch.setattr(bootstrap_module, "SchedulerService", capture_scheduler)
    monkeypatch.setattr(bootstrap_module, "RunOrchestrator", capture_runner)
    monkeypatch.setattr(bootstrap_module, "AsyncRunOrchestrator", capture_async_runner)
    monkeypatch.setattr(
        bootstrap_module,
        "_create_workflow_services",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("injected pre-context workflow failure")
        ),
    )

    try:
        with pytest.raises(RuntimeError, match="injected pre-context workflow failure"):
            bootstrap_module.bootstrap(
                tmp_path / "pre-context-rollback",
                safe_mode=True,
                start_scheduler=False,
            )
        assert observed["jobs"].shutdown_snapshot()["accepting"] is False
        assert observed["scheduler"].shutdown_snapshot()["accepting"] is False
        assert observed["runner"].shutdown_snapshot()["accepting"] is False
    finally:
        if "jobs" in observed:
            observed["jobs"].shutdown(wait=True, timeout=5.0)
        if "scheduler" in observed:
            observed["scheduler"].stop(timeout=5.0)
        if "runner" in observed:
            observed["runner"].shutdown(wait=True, timeout=5.0)


def test_ax_lc_002_foundation_failure_closes_configured_logging(
    tmp_path,
    monkeypatch,
) -> None:
    bootstrap_module = importlib.import_module("arenyxa.bootstrap")
    real_shutdown_logging = bootstrap_module.shutdown_logging
    shutdown_calls: list[str] = []
    monkeypatch.setattr(
        bootstrap_module,
        "_restore_dlp_policy",
        lambda store: (_ for _ in ()).throw(RuntimeError("injected store-stage failure")),
    )
    monkeypatch.setattr(
        bootstrap_module,
        "shutdown_logging",
        lambda: shutdown_calls.append("logging"),
    )

    try:
        with pytest.raises(RuntimeError, match="injected store-stage failure"):
            bootstrap_module.bootstrap(
                tmp_path / "foundation-rollback",
                safe_mode=True,
                start_scheduler=False,
            )
        assert shutdown_calls == ["logging"]
    finally:
        real_shutdown_logging()


@pytest.mark.parametrize(
    "fault_stage",
    ["proxy", "mitm", "plugin", "supervisor", "command_runtime", "scheduler_start"],
)
def test_ax_lc_002_bootstrap_rolls_back_context_at_every_late_fault_boundary(
    tmp_path,
    monkeypatch,
    fault_stage: str,
) -> None:
    bootstrap_module = importlib.import_module("arenyxa.bootstrap")
    contexts: list[ApplicationContext] = []
    original_context = bootstrap_module.ApplicationContext

    def capture_context(*args, **kwargs):
        context = original_context(*args, **kwargs)
        contexts.append(context)
        return context

    def injected_failure(*args, **kwargs):
        del args, kwargs
        raise RuntimeError(f"injected {fault_stage} bootstrap failure")

    monkeypatch.setattr(bootstrap_module, "ApplicationContext", capture_context)
    if fault_stage == "proxy":
        monkeypatch.setattr(bootstrap_module, "InterceptingProxy", injected_failure)
    elif fault_stage == "mitm":
        monkeypatch.setattr(bootstrap_module, "MitmEngine", injected_failure)
    elif fault_stage == "plugin":
        monkeypatch.setattr(bootstrap_module.ProtocolPluginLoader, "load", injected_failure)
    elif fault_stage == "supervisor":
        monkeypatch.setattr(bootstrap_module, "_start_runtime_supervisor", injected_failure)
    elif fault_stage == "command_runtime":
        monkeypatch.setattr(bootstrap_module, "ArenyxaCommandRuntime", injected_failure)
    else:
        original_start = bootstrap_module.SchedulerService.start

        def start_then_fail(scheduler) -> None:
            original_start(scheduler)
            injected_failure()

        monkeypatch.setattr(bootstrap_module.SchedulerService, "start", start_then_fail)

    try:
        with pytest.raises(RuntimeError, match=f"injected {fault_stage} bootstrap failure"):
            bootstrap_module.bootstrap(
                tmp_path / fault_stage,
                safe_mode=True,
                start_scheduler=fault_stage == "scheduler_start",
            )
        assert len(contexts) == 1
        context = contexts[0]
        assert context._shutdown_result is True
        assert context.job_system.shutdown_snapshot()["accepting"] is False
        assert context.scheduler.shutdown_snapshot()["accepting"] is False
        assert context.runner.shutdown_snapshot()["accepting"] is False
    finally:
        if contexts and contexts[0]._shutdown_result is not True:
            contexts[0].shutdown(reason="test_cleanup", timeout=8.0)


def test_ax_lc_009_live_recovery_repair_cannot_mutate_current_active_run(tmp_path) -> None:
    context = bootstrap(tmp_path / "live-recovery", safe_mode=False, start_scheduler=False)
    context.settings.developer_mode = True
    context.settings.developer_terms_version = DEVELOPER_TERMS_VERSION
    context.settings.developer_terms_accepted_at = "2026-08-30T00:00:00+00:00"
    task = Task("live-recovery", [RequestSpec("https://example.test/")])
    run = Run(task_id=task.id, task_snapshot=task.to_dict(), status=RunStatus.RUNNING)
    context.store.save_task(task)
    context.store.save_run(run)
    error: CommandRuntimeError | None = None

    try:
        try:
            context.command_runtime.execute("recovery repair")
        except CommandRuntimeError as exc:
            error = exc
        persisted = context.store.get_run(run.id)
        assert persisted is not None and persisted["status"] == RunStatus.RUNNING.value
        assert error is not None
        assert error.code == "LIVE_RUNTIME_RECOVERY_FORBIDDEN"
        audit = context.command_runtime.execute("recovery check")["data"]["audit"]
        assert run.id in audit["active_runs"]
    finally:
        context.shutdown(reason="test_cleanup", timeout=8.0)
