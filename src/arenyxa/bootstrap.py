from __future__ import annotations

import logging
import subprocess
import sys
import threading
from dataclasses import field
from arenyxa.compat import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from arenyxa.application.export import ExportService
from arenyxa.application.project_format import ArenyxaProjectService
from arenyxa.application.runner import RunHandle, RunOrchestrator
from arenyxa.application.async_runner import AsyncRunOrchestrator
from arenyxa.application.scheduler import SchedulerService, ScheduleRule
from arenyxa.application.terminal import TerminalSession
from arenyxa.application.terminal_workspace import TerminalWorkspaceManager
from arenyxa.application.command_runtime import ArenyxaCommandRuntime
from arenyxa.application.control_plane import PlatformControlPlane, create_local_control_session
from arenyxa.application.job_system import JobSystem
from arenyxa.application.traffic_control_plane import TrafficControlPlane
from arenyxa.application.enterprise_control_plane import EnterpriseControlPlane
from arenyxa.application.windows_runtime import WindowsRuntimeControl
from arenyxa.application.developer_access import DeveloperAccessManager, detect_root_capability_state
from arenyxa.application.root_owner_security import RootCapabilityState
from arenyxa.application.nextgen import NextGenFeatureHub
from arenyxa.application.versioning import DatasetVersionService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.application.workflow_test_lab import WorkflowTestLab
from arenyxa.enterprise import LocalEnterpriseIdentityService
from arenyxa.enterprise.enrollment import EnrollmentService
from arenyxa.enterprise.coordinator import OfficeCoordinatorService
from arenyxa.enterprise.governance import EnterpriseGovernanceService
from arenyxa.enterprise.operations import EnterpriseOperationGuard
from arenyxa.enterprise.distributed import EnterpriseServerRuntime
from arenyxa.application.reliability import (
    PreflightEstimator,
    ResourceGovernor,
    ResourceLeasePool,
    ResourceLimits,
    SystemResourceProbe,
)
from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.runtime_recovery import RuntimeRecoveryResult, RuntimeRecoveryService
from arenyxa.application.runtime_supervisor import ArenyxaRuntimeSupervisor
from arenyxa.application.resilience_scheduler import ResilienceDrillScheduler
from arenyxa.application.resilience_drills import ResilienceDrillService
from arenyxa.application.survivability import SurvivabilityManager
from arenyxa.application.performance_telemetry import PerformanceTelemetry
from arenyxa.application.traffic_automation import (
    TrafficAutomationEngine,
    TrafficEvent,
    configure_default_traffic_handlers,
)
from arenyxa.config import AppPaths, AppSettings
from arenyxa.domain.models import utc_now
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.capture.event_stream import BoundedEventStream
from arenyxa.infrastructure.capture.live_intelligence import LiveIntelligencePipeline
from arenyxa.infrastructure.capture.protocol_plugins import ProtocolPluginLoader
from arenyxa.infrastructure.capture.protocol_registry import global_protocol_registry
from arenyxa.infrastructure.capture.proxy import InterceptingProxy
from arenyxa.infrastructure.capture.mitm_engine import MitmEngine
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.observability import configure_logging, shutdown_logging
from arenyxa.infrastructure.shutdown import DependencyShutdownCoordinator, ShutdownDeadline
from arenyxa.performance import PerformancePolicy
from arenyxa.platform_compat import (
    apply_legacy_environment,
    select_runtime,
    validate_python_for_runtime,
    windows_reduced_motion_requested,
)
from arenyxa.infrastructure.plugins import PluginManager, PluginSandbox
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited
from arenyxa.security import DeveloperTrustStore, SecurityKernel, Session
from arenyxa.security.dlp import DlpMode, DlpPolicy, GLOBAL_DLP_ENGINE

from arenyxa.bootstrap_services import (
    _validate_python_runtime,
    _root_developer_clean_start,
    _persist_runtime_recovery_history,
    _start_runtime_supervisor,
    _attach_phase6_survivability,
    _build_resource_controls,
    _create_developer_access,
    _create_enterprise_services,
    _create_workflow_services,
    _restore_persisted_schedules,
    _configure_traffic_automation,
    _restore_dlp_policy,
    _create_platform_job_services,
    _retire_bootstrap_control_session,
    _run_bootstrap_cleanup,
    _attach_platform_control_plane,
    _prepare_bootstrap_foundation,
    _rollback_bootstrap_failure,
)

LOGGER = logging.getLogger(__name__)


class RepairShutdownState(str, Enum):
    RUNNING = "running"
    QUIESCING = "quiescing"
    PREPARED = "prepared"
    HANDOFF_COMMITTED = "handoff_committed"
    FAILED_QUIESCED = "failed_quiesced"


@dataclass(slots=True)
class ApplicationContext:
    """Own the initialized desktop runtime graph and coordinate deterministic shutdown."""

    paths: AppPaths
    settings: AppSettings
    store: SQLiteStore
    runner: RunOrchestrator
    scheduler: SchedulerService
    exporter: ExportService
    capture: CaptureController
    versioning: DatasetVersionService
    workflows: WorkflowEngine
    lineage: DataLineageService
    workflow_runtime: WorkflowDatasetService
    projects: ArenyxaProjectService
    plugins: PluginManager
    plugin_sandbox: PluginSandbox
    performance: PerformancePolicy
    terminal: TerminalSession
    nextgen: NextGenFeatureHub
    runtime_recovery: RuntimeRecoveryResult
    terminal_workspace: TerminalWorkspaceManager | None = None
    traffic_automation: TrafficAutomationEngine | None = None
    network_intelligence: LiveIntelligencePipeline | None = None
    protocol_plugin_status: dict[str, Any] | None = None
    # Runtime placement is independent from the user's Experience Mode.
    runtime_mode: str = "desktop"
    # Ephemeral measurements only; authority and Root session state never live here.
    navigation_metrics: dict[str, float] = field(default_factory=dict)
    runtime_supervisor: ArenyxaRuntimeSupervisor | None = None
    survivability: SurvivabilityManager | None = None
    performance_telemetry: PerformanceTelemetry | None = None
    resilience_drills: ResilienceDrillService | None = None

    workflow_test_lab: WorkflowTestLab | None = None
    resource_governor: ResourceGovernor | None = None
    resource_probe: SystemResourceProbe | None = None
    browser_pool: ResourceLeasePool | None = None
    preflight: PreflightEstimator | None = None

    security: SecurityKernel | None = None

    developer_access: DeveloperAccessManager | None = None
    enterprise_identity: LocalEnterpriseIdentityService | None = None
    enrollment: EnrollmentService | None = None
    office_coordinator: OfficeCoordinatorService | None = None
    enterprise_governance: EnterpriseGovernanceService | None = None
    enterprise_operations: EnterpriseOperationGuard | None = None
    enterprise_server: EnterpriseServerRuntime | None = None
    resilience_scheduler: ResilienceDrillScheduler | None = None

    # True only after a fresh Root Owner private-key challenge in this process.
    root_developer_workstation: bool = False
    # Durable workstation enrollment marker; never grants authority by itself.
    root_workstation_registered: bool = False
    # Read-only Root binding/key health projection. This never grants authority.
    root_capability_state: RootCapabilityState | None = None
    safe_mode: bool = False

    system_reduce_motion: bool = False
    proxy_engine: InterceptingProxy | None = None
    mitm_engine: MitmEngine | None = None
    command_runtime: ArenyxaCommandRuntime | None = None
    control_plane: PlatformControlPlane | None = None
    traffic_control: TrafficControlPlane | None = None
    enterprise_control: EnterpriseControlPlane | None = None
    windows_runtime: WindowsRuntimeControl | None = None
    job_system: JobSystem | None = None
    local_control_session: Session | None = None
    _shutdown: bool = field(default=False, init=False, repr=False)
    _shutdown_result: bool | None = field(default=None, init=False, repr=False)
    _shutdown_reason: str = field(default="unspecified", init=False, repr=False)
    _repair_prepared: bool = field(default=False, init=False, repr=False)
    _repair_shutdown_state: RepairShutdownState = field(
        default=RepairShutdownState.RUNNING,
        init=False,
        repr=False,
    )
    _shutdown_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def repair_shutdown_state(self) -> RepairShutdownState:
        with self._shutdown_lock:
            return self._repair_shutdown_state

    def mark_repair_shutdown_failed(self) -> None:
        with self._shutdown_lock:
            if self._repair_shutdown_state is not RepairShutdownState.RUNNING:
                self._repair_shutdown_state = RepairShutdownState.FAILED_QUIESCED

    def mark_repair_handoff_committed(self) -> None:
        with self._shutdown_lock:
            if self._repair_shutdown_state is not RepairShutdownState.PREPARED:
                raise RuntimeError("Repair handoff requires a prepared execution plane")
            self._repair_shutdown_state = RepairShutdownState.HANDOFF_COMMITTED

    def _prepare_execution_shutdown(
        self, *, reason: str, deadline: ShutdownDeadline
    ) -> bool:
        """Stop new work, signal cooperative cancellation, and drain execution owners.

        This is intentionally separate from full context teardown so Repair can quiesce
        dangerous work *before* launching the external worker while preserving one
        canonical owner for storage/service destruction.
        """
        normalized_reason = str(reason or "unspecified")
        self._shutdown_reason = normalized_reason

        # Close every producer/admission gate before waiting on any one owner.
        self.scheduler.begin_shutdown()
        if self.job_system is not None:
            self.job_system.begin_shutdown()
        self.workflow_runtime.shutdown(wait=False)
        self.runner.begin_shutdown()

        checks: list[tuple[str, Callable[[float], bool]]] = [
            ("scheduler", self.scheduler.drain),
        ]
        if self.job_system is not None:
            checks.append(("job_system", self.job_system.drain))
        checks.extend(
            [
                (
                    "workflow_runtime",
                    lambda timeout: self.workflow_runtime.shutdown(wait=True, timeout=timeout),
                ),
                ("runner", self.runner.drain),
            ]
        )

        complete = True
        for owner, drain in checks:
            remaining = deadline.remaining()
            if remaining <= 0.0:
                complete = False
                LOGGER.error(
                    "Shutdown preparation deadline exhausted reason=%s owner=%s",
                    normalized_reason,
                    owner,
                )
                continue
            phase_started = __import__("time").monotonic()
            owner_complete = bool(drain(remaining))
            LOGGER.info(
                "Shutdown preparation reason=%s owner=%s success=%s elapsed_ms=%d deadline_remaining_ms=%d",
                normalized_reason,
                owner,
                owner_complete,
                int((__import__("time").monotonic() - phase_started) * 1000.0),
                int(deadline.remaining() * 1000.0),
            )
            complete = complete and owner_complete

        if not complete:
            LOGGER.error(
                "Shutdown preparation incomplete reason=%s runner=%s job_system=%s scheduler=%s",
                normalized_reason,
                self.runner.shutdown_snapshot(),
                None if self.job_system is None else self.job_system.shutdown_snapshot(),
                self.scheduler.shutdown_snapshot(),
            )
        return complete

    def prepare_for_repair_shutdown(self, timeout: float = 8.0) -> bool:
        """Canonical Repair pre-shutdown policy shared by manual and startup repair."""
        with self._shutdown_lock:
            if self._shutdown:
                return bool(self._shutdown_result)
            if self._repair_shutdown_state in {
                RepairShutdownState.PREPARED,
                RepairShutdownState.HANDOFF_COMMITTED,
            }:
                return True
            self._shutdown_reason = "repair"
            self._repair_shutdown_state = RepairShutdownState.QUIESCING
        deadline = ShutdownDeadline.from_timeout(timeout)
        complete = self._prepare_execution_shutdown(reason="repair", deadline=deadline)
        with self._shutdown_lock:
            self._repair_prepared = complete
            self._repair_shutdown_state = (
                RepairShutdownState.PREPARED
                if complete
                else RepairShutdownState.FAILED_QUIESCED
            )
        return complete

    def _shutdown_actions(
        self, deadline: ShutdownDeadline
    ) -> dict[str, Callable[[], bool | None]]:
        """Build owner-level shutdown actions that all consume one deadline."""

        def remaining() -> float:
            return max(0.0, deadline.remaining())

        def stop_runtime_supervisor() -> None:
            if self.runtime_supervisor is not None:
                self.runtime_supervisor.stop(timeout=min(2.0, remaining()))

        def stop_survivability() -> None:
            if self.survivability is not None:
                self.survivability.stop(timeout=min(2.0, remaining()))

        def stop_job_system() -> bool:
            if self.job_system is None:
                return True
            return self.job_system.shutdown(wait=True, timeout=remaining())

        def stop_resilience_scheduler() -> None:
            if self.resilience_scheduler is not None:
                self.resilience_scheduler.shutdown()

        def stop_enterprise_server() -> None:
            if self.enterprise_server is not None:
                self.enterprise_server.close(reason="APPLICATION_SHUTDOWN")

        def stop_office_coordinator() -> None:
            if self.office_coordinator is not None:
                self.office_coordinator.stop()

        def stop_workflow_runtime() -> bool:
            stopped = self.workflow_runtime.shutdown(wait=True, timeout=remaining())
            if not stopped:
                LOGGER.warning("Workflow runtime did not quiesce within global shutdown deadline")
            return stopped

        def finalize_capture() -> None:
            if self.capture.session and self.capture.session.state.value in {
                "preparing", "capturing", "paused", "finalizing", "failed"
            }:
                self.capture.stop(cancelled=True)

        def stop_proxy() -> bool:
            if self.proxy_engine is None:
                return True
            return self.proxy_engine.close()

        def stop_mitm() -> None:
            if self.mitm_engine is not None:
                self.mitm_engine.stop()

        def close_terminal() -> None:
            self.terminal.close()
            if self.terminal_workspace is not None:
                self.terminal_workspace.close_all()

        def logout_developer() -> None:
            if self.developer_access is not None:
                self.developer_access.logout(reason="APPLICATION_SHUTDOWN")

        def retire_local_control_session() -> None:
            if self.security is None or self.local_control_session is None:
                return
            session = self.local_control_session
            self.security.state.revoke_session(session.id)
            self.security.state.remove_identity(session.identity_id)
            self.security.state.forget_session_revocation(session.id)
            self.local_control_session = None

        def close_enterprise_identity() -> None:
            if self.enterprise_identity is not None:
                self.enterprise_identity.close()

        return {
            "runtime_supervisor": stop_runtime_supervisor,
            "survivability": stop_survivability,
            "scheduler": lambda: self.scheduler.stop(timeout=remaining()),
            "resilience_scheduler": stop_resilience_scheduler,
            "job_system": stop_job_system,
            "enterprise_server": stop_enterprise_server,
            "office_coordinator": stop_office_coordinator,
            "workflow_runtime": stop_workflow_runtime,
            "capture": finalize_capture,
            "proxy": stop_proxy,
            "mitm": stop_mitm,
            "runner": lambda: self.runner.shutdown(wait=True, timeout=remaining()),
            "terminal": close_terminal,
            "developer_access": logout_developer,
            "local_control_session": retire_local_control_session,
            "enterprise_identity": close_enterprise_identity,
            "settings": lambda: self.settings.save(self.paths.root / "settings.json"),
            "database_checkpoint": lambda: self.store.checkpoint("PASSIVE"),
            "database_optimize": self.store.optimize,
            "logging": shutdown_logging,
        }

    def _shutdown_coordinator(
        self, *, reason: str, deadline: ShutdownDeadline
    ) -> DependencyShutdownCoordinator:
        """Create the existing dependency graph with deadline-aware owner actions."""
        actions = self._shutdown_actions(deadline)
        coordinator = DependencyShutdownCoordinator(LOGGER, reason=reason, deadline=deadline)
        coordinator.add("runtime_supervisor", actions["runtime_supervisor"])
        coordinator.add("survivability", actions["survivability"], after=("runtime_supervisor",))
        coordinator.add(
            "scheduler", actions["scheduler"], after=("runtime_supervisor", "survivability")
        )
        coordinator.add("resilience_scheduler", actions["resilience_scheduler"])
        coordinator.add(
            "job_system",
            actions["job_system"],
            after=("runtime_supervisor", "survivability", "scheduler", "resilience_scheduler"),
        )
        coordinator.add("enterprise_server", actions["enterprise_server"], after=("job_system",))
        coordinator.add(
            "office_coordinator", actions["office_coordinator"], after=("enterprise_server",)
        )
        coordinator.add(
            "workflow_runtime", actions["workflow_runtime"], after=("scheduler", "enterprise_server")
        )
        coordinator.add("capture", actions["capture"], after=("workflow_runtime",))
        coordinator.add("proxy", actions["proxy"], after=("capture",))
        coordinator.add("mitm", actions["mitm"], after=("capture",))
        coordinator.add(
            "runner", actions["runner"], after=("workflow_runtime", "capture", "proxy", "mitm")
        )
        coordinator.add("terminal", actions["terminal"], after=("runner",))
        coordinator.add(
            "developer_access",
            actions["developer_access"],
            after=("runner", "office_coordinator", "resilience_scheduler"),
        )
        coordinator.add(
            "local_control_session",
            actions["local_control_session"],
            after=("job_system", "developer_access"),
        )
        coordinator.add(
            "enterprise_identity",
            actions["enterprise_identity"],
            after=("developer_access", "office_coordinator"),
        )
        coordinator.add(
            "settings",
            actions["settings"],
            after=("terminal", "developer_access", "local_control_session"),
        )
        coordinator.add(
            "database_checkpoint",
            actions["database_checkpoint"],
            after=("runner", "capture", "enterprise_identity", "settings"),
        )
        coordinator.add(
            "database_optimize", actions["database_optimize"], after=("database_checkpoint",)
        )
        coordinator.add("logging", actions["logging"], after=("database_optimize",))
        return coordinator

    def shutdown(self, *, reason: str | None = None, timeout: float = 20.0) -> bool:
        """Shut down runtime components in dependency order within one global budget."""
        normalized_reason = str(reason or self._shutdown_reason or "user_exit")
        if normalized_reason == "unspecified":
            normalized_reason = "user_exit"
        with self._shutdown_lock:
            if self._shutdown:
                return bool(self._shutdown_result)
            self._shutdown = True
            self._shutdown_reason = normalized_reason
            self._shutdown_result = None

        deadline = ShutdownDeadline.from_timeout(timeout)
        if not self._repair_prepared or normalized_reason != "repair":
            if not self._prepare_execution_shutdown(reason=normalized_reason, deadline=deadline):
                with self._shutdown_lock:
                    self._shutdown = False
                    self._shutdown_result = False
                return False

        failures = self._shutdown_coordinator(reason=normalized_reason, deadline=deadline).run()
        success = not failures
        with self._shutdown_lock:
            self._shutdown_result = success
            if not success:
                self._shutdown = False
        if not success:
            LOGGER.error(
                "ApplicationContext shutdown incomplete reason=%s failures=%s elapsed_ms=%d",
                normalized_reason,
                failures,
                int(deadline.elapsed() * 1000.0),
            )
        return success





def bootstrap(
    data_dir: Path | None = None,
    safe_mode: bool = False,
    *,
    start_scheduler: bool = True,
    enterprise_runtime_database: Path | str | None = None,
    progress: Callable[[int, str], None] | None = None,
) -> ApplicationContext:
    def report(percent: int, label: str) -> None:
        if progress is None:
            return
        try:
            progress(max(0, min(100, int(percent))), str(label))
        except Exception:
            LOGGER.exception("Bootstrap progress callback failed")

    try:
        (
            runtime, paths, settings, system_reduce_motion, performance, store, recovery,
            root_capability_probe, root_workstation_registered,
        ) = _prepare_bootstrap_foundation(data_dir, safe_mode, report)
    except Exception:
        _run_bootstrap_cleanup("logging", shutdown_logging)
        raise
    context: ApplicationContext | None = None
    security: SecurityKernel | None = None
    local_control_session: Session | None = None
    job_system: JobSystem | None = None
    enterprise_identity: LocalEnterpriseIdentityService | None = None
    office_coordinator: OfficeCoordinatorService | None = None
    enterprise_server: EnterpriseServerRuntime | None = None
    scheduler: SchedulerService | None = None
    runner: RunOrchestrator | None = None
    workflow_runtime: WorkflowDatasetService | None = None
    terminal: TerminalSession | None = None
    terminal_workspace: TerminalWorkspaceManager | None = None
    try:
        report(30, "Building resource governor and runtime limits")
        resource_governor, resource_probe, browser_pool, preflight = _build_resource_controls(
            performance, settings, paths
        )
        report(36, "Initializing Security Kernel and local control plane")
        security = SecurityKernel.local_foundation(paths.root)
        local_control_session, job_system = _create_platform_job_services(
            store, security, performance
        )
        report(42, "Loading Developer and Root trust material")
        developer_access = _create_developer_access(security, paths)
        root_capability_state = developer_access.root_capability_state()
        root_workstation_registered = bool(
            root_workstation_registered or root_capability_state.registered
        )
        root_developer_workstation = False
        report(48, "Initializing Enterprise identity, enrollment, and Zero Trust")
        (
            enterprise_identity,
            enrollment,
            office_coordinator,
            enterprise_governance,
            enterprise_operations,
            enterprise_server,
        ) = _create_enterprise_services(security, paths, store, enterprise_runtime_database)

        report(56, "Creating scheduler and request execution runtime")
        scheduler = SchedulerService(
            on_reschedule=lambda schedule_id, next_run: store.update_schedule_next_run(
                schedule_id, next_run.isoformat()
            ),
            on_executed=lambda schedule_id, attempted_at: store.mark_schedule_executed(
                schedule_id, attempted_at.isoformat()
            ),
            max_callback_workers=max(1, performance.runner_workers),
        )
        runner = (RunOrchestrator if runtime.legacy else AsyncRunOrchestrator)(
            store,
            performance.runner_workers,
            settings.max_response_bytes,
            request_workers=performance.request_workers,
            per_host_workers=performance.per_host_workers,
            progress_interval_ms=performance.runner_progress_interval_ms,
            result_write_batch_size=performance.result_write_batch_size,
            adaptive_request_concurrency=settings.adaptive_request_concurrency,
            resource_governor=resource_governor if settings.resource_governor_enabled else None,
            resource_probe=resource_probe if settings.resource_governor_enabled else None,
            browser_pool=browser_pool,
            enterprise_operations=enterprise_operations,
        )
        report(64, "Restoring workflow, lineage, and dataset services")
        workflow_engine, workflow_test_lab, lineage, workflow_runtime = _create_workflow_services(
            store, performance, enterprise_operations, browser_pool
        )
        report(70, "Initializing packet capture and live protocol intelligence")
        capture_controller = CaptureController(
            store,
            queue_capacity=performance.capture_queue_capacity,
            flush_size=performance.capture_flush_size,
            enterprise_operations=enterprise_operations,
        )
        network_intelligence = LiveIntelligencePipeline(BoundedEventStream(capacity=50_000))
        capture_controller.add_listener(network_intelligence.on_capture_batch)
        capture_controller.add_finalization_listener(
            lambda session: network_intelligence.retire_session(session.id)
        )
        terminal = TerminalSession(paths.projects)
        terminal_workspace = TerminalWorkspaceManager(paths.projects)
        nextgen = NextGenFeatureHub.create(
            data_root=paths.root,
            projects_root=paths.projects,
            max_response_bytes=settings.max_response_bytes,
            browser_pool=browser_pool,
        )
        context = ApplicationContext(
            paths=paths,
            settings=settings,
            store=store,
            runner=runner,
            scheduler=scheduler,
            exporter=ExportService(store),
            capture=capture_controller,
            versioning=DatasetVersionService(),
            workflows=workflow_engine,
            workflow_test_lab=workflow_test_lab,
            lineage=lineage,
            workflow_runtime=workflow_runtime,
            projects=ArenyxaProjectService(),
            plugins=PluginManager(paths.plugins, trust_store=paths.root / "trusted-plugin-keys.json"),
            plugin_sandbox=PluginSandbox(),
            performance=performance,
            resource_governor=resource_governor,
            resource_probe=resource_probe,
            browser_pool=browser_pool,
            preflight=preflight,
            security=security,
            job_system=job_system,
            local_control_session=local_control_session,
            developer_access=developer_access,
            enterprise_identity=enterprise_identity,
            enrollment=enrollment,
            office_coordinator=office_coordinator,
            enterprise_governance=enterprise_governance,
            enterprise_operations=enterprise_operations,
            enterprise_server=enterprise_server,
            root_developer_workstation=root_developer_workstation,
            root_workstation_registered=root_workstation_registered,
            root_capability_state=root_capability_state,
            safe_mode=bool(safe_mode),
            terminal=terminal,
            terminal_workspace=terminal_workspace,
            network_intelligence=network_intelligence,
            nextgen=nextgen,
            runtime_recovery=recovery,
            system_reduce_motion=system_reduce_motion,
        )
        report(78, "Loading proxy, MITM, plugins, and traffic automation")
        context.proxy_engine = InterceptingProxy(paths.captures / "proxy")
        _configure_traffic_automation(context, paths)
        context.mitm_engine = MitmEngine(paths.captures / "mitm")
        context.protocol_plugin_status = ProtocolPluginLoader(
            context.plugins, context.plugin_sandbox, global_protocol_registry()
        ).load()
        report(84, "Starting runtime supervisor")
        _start_runtime_supervisor(context, paths)
        report(90, "Attaching resilience, recovery, and platform control plane")
        _attach_phase6_survivability(context, paths)
        _attach_platform_control_plane(context)
        report(94, "Preparing navigation and command runtime")
        context.command_runtime = ArenyxaCommandRuntime(context)
        report(97, "Restoring persisted schedules")
        _restore_persisted_schedules(store, scheduler, runner, enterprise_operations)
        if start_scheduler:
            report(99, "Starting scheduler")
            scheduler.start()
        return context
    except Exception:
        _rollback_bootstrap_failure(
            context, terminal_workspace, terminal, workflow_runtime, runner, scheduler,
            enterprise_server, office_coordinator, enterprise_identity, job_system,
            security, local_control_session,
        )
        raise
