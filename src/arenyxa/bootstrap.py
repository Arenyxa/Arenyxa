from __future__ import annotations

import logging
import subprocess
import sys
import threading
from dataclasses import field
from arenyxa.compat import dataclass
from datetime import datetime
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
from arenyxa.infrastructure.shutdown import DependencyShutdownCoordinator
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

LOGGER = logging.getLogger(__name__)


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
    _shutdown_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def shutdown(self) -> None:
        """Shut down runtime components in dependency order and preserve durable state."""
        with self._shutdown_lock:
            if self._shutdown:
                return
            self._shutdown = True

        coordinator = DependencyShutdownCoordinator(LOGGER)

        def stop_scheduler() -> None:
            self.scheduler.stop()

        def stop_runtime_supervisor() -> None:
            if self.runtime_supervisor is not None:
                self.runtime_supervisor.stop()

        def stop_survivability() -> None:
            if self.survivability is not None:
                self.survivability.stop()

        def stop_job_system() -> None:
            if self.job_system is not None:
                self.job_system.shutdown(wait=True)

        def stop_resilience_scheduler() -> None:
            if self.resilience_scheduler is not None:
                self.resilience_scheduler.shutdown()

        def stop_enterprise_server() -> None:
            if self.enterprise_server is not None:
                self.enterprise_server.close(reason="APPLICATION_SHUTDOWN")

        def stop_office_coordinator() -> None:
            if self.office_coordinator is not None:
                self.office_coordinator.stop()

        def stop_workflow_runtime() -> None:
            if not self.workflow_runtime.shutdown(wait=True, timeout=10.0):
                LOGGER.warning("Workflow runtime did not quiesce within shutdown timeout")

        def finalize_capture() -> None:
            if self.capture.session and self.capture.session.state.value in {
                "preparing",
                "capturing",
                "paused",
                "finalizing",
                "failed",
            }:
                self.capture.stop(cancelled=True)

        def stop_proxy() -> None:
            if self.proxy_engine is not None:
                self.proxy_engine.close()

        def stop_mitm() -> None:
            if self.mitm_engine is not None:
                self.mitm_engine.stop()

        def stop_runner() -> None:
            self.runner.shutdown(wait=True)

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

        def save_settings() -> None:
            self.settings.save(self.paths.root / "settings.json")

        def checkpoint_database() -> None:
            self.store.checkpoint("PASSIVE")

        def optimize_database() -> None:
            self.store.optimize()

        def stop_logging() -> None:
            shutdown_logging()

        # Dependencies describe data-flow shutdown, rather than relying on source order:
        # stop intake first, quiesce producers, finalize capture/network interception,
        # drain execution, close identities/sessions, then persist and checkpoint storage.
        coordinator.add("runtime_supervisor", stop_runtime_supervisor)
        coordinator.add("survivability", stop_survivability, after=("runtime_supervisor",))
        coordinator.add("scheduler", stop_scheduler, after=("runtime_supervisor", "survivability"))
        coordinator.add("resilience_scheduler", stop_resilience_scheduler)
        coordinator.add(
            "job_system",
            stop_job_system,
            after=("runtime_supervisor", "survivability", "scheduler", "resilience_scheduler"),
        )
        coordinator.add("enterprise_server", stop_enterprise_server, after=("job_system",))
        coordinator.add("office_coordinator", stop_office_coordinator, after=("enterprise_server",))
        coordinator.add("workflow_runtime", stop_workflow_runtime, after=("scheduler", "enterprise_server"))
        coordinator.add("capture", finalize_capture, after=("workflow_runtime",))
        coordinator.add("proxy", stop_proxy, after=("capture",))
        coordinator.add("mitm", stop_mitm, after=("capture",))
        coordinator.add("runner", stop_runner, after=("workflow_runtime", "capture", "proxy", "mitm"))
        coordinator.add("terminal", close_terminal, after=("runner",))
        coordinator.add(
            "developer_access",
            logout_developer,
            after=("runner", "office_coordinator", "resilience_scheduler"),
        )
        coordinator.add(
            "local_control_session",
            retire_local_control_session,
            after=("job_system", "developer_access"),
        )
        coordinator.add(
            "enterprise_identity", close_enterprise_identity, after=("developer_access", "office_coordinator")
        )
        coordinator.add(
            "settings", save_settings, after=("terminal", "developer_access", "local_control_session")
        )
        coordinator.add(
            "database_checkpoint",
            checkpoint_database,
            after=("runner", "capture", "enterprise_identity", "settings"),
        )
        coordinator.add("database_optimize", optimize_database, after=("database_checkpoint",))
        coordinator.add("logging", stop_logging, after=("database_optimize",))
        coordinator.run()


def _validate_python_runtime() -> Any:
    runtime = select_runtime()
    validate_python_for_runtime(runtime)
    apply_legacy_environment(runtime)
    return runtime


def _root_developer_clean_start(paths: AppPaths, previous: AppSettings) -> AppSettings:
    """Preserve durable UX preferences on a verified Root Developer workstation.

    Previous builds reset the full settings file on every verified Root
    workstation launch. That coupled authority state to first-run UX state and
    repeatedly reopened Welcome Center. Root trust must not mutate user
    preferences; keep a one-time recovery snapshot and continue with the
    validated settings already loaded from disk.
    """
    snapshot = paths.root / "settings.root-developer-previous.json"
    if not snapshot.exists():
        try:
            previous.save(snapshot)
        except (OSError, TypeError, ValueError):
            LOGGER.exception("Failed to snapshot settings for Root Developer recovery")
    return previous


def _persist_runtime_recovery_history(
    paths: AppPaths,
    recovery_before: Any,
    recovery: RuntimeRecoveryResult,
) -> None:
    """Persist one bounded runtime-recovery audit entry without blocking bootstrap on I/O failure."""
    history_path = paths.root / "repair" / "runtime_recovery_history.json"
    history: list[dict[str, object]] = []
    try:
        import json

        raw = json.loads(read_text_limited(history_path, 2 * 1024 * 1024, encoding="utf-8"))
        if isinstance(raw, list):
            history = [item for item in raw if isinstance(item, dict)][-99:]
    except (OSError, ValueError, TypeError):
        history = []
    history.append(
        {
            "recovered_at": recovery.recovered_at,
            "source": "bootstrap",
            "before": recovery_before.to_dict(),
            "result": recovery.to_dict(),
        }
    )
    try:
        atomic_write_json(history_path, history)
    except OSError:
        LOGGER.exception("Failed to persist runtime recovery history")


def _start_runtime_supervisor(context: ApplicationContext, paths: AppPaths) -> None:
    """Attach bounded component probes and start process-local liveness supervision."""
    supervisor = ArenyxaRuntimeSupervisor(paths.logs / "runtime-supervisor")
    supervisor.register_probe("database", lambda: context.store.stability_snapshot())
    supervisor.register_probe(
        "worker",
        lambda: {
            "healthy": True,
            "active": sum(1 for handle in context.runner.active_handles() if not handle.future.done()),
        },
    )
    supervisor.register_probe(
        "capture_engine",
        lambda: {
            "healthy": True,
            "state": context.capture.session.state.value if context.capture.session else "idle",
        },
    )
    supervisor.register_probe(
        "async_loop",
        lambda: {"healthy": True, "runner": type(context.runner).__name__},
    )
    context.runtime_supervisor = supervisor
    supervisor.start()
    context.resilience_scheduler = ResilienceDrillScheduler(context)
    context.resilience_scheduler.start_if_enabled()


def _attach_phase6_survivability(context: ApplicationContext, paths: AppPaths) -> None:
    """Attach bounded Phase-6 survivability, telemetry, and isolated drill services."""
    context.performance_telemetry = PerformanceTelemetry(max_metrics=192, max_samples_per_metric=4096)
    context.survivability = SurvivabilityManager(
        paths.root,
        resource_governor=context.resource_governor,
        resource_probe=context.resource_probe,
        safe_mode=context.safe_mode,
        sample_interval_seconds=2.0,
        worker_count=lambda: sum(1 for handle in context.runner.active_handles() if not handle.future.done()),
        browser_count=lambda: 0 if context.browser_pool is None else context.browser_pool.active_count(),
    )
    if context.runtime_supervisor is not None:
        context.runtime_supervisor.register_incident_listener(
            lambda incident: context.survivability.mark_component(
                incident.component,
                "degraded",
                f"{incident.code}: blocked for {incident.blocked_seconds:.3f}s",
                {"diagnostic_path": incident.diagnostic_path},
            )
        )
    context.job_system.set_admission_provider(context.survivability.admission)
    context.job_system.set_performance_telemetry(context.performance_telemetry)
    if context.proxy_engine is not None:
        context.proxy_engine.set_performance_telemetry(context.performance_telemetry)
        context.survivability.register_pressure_handler(
            "proxy-memory-history", context.proxy_engine.apply_memory_pressure
        )
    context.survivability.start()
    context.resilience_drills = ResilienceDrillService(context)


def _build_resource_controls(
    performance: PerformancePolicy,
    settings: AppSettings,
    paths: AppPaths,
) -> tuple[ResourceGovernor, SystemResourceProbe, ResourceLeasePool, PreflightEstimator]:
    """Build normalized local resource-governance controls for runner and browser workloads."""
    resource_limits = ResourceLimits(
        max_request_concurrency=max(1, min(performance.request_workers, settings.request_concurrency)),
        max_worker_count=max(1, performance.runner_workers),
        max_browser_instances=settings.resource_max_browser_instances,
        cpu_soft_percent=float(settings.resource_cpu_soft_percent),
        cpu_critical_percent=min(100.0, float(settings.resource_cpu_soft_percent) + 8.0),
        memory_soft_percent=float(settings.resource_memory_soft_percent),
        memory_critical_percent=min(100.0, float(settings.resource_memory_soft_percent) + 10.0),
        min_free_disk_bytes=settings.resource_min_free_disk_mb * 1024 * 1024,
        critical_free_disk_bytes=max(
            64 * 1024 * 1024,
            min(256 * 1024 * 1024, settings.resource_min_free_disk_mb * 256 * 1024),
        ),
    ).normalized()
    resource_governor = ResourceGovernor(resource_limits)
    resource_probe = SystemResourceProbe(paths.root)
    browser_pool = ResourceLeasePool(resource_limits.max_browser_instances)
    preflight = PreflightEstimator(resource_limits)
    return resource_governor, resource_probe, browser_pool, preflight


def _create_developer_access(
    security: SecurityKernel,
    paths: AppPaths,
) -> DeveloperAccessManager:
    """Load developer trust material without minting Root authority from disk state.

    A durable Root workstation binding is only a startup-authentication trigger.
    Root authority is granted later, after the interactive Owner-device key
    challenge succeeds for this process.
    """
    try:
        return DeveloperAccessManager.local(security, paths.root, Path(__file__).resolve().parent)
    except Exception:
        LOGGER.exception("Official Developer Access trust material failed to load; disabling login")
        return DeveloperAccessManager(security, trust_store=DeveloperTrustStore())


def _create_enterprise_services(
    security: SecurityKernel,
    paths: AppPaths,
    store: SQLiteStore,
    enterprise_runtime_database: Path | str | None,
) -> tuple[
    LocalEnterpriseIdentityService,
    EnrollmentService,
    OfficeCoordinatorService,
    EnterpriseGovernanceService,
    EnterpriseOperationGuard,
    EnterpriseServerRuntime,
]:
    """Create enterprise identity, governance, Zero Trust context, and distributed runtime services."""
    enterprise_identity = LocalEnterpriseIdentityService(security, paths.root)
    enrollment = EnrollmentService(enterprise_identity, paths.root)
    enterprise_governance = EnterpriseGovernanceService(enterprise_identity, store)

    def enterprise_access_context() -> dict[str, object]:
        context = enterprise_identity.dynamic_access_context()
        try:
            context.update(enrollment.local_device_posture())
        except Exception:
            LOGGER.exception(
                "Enterprise device-posture evaluation failed; Zero Trust will fail closed for device signals"
            )
            context.update({"managed_device": False, "device_compliant": False})
        return context

    enterprise_operations = EnterpriseOperationGuard(
        store,
        enterprise_identity,
        enterprise_governance,
        access_context_provider=enterprise_access_context,
    )
    office_coordinator = OfficeCoordinatorService(enterprise_identity, enrollment, paths.root)
    enterprise_server = EnterpriseServerRuntime(
        enterprise_identity,
        enterprise_governance,
        paths.root,
        distributed_storage_target=enterprise_runtime_database,
    )
    try:
        recovered_distributed = enterprise_server.queue.recover_expired_leases()
        if recovered_distributed:
            LOGGER.warning("Recovered %d expired distributed job leases", recovered_distributed)
    except Exception:
        LOGGER.exception("Distributed queue recovery failed; remote enterprise operations remain fail-closed")
    return (
        enterprise_identity,
        enrollment,
        office_coordinator,
        enterprise_governance,
        enterprise_operations,
        enterprise_server,
    )


def _create_workflow_services(
    store: SQLiteStore,
    performance: PerformancePolicy,
    enterprise_operations: EnterpriseOperationGuard,
    browser_pool: ResourceLeasePool | None = None,
) -> tuple[WorkflowEngine, WorkflowTestLab, DataLineageService, WorkflowDatasetService]:
    """Build workflow and lineage services and reconcile durable lineage indexes."""
    workflow_engine = WorkflowEngine()
    workflow_engine.configure_browser_runtime(browser_pool)
    workflow_test_lab = WorkflowTestLab(workflow_engine)
    lineage = DataLineageService(
        store,
        write_batch_size=max(100, performance.result_write_batch_size),
    )
    try:
        rebuilt_dataset_lineage = lineage.reconcile_ready_revision_lineage()
        if rebuilt_dataset_lineage:
            LOGGER.info("Reconciled lineage for %d ready Dataset Revisions", rebuilt_dataset_lineage)
    except Exception:
        LOGGER.exception("Ready Dataset lineage reconciliation failed")
    workflow_runtime = WorkflowDatasetService(
        store,
        workflow_engine,
        lineage,
        write_batch_size=max(100, performance.result_write_batch_size),
        enterprise_operations=enterprise_operations,
    )
    try:
        rebuilt_lineage = workflow_runtime.reconcile_completed_lineage()
        if rebuilt_lineage:
            LOGGER.info("Reconciled lineage for %d completed workflow executions", rebuilt_lineage)
    except Exception:
        LOGGER.exception("Completed workflow lineage reconciliation failed")
    return workflow_engine, workflow_test_lab, lineage, workflow_runtime


def _restore_persisted_schedules(
    store: SQLiteStore,
    scheduler: SchedulerService,
    runner: RunOrchestrator,
    enterprise_operations: EnterpriseOperationGuard,
) -> None:
    """Restore validated persisted schedules with overlap protection and enterprise authorization."""
    scheduled_run_lock = threading.Lock()
    scheduled_run_handles: dict[str, RunHandle] = {}
    for persisted in store.list_schedules():
        try:
            if persisted.get("rule_error"):
                raise ValueError(str(persisted["rule_error"]))
            rule_data = dict(persisted["rule"])
            if isinstance(rule_data.get("weekdays"), list):
                rule_data["weekdays"] = tuple(rule_data["weekdays"])
            rule = ScheduleRule(**rule_data)
            rule.validate()
            next_run = None
            if persisted.get("next_run_at"):
                next_run = datetime.fromisoformat(str(persisted["next_run_at"]))
            task_id = str(persisted["task_id"])
            schedule_id = str(persisted["id"])

            def scheduled_run(task_id: str = task_id, schedule_id: str = schedule_id) -> None:
                with scheduled_run_lock:
                    previous = scheduled_run_handles.get(schedule_id)
                    if previous is not None and not previous.future.done():
                        LOGGER.warning(
                            "Skipping schedule %s because its previous Run is still active",
                            schedule_id,
                        )
                        return
                    enterprise_operations.authorize_if_bound(
                        "schedule",
                        schedule_id,
                        "schedule.manage",
                        correlation_id=f"schedule-run:{schedule_id}",
                    )
                    task = store.get_task(task_id)
                    if task is None:
                        LOGGER.warning("Schedule %s references missing task %s", schedule_id, task_id)
                        return
                    scheduled_run_handles[schedule_id] = runner.submit(task)

            scheduler.add(
                schedule_id,
                rule,
                scheduled_run,
                bool(persisted["enabled"]),
                next_run=next_run,
            )
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            LOGGER.error("Skipping invalid persisted schedule %r: %s", persisted.get("id"), exc)


def _configure_traffic_automation(context: ApplicationContext, paths: AppPaths) -> None:
    engine = TrafficAutomationEngine(paths.captures / "automation" / "traffic-rules.json")
    configure_default_traffic_handlers(engine, paths.captures / "automation")
    context.traffic_automation = engine

    def dispatch_proxy_automation(kind: str, value: Any) -> None:
        if kind == "flow" and hasattr(value, "summary"):
            payload = value.summary()
            is_tls = str(payload.get("method")) == "CONNECT"
            payload["event"] = "TLS_ESTABLISHED" if is_tls else "HTTP_RESPONSE"
            event = TrafficEvent.TLS_ESTABLISHED if is_tls else TrafficEvent.HTTP_RESPONSE
        elif kind == "intercept" and isinstance(value, dict):
            payload = dict(value)
            is_request = payload.get("phase") == "request"
            payload["event"] = "HTTP_REQUEST" if is_request else "HTTP_RESPONSE"
            event = TrafficEvent.HTTP_REQUEST if is_request else TrafficEvent.HTTP_RESPONSE
        else:
            return
        failures = [item for item in engine.process(event, payload) if not item.get("ok")]
        if failures:
            LOGGER.error("Traffic automation action failures: %s", failures)

    context.proxy_engine.add_listener(dispatch_proxy_automation)


def _restore_dlp_policy(store: SQLiteStore) -> None:
    try:
        dlp_raw = store.get_setting("security.dlp_policy", {})
        if not isinstance(dlp_raw, dict) or not dlp_raw:
            return
        trusted_raw = dlp_raw.get("trusted_domains", ())
        if not isinstance(trusted_raw, (list, tuple, set, frozenset)):
            trusted_raw = ()
        GLOBAL_DLP_ENGINE.configure(
            DlpPolicy(
                mode=DlpMode(str(dlp_raw.get("mode", DlpMode.MONITOR.value)).strip().casefold()),
                trusted_domains=tuple(
                    sorted(
                        {
                            str(item).strip().casefold().lstrip(".")
                            for item in trusted_raw
                            if str(item).strip()
                        }
                    )
                ),
                block_plaintext_secrets=bool(dlp_raw.get("block_plaintext_secrets", True)),
                block_private_keys=bool(dlp_raw.get("block_private_keys", True)),
                max_scan_chars=max(
                    16 * 1024, min(1024 * 1024, int(dlp_raw.get("max_scan_chars", 256 * 1024)))
                ),
            )
        )
    except (TypeError, ValueError, OverflowError):
        LOGGER.exception("Stored DLP policy is invalid; using safe monitor defaults")
        GLOBAL_DLP_ENGINE.configure(DlpPolicy())


def _create_platform_job_services(
    store: SQLiteStore,
    security: SecurityKernel,
    performance: PerformancePolicy,
) -> tuple[Session, JobSystem]:
    session = create_local_control_session(security)
    jobs = JobSystem(
        store,
        security,
        max_workers=max(1, min(8, performance.runner_workers)),
        queue_capacity=max(16, min(512, performance.capture_queue_capacity // 100)),
    )
    return session, jobs


def _attach_platform_control_plane(context: ApplicationContext) -> None:
    if context.security is None or context.job_system is None:
        raise RuntimeError("platform control plane requires initialized security and Job System")
    if (
        context.enterprise_identity is not None
        and context.enterprise_governance is not None
        and context.enrollment is not None
        and context.enterprise_server is not None
    ):
        context.enterprise_control = EnterpriseControlPlane(
            identity=context.enterprise_identity,
            governance=context.enterprise_governance,
            enrollment=context.enrollment,
            server=context.enterprise_server,
            security=context.security,
            data_root=context.paths.root,
        )
    context.windows_runtime = WindowsRuntimeControl()
    context.control_plane = PlatformControlPlane(
        paths=context.paths,
        store=context.store,
        security=context.security,
        jobs=context.job_system,
        runner=context.runner,
        capture=context.capture,
        proxy=context.proxy_engine,
        mitm=context.mitm_engine,
        plugins=context.plugin_sandbox,
        runtime_supervisor=context.runtime_supervisor,
        runtime_recovery=context.runtime_recovery,
        enterprise_server=context.enterprise_server,
        enterprise_control=context.enterprise_control,
        windows_runtime=context.windows_runtime,
        survivability=context.survivability,
        performance_telemetry=context.performance_telemetry,
        resilience_drills=context.resilience_drills,
    )
    context.traffic_control = TrafficControlPlane(
        paths=context.paths,
        store=context.store,
        security=context.security,
        jobs=context.job_system,
        capture=context.capture,
        proxy=context.proxy_engine,
        mitm=context.mitm_engine,
        network_intelligence=context.network_intelligence,
    )


def _prepare_bootstrap_foundation(
    data_dir: Path | None,
    safe_mode: bool,
    report: Callable[[int, str], None],
) -> tuple[Any, AppPaths, AppSettings, bool, PerformancePolicy, SQLiteStore, Any, Any, bool]:
    """Prepare durable/runtime foundations before service graph construction."""
    runtime = _validate_python_runtime()
    paths = AppPaths.discover(data_dir)
    paths.initialize()
    configure_logging(paths.logs)
    settings_path = paths.root / "settings.json"
    settings = AppSettings.load(settings_path)
    report(4, "Loading settings and runtime preferences")
    root_capability_probe = detect_root_capability_state(paths.root)
    report(10, "Checking Root workstation binding and trust")
    root_workstation_registered = (paths.root / "developer" / "root_workstation.binding.json").is_file()
    if root_capability_probe.available:
        settings = _root_developer_clean_start(paths, settings)
        LOGGER.info(
            "Verified Root Developer workstation and Root trust key %s: preserved durable application preferences and Welcome state",
            root_capability_probe.root_key_id,
        )
    system_reduce_motion = windows_reduced_motion_requested()

    if runtime.reduced_visuals:
        settings.reduce_motion = True
        if settings.performance_mode == "performance":
            settings.performance_mode = "balanced"
    if safe_mode:
        settings.theme = "clean_light"
        settings.reduce_motion = True
        settings.performance_mode = "efficiency"
        settings.developer_mode = False
    performance = PerformancePolicy.resolve(
        settings.performance_mode,
        settings.max_workers,
        settings.request_concurrency,
        settings.per_host_concurrency,
    )
    report(16, "Resolving performance and resource policy")
    store = SQLiteStore(paths.database)
    report(20, "Opening database and validating schema")
    store.initialize()
    _restore_dlp_policy(store)
    report(24, "Checking previous runtime state and recovery journal")
    recovery_service = RuntimeRecoveryService(store)
    recovery_before = recovery_service.audit()
    recovery = recovery_service.recover()
    if recovery.changed:
        LOGGER.warning(
            "Recovered interrupted lifecycle state from a previous process: "
            "runs=%d captures=%d completed_workflows=%d workflows=%d revisions=%d invalid_schedules=%d",
            recovery.recovered_runs,
            recovery.recovered_captures,
            recovery.reconciled_completed_workflows,
            recovery.interrupted_workflows,
            recovery.interrupted_revisions,
            recovery.disabled_invalid_schedules,
        )

        _persist_runtime_recovery_history(paths, recovery_before, recovery)
    return (
        runtime, paths, settings, system_reduce_motion, performance, store, recovery,
        root_capability_probe, root_workstation_registered,
    )


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

    (
        runtime, paths, settings, system_reduce_motion, performance, store, recovery,
        root_capability_probe, root_workstation_registered,
    ) = _prepare_bootstrap_foundation(data_dir, safe_mode, report)
    report(30, "Building resource governor and runtime limits")
    resource_governor, resource_probe, browser_pool, preflight = _build_resource_controls(
        performance, settings, paths
    )
    report(36, "Initializing Security Kernel and local control plane")
    security = SecurityKernel.local_foundation(paths.root)
    local_control_session, job_system = _create_platform_job_services(store, security, performance)
    report(42, "Loading Developer and Root trust material")
    developer_access = _create_developer_access(security, paths)
    root_capability_state = developer_access.root_capability_state()
    root_workstation_registered = bool(root_workstation_registered or root_capability_state.registered)
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
        terminal=TerminalSession(paths.projects),
        terminal_workspace=TerminalWorkspaceManager(paths.projects),
        network_intelligence=network_intelligence,
        nextgen=NextGenFeatureHub.create(
            data_root=paths.root,
            projects_root=paths.projects,
            max_response_bytes=settings.max_response_bytes,
            browser_pool=browser_pool,
        ),
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
