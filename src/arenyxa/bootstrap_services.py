from __future__ import annotations

import logging
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

from arenyxa.exception_boundary import call_exception_boundary

from arenyxa.application.export import ExportService
from arenyxa.application.project_format import ArenyxaProjectService
from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.runner_support import RunHandle
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
from arenyxa.application.reliability import PreflightEstimator, ResourceGovernor, ResourceLeasePool, ResourceLimits, SystemResourceProbe
from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.runtime_recovery import RuntimeRecoveryResult, RuntimeRecoveryService
from arenyxa.application.runtime_supervisor import ArenyxaRuntimeSupervisor
from arenyxa.application.resilience_scheduler import ResilienceDrillScheduler
from arenyxa.application.resilience_drills import ResilienceDrillService
from arenyxa.application.survivability import SurvivabilityManager
from arenyxa.application.performance_telemetry import PerformanceTelemetry
from arenyxa.application.traffic_automation import TrafficAutomationEngine, TrafficEvent, configure_default_traffic_handlers
from arenyxa.config import AppPaths, AppSettings
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.capture.event_stream import BoundedEventStream
from arenyxa.infrastructure.capture.live_intelligence import LiveIntelligencePipeline
from arenyxa.infrastructure.capture.protocol_plugins import ProtocolPluginLoader
from arenyxa.infrastructure.capture.protocol_registry import global_protocol_registry
from arenyxa.infrastructure.capture.proxy import InterceptingProxy
from arenyxa.infrastructure.capture.mitm_engine import MitmEngine
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.observability import configure_logging, shutdown_logging
from arenyxa.performance import PerformancePolicy
from arenyxa.platform_compat import apply_legacy_environment, select_runtime, validate_python_for_runtime, windows_reduced_motion_requested
from arenyxa.infrastructure.plugins import PluginManager, PluginSandbox
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited
from arenyxa.security import DeveloperTrustStore, SecurityKernel, Session
from arenyxa.security.dlp import DlpMode, DlpPolicy, GLOBAL_DLP_ENGINE

if TYPE_CHECKING:
    from arenyxa.bootstrap import ApplicationContext

LOGGER = logging.getLogger(__name__)

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
    manager = call_exception_boundary(
        lambda: DeveloperAccessManager.local(security, paths.root, Path(__file__).resolve().parent),
        on_error=lambda exc: LOGGER.exception(
            "Official Developer Access trust material failed to load; disabling login"
        ),
    )
    if manager is None:
        return DeveloperAccessManager(security, trust_store=DeveloperTrustStore())
    return manager


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
    office_coordinator: OfficeCoordinatorService | None = None
    enterprise_server: EnterpriseServerRuntime | None = None
    try:
        enrollment = EnrollmentService(enterprise_identity, paths.root)
        enterprise_governance = EnterpriseGovernanceService(enterprise_identity, store)

        def enterprise_access_context() -> dict[str, object]:
            context = enterprise_identity.dynamic_access_context()
            posture = call_exception_boundary(
                enrollment.local_device_posture,
                on_error=lambda exc: LOGGER.exception(
                    "Enterprise device-posture evaluation failed; Zero Trust will fail closed for device signals"
                ),
            )
            if posture is None:
                context.update({"managed_device": False, "device_compliant": False})
            else:
                context.update(posture)
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
        recovered_distributed = call_exception_boundary(
            enterprise_server.queue.recover_expired_leases,
            on_error=lambda exc: LOGGER.exception(
                "Distributed queue recovery failed; remote enterprise operations remain fail-closed"
            ),
            fallback=0,
        )
        if recovered_distributed:
            LOGGER.warning("Recovered %d expired distributed job leases", recovered_distributed)
        retention = call_exception_boundary(
            enterprise_server.queue.retain_terminal_jobs,
            on_error=lambda exc: LOGGER.exception(
                "Distributed queue startup retention maintenance failed; no history was assumed pruned"
            ),
        )
        if retention is not None:
            if retention["jobs_pruned"] or retention["idempotent_tombstones_pruned"]:
                LOGGER.info("Distributed queue startup retention maintenance: %s", retention)
            elif retention["pruning_disabled"]:
                LOGGER.warning("Distributed queue startup retention is fail-closed: %s", retention)
    except Exception:
        if enterprise_server is not None:
            _run_bootstrap_cleanup(
                "enterprise_server",
                lambda: enterprise_server.close(reason="BOOTSTRAP_FAILURE"),
            )
        if office_coordinator is not None:
            _run_bootstrap_cleanup("office_coordinator", office_coordinator.stop)
        _run_bootstrap_cleanup("enterprise_identity", enterprise_identity.close)
        raise
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
    jobs = call_exception_boundary(
        lambda: JobSystem(
            store,
            security,
            max_workers=max(1, min(8, performance.runner_workers)),
            queue_capacity=max(16, min(512, performance.capture_queue_capacity // 100)),
        ),
        on_error=lambda exc: _retire_bootstrap_control_session(security, session),
        reraise=True,
    )
    assert jobs is not None
    return session, jobs


def _retire_bootstrap_control_session(security: SecurityKernel, session: Session) -> None:
    def retire() -> None:
        security.state.revoke_session(session.id)
        security.state.remove_identity(session.identity_id)
        security.state.forget_session_revocation(session.id)

    call_exception_boundary(
        retire,
        on_error=lambda exc: LOGGER.exception(
            "Bootstrap rollback failed to retire the local control session"
        ),
    )


def _run_bootstrap_cleanup(name: str, action: Callable[[], Any]) -> bool:
    result = call_exception_boundary(
        action,
        on_error=lambda exc: LOGGER.exception("Bootstrap rollback action failed owner=%s", name),
        fallback=False,
    )
    if result is False:
        LOGGER.error("Bootstrap rollback action incomplete owner=%s", name)
        return False
    return True


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


def _rollback_bootstrap_failure(
    context: ApplicationContext | None,
    terminal_workspace: TerminalWorkspaceManager | None,
    terminal: TerminalSession | None,
    workflow_runtime: WorkflowDatasetService | None,
    runner: RunOrchestrator | None,
    scheduler: SchedulerService | None,
    enterprise_server: EnterpriseServerRuntime | None,
    office_coordinator: OfficeCoordinatorService | None,
    enterprise_identity: LocalEnterpriseIdentityService | None,
    job_system: JobSystem | None,
    security: SecurityKernel | None,
    local_control_session: Session | None,
) -> None:
    if context is not None:
        complete = _run_bootstrap_cleanup(
            "application_context",
            lambda: context.shutdown(reason="bootstrap_failure", timeout=8.0),
        )
        if not complete:
            _run_bootstrap_cleanup(
                "application_context_retry",
                lambda: context.shutdown(reason="bootstrap_failure", timeout=8.0),
            )
        return
    if terminal_workspace is not None:
        _run_bootstrap_cleanup("terminal_workspace", terminal_workspace.close_all)
    if terminal is not None:
        _run_bootstrap_cleanup("terminal", terminal.close)
    if workflow_runtime is not None:
        _run_bootstrap_cleanup(
            "workflow_runtime", lambda: workflow_runtime.shutdown(wait=True, timeout=5.0)
        )
    if runner is not None:
        _run_bootstrap_cleanup("runner", lambda: runner.shutdown(wait=True, timeout=5.0))
    if scheduler is not None:
        _run_bootstrap_cleanup("scheduler", lambda: scheduler.stop(timeout=5.0))
    if enterprise_server is not None:
        _run_bootstrap_cleanup(
            "enterprise_server", lambda: enterprise_server.close(reason="BOOTSTRAP_FAILURE")
        )
    if office_coordinator is not None:
        _run_bootstrap_cleanup("office_coordinator", office_coordinator.stop)
    if enterprise_identity is not None:
        _run_bootstrap_cleanup("enterprise_identity", enterprise_identity.close)
    if job_system is not None:
        _run_bootstrap_cleanup(
            "job_system", lambda: job_system.shutdown(wait=True, timeout=5.0)
        )
    if security is not None and local_control_session is not None:
        _retire_bootstrap_control_session(security, local_control_session)
    _run_bootstrap_cleanup("logging", shutdown_logging)
