from __future__ import annotations

import logging
import sys
import threading
from dataclasses import field
from arenyxa.compat import dataclass
from datetime import datetime
from pathlib import Path

from arenyxa.application.export import ExportService
from arenyxa.application.project_format import ArenyxaProjectService
from arenyxa.application.runner import RunHandle, RunOrchestrator
from arenyxa.application.scheduler import SchedulerService, ScheduleRule
from arenyxa.application.terminal import TerminalSession
from arenyxa.application.developer_access import DeveloperAccessManager, detect_root_developer_workstation
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
    PreflightEstimator, ResourceGovernor, ResourceLeasePool, ResourceLimits, SystemResourceProbe,
)
from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.runtime_recovery import RuntimeRecoveryResult, RuntimeRecoveryService
from arenyxa.config import AppPaths, AppSettings
from arenyxa.domain.models import utc_now
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.observability import configure_logging
from arenyxa.performance import PerformancePolicy
from arenyxa.platform_compat import (
    apply_legacy_environment,
    select_runtime,
    validate_python_for_runtime,
    windows_reduced_motion_requested,
)
from arenyxa.infrastructure.plugins import PluginManager, PluginSandbox
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited
from arenyxa.security import DeveloperTrustStore, SecurityKernel

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ApplicationContext:
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
                                                                                         
                                                                               
    root_developer_workstation: bool = False
    safe_mode: bool = False
                                                                                              
                                                                                  
    system_reduce_motion: bool = False
    _shutdown: bool = field(default=False, init=False, repr=False)
    _shutdown_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def shutdown(self) -> None:
        




                                                                                          
                                                                                               
                                                            
        with self._shutdown_lock:
            if self._shutdown:
                return
            self._shutdown = True
        try:
            self.scheduler.stop()
        except Exception:
            LOGGER.exception("Scheduler shutdown failed")
        try:
            if not self.workflow_runtime.shutdown(wait=True, timeout=10.0):
                LOGGER.warning("Workflow runtime did not quiesce within shutdown timeout")
        except Exception:
            LOGGER.exception("Workflow runtime shutdown failed")
        try:
            if self.capture.session and self.capture.session.state.value in {
                "preparing", "capturing", "paused", "finalizing", "failed"
            }:
                self.capture.stop(cancelled=True)
        except Exception:
            LOGGER.exception("Capture shutdown failed")
        try:
            self.runner.shutdown(wait=True)
        except Exception:
            LOGGER.exception("Runner shutdown failed")
        try:
            if self.developer_access is not None:
                self.developer_access.logout(reason="APPLICATION_SHUTDOWN")
        except Exception:
            LOGGER.exception("Developer Access shutdown failed")
        try:
            if self.enterprise_server is not None:
                self.enterprise_server.deactivate_service(reason="APPLICATION_SHUTDOWN")
        except Exception:
            LOGGER.exception("Enterprise Server service shutdown failed")
        try:
            if self.office_coordinator is not None:
                self.office_coordinator.stop()
        except Exception:
            LOGGER.exception("Office Coordinator shutdown failed")
        try:
            if self.enterprise_identity is not None:
                self.enterprise_identity.close()
        except Exception:
            LOGGER.exception("Enterprise Identity shutdown failed")
        try:
            self.terminal.close()
        except Exception:
            LOGGER.exception("Terminal shutdown failed")
        try:
            self.settings.save(self.paths.root / "settings.json")
        except Exception:
            LOGGER.exception("Settings save during shutdown failed")
                                                                                        
                                                                                             
                                                                                         
        try:
            self.store.checkpoint("PASSIVE")
        except Exception:
            LOGGER.exception("Database WAL checkpoint during shutdown failed")
        try:
            self.store.optimize()
        except Exception:
            LOGGER.exception("Database optimize during shutdown failed")


def _validate_python_runtime():
    runtime = select_runtime()
    validate_python_for_runtime(runtime)
    apply_legacy_environment(runtime)
    return runtime


def _root_developer_clean_start(paths: AppPaths, previous: AppSettings) -> AppSettings:
    """Preserve durable UX preferences on a verified Root Developer workstation.

    Older v7.7 builds reset the full settings file on every verified Root
    workstation launch. That coupled authority state to first-run UX state and
    repeatedly reopened Welcome Center. Root trust must not mutate user
    preferences; keep a one-time recovery snapshot and continue with the
    validated settings already loaded from disk.
    """
    snapshot = paths.root / "settings.root-developer-previous.json"
    if not snapshot.exists():
        try:
            previous.save(snapshot)
        except Exception:
            LOGGER.exception("Failed to snapshot settings for Root Developer recovery")
    return previous


def bootstrap(
    data_dir: Path | None = None,
    safe_mode: bool = False,
    *,
    start_scheduler: bool = True,
    enterprise_runtime_database: Path | str | None = None,
) -> ApplicationContext:
    runtime = _validate_python_runtime()
    paths = AppPaths.discover(data_dir)
    paths.initialize()
    configure_logging(paths.logs)
    settings_path = paths.root / "settings.json"
    settings = AppSettings.load(settings_path)
    root_workstation_probe = detect_root_developer_workstation(paths.root)
    root_developer_workstation = bool(root_workstation_probe.active)
    if root_developer_workstation:
        settings = _root_developer_clean_start(paths, settings)
        LOGGER.info(
            "Verified Root Developer workstation: preserved durable application preferences and Welcome state"
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
    store = SQLiteStore(paths.database)
    store.initialize()
    recovery_service = RuntimeRecoveryService(store)
    recovery_before = recovery_service.audit()
    recovery = recovery_service.recover()
    if recovery.changed:
        LOGGER.warning(
            "Recovered interrupted lifecycle state from a previous process: "
            "runs=%d captures=%d completed_workflows=%d workflows=%d revisions=%d invalid_schedules=%d",
            recovery.recovered_runs, recovery.recovered_captures, recovery.reconciled_completed_workflows,
            recovery.interrupted_workflows,
            recovery.interrupted_revisions, recovery.disabled_invalid_schedules,
        )
                                                                                             
                                                                                            
        history_path = paths.root / "repair" / "runtime_recovery_history.json"
        history: list[dict[str, object]] = []
        try:
            import json
            raw = json.loads(read_text_limited(history_path, 2 * 1024 * 1024, encoding="utf-8"))
            if isinstance(raw, list):
                history = [item for item in raw if isinstance(item, dict)][-99:]
        except (OSError, ValueError, TypeError):
            history = []
        history.append({
            "recovered_at": recovery.recovered_at,
            "source": "bootstrap",
            "before": recovery_before.to_dict(),
            "result": recovery.to_dict(),
        })
        try:
            atomic_write_json(history_path, history)
        except OSError:
            LOGGER.exception("Failed to persist runtime recovery history")
    resource_limits = ResourceLimits(
        max_request_concurrency=max(1, min(performance.request_workers, settings.request_concurrency)),
        max_worker_count=max(1, performance.runner_workers),
        max_browser_instances=settings.resource_max_browser_instances,
        cpu_soft_percent=float(settings.resource_cpu_soft_percent),
        cpu_critical_percent=min(100.0, float(settings.resource_cpu_soft_percent) + 8.0),
        memory_soft_percent=float(settings.resource_memory_soft_percent),
        memory_critical_percent=min(100.0, float(settings.resource_memory_soft_percent) + 10.0),
        min_free_disk_bytes=settings.resource_min_free_disk_mb * 1024 * 1024,
        critical_free_disk_bytes=max(64 * 1024 * 1024, min(256 * 1024 * 1024, settings.resource_min_free_disk_mb * 256 * 1024)),
    ).normalized()
    resource_governor = ResourceGovernor(resource_limits)
    resource_probe = SystemResourceProbe(paths.root)
    browser_pool = ResourceLeasePool(resource_limits.max_browser_instances)
    preflight = PreflightEstimator(resource_limits)
    security = SecurityKernel.local_foundation(paths.root)
    try:
        developer_access = DeveloperAccessManager.local(
            security, paths.root, Path(__file__).resolve().parent
        )
        if root_developer_workstation:
            try:
                if developer_access.activate_root_workstation_session() is None:
                    root_developer_workstation = False
            except Exception:
                root_developer_workstation = False
                LOGGER.exception("Root Developer workstation session activation failed closed")
    except Exception:
                                                                                            
                                                                             
        LOGGER.exception("Official Developer Access trust material failed to load; disabling login")
        root_developer_workstation = False
        developer_access = DeveloperAccessManager(security, trust_store=DeveloperTrustStore())
    enterprise_identity = LocalEnterpriseIdentityService(security, paths.root)
    enrollment = EnrollmentService(enterprise_identity, paths.root)
    enterprise_governance = EnterpriseGovernanceService(enterprise_identity, store)
    enterprise_operations = EnterpriseOperationGuard(store, enterprise_identity, enterprise_governance)
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

    scheduler = SchedulerService(
        on_reschedule=lambda schedule_id, next_run: store.update_schedule_next_run(
            schedule_id, next_run.isoformat()
        ),
        on_executed=lambda schedule_id, attempted_at: store.mark_schedule_executed(
            schedule_id, attempted_at.isoformat()
        ),
        max_callback_workers=max(1, performance.runner_workers),
    )
    runner = RunOrchestrator(
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
    scheduled_run_lock = threading.Lock()
    scheduled_run_handles: dict[str, RunHandle] = {}
    workflow_engine = WorkflowEngine()
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
    context = ApplicationContext(
        paths=paths,
        settings=settings,
        store=store,
        runner=runner,
        scheduler=scheduler,
        exporter=ExportService(store),
        capture=CaptureController(
            store,
            queue_capacity=performance.capture_queue_capacity,
            flush_size=performance.capture_flush_size,
            enterprise_operations=enterprise_operations,
        ),
        versioning=DatasetVersionService(),
        workflows=workflow_engine,
        workflow_test_lab=workflow_test_lab,
        lineage=lineage,
        workflow_runtime=workflow_runtime,
        projects=ArenyxaProjectService(),
        plugins=PluginManager(paths.plugins),
        plugin_sandbox=PluginSandbox(),
        performance=performance,
        resource_governor=resource_governor,
        resource_probe=resource_probe,
        browser_pool=browser_pool,
        preflight=preflight,
        security=security,
        developer_access=developer_access,
        enterprise_identity=enterprise_identity,
        enrollment=enrollment,
        office_coordinator=office_coordinator,
        enterprise_governance=enterprise_governance,
        enterprise_operations=enterprise_operations,
        enterprise_server=enterprise_server,
        root_developer_workstation=root_developer_workstation,
        safe_mode=bool(safe_mode),
        terminal=TerminalSession(paths.projects),
        nextgen=NextGenFeatureHub.create(data_root=paths.root, projects_root=paths.projects, max_response_bytes=settings.max_response_bytes, browser_pool=browser_pool),
        runtime_recovery=recovery,
        system_reduce_motion=system_reduce_motion,
    )
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
                        "schedule", schedule_id, "schedule.manage",
                        correlation_id=f"schedule-run:{schedule_id}",
                    )
                    task = store.get_task(task_id)
                    if task is None:
                        LOGGER.warning("Schedule %s references missing task %s", schedule_id, task_id)
                        return
                    scheduled_run_handles[schedule_id] = runner.submit(task)

            scheduler.add(
                schedule_id, rule, scheduled_run, bool(persisted["enabled"]), next_run=next_run
            )
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
                                                                                                
            LOGGER.error("Skipping invalid persisted schedule %r: %s", persisted.get("id"), exc)
    if start_scheduler:
        scheduler.start()
    return context
