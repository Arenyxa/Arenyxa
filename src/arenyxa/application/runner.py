from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait as wait_futures
from typing import Callable, ClassVar
from urllib.parse import urlparse
from arenyxa.application.nextgen import AdaptiveRateLimiter
from arenyxa.application.future_callbacks import WeakMethodFutureCallback
from arenyxa.application.reliability import (
    BoundedPerformanceHistory, PerformanceIntelligence, ResourceDecision,
    ResourceGovernor, ResourceLeasePool, ResourceSnapshot, SystemResourceProbe,
)
from arenyxa.compat import shutdown_executor
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, ResultRecord, Run, Task, utc_now
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher
from arenyxa.infrastructure.parsers import FieldExtractor

ProgressCallback = Callable[[Run], None]

from arenyxa.application.runner_support import (
    RunHandle,
    _RequestOutcome,
    _DynamicRequestGate,
    _AdaptiveRequestController,
    _HostGate,
    _HostLease,
    _HostLimiter,
    _AdaptiveHostState,
    _AdaptiveRateCoordinator,
)
from arenyxa.application.run_execution import RunExecutionMixin, _RunExecutionState



class RunOrchestrator(RunExecutionMixin):
    """Execute task runs with bounded concurrency, host fairness, persistence, and cancellation."""
    











    def __init__(
        self,
        store: SQLiteStore,
        max_workers: int = 4,
        max_response_bytes: int = 32 * 1024 * 1024,
        *,
        request_workers: int = 8,
        per_host_workers: int = 4,
        progress_interval_ms: int = 180,
        result_write_batch_size: int = 32,
        result_flush_interval_ms: int = 1_000,
        adaptive_request_concurrency: bool = True,
        resource_governor: ResourceGovernor | None = None,
        resource_probe: SystemResourceProbe | None = None,
        browser_pool: ResourceLeasePool | None = None,
        enterprise_operations: object | None = None,
    ) -> None:
        self.store = store
        self.run_workers = max(1, int(max_workers))
        self.request_workers = max(1, int(request_workers))
        self.per_host_workers = max(1, min(int(per_host_workers), self.request_workers))
        self.progress_interval_seconds = max(0.05, int(progress_interval_ms) / 1000.0)
        self.result_write_batch_size = max(1, int(result_write_batch_size))
        self._dynamic_result_write_batch_size = self.result_write_batch_size
        self._max_result_write_batch_size = max(self.result_write_batch_size, min(4096, self.result_write_batch_size * 8))
                                                                                                
                                                                                                 
                                             
        self.result_flush_interval_seconds = max(0.05, int(result_flush_interval_ms) / 1000.0)

        self.executor = ThreadPoolExecutor(
            max_workers=self.run_workers,
            thread_name_prefix="arenyxa-run",
        )
        self.request_executor = ThreadPoolExecutor(
            max_workers=self.request_workers,
            thread_name_prefix="arenyxa-fetch",
        )
                                                                                           
                                                                                          
                                                                                           
                                                                                          
        self._request_gate = _DynamicRequestGate(self.request_workers)
        self._adaptive_requests = _AdaptiveRequestController(
            self._request_gate,
            self.request_workers,
            enabled=adaptive_request_concurrency,
        )
        self._resource_governor = resource_governor
        self._resource_probe = resource_probe
        self._browser_pool = browser_pool
        self._enterprise_operations = enterprise_operations
        self._resource_snapshot: ResourceSnapshot | None = None
        self._resource_decision: ResourceDecision | None = None
        self._last_resource_sample_at = 0.0
        self._performance_history = BoundedPerformanceHistory(256)
        self._performance_intelligence = PerformanceIntelligence()
        self.fetcher = HttpFetcher(max_response_bytes)
        self.extractor = FieldExtractor()
        self._host_limiter = _HostLimiter(self.per_host_workers)
        self._adaptive_rate = _AdaptiveRateCoordinator(self.per_host_workers)
        self._handles: dict[str, RunHandle] = {}
        self._request_futures: set[Future[_RequestOutcome]] = set()
        self._lock = threading.RLock()
        self._closed = False
        self._executor_shutdown_requested = False
        self._fetcher_closed = False
        self.logger = logging.getLogger("arenyxa.runner")

    def submit(
        self, task: Task, on_progress: ProgressCallback | None = None, preview: bool = False
    ) -> RunHandle:
        """Submit a task run after concurrency, resource, and enterprise authorization checks."""
        errors = task.validate()
        if errors:
            raise ArenyxaError("TASK_INVALID", "；".join(errors), domain="TASK")
        if task.status in {TaskStatus.ARCHIVED, TaskStatus.DELETED}:
            raise ArenyxaError(
                "TASK_INACTIVE",
                "已归档或删除的任务不能直接运行；请先恢复为活动任务。",
                domain="TASK",
                context={"task_id": task.id, "status": task.status.value},
            )
        if self._enterprise_operations is not None:
                                                                                               
                                                                                           
                                                                                             
            self._enterprise_operations.authorize_if_bound(
                "workflow", task.id, "workflow.execute",
                correlation_id=f"task-run:{task.id}",
            )
        decision = self._refresh_resource_governance(force=True)
        if decision is not None and not decision.admit_new_runs:
            raise ArenyxaError(
                "RESOURCE_PREFLIGHT_BLOCKED",
                "本机资源处于临界状态，Arenyxa 已阻止新的运行以保护现有数据和系统稳定性。",
                domain="RESOURCE",
                context={"pressure": decision.pressure, "reasons": list(decision.reasons)},
            )
        run = Run(task_id=task.id, task_snapshot=task.to_dict(), total_units=len(task.requests))
        token = CancellationToken()
        state_lock = threading.RLock()
                                                                                       
                                                                
        with self._lock:
            if self._closed:
                raise ArenyxaError("RUNNER_SHUTDOWN", "运行器已关闭，不能再提交任务。", domain="RUN")
            if decision is not None and len(self._handles) >= decision.worker_ceiling:
                raise ArenyxaError(
                    "RESOURCE_WORKER_PRESSURE",
                    "当前运行任务数已达到 Resource Governor 的动态上限；请等待现有任务释放资源。",
                    domain="RESOURCE",
                    context={"active_runs": len(self._handles), "worker_ceiling": decision.worker_ceiling},
                )
            try:
                self.store.save_run(run)
            except Exception as exc:
                raise ArenyxaError(
                    "RUN_STORAGE_FAILED",
                    "无法创建运行记录；任务尚未开始。",
                    domain="RUN",
                    context={"task_id": task.id},
                ) from exc
            try:
                future = self.executor.submit(
                    self._execute, task, run, token, on_progress, preview, state_lock=state_lock
                )
            except RuntimeError as exc:
                run.status = RunStatus.FAILED
                run.error_code = "RUNNER_SHUTDOWN"
                run.stage = "failed"
                run.finished_at = utc_now()
                try:
                    self.store.save_run(run)
                except Exception:
                    self.logger.exception("Unable to persist RUNNER_SHUTDOWN terminal state")
                raise ArenyxaError(
                    "RUNNER_SHUTDOWN", "运行器正在关闭，任务未能启动。", domain="RUN"
                ) from exc
            handle = RunHandle(
                run=run, token=token, future=future, persist_status=self.store.update_run_control_status,
                state_lock=state_lock,
            )
            self._handles[run.id] = handle
        future.add_done_callback(
            WeakMethodFutureCallback(self, "_on_run_done", prefix=(run,), suffix=(state_lock,))
        )
        return handle

    def preview(self, task: Task) -> Run:
        """Execute a task as a non-persistent preview run."""
        handle = self.submit(task, preview=True)
        return handle.future.result()

    def cancel_all(self) -> None:
        """Cancel every active run managed by this orchestrator."""
        with self._lock:
            handles = list(self._handles.values())
        for handle in handles:
            handle.cancel()

    def active_handles(self) -> list[RunHandle]:
        """Return a stable snapshot of active run handles."""
        with self._lock:
            return list(self._handles.values())

    def concurrency_snapshot(self) -> dict[str, object]:
        
        """Return current run, request, host, and browser concurrency telemetry."""
        with self._lock:
            active_runs = len(self._handles)
            active_requests = self._request_gate.active_count()
            request_limit = self._request_gate.limit()
        adaptive = self._adaptive_requests.snapshot()
        return {
            "run_workers": self.run_workers,
            "request_workers": self.request_workers,
            "request_limit": request_limit,
            "request_limit_mode": adaptive["mode"],
            "request_adaptive_floor": adaptive["floor"],
            "request_adaptive_ceiling": adaptive["ceiling"],
            "request_local_p95_ms": adaptive["last_local_p95_ms"],
            "request_adaptive_decision": adaptive["last_decision"],
            "request_resource_ceiling": adaptive.get("resource_ceiling", self.request_workers),
            "per_host_workers": self.per_host_workers,
            "active_runs": active_runs,
            "active_requests": active_requests,
            "request_queue_bound": self.request_workers,
            "request_waiting_runs": self._request_gate.waiting_count(),
            "adaptive_hosts": len(self._adaptive_rate.snapshot()),
            "resource_pressure": None if self._resource_decision is None else self._resource_decision.pressure,
            "resource_reasons": [] if self._resource_decision is None else list(self._resource_decision.reasons),
            "browser_limit": None if self._browser_pool is None else self._browser_pool.limit(),
            "browser_active": 0 if self._browser_pool is None else self._browser_pool.active_count(),
        }

    def resource_snapshot(self) -> dict[str, object]:
        """Return the latest sampled local resource state when available."""
        self._refresh_resource_governance(force=False)
        snapshot = self._resource_snapshot
        decision = self._resource_decision
        return {
            "sample": None if snapshot is None else snapshot.to_dict(),
            "decision": None if decision is None else decision.to_dict(),
        }

    def performance_explanation(self) -> dict[str, object]:
        """Explain adaptive performance decisions using bounded recent telemetry."""
        return self._performance_intelligence.explain(self._performance_history.snapshot()).to_dict()

    def _refresh_resource_governance(self, *, force: bool = False) -> ResourceDecision | None:
        if self._resource_governor is None or self._resource_probe is None:
            return None
        now = time.monotonic()
        if not force and now - self._last_resource_sample_at < 0.75:
            return self._resource_decision
        browser_active = 0 if self._browser_pool is None else self._browser_pool.active_count()
        try:
            snapshot = self._resource_probe.sample(
                active_browser_instances=browser_active,
                active_workers=self._request_gate.active_count(),
            )
            decision = self._resource_governor.evaluate(snapshot)
        except Exception:
                                                                                                 
                                                                                              
            self.logger.exception("resource governor sample failed")
            return self._resource_decision
        self._resource_snapshot = snapshot
        self._resource_decision = decision
        self._last_resource_sample_at = now
        self._adaptive_requests.set_resource_ceiling(decision.request_ceiling)
        if self._browser_pool is not None:
            self._browser_pool.set_limit(decision.browser_ceiling)
        return decision

    def adaptive_rate_snapshot(self) -> dict[str, dict[str, object]]:
        """Return per-host adaptive rate-control state."""
        return self._adaptive_rate.snapshot()

    def request_limit(self) -> int:
        """Return the current global request concurrency limit."""
        return self._request_gate.limit()

    def set_request_limit(self, limit: int) -> int:
        





        """Set the bounded request concurrency limit and return the applied value."""
        return self._adaptive_requests.set_manual(limit)

    def enable_adaptive_request_limit(self) -> int:
        
        """Enable or disable adaptive request concurrency control."""
        return self._adaptive_requests.enable_auto()

    def begin_shutdown(self) -> None:
        """Stop intake and signal cooperative cancellation without pretending work is gone."""
        with self._lock:
            self._closed = True
            handles = tuple(self._handles.values())
            request_futures = tuple(self._request_futures)
        for handle in handles:
            handle.cancel()
        # Future.cancel() is only authoritative for work that has not started.
        # Running request workers receive the shared CancellationToken via handle.cancel().
        for future in request_futures:
            future.cancel()

    def shutdown_snapshot(self) -> dict[str, object]:
        """Return truthful run/request lifecycle state for shutdown diagnostics."""
        with self._lock:
            handles = tuple(self._handles.values())
            requests = tuple(self._request_futures)
            accepting = not self._closed
        run_futures = tuple(handle.future for handle in handles)
        return {
            "accepting": accepting,
            "active_runs": len(handles),
            "running_runs": sum(1 for future in run_futures if future.running()),
            "queued_runs": sum(
                1 for future in run_futures if not future.running() and not future.done()
            ),
            "pending_request_futures": sum(1 for future in requests if not future.done()),
            "running_request_futures": sum(1 for future in requests if future.running()),
            "queued_request_futures": sum(
                1 for future in requests if not future.running() and not future.done()
            ),
        }

    def drain(self, timeout: float) -> bool:
        """Wait up to *timeout* for already-signalled run and request work to really finish."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            with self._lock:
                futures = {
                    *(handle.future for handle in self._handles.values()),
                    *self._request_futures,
                }
            pending = {future for future in futures if not future.done()}
            if not pending:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                snapshot = self.shutdown_snapshot()
                self.logger.error("Runner drain deadline exceeded: %s", snapshot)
                return False
            wait_futures(pending, timeout=min(0.05, remaining))

    def _request_executor_shutdown(self, *, wait: bool) -> None:
        # Calling shutdown(wait=False) does not terminate running Python functions.
        # It merely prevents future executor submissions and lets workers retire after return.
        shutdown_executor(self.executor, wait=wait, cancel_futures=True)
        shutdown_executor(self.request_executor, wait=wait, cancel_futures=True)
        self._executor_shutdown_requested = True

    def _close_fetcher_after_drain(self) -> None:
        if self._fetcher_closed:
            return
        close_fetcher = getattr(self.fetcher, "close", None)
        if callable(close_fetcher):
            close_fetcher()
        self._fetcher_closed = True

    def shutdown(
        self,
        wait_for_runs: bool = True,
        *,
        timeout: float | None = 10.0,
        **legacy: object,
    ) -> bool:
        """Stop intake, cancel cooperatively, drain truthfully, then retire executors.

        A False result means at least one running function is still alive.  In that case
        executors are placed into non-waiting shutdown state so no queued/new work can run,
        but the method never claims those running threads were terminated.
        """
        if "wait" in legacy:
            wait_for_runs = bool(legacy["wait"])
        if "timeout" in legacy and timeout == 10.0:
            timeout = None if legacy["timeout"] is None else float(legacy["timeout"])

        self.begin_shutdown()
        if not wait_for_runs:
            self._request_executor_shutdown(wait=False)
            return not any(
                int(self.shutdown_snapshot()[key])
                for key in ("active_runs", "pending_request_futures")
            )

        completed = self.drain(10.0 if timeout is None else max(0.0, float(timeout)))
        if not completed:
            self._request_executor_shutdown(wait=False)
            return False

        # wait=True is safe and useful *after* every owned Future has actually returned.
        self._request_executor_shutdown(wait=True)
        self._close_fetcher_after_drain()
        return True













    def _persist_progress(self, run: Run, callback: ProgressCallback | None) -> None:
        try:
            self.store.save_run(run)
        except Exception as exc:
            raise ArenyxaError(
                "RUN_STORAGE_FAILED",
                "运行状态无法写入本地数据库。",
                domain="RUN",
                context={"run_id": run.id, "stage": run.stage},
            ) from exc
        if callback:
            try:
                callback(run)
            except Exception:
                                                                                             
                                                                                  
                self.logger.exception("run progress callback failed")

    @staticmethod
    def _host_key(url: str) -> str:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").rstrip(".").casefold()
                                                                                       
                                                                       
            host = host.encode("idna").decode("ascii") if host else host
        except (TypeError, ValueError, UnicodeError):
            return "<invalid-host>"
        if not host:
            return "<unknown-host>"
                                                                                       
                                                                                           
        return host

    def _forget_request_future(self, future: Future[_RequestOutcome]) -> None:
        with self._lock:
            self._request_futures.discard(future)

    def _on_run_done(
        self, run: Run, future: Future[Run], state_lock: threading.RLock
    ) -> None:
        if future.cancelled():
            with state_lock:
                if run.status not in RunHandle._TERMINAL:
                    run.status = RunStatus.CANCELLED
                    run.stage = "cancelled"
                    run.finished_at = utc_now()
                    try:
                        self.store.save_run(run)
                    except Exception:
                        self.logger.exception(
                            "failed to persist cancelled queued run", extra={"run_id": run.id}
                        )
        self._forget(run.id)

    def _forget(self, run_id: str) -> None:
        with self._lock:
            self._handles.pop(run_id, None)
