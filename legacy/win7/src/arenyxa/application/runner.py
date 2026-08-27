from __future__ import annotations

import logging
import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import field
from typing import Callable, ClassVar
from urllib.parse import urlparse

from arenyxa.application.nextgen import AdaptiveRateLimiter
from arenyxa.application.reliability import (
    BoundedPerformanceHistory, PerformanceIntelligence, PerformanceSample, ResourceDecision,
    ResourceGovernor, ResourceLeasePool, ResourceSnapshot, SystemResourceProbe,
)
from arenyxa.compat import dataclass, shutdown_executor
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, ResultRecord, Run, Task, utc_now
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher
from arenyxa.infrastructure.parsers import FieldExtractor, ParserRegistry

ProgressCallback = Callable[[Run], None]


@dataclass(slots=True)
class RunHandle:
    run: Run
    token: CancellationToken
    future: Future[Run]
    persist_status: Callable[[str, RunStatus], bool] | None = field(default=None, repr=False)
    state_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    control_io_lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    _TERMINAL: ClassVar[set[RunStatus]] = {
        RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.CANCELLED
    }

    def cancel(self) -> None:
        with self.state_lock:
            if self.future.done() or self.run.status in self._TERMINAL:
                return
            self.token.cancel()
            future = self.future
                                                                                               
                                                                                             
                                                                                       
        future.cancel()

    def pause(self) -> None:
                                                                                              
                                                                                          
                                                           
        with self.control_io_lock:
            self._pause_control_transaction()

    def _pause_control_transaction(self) -> None:
                                                                                              
                                                                                               
                                                                                              
                                                                                        
        changed = False
        with self.state_lock:
            if self.future.done() or self.token.cancelled or self.run.status in self._TERMINAL:
                return
            try:
                self.token.pause()
            except Exception:
                logging.getLogger("arenyxa.runner").exception(
                    "pause token transition failed",
                    extra={"run_id": self.run.id},
                )
                return
            if not self.future.done() and self.run.status not in self._TERMINAL:
                self.run.status = RunStatus.PAUSED
                changed = True
        if changed and not self._persist_status(RunStatus.PAUSED):
            with self.state_lock:
                if (
                    not self.future.done()
                    and not self.token.cancelled
                    and self.run.status == RunStatus.PAUSED
                ):
                    try:
                        self.token.resume()
                    except Exception:
                        logging.getLogger("arenyxa.runner").exception(
                            "pause rollback token transition failed",
                            extra={"run_id": self.run.id},
                        )
                        return
                    self.run.status = RunStatus.RUNNING

    def resume(self) -> None:
        with self.control_io_lock:
            self._resume_control_transaction()

    def _resume_control_transaction(self) -> None:
        changed = False
        with self.state_lock:
            if self.future.done() or self.token.cancelled or self.run.status in self._TERMINAL:
                return
            try:
                self.token.resume()
            except Exception:
                logging.getLogger("arenyxa.runner").exception(
                    "resume token transition failed",
                    extra={"run_id": self.run.id},
                )
                return
            if not self.future.done() and self.run.status == RunStatus.PAUSED:
                self.run.status = RunStatus.RUNNING
                changed = True
        if changed and not self._persist_status(RunStatus.RUNNING):
            with self.state_lock:
                if (
                    not self.future.done()
                    and not self.token.cancelled
                    and self.run.status == RunStatus.RUNNING
                ):
                    try:
                        self.token.pause()
                    except Exception:
                        logging.getLogger("arenyxa.runner").exception(
                            "resume rollback token transition failed",
                            extra={"run_id": self.run.id},
                        )
                        return
                    self.run.status = RunStatus.PAUSED

    def _persist_status(self, status: RunStatus) -> bool:
        if self.persist_status is None:
            return True
        try:
            persisted = self.persist_status(self.run.id, status)
            if persisted is False:
                logging.getLogger("arenyxa.runner").error(
                    "pause/resume status persistence was rejected",
                    extra={"run_id": self.run.id, "requested_status": status.value},
                )
                return False
            return True
        except Exception:
                                                                                         
                                                                                         
                                                                     
            logging.getLogger("arenyxa.runner").exception(
                "pause/resume status persistence failed",
                extra={"run_id": self.run.id, "requested_status": status.value},
            )
            return False


@dataclass(slots=True)
class _RequestOutcome:
    index: int
    record: ResultRecord | None
    retries: int = 0
    error_code: str | None = None
    error_message: str | None = None
    local_processing_ms: float | None = None
    status_code: int | None = None
    network_latency_ms: float | None = None


class _DynamicRequestGate:
    







    def __init__(self, maximum: int) -> None:
        self.maximum = max(1, int(maximum))
        self._limit = self.maximum
        self._active = 0
        self._waiters: deque[str] = deque()
        self._waiting: set[str] = set()
        self._lock = threading.Lock()

    def try_acquire(self, owner: str) -> bool:
        owner = str(owner)
        with self._lock:
            if owner not in self._waiting:
                self._waiters.append(owner)
                self._waiting.add(owner)
            if self._active >= self._limit or not self._waiters or self._waiters[0] != owner:
                return False
            self._waiters.popleft()
            self._waiting.discard(owner)
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active <= 0:
                                                                                       
                                                                                        
                self._active = 0
                return
            self._active -= 1

    def withdraw(self, owner: str) -> None:
        
        owner = str(owner)
        with self._lock:
            if owner not in self._waiting:
                return
            self._waiting.discard(owner)
            try:
                self._waiters.remove(owner)
            except ValueError:
                pass

    def set_limit(self, limit: int) -> int:
        with self._lock:
            self._limit = max(1, min(self.maximum, int(limit)))
            return self._limit

    def limit(self) -> int:
        with self._lock:
            return self._limit

    def active_count(self) -> int:
        with self._lock:
            return self._active

    def waiting_count(self) -> int:
        with self._lock:
            return len(self._waiting)


class _AdaptiveRequestController:
    







    def __init__(self, gate: _DynamicRequestGate, maximum: int, enabled: bool = True) -> None:
        self.gate = gate
        self.maximum = max(1, int(maximum))
        self.floor = min(self.maximum, 4)
        self.enabled = bool(enabled) and self.maximum > self.floor
        self._manual = not bool(enabled)
        self._manual_requested = self.maximum
        self._resource_ceiling = self.maximum
        self._target = self.maximum if self._manual or not self.enabled else self.floor
        self._lock = threading.RLock()
        self._samples: deque[float] = deque(maxlen=24)
        self._baseline_p95_ms: float | None = None
        self._last_p95_ms: float = 0.0
        self._last_decision = "manual" if self._manual else "steady"
        self._apply_target_locked()

    @staticmethod
    def _p95(values: deque[float]) -> float:
        ordered = sorted(values)
        if not ordered:
            return 0.0
        index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * 0.95 + 0.999999)))
        return float(ordered[index])

    def _apply_target_locked(self) -> int:
        requested = self._manual_requested if self._manual else self._target
        effective = max(1, min(self.maximum, int(requested), int(self._resource_ceiling)))
        return self.gate.set_limit(effective)

    def observe(self, local_processing_ms: float | None, *, saturated: bool) -> int:
        if local_processing_ms is None:
            return self.gate.limit()
        value = max(0.0, float(local_processing_ms))
        with self._lock:
            if not self.enabled or self._manual:
                return self._apply_target_locked()
            self._samples.append(value)
            if len(self._samples) < self._samples.maxlen:
                return self._apply_target_locked()

            p95 = self._p95(self._samples)
            self._last_p95_ms = p95
            current = max(self.floor, min(self._target, self._resource_ceiling))
            if self._baseline_p95_ms is None:
                self._baseline_p95_ms = max(0.05, p95)
            elif current <= self.floor and p95 <= self._baseline_p95_ms * 1.35 + 0.25:
                self._baseline_p95_ms = self._baseline_p95_ms * 0.85 + p95 * 0.15

            baseline = max(0.05, float(self._baseline_p95_ms))
            pressure_threshold = max(8.0, baseline * 2.25 + 0.5)
            healthy_threshold = max(4.0, baseline * 1.55 + 0.35)

            if current > self.floor and p95 > pressure_threshold:
                new_target = max(self.floor, int((current * 3 + 3) // 4))
                if new_target >= current:
                    new_target = current - 1
                self._target = max(self.floor, new_target)
                self._last_decision = "backoff"
            elif saturated and current < self.maximum and current < self._resource_ceiling and p95 <= healthy_threshold:
                self._target = min(self.maximum, current + 1)
                self._last_decision = "grow"
            else:
                                                                                            
                                                                                   
                self._target = min(self._target, max(self.floor, self._resource_ceiling))
                self._last_decision = "steady"

            self._samples.clear()
            return self._apply_target_locked()

    def set_manual(self, limit: int) -> int:
        with self._lock:
            self._manual = True
            self._manual_requested = max(1, min(self.maximum, int(limit)))
            self._samples.clear()
            self._last_decision = "manual"
            return self._apply_target_locked()

    def enable_auto(self) -> int:
        with self._lock:
            self._manual = False
            self.enabled = self.maximum > self.floor
            self._target = self.floor if self.enabled else self.maximum
            self._samples.clear()
            self._baseline_p95_ms = None
            self._last_p95_ms = 0.0
            self._last_decision = "steady"
            return self._apply_target_locked()

    def set_resource_ceiling(self, limit: int) -> int:
        with self._lock:
            self._resource_ceiling = max(1, min(self.maximum, int(limit)))
            return self._apply_target_locked()

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "mode": "manual" if self._manual else ("adaptive" if self.enabled else "fixed"),
                "floor": self.floor,
                "ceiling": self.maximum,
                "current": self.gate.limit(),
                "resource_ceiling": self._resource_ceiling,
                "manual_requested": self._manual_requested if self._manual else None,
                "baseline_local_p95_ms": round(float(self._baseline_p95_ms or 0.0), 3),
                "last_local_p95_ms": round(self._last_p95_ms, 3),
                "last_decision": self._last_decision,
            }


@dataclass(slots=True)
class _HostGate:
    semaphore: threading.BoundedSemaphore
    users: int = 0


@dataclass(slots=True)
class _HostLease:
    limiter: "_HostLimiter"
    host: str
    gate: _HostGate
    _released: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def release(self) -> None:
                                                                                        
                                                                                        
        with self._lock:
            if self._released:
                return
            self._released = True
        self.limiter._release(self.host, self.gate)


class _HostLimiter:
    






    def __init__(self, per_host_workers: int) -> None:
        self.per_host_workers = max(1, int(per_host_workers))
        self._lock = threading.RLock()
        self._gates: dict[str, _HostGate] = {}

    def try_acquire(self, host: str, max_active: int | None = None) -> _HostLease | None:
        
        with self._lock:
            gate = self._gates.get(host)
            if gate is None:
                gate = _HostGate(threading.BoundedSemaphore(self.per_host_workers))
                self._gates[host] = gate
            if max_active is not None and gate.users >= max(1, int(max_active)):
                return None
            if not gate.semaphore.acquire(blocking=False):
                                                                                     
                                                                
                if gate.users == 0 and self._gates.get(host) is gate:
                                                                                      
                                                                               
                    self._gates.pop(host, None)
                return None
            gate.users += 1
            return _HostLease(self, host, gate)

    def _release(self, host: str, gate: _HostGate) -> None:
                                                                                        
                                                                                           
                                                                                          
                                                                                    
                                                                                    
        with self._lock:
            gate.semaphore.release()
            gate.users = max(0, gate.users - 1)
            if gate.users == 0 and self._gates.get(host) is gate:
                self._gates.pop(host, None)


@dataclass(slots=True)
class _AdaptiveHostState:
    limiter: AdaptiveRateLimiter
    next_allowed: float = 0.0
    last_decision: str = "steady"
    last_seen: float = field(default_factory=time.monotonic)


class _AdaptiveRateCoordinator:
    

    def __init__(self, maximum: int, *, max_hosts: int = 4096, idle_ttl_seconds: float = 1800.0) -> None:
        self.maximum = max(1, int(maximum))
        self.max_hosts = max(64, int(max_hosts))
        self.idle_ttl_seconds = max(60.0, float(idle_ttl_seconds))
        self._lock = threading.RLock()
        self._states: dict[str, _AdaptiveHostState] = {}

    def _prune_locked(self, now: float) -> None:
        stale = [
            host for host, state in self._states.items()
            if now - state.last_seen >= self.idle_ttl_seconds
        ]
        for host in stale:
            self._states.pop(host, None)
        if len(self._states) > self.max_hosts:
            overflow = len(self._states) - self.max_hosts
            oldest = sorted(self._states.items(), key=lambda pair: pair[1].last_seen)[:overflow]
            for host, _state in oldest:
                self._states.pop(host, None)

    def _state(self, host: str) -> _AdaptiveHostState:
        with self._lock:
            now = time.monotonic()
            state = self._states.get(host)
            if state is None:
                self._prune_locked(now)
                if len(self._states) >= self.max_hosts:
                    oldest_host = min(self._states, key=lambda key: self._states[key].last_seen)
                    self._states.pop(oldest_host, None)
                state = _AdaptiveHostState(AdaptiveRateLimiter(1, self.maximum, self.maximum), last_seen=now)
                self._states[host] = state
            else:
                state.last_seen = now
            return state

    def limit(self, host: str) -> int:
        return self._state(host).limiter.concurrency

    def ready_and_reserve(self, host: str) -> bool:
        now = time.monotonic()
        with self._lock:
            state = self._state(host)
            state.last_seen = now
            if now < state.next_allowed:
                return False
            state.next_allowed = now + max(0.0, state.limiter.delay_seconds)
            return True

    def observe(self, host: str, status: int | None, latency_ms: float | None, retry_after: float | None = None) -> None:
        with self._lock:
            state = self._state(host)
            state.last_seen = time.monotonic()
            decision = state.limiter.observe(status, latency_ms, retry_after)
            state.last_decision = decision.mode
            if decision.delay_seconds > 0:
                state.next_allowed = max(state.next_allowed, time.monotonic() + decision.delay_seconds)

    def snapshot(self) -> dict[str, dict[str, object]]:
        with self._lock:
            self._prune_locked(time.monotonic())
            return {
                host: {
                    "concurrency": state.limiter.concurrency,
                    "delay_seconds": round(state.limiter.delay_seconds, 3),
                    "mode": state.last_decision,
                }
                for host, state in self._states.items()
            }


class RunOrchestrator:
    











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
        self.logger = logging.getLogger("arenyxa.runner")

    def submit(
        self, task: Task, on_progress: ProgressCallback | None = None, preview: bool = False
    ) -> RunHandle:
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
            lambda done, item=run, lock=state_lock: self._on_run_done(item, done, lock)
        )
        return handle

    def preview(self, task: Task) -> Run:
        handle = self.submit(task, preview=True)
        return handle.future.result()

    def cancel_all(self) -> None:
        with self._lock:
            handles = list(self._handles.values())
        for handle in handles:
            handle.cancel()

    def active_handles(self) -> list[RunHandle]:
        with self._lock:
            return list(self._handles.values())

    def concurrency_snapshot(self) -> dict[str, object]:
        
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
        self._refresh_resource_governance(force=False)
        snapshot = self._resource_snapshot
        decision = self._resource_decision
        return {
            "sample": None if snapshot is None else snapshot.to_dict(),
            "decision": None if decision is None else decision.to_dict(),
        }

    def performance_explanation(self) -> dict[str, object]:
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
        return self._adaptive_rate.snapshot()

    def request_limit(self) -> int:
        return self._request_gate.limit()

    def set_request_limit(self, limit: int) -> int:
        





        return self._adaptive_requests.set_manual(limit)

    def enable_adaptive_request_limit(self) -> int:
        
        return self._adaptive_requests.enable_auto()

    def shutdown(self, wait_for_runs: bool = True, **legacy: object) -> None:
                                                                                        
                                                                                            
        if "wait" in legacy:
            wait_for_runs = bool(legacy["wait"])
        with self._lock:
            self._closed = True
            handles = list(self._handles.values())
            request_futures = list(self._request_futures)
        self.cancel_all()
                                                                                             
                                                                                             
                                                                                            
        for future in request_futures:
            future.cancel()
        if not wait_for_runs:
            for handle in handles:
                handle.future.cancel()
                                                                                   
        shutdown_executor(self.executor, wait=wait_for_runs, cancel_futures=not wait_for_runs)
        shutdown_executor(self.request_executor, wait=wait_for_runs, cancel_futures=True)

    def _admit_request(
        self,
        *,
        run: Run,
        task: Task,
        token: CancellationToken,
        index: int,
        spec: RequestSpec,
        host: str,
    ) -> tuple[Future[_RequestOutcome], _HostLease] | bool | None:
        






        if not self._request_gate.try_acquire(run.id):
            return None
        lease = self._host_limiter.try_acquire(host, self._adaptive_rate.limit(host))
        if lease is None:
            self._request_gate.release()
            return False
        if not self._adaptive_rate.ready_and_reserve(host):
            lease.release()
            self._request_gate.release()
            return False
        try:
            future = self.request_executor.submit(
                self._process_request, index, task, run.id, spec, token, lease
            )
        except RuntimeError as exc:
            lease.release()
            self._request_gate.release()
            with self._lock:
                shutting_down = self._closed
            if token.cancelled or shutting_down:
                token.cancel()
                raise ArenyxaError("RUN_CANCELLED", "操作已取消。", domain="RUN") from exc
            raise
        except Exception:
            lease.release()
            self._request_gate.release()
            raise

                                                                                          
                                                                                  
        future.add_done_callback(lambda _done: self._request_gate.release())
        with self._lock:
            self._request_futures.add(future)
        future.add_done_callback(self._forget_request_future)
                                                                                                
                                                                                                 
        future.add_done_callback(
            lambda done, held=lease: held.release() if done.cancelled() else None
        )
        run.request_count += 1
        return future, lease

    def _flush_result_batch(self, run: Run, write_batch: list[ResultRecord], *, preview: bool) -> None:
        if preview or not write_batch:
            return
        try:
            written = self.store.append_results(write_batch)
        except Exception as exc:
            raise ArenyxaError(
                "RUN_STORAGE_FAILED",
                "运行结果无法写入本地数据库。",
                domain="RUN",
                context={"run_id": run.id, "pending_records": len(write_batch)},
            ) from exc
        run.result_count += written
        write_batch.clear()

    def _execute(
        self,
        task: Task,
        run: Run,
        token: CancellationToken,
        on_progress: ProgressCallback | None,
        preview: bool,
        *,
        state_lock: threading.RLock | None = None,
    ) -> Run:
        state_lock = state_lock or threading.RLock()
        with state_lock:
                                                                                              
                                                                                             
                                                          
            run.status = RunStatus.PAUSED if token.paused else RunStatus.RUNNING
            run.started_at = utc_now()
            run.stage = "fetch"

                                                                                          
                                                                                         
        pending = deque(enumerate(task.requests))
                                                                                              
                                                                                              
                                                                                              
                                                         
        deferred_by_host: dict[str, deque[tuple[int, RequestSpec]]] = {}
        deferred_hosts: deque[str] = deque()
        in_flight: dict[Future[_RequestOutcome], tuple[int, _HostLease]] = {}
        preview_seen: set[str] = set()
        write_batch: list[ResultRecord] = []
        first_error: str | None = None
        last_persist = time.monotonic()
        last_result_flush = last_persist

        def admit(index: int, spec: RequestSpec, host: str) -> bool | None:
            admitted = self._admit_request(
                run=run, task=task, token=token, index=index, spec=spec, host=host
            )
            if admitted is None or admitted is False:
                return admitted
            future, lease = admitted
            in_flight[future] = (index, lease)
            return True

        def defer(host: str, item: tuple[int, RequestSpec]) -> None:
            bucket = deferred_by_host.get(host)
            if bucket is None:
                bucket = deque()
                deferred_by_host[host] = bucket
                deferred_hosts.append(host)
            bucket.append(item)

        def fill_workers() -> int:
            submitted = 0
            resource_decision = self._refresh_resource_governance(force=False)
            if resource_decision is not None and not resource_decision.admit_new_runs:
                raise ArenyxaError(
                    "RUN_RESOURCE_PRESSURE",
                    "运行过程中本机可用磁盘进入临界区，已停止继续产生新结果。",
                    domain="RESOURCE",
                    context={"run_id": run.id, "reasons": list(resource_decision.reasons)},
                )
            capacity = max(0, self.request_limit() - len(in_flight))
            if capacity <= 0 or (not pending and not deferred_hosts):
                return submitted

                                                                                            
                                                                                                
                                                                                                
            no_progress = 0
            scan_index = 0
            while submitted < capacity and deferred_hosts:
                if scan_index % 64 == 0:
                    token.checkpoint()
                scan_index += 1
                host = deferred_hosts.popleft()
                bucket = deferred_by_host.get(host)
                if not bucket:
                    deferred_by_host.pop(host, None)
                    continue
                index, spec = bucket[0]
                accepted = admit(index, spec, host)
                if accepted is None:
                    deferred_hosts.appendleft(host)
                    return submitted
                if not accepted:
                    deferred_hosts.append(host)
                    no_progress += 1
                    if no_progress >= len(deferred_hosts):
                        break
                    continue
                bucket.popleft()
                submitted += 1
                no_progress = 0
                if bucket:
                    deferred_hosts.append(host)
                else:
                    deferred_by_host.pop(host, None)

                                                                                                
                                                                                                    
            scan_count = len(pending)
            for scan_index in range(scan_count):
                if submitted >= capacity or not pending:
                    break
                if scan_index % 256 == 0:
                    token.checkpoint()
                item = pending.popleft()
                index, spec = item
                host = self._host_key(spec.url)
                if host in deferred_by_host:
                    deferred_by_host[host].append(item)
                    continue
                accepted = admit(index, spec, host)
                if accepted is None:
                    pending.appendleft(item)
                    break
                if not accepted:
                    defer(host, item)
                    continue
                submitted += 1
            return submitted


        def flush_results() -> None:
            nonlocal last_result_flush
            self._flush_result_batch(run, write_batch, preview=preview)
            last_result_flush = time.monotonic()

        def flush_results_if_due(now: float | None = None) -> bool:
            checked_at = time.monotonic() if now is None else now
            if (
                not write_batch
                or checked_at - last_result_flush < self.result_flush_interval_seconds
            ):
                return False
            run.stage = "write"
            flush_results()
            run.stage = "fetch"
            return True

        try:
                                                                                           
                                                                                          
                                                                                     
            self._persist_progress(run, on_progress)
            fill_workers()
            while pending or deferred_hosts or in_flight:
                token.checkpoint()
                                                                                          
                                                                                            
                                                        
                if not in_flight:
                    time.sleep(0.02)
                    flush_results_if_due()
                    fill_workers()
                    continue
                completed, _ = wait(
                    tuple(in_flight), timeout=0.10, return_when=FIRST_COMPLETED
                )
                if not completed:
                    flush_results_if_due()
                    fill_workers()
                    continue
                for future in completed:
                    _index, _lease = in_flight.pop(future)
                    try:
                        outcome = future.result()
                    except ArenyxaError as exc:
                        if exc.code == "RUN_CANCELLED":
                            raise
                        outcome = _RequestOutcome(
                            _index,
                            None,
                            error_code=exc.code,
                            error_message=str(exc),
                        )
                    except Exception as exc:                                             
                        self.logger.exception(
                            "request worker escaped its error boundary",
                            extra={"run_id": run.id, "request_index": _index},
                        )
                        outcome = _RequestOutcome(
                            _index,
                            None,
                            error_code="RUN_REQUEST_UNEXPECTED",
                            error_message=str(exc),
                        )

                    run.retry_count += outcome.retries
                    run.completed_units += 1
                    self._adaptive_requests.observe(
                        outcome.local_processing_ms,
                        saturated=bool(pending or deferred_hosts or in_flight),
                    )
                    sample = self._resource_snapshot
                    self._performance_history.append(
                        PerformanceSample(
                            timestamp=time.monotonic(),
                            completed=0 if outcome.error_code else 1,
                            failed=1 if outcome.error_code else 0,
                            retries=outcome.retries,
                            http_429=1 if outcome.status_code == 429 else 0,
                            latency_ms=outcome.network_latency_ms,
                            local_processing_ms=outcome.local_processing_ms,
                            cpu_percent=None if sample is None else sample.cpu_percent,
                            memory_percent=None if sample is None else sample.memory_percent,
                            disk_free_bytes=None if sample is None else sample.disk_free_bytes,
                            request_limit=self._request_gate.limit(),
                            request_active=self._request_gate.active_count(),
                            request_waiting=self._request_gate.waiting_count(),
                            browser_active=0 if self._browser_pool is None else self._browser_pool.active_count(),
                            browser_limit=0 if self._browser_pool is None else self._browser_pool.limit(),
                        )
                    )
                    if outcome.error_code:
                        run.failure_count += 1
                        first_error = first_error or outcome.error_code
                        self.logger.warning(
                            "request failed but run continues",
                            extra={
                                "error_code": outcome.error_code,
                                "context": {
                                    "run_id": run.id,
                                    "request_index": outcome.index,
                                    "details": outcome.error_message,
                                },
                            },
                        )
                    else:
                        run.success_count += 1
                        record = outcome.record
                        if record is not None:
                            if preview:
                                if record.content_hash not in preview_seen:
                                    preview_seen.add(record.content_hash)
                                    run.result_count += 1
                            else:
                                                                                           
                                                                                             
                                                                                               
                                write_batch.append(record)
                                if len(write_batch) >= self.result_write_batch_size:
                                    run.stage = "write"
                                    flush_results()
                                    run.stage = "fetch"

                    now = time.monotonic()
                    flush_results_if_due(now)
                    if now - last_persist >= self.progress_interval_seconds:
                        self._persist_progress(run, on_progress)
                        last_persist = now

                fill_workers()

            token.checkpoint()
            if write_batch:
                run.stage = "write"
                flush_results()

            with state_lock:
                if run.failure_count == 0:
                    run.status = RunStatus.COMPLETED
                    run.error_code = None
                    run.stage = "completed"
                elif run.success_count > 0:
                    run.status = RunStatus.PARTIAL
                    run.error_code = "RUN_PARTIAL_FAILURE"
                    run.stage = "partial"
                else:
                    run.status = RunStatus.FAILED
                    run.error_code = first_error or "RUN_REQUEST_FAILED"
                    run.stage = "failed"
        except ArenyxaError as exc:
            with state_lock:
                if exc.code == "RUN_CANCELLED":
                    run.status = RunStatus.CANCELLED
                    run.error_code = None
                    run.stage = "cancelled"
                else:
                    run.failure_count += 1
                    run.error_code = exc.code
                    run.status = RunStatus.FAILED
                    run.stage = "failed"
            if exc.code != "RUN_CANCELLED":
                self.logger.exception(
                    "run failed",
                    extra={"error_code": exc.code, "context": exc.context},
                )
        except Exception:
            with state_lock:
                run.failure_count += 1
                run.error_code = "RUN_UNEXPECTED"
                run.status = RunStatus.FAILED
                run.stage = "failed"
            self.logger.exception("unexpected run failure")
        finally:
                                                                                           
                                                                                            
            self._request_gate.withdraw(run.id)
                                                                                                  
                                                                                                
                                                     
            if in_flight:
                token.cancel()
                                                                                              
                                                                                    
            for future in tuple(in_flight):
                future.cancel()
            with state_lock:
                run.finished_at = utc_now()
            try:
                self._persist_progress(run, on_progress)
            except ArenyxaError as exc:
                                                                                             
                                                                                           
                                                                                            
                                                                                        
                with state_lock:
                    run.status = RunStatus.FAILED
                    run.error_code = "RUN_STORAGE_FAILED"
                    run.stage = "failed"
                self.logger.error(
                    "final run persistence failed",
                    extra={"error_code": exc.code, "context": {"run_id": run.id}},
                )
        return run

    def _process_request(
        self,
        index: int,
        task: Task,
        run_id: str,
        spec,
        token: CancellationToken,
        host_lease: _HostLease,
    ) -> _RequestOutcome:
        retries = 0

        def on_attempt(attempt: int) -> None:
            nonlocal retries
            if attempt:
                retries += 1

        try:
            try:
                                                                                             
                                                                                             
                                                                                               
                response = self.fetcher.fetch(spec, token, on_attempt)
                self._adaptive_rate.observe(host_lease.host, response.status, response.elapsed_ms)
            except ArenyxaError as exc:
                status = exc.context.get("status") if isinstance(exc.context, dict) else None
                retry_after = exc.context.get("retry_after") if isinstance(exc.context, dict) else None
                self._adaptive_rate.observe(host_lease.host, int(status) if isinstance(status, int) else None, None, float(retry_after) if isinstance(retry_after, (int, float)) else None)
                raise
            finally:
                host_lease.release()

            token.checkpoint()
            local_started = time.perf_counter()
            source_url = response.final_url
            status_code = int(response.status)
            network_latency_ms = float(response.elapsed_ms)
            document = ParserRegistry.parse(response, task.parser_hint)
                                                                                             
                                                                                             
                                                                             
            del response
            token.checkpoint()
            record_data, quality_flags = self.extractor.extract(document, task.fields)
            del document
            record = ResultRecord(
                task_id=task.id,
                run_id=run_id,
                source_url=source_url,
                data=record_data,
                quality_flags=quality_flags,
            )
                                                                                               
                                                                                              
                                                                                              
            local_processing_ms = (time.perf_counter() - local_started) * 1000.0
            return _RequestOutcome(
                index=index,
                record=record,
                retries=retries,
                local_processing_ms=local_processing_ms,
                status_code=status_code,
                network_latency_ms=network_latency_ms,
            )
        except ArenyxaError as exc:
            if exc.code == "RUN_CANCELLED":
                raise
            raw_status = exc.context.get("status") if isinstance(exc.context, dict) else None
            return _RequestOutcome(
                index=index,
                record=None,
                retries=retries,
                error_code=exc.code,
                error_message=str(exc),
                status_code=int(raw_status) if isinstance(raw_status, int) else None,
            )
        except Exception as exc:
            self.logger.exception(
                "unexpected request failure",
                extra={"run_id": run_id, "request_index": index, "host": host_lease.host},
            )
            return _RequestOutcome(
                index=index,
                record=None,
                retries=retries,
                error_code="RUN_REQUEST_UNEXPECTED",
                error_message=str(exc),
            )

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
