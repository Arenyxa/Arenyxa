from __future__ import annotations
from arenyxa.recoverable import record_current_exception

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
                record_current_exception(__name__, '_DynamicRequestGate.withdraw:212')

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

    def observe(
        self,
        local_processing_ms: float | None,
        *,
        saturated: bool,
        storage_write_p95_ms: float | None = None,
        storage_wal_pages: int = 0,
        storage_backpressured: bool = False,
        failed: bool = False,
    ) -> int:
        if local_processing_ms is None:
            with self._lock:
                if not self.enabled or self._manual:
                    return self._apply_target_locked()
                if failed:
                    # Missing timing on a failed request is negative feedback, not a
                    # zero-latency success. Back off conservatively and reset the
                    # latency window so repeated timeouts/errors cannot leave the
                    # controller permanently optimistic.
                    self._samples.clear()
                    self._target = max(self.floor, self._target - 1)
                    self._last_decision = "failure-backoff"
                    return self._apply_target_locked()
                return self._apply_target_locked()
        value = max(0.0, float(local_processing_ms))
        storage_p95 = max(0.0, float(storage_write_p95_ms or 0.0))
        wal_pages = max(0, int(storage_wal_pages))
        with self._lock:
            if not self.enabled or self._manual:
                return self._apply_target_locked()
            # Storage pressure is deliberately treated as a different causal signal from
            # parser/CPU pressure.  Do not reduce fetch concurrency merely because durable
            # writes are slow; let the result batching/backpressure layer absorb the pressure.
            if storage_backpressured or storage_p95 >= 250.0 or wal_pages >= 8192:
                self._samples.clear()
                self._last_decision = "storage-backpressure"
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

