from __future__ import annotations

"""Bounded request execution engine used by Arenyxa run orchestrators.

This module owns request admission, host fairness, result batching, request processing,
and terminal run-state transitions.  Keeping it separate from the public orchestrator
reduces lifecycle/state-machine coupling and gives the current async data plane a stable
compatibility boundary.
"""

import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, wait
from dataclasses import field
from typing import Callable

from arenyxa.application.future_callbacks import ReleaseFutureCallback
from arenyxa.application.reliability import PerformanceSample
from arenyxa.application.runner_support import _HostLease, _RequestOutcome
from arenyxa.compat import dataclass
from arenyxa.domain.enums import RunStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, ResultRecord, Run, Task, utc_now
from arenyxa.infrastructure.http_client import CancellationToken
from arenyxa.infrastructure.parsers import ParserRegistry

ProgressCallback = Callable[[Run], None]

@dataclass(slots=True)
class _RunExecutionState:
    """Mutable state for one orchestrated run execution loop."""

    pending: deque[tuple[int, RequestSpec]]
    deferred_by_host: dict[str, deque[tuple[int, RequestSpec]]] = field(default_factory=dict)
    deferred_hosts: deque[str] = field(default_factory=deque)
    in_flight: dict[Future[_RequestOutcome], tuple[int, _HostLease]] = field(default_factory=dict)
    preview_seen: set[str] = field(default_factory=set)
    write_batch: list[ResultRecord] = field(default_factory=list)
    first_error: str | None = None
    last_persist: float = field(default_factory=time.monotonic)
    last_result_flush: float = 0.0

    def __post_init__(self) -> None:
        if self.last_result_flush <= 0.0:
            self.last_result_flush = self.last_persist


class RunExecutionMixin:
    """Request/data-plane half of RunOrchestrator."""

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
        






        lease = self._host_limiter.try_acquire(host, self._adaptive_rate.limit(host))
        if lease is None:
            return False
        if not self._request_gate.try_acquire(run.id):
            lease.release()
            return None
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
        # broad-exception-boundary: resource accounting must roll back for every submission failure.
        except Exception:
            lease.release()
            self._request_gate.release()
            raise

                                                                                          
                                                                                  
        future.add_done_callback(ReleaseFutureCallback(self._request_gate.release))
        with self._lock:
            self._request_futures.add(future)
        future.add_done_callback(self._forget_request_future)
                                                                                                
                                                                                                 
        future.add_done_callback(ReleaseFutureCallback(lease.release, cancelled_only=True))
        run.request_count += 1
        return future, lease

    def _storage_pressure_snapshot(self) -> dict[str, object]:
        probe = getattr(self.store, "write_pressure_snapshot", None)
        if not callable(probe):
            return {}
        try:
            value = probe()
            return dict(value) if isinstance(value, dict) else {}
        except (OSError, RuntimeError, ValueError, TypeError):
            self.logger.exception("storage pressure telemetry failed")
            return {}

    def _adapt_result_batch_size(self, pressure: dict[str, object]) -> None:
        p95 = float(pressure.get("write_p95_ms", 0.0) or 0.0)
        wal_pages = int(pressure.get("wal_pages_approx", 0) or 0)
        busy_events = int(pressure.get("busy_events", 0) or 0)
        pressured = bool(pressure.get("pressured", False))
        if pressured or p95 >= 250.0 or wal_pages >= 8192 or busy_events > 0:
            self._dynamic_result_write_batch_size = min(
                self._max_result_write_batch_size,
                max(self._dynamic_result_write_batch_size + 1, self._dynamic_result_write_batch_size * 2),
            )
        elif p95 and p95 < 80.0 and wal_pages < 2048 and self._dynamic_result_write_batch_size > self.result_write_batch_size:
            self._dynamic_result_write_batch_size = max(
                self.result_write_batch_size, self._dynamic_result_write_batch_size // 2
            )

    def _flush_result_batch(self, run: Run, write_batch: list[ResultRecord], *, preview: bool) -> None:
        if preview or not write_batch:
            return
        pending = len(write_batch)
        try:
            written = self.store.append_results(write_batch, batch_size=self._dynamic_result_write_batch_size)
        # broad-exception-boundary: storage adapters expose heterogeneous driver exceptions.
        except Exception as exc:
            raise ArenyxaError(
                "RUN_STORAGE_BACKPRESSURE" if "locked" in str(exc).casefold() or "busy" in str(exc).casefold() else "RUN_STORAGE_FAILED",
                "运行结果无法写入本地数据库。",
                domain="RUN",
                context={"run_id": run.id, "pending_records": pending},
            ) from exc
        run.result_count += written
        write_batch.clear()
        self._adapt_result_batch_size(self._storage_pressure_snapshot())

    def _admit_execution_request(
        self,
        state: _RunExecutionState,
        run: Run,
        task: Task,
        token: CancellationToken,
        index: int,
        spec: RequestSpec,
        host: str,
    ) -> bool | None:
        """Admit one request and attach its future to the current execution state."""
        admitted = self._admit_request(
            run=run, task=task, token=token, index=index, spec=spec, host=host
        )
        if admitted is None or admitted is False:
            return admitted
        future, lease = admitted
        state.in_flight[future] = (index, lease)
        return True

    @staticmethod
    def _defer_execution_request(
        state: _RunExecutionState,
        host: str,
        item: tuple[int, RequestSpec],
    ) -> None:
        """Queue one request behind an already saturated host without busy waiting."""
        bucket = state.deferred_by_host.get(host)
        if bucket is None:
            bucket = deque()
            state.deferred_by_host[host] = bucket
            state.deferred_hosts.append(host)
        bucket.append(item)

    def _fill_execution_workers(
        self,
        state: _RunExecutionState,
        run: Run,
        task: Task,
        token: CancellationToken,
    ) -> int:
        """Fill available request slots while preserving host fairness and resource bounds."""
        submitted = 0
        resource_decision = self._refresh_resource_governance(force=False)
        if resource_decision is not None and not resource_decision.admit_new_runs:
            raise ArenyxaError(
                "RUN_RESOURCE_PRESSURE",
                "运行过程中本机可用磁盘进入临界区，已停止继续产生新结果。",
                domain="RESOURCE",
                context={"run_id": run.id, "reasons": list(resource_decision.reasons)},
            )
        capacity = max(0, self.request_limit() - len(state.in_flight))
        if capacity <= 0 or (not state.pending and not state.deferred_hosts):
            return submitted

        no_progress = 0
        scan_index = 0
        while submitted < capacity and state.deferred_hosts:
            if scan_index % 64 == 0:
                token.checkpoint()
            scan_index += 1
            host = state.deferred_hosts.popleft()
            bucket = state.deferred_by_host.get(host)
            if not bucket:
                state.deferred_by_host.pop(host, None)
                continue
            index, spec = bucket[0]
            accepted = self._admit_execution_request(state, run, task, token, index, spec, host)
            if accepted is None:
                state.deferred_hosts.appendleft(host)
                return submitted
            if not accepted:
                state.deferred_hosts.append(host)
                no_progress += 1
                if no_progress >= len(state.deferred_hosts):
                    break
                continue
            bucket.popleft()
            submitted += 1
            no_progress = 0
            if bucket:
                state.deferred_hosts.append(host)
            else:
                state.deferred_by_host.pop(host, None)

        scan_count = len(state.pending)
        for scan_index in range(scan_count):
            if submitted >= capacity or not state.pending:
                break
            if scan_index % 256 == 0:
                token.checkpoint()
            item = state.pending.popleft()
            index, spec = item
            host = self._host_key(spec.url)
            if host in state.deferred_by_host:
                state.deferred_by_host[host].append(item)
                continue
            accepted = self._admit_execution_request(state, run, task, token, index, spec, host)
            if accepted is None:
                state.pending.appendleft(item)
                break
            if not accepted:
                self._defer_execution_request(state, host, item)
                continue
            submitted += 1
        return submitted

    def _flush_execution_results(
        self,
        state: _RunExecutionState,
        run: Run,
        *,
        preview: bool,
    ) -> None:
        """Flush the current result batch and advance the flush timestamp."""
        self._flush_result_batch(run, state.write_batch, preview=preview)
        state.last_result_flush = time.monotonic()

    def _flush_execution_results_if_due(
        self,
        state: _RunExecutionState,
        run: Run,
        *,
        preview: bool,
        now: float | None = None,
    ) -> bool:
        """Flush buffered results when the configured latency budget expires."""
        checked_at = time.monotonic() if now is None else now
        if (
            not state.write_batch
            or checked_at - state.last_result_flush < self.result_flush_interval_seconds
        ):
            return False
        run.stage = "write"
        self._flush_execution_results(state, run, preview=preview)
        run.stage = "fetch"
        return True

    def _future_outcome(
        self,
        future: Future[_RequestOutcome],
        request_index: int,
        run: Run,
    ) -> _RequestOutcome:
        """Normalize worker-future exceptions into a request outcome at the worker boundary."""
        try:
            return future.result()
        except ArenyxaError as exc:
            if exc.code == "RUN_CANCELLED":
                raise
            return _RequestOutcome(
                request_index,
                None,
                error_code=exc.code,
                error_message=str(exc),
            )
        # broad-exception-boundary: Future boundary normalizes arbitrary worker defects.
        except Exception as exc:
            self.logger.exception(
                "request worker escaped its error boundary",
                extra={"run_id": run.id, "request_index": request_index},
            )
            return _RequestOutcome(
                request_index,
                None,
                error_code="RUN_REQUEST_UNEXPECTED",
                error_message=str(exc),
            )

    def _record_execution_outcome(
        self,
        state: _RunExecutionState,
        run: Run,
        outcome: _RequestOutcome,
        *,
        preview: bool,
        auto_flush: bool = True,
    ) -> None:
        """Update counters, performance history, and result buffers for one completed request."""
        run.retry_count += outcome.retries
        run.completed_units += 1
        storage_pressure = self._storage_pressure_snapshot()
        self._adaptive_requests.observe(
            outcome.local_processing_ms,
            saturated=bool(state.pending or state.deferred_hosts or state.in_flight),
            storage_write_p95_ms=float(storage_pressure.get("write_p95_ms", 0.0) or 0.0),
            storage_wal_pages=int(storage_pressure.get("wal_pages_approx", 0) or 0),
            storage_backpressured=bool(storage_pressure.get("pressured", False)),
            failed=bool(outcome.error_code),
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
            state.first_error = state.first_error or outcome.error_code
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
            return
        run.success_count += 1
        record = outcome.record
        if record is None:
            return
        if preview:
            if record.content_hash not in state.preview_seen:
                state.preview_seen.add(record.content_hash)
                run.result_count += 1
            return
        state.write_batch.append(record)
        if auto_flush and len(state.write_batch) >= self._dynamic_result_write_batch_size:
            run.stage = "write"
            self._flush_execution_results(state, run, preview=False)
            run.stage = "fetch"

    @staticmethod
    def _complete_execution_status(
        run: Run,
        state: _RunExecutionState,
        state_lock: threading.RLock,
    ) -> None:
        """Commit the terminal run status from success and failure counters."""
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
                run.error_code = state.first_error or "RUN_REQUEST_FAILED"
                run.stage = "failed"

    def _finalize_execution(
        self,
        state: _RunExecutionState,
        run: Run,
        token: CancellationToken,
        state_lock: threading.RLock,
        on_progress: ProgressCallback | None,
    ) -> None:
        """Cancel residual work, stamp completion time, and persist final progress."""
        self._request_gate.withdraw(run.id)
        if state.in_flight:
            token.cancel()
        for future in tuple(state.in_flight):
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
        """Execute one run using bounded request workers and durable progress checkpoints."""
        state_lock = state_lock or threading.RLock()
        with state_lock:
            run.status = RunStatus.PAUSED if token.paused else RunStatus.RUNNING
            run.started_at = utc_now()
            run.stage = "fetch"

        state = _RunExecutionState(pending=deque(enumerate(task.requests)))
        try:
            self._persist_progress(run, on_progress)
            self._fill_execution_workers(state, run, task, token)
            while state.pending or state.deferred_hosts or state.in_flight:
                token.checkpoint()
                if not state.in_flight:
                    time.sleep(0.02)
                    self._flush_execution_results_if_due(state, run, preview=preview)
                    self._fill_execution_workers(state, run, task, token)
                    continue
                completed, _ = wait(
                    tuple(state.in_flight), timeout=0.10, return_when=FIRST_COMPLETED
                )
                if not completed:
                    self._flush_execution_results_if_due(state, run, preview=preview)
                    self._fill_execution_workers(state, run, task, token)
                    continue
                for future in completed:
                    request_index, _lease = state.in_flight.pop(future)
                    outcome = self._future_outcome(future, request_index, run)
                    self._record_execution_outcome(state, run, outcome, preview=preview)
                    now = time.monotonic()
                    self._flush_execution_results_if_due(
                        state, run, preview=preview, now=now
                    )
                    if now - state.last_persist >= self.progress_interval_seconds:
                        self._persist_progress(run, on_progress)
                        state.last_persist = now
                self._fill_execution_workers(state, run, task, token)

            token.checkpoint()
            if state.write_batch:
                run.stage = "write"
                self._flush_execution_results(state, run, preview=preview)
            self._complete_execution_status(run, state, state_lock)
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
        # broad-exception-boundary: terminal run guard converts escaped defects to durable failure.
        except Exception:
            with state_lock:
                run.failure_count += 1
                run.error_code = "RUN_UNEXPECTED"
                run.status = RunStatus.FAILED
                run.stage = "failed"
            self.logger.exception("unexpected run failure")
        finally:
            self._finalize_execution(state, run, token, state_lock, on_progress)
        return run

    def _process_request(
        self,
        index: int,
        task: Task,
        run_id: str,
        spec: RequestSpec,
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
        # broad-exception-boundary: request isolation keeps one parser/plugin defect from killing the pool.
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
