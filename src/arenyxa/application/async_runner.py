from __future__ import annotations
from arenyxa.recoverable import record_current_exception

"""Modern asyncio request engine for Arenyxa v8.1.1.

Run lifecycle/persistence remains compatible with :class:`RunOrchestrator`, while high-I/O
HTTP work is multiplexed on an event loop instead of allocating one request worker thread
per in-flight socket.  The outer run pool is intentionally retained as a small isolation
boundary for the desktop UI and synchronous storage/state-machine APIs.
"""

import asyncio
import ctypes
import os
import threading
import time
from collections import deque
from typing import Any

from arenyxa.application.runner import ProgressCallback, RunOrchestrator, _RunExecutionState
from arenyxa.application.runner_support import _HostLease, _RequestOutcome
from arenyxa.domain.enums import RunStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, ResultRecord, Run, Task, utc_now
from arenyxa.infrastructure.async_http_client import AsyncHttpFetcher, async_checkpoint
from arenyxa.infrastructure.http_client import CancellationToken
from arenyxa.infrastructure.parsers import ParserRegistry


_ASYNC_TIMER_LOCK = threading.Lock()
_ASYNC_TIMER_RESOLUTION_READY = False


def _ensure_async_timer_resolution() -> None:
    """Request 1 ms Windows timer resolution once for responsive asyncio scheduling."""
    global _ASYNC_TIMER_RESOLUTION_READY
    if _ASYNC_TIMER_RESOLUTION_READY or os.name != "nt":
        return
    with _ASYNC_TIMER_LOCK:
        if _ASYNC_TIMER_RESOLUTION_READY:
            return
        try:
            ctypes.windll.winmm.timeBeginPeriod(1)
        except (AttributeError, OSError):
            record_current_exception(__name__, '_ensure_async_timer_resolution:43')
        _ASYNC_TIMER_RESOLUTION_READY = True


class AsyncRunOrchestrator(RunOrchestrator):
    """RunOrchestrator variant whose request data plane is asyncio/HTTPX based."""

    request_backend = "asyncio-httpx"

    def concurrency_snapshot(self) -> dict[str, object]:
        snapshot = super().concurrency_snapshot()
        snapshot["request_backend"] = self.request_backend
        snapshot["request_worker_model"] = "event-loop"
        return snapshot

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
        """Bridge the synchronous run Future API to one isolated asyncio event loop."""
        try:
            return asyncio.run(
                self._execute_async(
                    task,
                    run,
                    token,
                    on_progress,
                    preview,
                    state_lock=state_lock,
                )
            )
        except RuntimeError as exc:
            # A missing/unsupported async transport must not make the product unusable.
            # The compatibility thread engine remains an explicit safe fallback.
            if "httpx" not in str(exc).casefold():
                raise
            self.logger.warning("async request backend unavailable; using thread fallback")
            return super()._execute(
                task,
                run,
                token,
                on_progress,
                preview,
                state_lock=state_lock,
            )

    async def _admit_async_request(
        self,
        state: _RunExecutionState,
        run: Run,
        task: Task,
        token: CancellationToken,
        fetcher: AsyncHttpFetcher,
        index: int,
        spec: RequestSpec,
        host: str,
    ) -> bool | None:
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

        async def request_boundary() -> _RequestOutcome:
            try:
                return await self._process_request_async(
                    index, task, run.id, spec, token, lease, fetcher
                )
            finally:
                # These two leases are the cross-run/global accounting boundary.  Release
                # exactly once regardless of cancellation, parser failure, or transport error.
                lease.release()
                self._request_gate.release()

        future = asyncio.create_task(
            request_boundary(), name=f"arenyxa-fetch-{run.id[:8]}-{index}"
        )
        state.in_flight[future] = (index, lease)  # type: ignore[index]
        run.request_count += 1
        return True

    async def _fill_async_execution_workers(
        self,
        state: _RunExecutionState,
        run: Run,
        task: Task,
        token: CancellationToken,
        fetcher: AsyncHttpFetcher,
    ) -> int:
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
                await async_checkpoint(token)
            scan_index += 1
            host = state.deferred_hosts.popleft()
            bucket = state.deferred_by_host.get(host)
            if not bucket:
                state.deferred_by_host.pop(host, None)
                continue
            index, spec = bucket[0]
            accepted = await self._admit_async_request(
                state, run, task, token, fetcher, index, spec, host
            )
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
                await async_checkpoint(token)
            item = state.pending.popleft()
            index, spec = item
            host = self._host_key(spec.url)
            if host in state.deferred_by_host:
                state.deferred_by_host[host].append(item)
                continue
            accepted = await self._admit_async_request(
                state, run, task, token, fetcher, index, spec, host
            )
            if accepted is None:
                state.pending.appendleft(item)
                break
            if not accepted:
                self._defer_execution_request(state, host, item)
                continue
            submitted += 1
        return submitted

    async def _future_outcome_async(
        self,
        future: asyncio.Task[_RequestOutcome],
        request_index: int,
        run: Run,
    ) -> _RequestOutcome:
        try:
            return future.result()
        except asyncio.CancelledError as exc:
            raise ArenyxaError("RUN_CANCELLED", "操作已取消。", domain="RUN") from exc
        except ArenyxaError as exc:
            if exc.code == "RUN_CANCELLED":
                raise
            return _RequestOutcome(
                request_index,
                None,
                error_code=exc.code,
                error_message=str(exc),
            )
        # broad-exception-boundary: normalize arbitrary asyncio task failures at Future boundary.
        except Exception as exc:
            self.logger.exception(
                "async request escaped its error boundary",
                extra={"run_id": run.id, "request_index": request_index},
            )
            return _RequestOutcome(
                request_index,
                None,
                error_code="RUN_REQUEST_UNEXPECTED",
                error_message=str(exc),
            )

    async def _process_request_async(
        self,
        index: int,
        task: Task,
        run_id: str,
        spec: RequestSpec,
        token: CancellationToken,
        host_lease: _HostLease,
        fetcher: AsyncHttpFetcher,
    ) -> _RequestOutcome:
        retries = 0

        def on_attempt(attempt: int) -> None:
            nonlocal retries
            if attempt:
                retries += 1

        try:
            try:
                response = await fetcher.fetch_async(spec, token, on_attempt)
                self._adaptive_rate.observe(
                    host_lease.host, response.status, response.elapsed_ms
                )
            except ArenyxaError as exc:
                status = exc.context.get("status") if isinstance(exc.context, dict) else None
                retry_after = (
                    exc.context.get("retry_after") if isinstance(exc.context, dict) else None
                )
                self._adaptive_rate.observe(
                    host_lease.host,
                    int(status) if isinstance(status, int) else None,
                    None,
                    float(retry_after) if isinstance(retry_after, (int, float)) else None,
                )
                raise

            await async_checkpoint(token)
            local_started = time.perf_counter()
            source_url = response.final_url
            status_code = int(response.status)
            network_latency_ms = float(response.elapsed_ms)
            # Parsing/extraction is deterministic local work.  It deliberately stays on the
            # run loop so the request plane does not recreate a large per-request thread pool.
            document = ParserRegistry.parse(response, task.parser_hint)
            del response
            await async_checkpoint(token)
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
        # broad-exception-boundary: isolate parser/extractor/plugin defects to one request.
        except Exception as exc:
            self.logger.exception(
                "unexpected async request failure",
                extra={"run_id": run_id, "request_index": index, "host": host_lease.host},
            )
            return _RequestOutcome(
                index=index,
                record=None,
                retries=retries,
                error_code="RUN_REQUEST_UNEXPECTED",
                error_message=str(exc),
            )

    async def _persist_progress_async(
        self, run: Run, on_progress: ProgressCallback | None
    ) -> None:
        """Move synchronous storage/callback work off the event-loop thread."""
        _ensure_async_timer_resolution()
        storage_task = asyncio.create_task(
            asyncio.to_thread(self._persist_progress, run, on_progress)
        )
        try:
            while not storage_task.done():
                # Keep the Windows selector's wait budget short while a storage
                # boundary is active so UI/heartbeat coroutines remain schedulable.
                await asyncio.wait((storage_task,), timeout=0.001)
            await storage_task
        finally:
            if not storage_task.done():
                storage_task.cancel()

    async def _flush_execution_results_async(
        self, state: _RunExecutionState, run: Run, *, preview: bool
    ) -> None:
        await asyncio.to_thread(self._flush_execution_results, state, run, preview=preview)

    async def _flush_execution_results_if_due_async(
        self,
        state: _RunExecutionState,
        run: Run,
        *,
        preview: bool,
        now: float | None = None,
    ) -> bool:
        checked_at = time.monotonic() if now is None else now
        if (
            not state.write_batch
            or checked_at - state.last_result_flush < self.result_flush_interval_seconds
        ):
            return False
        run.stage = "write"
        await self._flush_execution_results_async(state, run, preview=preview)
        run.stage = "fetch"
        return True

    async def _finalize_execution_async(
        self,
        state: _RunExecutionState,
        run: Run,
        token: CancellationToken,
        state_lock: threading.RLock,
        on_progress: ProgressCallback | None,
    ) -> None:
        """Finalize without blocking the event loop on SQLite or UI callbacks."""
        self._request_gate.withdraw(run.id)
        if state.in_flight:
            token.cancel()
        for future in tuple(state.in_flight):
            future.cancel()
        with state_lock:
            run.finished_at = utc_now()
        try:
            await self._persist_progress_async(run, on_progress)
        except ArenyxaError as exc:
            with state_lock:
                run.status = RunStatus.FAILED
                run.error_code = "RUN_STORAGE_FAILED"
                run.stage = "failed"
            self.logger.error(
                "final async run persistence failed",
                extra={"error_code": exc.code, "context": {"run_id": run.id}},
            )

    async def _execute_async(
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

        state = _RunExecutionState(pending=deque(enumerate(task.requests)))
        fetcher = AsyncHttpFetcher(
            self.fetcher.max_response_bytes,
            network_guard=self.fetcher.network_guard,
        )
        try:
            await self._persist_progress_async(run, on_progress)
            await self._fill_async_execution_workers(state, run, task, token, fetcher)
            while state.pending or state.deferred_hosts or state.in_flight:
                await async_checkpoint(token)
                if not state.in_flight:
                    await asyncio.sleep(0.02)
                    await self._flush_execution_results_if_due_async(state, run, preview=preview)
                    await self._fill_async_execution_workers(state, run, task, token, fetcher)
                    continue

                completed, _ = await asyncio.wait(
                    tuple(state.in_flight),  # type: ignore[arg-type]
                    timeout=0.10,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not completed:
                    await self._flush_execution_results_if_due_async(state, run, preview=preview)
                    await self._fill_async_execution_workers(state, run, task, token, fetcher)
                    continue

                for future in completed:
                    request_index, _lease = state.in_flight.pop(future)  # type: ignore[arg-type]
                    outcome = await self._future_outcome_async(future, request_index, run)
                    self._record_execution_outcome(
                        state, run, outcome, preview=preview, auto_flush=False
                    )
                    if not preview and len(state.write_batch) >= self.result_write_batch_size:
                        run.stage = "write"
                        await self._flush_execution_results_async(state, run, preview=False)
                        run.stage = "fetch"
                    now = time.monotonic()
                    await self._flush_execution_results_if_due_async(
                        state, run, preview=preview, now=now
                    )
                    if now - state.last_persist >= self.progress_interval_seconds:
                        await self._persist_progress_async(run, on_progress)
                        state.last_persist = now
                await self._fill_async_execution_workers(state, run, task, token, fetcher)

            await async_checkpoint(token)
            if state.write_batch:
                run.stage = "write"
                await self._flush_execution_results_async(state, run, preview=preview)
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
                    "async run failed",
                    extra={"error_code": exc.code, "context": exc.context},
                )
        # broad-exception-boundary: terminal run guard converts escaped defects to durable failure.
        except Exception:
            with state_lock:
                run.failure_count += 1
                run.error_code = "RUN_UNEXPECTED"
                run.status = RunStatus.FAILED
                run.stage = "failed"
            self.logger.exception("unexpected async run failure")
        finally:
            pending_tasks = [future for future in tuple(state.in_flight) if not future.done()]
            for future in pending_tasks:
                future.cancel()
            if pending_tasks:
                await asyncio.gather(*pending_tasks, return_exceptions=True)
            state.in_flight.clear()
            await fetcher.aclose()
            await self._finalize_execution_async(state, run, token, state_lock, on_progress)
        return run


__all__ = ["AsyncRunOrchestrator"]
