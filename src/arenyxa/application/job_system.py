from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait as wait_futures
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from arenyxa.exception_boundary import call_exception_boundary
from arenyxa.application.future_callbacks import WeakMethodFutureCallback
from arenyxa.compat import shutdown_executor
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.security import SecurityKernel, Session, TrustDomain

LOGGER = logging.getLogger(__name__)


class JobCancelled(RuntimeError):
    """Raised cooperatively when a platform job receives a cancellation request."""


class JobTimedOut(RuntimeError):
    """Raised cooperatively when a platform job exhausts its execution budget."""


@dataclass(slots=True)
class JobExecutionContext:
    job_id: str
    _cancelled: threading.Event
    _deadline: float
    _progress: Callable[[float, str], None]

    def check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise JobCancelled(f"platform job cancelled: {self.job_id}")
        if time.monotonic() >= self._deadline:
            raise JobTimedOut(f"platform job timed out: {self.job_id}")

    def report_progress(self, progress: float, message: str = "") -> None:
        self.check_cancelled()
        self._progress(max(0.0, min(1.0, float(progress))), str(message))


JobOperation = Callable[[JobExecutionContext], Any]


class JobSystem:
    """Bounded, persistent, auditable executor shared by desktop, CLI, server, and worker."""

    def __init__(
        self,
        store: Any,
        security: SecurityKernel,
        *,
        max_workers: int = 4,
        queue_capacity: int = 64,
    ) -> None:
        self.store = store
        self.security = security
        self.max_workers = max(1, min(32, int(max_workers)))
        self.queue_capacity = max(1, min(10_000, int(queue_capacity)))
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="arenyxa-platform-job",
        )
        self._slots = threading.BoundedSemaphore(self.max_workers + self.queue_capacity)
        self._lock = threading.Lock()
        self._futures: dict[str, Future[None]] = {}
        self._cancellation: dict[str, threading.Event] = {}
        self._accepting = True
        self._executor_shutdown_requested = False
        self._admission_provider: Callable[[], Mapping[str, bool]] | None = None
        self._telemetry: Any = None
        self.recovered_jobs = int(self.store.recover_platform_jobs())

    def set_admission_provider(self, provider: Callable[[], Mapping[str, bool]] | None) -> None:
        """Attach a process-local survivability admission policy without coupling JobSystem to it."""
        if provider is not None and not callable(provider):
            raise TypeError("job admission provider must be callable")
        with self._lock:
            self._admission_provider = provider

    def set_performance_telemetry(self, telemetry: Any) -> None:
        """Attach bounded telemetry used for queue/run latency and backpressure counters."""
        with self._lock:
            self._telemetry = telemetry

    def _metric_increment(self, name: str, amount: int = 1) -> None:
        telemetry = self._telemetry
        if telemetry is not None:
            telemetry.increment(name, amount)

    def _metric_latency(self, name: str, milliseconds: float) -> None:
        telemetry = self._telemetry
        if telemetry is not None:
            telemetry.record_latency(name, milliseconds)

    def _metric_gauge(self, name: str, value: float) -> None:
        telemetry = self._telemetry
        if telemetry is not None:
            telemetry.gauge(name, value)

    def _check_survivability_admission(self, workload: str) -> None:
        with self._lock:
            provider = self._admission_provider
        if provider is None:
            return
        try:
            admission = dict(provider())
        except (LookupError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise ArenyxaError(
                "JOB_ADMISSION_UNKNOWN",
                "survivability admission state is unavailable",
                domain="JOB",
                context={"workload": workload},
            ) from exc
        if workload == "heavy" and not bool(admission.get("new_heavy_jobs", True)):
            self._metric_increment("job.admission_rejected")
            raise ArenyxaError(
                "JOB_ADMISSION_DEGRADED",
                "runtime survivability policy is not admitting new heavy jobs",
                domain="JOB",
                context={"workload": workload, "admission": admission},
            )
        if workload == "write" and not bool(admission.get("noncritical_writes", True)):
            self._metric_increment("job.admission_rejected")
            raise ArenyxaError(
                "JOB_READ_ONLY",
                "runtime is in read-only survivability mode",
                domain="JOB",
                context={"workload": workload, "admission": admission},
            )

    @staticmethod
    def _normalize_submission(kind: str, surface: str, timeout_seconds: float, workload: str) -> tuple[str, str, float, str]:
        normalized_kind = str(kind).strip().casefold()
        normalized_surface = str(surface).strip().casefold()
        if not normalized_kind or len(normalized_kind) > 128:
            raise ValueError("job kind must contain 1-128 characters")
        if not normalized_surface or len(normalized_surface) > 64:
            raise ValueError("job surface must contain 1-64 characters")
        timeout = float(timeout_seconds)
        if timeout <= 0.0 or timeout > 24 * 60 * 60:
            raise ValueError("job timeout must be within 1 second and 24 hours")
        normalized_workload = str(workload or "standard").strip().casefold()
        if normalized_workload not in {"standard", "heavy", "write", "diagnostics"}:
            raise ValueError("job workload must be standard, heavy, write, or diagnostics")
        return normalized_kind, normalized_surface, timeout, normalized_workload

    def submit(
        self,
        kind: str,
        operation: JobOperation,
        *,
        session: Session | None,
        capability: str,
        resource: str,
        surface: str,
        timeout_seconds: float = 300.0,
        workload: str = "standard",
    ) -> dict[str, Any]:
        normalized_kind, normalized_surface, timeout, normalized_workload = self._normalize_submission(
            kind, surface, timeout_seconds, workload
        )
        if not callable(operation):
            raise TypeError("job operation must be callable")
        correlation_id = new_id("corr")
        self.security.require(
            session,
            str(capability),
            str(resource),
            context={"surface": "application-control-plane", "entry_surface": normalized_surface},
            correlation_id=correlation_id,
        )
        self._check_survivability_admission(normalized_workload)
        with self._lock:
            if not self._accepting:
                raise ArenyxaError(
                    "JOB_SYSTEM_STOPPING",
                    "the platform Job System is not accepting new work",
                    domain="JOB",
                )
        if not self._slots.acquire(blocking=False):
            self._metric_increment("job.backpressure")
            raise ArenyxaError(
                "JOB_BACKPRESSURE",
                "the bounded platform job queue is full",
                domain="JOB",
                context={"max_workers": self.max_workers, "queue_capacity": self.queue_capacity},
            )

        job_id = new_id("job")
        submitted_monotonic = time.monotonic()
        cancelled = threading.Event()
        self._metric_increment("job.submitted")
        created_at = utc_now()
        actor = "anonymous" if session is None else session.principal_id
        call_exception_boundary(
            lambda: self.store.create_platform_job(
                {
                    "id": job_id,
                    "kind": normalized_kind,
                    "surface": normalized_surface,
                    "state": "queued",
                    "progress": 0.0,
                    "message": "Queued",
                    "actor": actor,
                    "correlation_id": correlation_id,
                    "timeout_seconds": timeout,
                    "created_at": created_at,
                }
            ),
            # The semaphore permit remains owned by submit() until Future publication.
            on_error=lambda exc: self._slots.release(),
            reraise=True,
        )
        try:
            # Admission and registry publication share the shutdown lock.  Without
            # this boundary, shutdown could snapshot futures between submit() and
            # _futures registration, leaving an owned job outside cancellation.
            with self._lock:
                if not self._accepting:
                    raise ArenyxaError(
                        "JOB_SYSTEM_STOPPING",
                        "the platform Job System is not accepting new work",
                        domain="JOB",
                    )
                future = self._executor.submit(
                    self._run,
                    job_id,
                    normalized_kind,
                    operation,
                    cancelled,
                    timeout,
                    session,
                    correlation_id,
                    str(resource),
                    submitted_monotonic,
                )
                self._futures[job_id] = future
                self._cancellation[job_id] = cancelled
        except (RuntimeError, ArenyxaError) as exc:
            self._slots.release()
            self.store.update_platform_job(
                job_id,
                state="cancelled" if isinstance(exc, ArenyxaError) else "failed",
                progress=1.0,
                message=(
                    "Job System shutdown began before the job could start"
                    if isinstance(exc, ArenyxaError)
                    else "Executor rejected the job"
                ),
                error_code=("JOB_SYSTEM_STOPPING" if isinstance(exc, ArenyxaError) else "JOB_SUBMIT_FAILED"),
                error_message=str(exc),
                finished_at=utc_now(),
                expected_states=("queued",),
            )
            raise
        future.add_done_callback(WeakMethodFutureCallback(self, "_retire", prefix=(job_id,)))
        row = self.store.get_platform_job(job_id)
        if row is None:
            raise RuntimeError(f"persisted platform job disappeared after submission: {job_id}")
        return row

    def _run(
        self,
        job_id: str,
        kind: str,
        operation: JobOperation,
        cancelled: threading.Event,
        timeout_seconds: float,
        session: Session | None,
        correlation_id: str,
        resource: str,
        submitted_monotonic: float,
    ) -> None:
        run_started_monotonic = time.monotonic()
        self._metric_latency("job.queue_wait", (run_started_monotonic - submitted_monotonic) * 1000.0)
        self._metric_increment("job.started")
        started_at = utc_now()
        self.store.update_platform_job(
            job_id,
            state="running",
            progress=0.0,
            message="Running",
            started_at=started_at,
            expected_states=("queued",),
        )
        deadline = time.monotonic() + timeout_seconds

        def progress(value: float, message: str) -> None:
            self.store.update_platform_job(
                job_id,
                progress=value,
                message=message,
                expected_states=("running",),
            )

        execution = JobExecutionContext(job_id, cancelled, deadline, progress)
        try:
            execution.check_cancelled()
            result = operation(execution)
            execution.check_cancelled()
            self._terminal_audit(
                session,
                action=f"job.{kind}.complete",
                resource=resource,
                decision="success",
                correlation_id=correlation_id,
                reason="JOB_SUCCEEDED",
            )
            self.store.update_platform_job(
                job_id,
                state="succeeded",
                progress=1.0,
                message="Completed",
                result=result,
                result_present=True,
                error_code="",
                error_message="",
                finished_at=utc_now(),
                expected_states=("running",),
            )
        except JobCancelled as exc:
            self._finish_failure(
                job_id, "cancelled", "JOB_CANCELLED", str(exc), session, correlation_id, resource, kind
            )
        except JobTimedOut as exc:
            self._finish_failure(
                job_id, "timed_out", "JOB_TIMEOUT", str(exc), session, correlation_id, resource, kind
            )
        except Exception as exc:  # broad-exception-boundary: isolate one Job from the process
            LOGGER.exception("Platform job %s (%s) failed", job_id, kind)
            self._finish_failure(
                job_id,
                "failed",
                type(exc).__name__.upper()[:128],
                str(exc),
                session,
                correlation_id,
                resource,
                kind,
            )
        finally:
            self._metric_latency(f"job.run.{kind}", (time.monotonic() - run_started_monotonic) * 1000.0)

    def _finish_failure(
        self,
        job_id: str,
        state: str,
        code: str,
        message: str,
        session: Session | None,
        correlation_id: str,
        resource: str,
        kind: str,
    ) -> None:
        try:
            self._terminal_audit(
                session,
                action=f"job.{kind}.{state}",
                resource=resource,
                decision="failure",
                correlation_id=correlation_id,
                reason=code,
            )
        finally:
            self.store.update_platform_job(
                job_id,
                state=state,
                progress=1.0,
                message=message,
                error_code=code,
                error_message=message,
                finished_at=utc_now(),
                expected_states=("queued", "running"),
            )

    def _terminal_audit(
        self,
        session: Session | None,
        *,
        action: str,
        resource: str,
        decision: str,
        correlation_id: str,
        reason: str,
    ) -> None:
        self.security.audit.emit(
            actor="anonymous" if session is None else session.principal_id,
            action=action,
            resource=resource,
            decision=decision,
            trust_domain=(
                TrustDomain.PERSONAL if session is None else session.trust_domain
            ),
            device="" if session is None else session.device_id,
            correlation_id=correlation_id,
            reason=reason,
        )

    def _retire(self, job_id: str, future: Future[None]) -> None:
        try:
            if future.cancelled():
                self.store.update_platform_job(
                    job_id,
                    state="cancelled",
                    progress=1.0,
                    message="Cancelled before execution",
                    error_code="JOB_CANCELLED",
                    error_message="The job was cancelled before execution.",
                    finished_at=utc_now(),
                    expected_states=("queued",),
                )
        finally:
            with self._lock:
                self._futures.pop(job_id, None)
                self._cancellation.pop(job_id, None)
                active = len(self._futures)
            self._slots.release()
            self._metric_increment("job.retired")
            self._metric_gauge("job.active", float(active))

    def cancel(self, job_id: str, *, session: Session | None, surface: str) -> dict[str, Any]:
        resource = f"job:{job_id!s}"
        self.security.require(
            session,
            "system.configure",
            resource,
            context={"surface": "application-control-plane", "entry_surface": str(surface)},
        )
        row = self.store.get_platform_job(job_id)
        if row is None:
            raise ArenyxaError("JOB_NOT_FOUND", "platform job was not found", domain="JOB")
        if row["state"] not in {"queued", "running"}:
            return row
        with self._lock:
            event = self._cancellation.get(str(job_id))
            future = self._futures.get(str(job_id))
        if event is None or future is None:
            raise ArenyxaError(
                "JOB_NOT_OWNED",
                "the job is not active in this process and cannot be cancelled here",
                domain="JOB",
            )
        # Publish the acknowledgement before waking a running worker.  Otherwise a
        # fast cooperative cancellation can commit its terminal row first and make
        # this synchronous API appear to have skipped the request acknowledgement.
        self.store.update_platform_job(
            job_id,
            message="Cancellation requested",
            expected_states=("queued", "running"),
        )
        acknowledged = self.store.get_platform_job(job_id) or row
        event.set()
        future.cancel()
        return acknowledged

    def wait(self, job_id: str, timeout_seconds: float | None = None) -> dict[str, Any]:
        with self._lock:
            future = self._futures.get(str(job_id))
        if future is not None:
            try:
                future.result(timeout=None if timeout_seconds is None else max(0.0, float(timeout_seconds)))
            except FutureTimeout as exc:
                raise TimeoutError(f"timed out waiting for platform job {job_id}") from exc
        row = self.store.get_platform_job(job_id)
        if row is None:
            raise ArenyxaError("JOB_NOT_FOUND", "platform job was not found", domain="JOB")
        return row

    def health(self) -> dict[str, Any]:
        with self._lock:
            active = len(self._futures)
            accepting = self._accepting
        queued = len(self.store.list_platform_jobs(limit=1000, state="queued"))
        running = len(self.store.list_platform_jobs(limit=1000, state="running"))
        capacity = self.max_workers + self.queue_capacity
        with self._lock:
            provider = self._admission_provider
        try:
            admission = {} if provider is None else dict(provider())
        except (LookupError, OSError, RuntimeError, TypeError, ValueError):
            admission = {"available": False}
        return {
            "healthy": accepting,
            "accepting": accepting,
            "max_workers": self.max_workers,
            "queue_capacity": self.queue_capacity,
            "active_futures": active,
            "persisted_queued": queued,
            "persisted_running": running,
            "capacity": capacity,
            "recovered_interrupted": self.recovered_jobs,
            "survivability_admission": admission,
        }

    def begin_shutdown(self) -> None:
        """Stop admission and signal every active job's cooperative cancellation event."""
        with self._lock:
            self._accepting = False
            events = tuple(self._cancellation.values())
            futures = tuple(self._futures.values())
        for event in events:
            event.set()
        for future in futures:
            # Authoritative only for queued jobs. Running operations must observe
            # JobExecutionContext.check_cancelled()/report_progress().
            future.cancel()

    def shutdown_snapshot(self) -> dict[str, object]:
        with self._lock:
            futures = tuple(self._futures.values())
            accepting = self._accepting
        return {
            "accepting": accepting,
            "active_futures": sum(1 for future in futures if not future.done()),
            "running_futures": sum(1 for future in futures if future.running()),
            "queued_futures": sum(
                1 for future in futures if not future.running() and not future.done()
            ),
        }

    def drain(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            with self._lock:
                pending = {future for future in self._futures.values() if not future.done()}
            if not pending:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                LOGGER.error("JobSystem drain deadline exceeded: %s", self.shutdown_snapshot())
                return False
            wait_futures(pending, timeout=min(0.05, remaining))

    def shutdown(self, *, wait: bool = True, timeout: float | None = 10.0) -> bool:
        self.begin_shutdown()
        if not wait:
            shutdown_executor(self._executor, wait=False, cancel_futures=True)
            self._executor_shutdown_requested = True
            return int(self.shutdown_snapshot()["active_futures"]) == 0

        completed = self.drain(10.0 if timeout is None else max(0.0, float(timeout)))
        if not completed:
            # Do not claim success: wait=False only retires executor workers *after*
            # running functions return on their own.
            shutdown_executor(self._executor, wait=False, cancel_futures=True)
            self._executor_shutdown_requested = True
            return False
        shutdown_executor(self._executor, wait=True, cancel_futures=True)
        self._executor_shutdown_requested = True
        return True
