from __future__ import annotations

import logging
import sys
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Callable, Mapping

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
        self._drained = threading.Condition(self._lock)
        self._pending_submissions = 0
        self._shutdown_started = False
        self._shutdown_cancelling = False
        self._shutdown_failed = False
        self._futures: dict[str, Future[None]] = {}
        self._cancellation: dict[str, threading.Event] = {}
        self._state_locks: dict[str, Any] = {}
        self._retiring: set[str] = set()
        self._failed_retirements: set[str] = set()
        self._terminal_updates: dict[str, dict[str, Any]] = {}
        self._terminal_persisted: set[str] = set()
        self._accepting = True
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
        # Authorization/admission providers may themselves use durable state.
        # Count the entire submission lifetime before calling either of them.
        with self._drained:
            if not self._accepting:
                raise ArenyxaError("JOB_SYSTEM_STOPPING", "the platform Job System is not accepting new work", domain="JOB")
            self._pending_submissions += 1
        try:
            return self._submit(
                kind, operation, session=session, capability=capability, resource=resource,
                surface=surface, timeout_seconds=timeout_seconds, workload=workload,
            )
        finally:
            with self._drained:
                self._pending_submissions -= 1
                self._drained.notify_all()

    def _submit(
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
            acquired = self._slots.acquire(blocking=False)
        if not acquired:
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
        state_lock = threading.RLock()
        persisted = False
        owned = False
        try:
            self._metric_increment("job.submitted")
            created_at = utc_now()
            actor = "anonymous" if session is None else session.principal_id
            self.store.create_platform_job({
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
            })
            persisted = True
            # Persistence must not hold the ownership lock. Recheck admission
            # at the executor handoff, then publish both registries atomically.
            with self._lock:
                if not self._accepting:
                    raise ArenyxaError(
                        "JOB_SYSTEM_STOPPING", "the platform Job System is not accepting new work", domain="JOB"
                    )
                future = self._executor.submit(
                    self._run, job_id, normalized_kind, operation, cancelled, timeout,
                    session, correlation_id, str(resource), submitted_monotonic, state_lock,
                )
                self._futures[job_id] = future
                self._cancellation[job_id] = cancelled
                self._state_locks[job_id] = state_lock
                owned = True
            # An already-completed Future invokes its callback synchronously.
            # Register outside the ownership lock to avoid callback deadlock.
            future.add_done_callback(WeakMethodFutureCallback(self, "_retire", prefix=(job_id,)))
            row = self.store.get_platform_job(job_id)
            if row is None:
                raise RuntimeError(f"persisted platform job disappeared after submission: {job_id}")
            return row
        finally:
            # Cleanup runs for interrupts as well, without catching or replacing
            # KeyboardInterrupt/SystemExit at this library boundary.
            exc = sys.exc_info()[1]
            try:
                if persisted and not owned and exc is not None:
                    self._persist_rejected_submission(job_id, exc)
            finally:
                if not owned:
                    self._slots.release()

    def _persist_rejected_submission(self, job_id: str, exc: BaseException) -> None:
        stopping = isinstance(exc, ArenyxaError) and exc.code == "JOB_SYSTEM_STOPPING"
        try:
            self.store.update_platform_job(
                job_id, state="cancelled" if stopping else "failed", progress=1.0,
                message="Rejected before execution", error_code="JOB_SYSTEM_STOPPING" if stopping else "JOB_SUBMIT_FAILED",
                error_message=str(exc), finished_at=utc_now(), expected_states=("queued",),
            )
        except Exception:
            LOGGER.exception("Failed to persist rejected platform job %s", job_id)

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
        state_lock: Any,
    ) -> None:
        run_started_monotonic = time.monotonic()
        self._metric_latency("job.queue_wait", (run_started_monotonic - submitted_monotonic) * 1000.0)
        self._metric_increment("job.started")
        started_at = utc_now()
        with state_lock:
            self.store.update_platform_job(
                job_id,
                state="running",
                progress=0.0,
                message="Cancellation requested" if cancelled.is_set() else "Running",
                started_at=started_at,
                expected_states=("queued",),
            )
        deadline = time.monotonic() + timeout_seconds

        def progress(value: float, message: str) -> None:
            with state_lock:
                if not cancelled.is_set():
                    self.store.update_platform_job(
                        job_id, progress=value, message=message, expected_states=("running",),
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
        else:
            # Storage failure must not rewrite a successful operation as failed.
            # Retain its exact result and timestamp for retirement to retry.
            self._write_terminal(
                job_id, state="succeeded", progress=1.0, message="Completed",
                result=result, result_present=True, error_code="", error_message="",
                finished_at=utc_now(), expected_states=("running", "succeeded"),
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
            self._write_terminal(
                job_id,
                state=state,
                progress=1.0,
                message=message,
                error_code=code,
                error_message=message,
                finished_at=utc_now(),
                expected_states=("queued", "running", state),
            )

    def _write_terminal(self, job_id: str, **values: Any) -> None:
        """Keep the terminal intent until its write and retirement both succeed."""
        with self._lock:
            self._terminal_updates[job_id] = values
        self._persist_terminal(job_id)

    def _persist_terminal(self, job_id: str) -> None:
        with self._lock:
            values = self._terminal_updates[job_id]
        if not self.store.update_platform_job(job_id, **values):
            raise RuntimeError(f"terminal platform job update rejected: {job_id}")
        with self._lock:
            self._terminal_persisted.add(job_id)

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
        with self._drained:
            if job_id not in self._futures or job_id in self._retiring:
                return
            self._retiring.add(job_id)
            self._failed_retirements.discard(job_id)
        retired = False
        try:
            with self._lock:
                has_intent = job_id in self._terminal_updates
                persisted = job_id in self._terminal_persisted
            if not has_intent:
                cancelled = future.cancelled()
                error = None if cancelled else future.exception()
                state = "cancelled" if cancelled else "failed"
                message = "Cancelled before execution" if cancelled else str(error or "Missing terminal job outcome")
                self._write_terminal(
                    job_id, state=state, progress=1.0, message=message,
                    error_code="JOB_CANCELLED" if cancelled else type(error).__name__.upper(),
                    error_message=message, finished_at=utc_now(),
                    expected_states=("queued", "running", state),
                )
            elif not persisted:
                self._persist_terminal(job_id)
            self._metric_increment("job.retired")
            with self._lock:
                active = len(self._futures) - 1
            self._metric_gauge("job.active", float(active))
            self._slots.release()
            retired = True
        finally:
            # Future.cancel() observes/logs callback errors itself. Retain the
            # owner explicitly so a later shutdown can retry failed retirement.
            with self._drained:
                self._retiring.discard(job_id)
                if retired:
                    self._futures.pop(job_id, None)
                    self._cancellation.pop(job_id, None)
                    self._state_locks.pop(job_id, None)
                    self._terminal_updates.pop(job_id, None)
                    self._terminal_persisted.discard(job_id)
                else:
                    self._failed_retirements.add(job_id)
                    self._shutdown_started = False
                    self._shutdown_failed = True
                self._drained.notify_all()

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
            state_lock = self._state_locks.get(str(job_id))
        if event is None or future is None or state_lock is None:
            raise ArenyxaError(
                "JOB_NOT_OWNED",
                "the job is not active in this process and cannot be cancelled here",
                domain="JOB",
            )
        event.set()
        # This per-job lock orders durable start/progress/cancellation writes.
        # Persistence never holds the global shutdown ownership lock.
        with state_lock:
            future.cancel()
            self.store.update_platform_job(
                job_id, message="Cancellation requested", expected_states=("queued", "running"),
            )
            return self.store.get_platform_job(job_id) or row

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
        with self._lock:
            self._accepting = False
            if self._shutdown_cancelling or (self._shutdown_started and not self._failed_retirements):
                return
            self._shutdown_started = True
            self._shutdown_failed = False
            events = tuple(self._cancellation.values())
            futures = tuple(self._futures.values())
            retry_retirements = tuple((job_id, self._futures[job_id]) for job_id in self._failed_retirements)
            self._shutdown_cancelling = True
        for event in events:
            event.set()

        def cancel_owned() -> None:
            failed = False
            try:
                for job_id, future in retry_retirements:
                    self._retire(job_id, future)
                for future in futures:
                    future.cancel()
                shutdown_executor(self._executor, wait=False, cancel_futures=True)
            except Exception:
                failed = True
                LOGGER.exception("Platform executor cleanup incomplete; shutdown can be retried")
            finally:
                with self._drained:
                    failed = failed or bool(self._failed_retirements)
                    self._shutdown_failed = failed
                    self._shutdown_started = not failed
                    self._shutdown_cancelling = False
                    self._drained.notify_all()

        # Future.cancel invokes retirement synchronously, including persistence.
        # Track that ownership while letting the caller obey its own deadline.
        if futures:
            try:
                threading.Thread(target=cancel_owned, name="arenyxa-platform-job-shutdown", daemon=True).start()
            except RuntimeError:
                with self._drained:
                    self._shutdown_started = False
                    self._shutdown_cancelling = False
                    self._shutdown_failed = True
                    self._drained.notify_all()
                raise
        else:
            cancel_owned()

    def drain(self, timeout: float = 10.0, *, include_submissions: bool = False) -> bool:
        """Wait for owned callbacks, and optionally for pre-handoff storage users."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._drained:
            while self._futures or self._shutdown_cancelling or (include_submissions and self._pending_submissions):
                if self._failed_retirements and not self._shutdown_cancelling:
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._drained.wait(remaining)
            return not self._shutdown_failed

    def shutdown_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "accepting": self._accepting,
                "active_futures": len(self._futures),
                "running_futures": sum(future.running() for future in self._futures.values()),
                "pending_submissions": self._pending_submissions,
                "cancelling": self._shutdown_cancelling,
                "retiring_callbacks": len(self._retiring),
                "failed_retirements": len(self._failed_retirements),
            }

    def shutdown(self, *, wait: bool = True, timeout: float = 10.0) -> bool:
        """Stop executor ownership; context teardown also drains pending submissions."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        self.begin_shutdown()
        return self.drain(max(0.0, deadline - time.monotonic()) if wait else 0.0)
