from __future__ import annotations

import http.client
import logging
import ssl
import threading
import time
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor, wait as wait_futures
from dataclasses import dataclass, field
from typing import Any, Mapping

from arenyxa.compat import shutdown_executor
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.enterprise.distributed_protocol import DistributedLease, MAX_WORKER_SLOTS
from arenyxa.enterprise.distributed_runtime import EnterpriseWorkerRuntime
from arenyxa.enterprise.server_api import EnterpriseWorkerHTTPClient

MIN_RECONNECT_BACKOFF_SECONDS = 1.0
MAX_RECONNECT_BACKOFF_SECONDS = 30.0
LOGGER = logging.getLogger(__name__)


@dataclass
class _AgentGeneration:
    """Executor/control-loop ownership for one restartable Worker generation."""

    number: int
    stop: threading.Event
    pool: ThreadPoolExecutor
    thread: threading.Thread | None = None
    handover_thread: threading.Thread | None = None
    active: dict[str, Future[Any]] = field(default_factory=dict)
    active_leases: dict[str, DistributedLease] = field(default_factory=dict)
    last_heartbeat: float = 0.0
    partition_since_monotonic: float = 0.0
    shutdown_started: bool = False


class _RemoteQueueAdapter:
    """Queue protocol adapter used by EnterpriseWorkerRuntime over authenticated HTTPS."""

    def __init__(self, agent: "EnterpriseWorkerAgent") -> None:
        self.agent = agent

    def start_job(self, job_id: str, worker_id: str, lease_token: str) -> None:
        del worker_id
        self.agent._request(
            "/enterprise/v1/worker/job/start",
            {"job_id": job_id, "lease_token": lease_token},
            correlation_id=f"job:{job_id}",
        )

    def renew_lease(self, job_id: str, worker_id: str, lease_token: str, lease_seconds: int = 60) -> float:
        del worker_id
        result = self.agent._request(
            "/enterprise/v1/worker/job/renew",
            {"job_id": job_id, "lease_token": lease_token, "lease_seconds": int(lease_seconds)},
            correlation_id=f"job:{job_id}",
        )
        return float(result["lease_expires_at"])

    def handover(self, job_id: str, worker_id: str, lease_token: str, reason: str) -> str:
        del worker_id
        result = self.agent._request(
            "/enterprise/v1/worker/job/handover",
            {"job_id": job_id, "lease_token": lease_token, "reason": str(reason)[:128]},
            correlation_id=f"job:{job_id}",
        )
        return str(result.get("state", "review_required"))

    def checkpoint(self, job_id: str, worker_id: str, lease_token: str, checkpoint: Mapping[str, Any]) -> int:
        del worker_id
        result = self.agent._request(
            "/enterprise/v1/worker/job/checkpoint",
            {"job_id": job_id, "lease_token": lease_token, "checkpoint": dict(checkpoint)},
            correlation_id=f"job:{job_id}",
        )
        return int(result["checkpoint_seq"])

    def mark_side_effect_started(self, job_id: str, worker_id: str, lease_token: str) -> None:
        del worker_id
        self.agent._request(
            "/enterprise/v1/worker/job/side-effect-started",
            {"job_id": job_id, "lease_token": lease_token},
            correlation_id=f"job:{job_id}",
        )

    def complete(self, job_id: str, worker_id: str, lease_token: str, result: Mapping[str, Any]) -> None:
        del worker_id
        self.agent._terminal_request(
            "/enterprise/v1/worker/job/complete",
            {"job_id": job_id, "lease_token": lease_token, "result": dict(result)},
            correlation_id=f"job:{job_id}",
        )

    def fail(
        self,
        job_id: str,
        worker_id: str,
        lease_token: str,
        error_code: str,
        *,
        retryable: bool = True,
    ) -> str:
        del worker_id
        result = self.agent._request(
            "/enterprise/v1/worker/job/fail",
            {
                "job_id": job_id,
                "lease_token": lease_token,
                "error_code": str(error_code)[:128],
                "retryable": bool(retryable),
            },
            correlation_id=f"job:{job_id}",
        )
        return str(result.get("state", "failed"))


class EnterpriseWorkerAgent:
    """Bounded remote Worker/Agent loop with graceful stop and lease isolation."""

    def __init__(
        self,
        *,
        client: EnterpriseWorkerHTTPClient,
        runner: Any,
        worker_id: str,
        signer: Any,
        max_slots: int = 1,
        worker_runtime: Any | None = None,
        preauthenticated: bool = False,
        resources: Mapping[str, Any] | None = None,
        heartbeat_seconds: float = 15.0,
        idle_seconds: float = 1.0,
    ) -> None:
        self.client = client
        self._client_local = threading.local()
        self._auth_lock = threading.Lock()
        self.runner = runner
        self.worker_id = str(worker_id).strip()
        if not self.worker_id:
            raise ValueError("worker_id is required")
        self.signer = signer
        self.max_slots = max(1, min(MAX_WORKER_SLOTS, int(max_slots)))
        self.resources = dict(resources or {})
        self.heartbeat_seconds = max(2.0, min(120.0, float(heartbeat_seconds)))
        self.idle_seconds = max(0.1, min(10.0, float(idle_seconds)))
        self.worker = worker_runtime if worker_runtime is not None else EnterpriseWorkerRuntime(runner, self.worker_id)
        self.queue = _RemoteQueueAdapter(self)
        self._lock = threading.Lock()
        self._generation_serial = 0
        self._current_generation: _AgentGeneration | None = None
        self._draining_generations: dict[int, _AgentGeneration] = {}
        self._partition_events = 0
        self._last_error = ""
        self._authenticated_at = utc_now() if preauthenticated else ""
        self._leases_seen = 0
        self._jobs_succeeded = 0
        self._jobs_failed = 0

    @staticmethod
    def _lease_from_dict(value: Mapping[str, Any]) -> DistributedLease:
        payload = value.get("payload")
        checkpoint = value.get("checkpoint")
        if not isinstance(payload, Mapping) or not isinstance(checkpoint, Mapping):
            raise ValueError("remote lease payload/checkpoint must be objects")
        return DistributedLease(
            job_id=str(value.get("job_id", "")),
            worker_id=str(value.get("worker_id", "")),
            lease_token=str(value.get("lease_token", "")),
            lease_expires_at=float(value.get("lease_expires_at", 0.0)),
            kind=str(value.get("kind", "")),
            payload=dict(payload),
            resource_id=str(value.get("resource_id", "")),
            permission=str(value.get("permission", "")),
            attempt=int(value.get("attempt", 0)),
            max_attempts=int(value.get("max_attempts", 0)),
            side_effect_mode=str(value.get("side_effect_mode", "idempotent")),
            checkpoint=dict(checkpoint),
            checkpoint_seq=int(value.get("checkpoint_seq", 0)),
            protocol_version=int(value.get("protocol_version", 0)),
            traceparent=str(value.get("traceparent", "")),
            tracestate=str(value.get("tracestate", "")),
        )

    @staticmethod
    def _session_expired(exc: Exception) -> bool:
        text = str(exc)
        return "WORKER_SESSION_INVALID" in text or "worker session is not authenticated" in text

    @staticmethod
    def _transient_transport_error(exc: Exception) -> bool:
        return isinstance(exc, (OSError, TimeoutError, http.client.HTTPException)) and not isinstance(
            exc, ssl.SSLCertVerificationError
        )

    @staticmethod
    def _lease_lost_error(exc: Exception) -> bool:
        text = str(exc)
        return any(
            marker in text
            for marker in ("DISTRIBUTED_LEASE_LOST", "DISTRIBUTED_LEASE_STALE", "DISTRIBUTED_LEASE_EXPIRED")
        )

    @classmethod
    def _recoverable_control_error(cls, exc: Exception) -> bool:
        return cls._session_expired(exc) or cls._transient_transport_error(exc) or cls._lease_lost_error(exc)

    def _active_client(self) -> EnterpriseWorkerHTTPClient:
        client = getattr(self._client_local, "client", None)
        if client is None:
            client = self.client.fork()
            self._client_local.client = client
        return client

    def authenticate(self) -> dict[str, Any]:
        with self._auth_lock:
            result = self.client.authenticate(self.worker_id, self.signer)
            self._client_local.client = self.client.fork()
            with self._lock:
                self._authenticated_at = utc_now()
                self._last_error = ""
            return dict(result)

    def _reauthenticate(self, observed_generation: int) -> None:
        with self._auth_lock:
            _identity, token, generation = self.client._auth_state.snapshot()
            if token and generation != int(observed_generation):
                return
            refresh = self.client.fork()
            refresh.verify_peer("worker-session-refresh:" + self.worker_id[:80])
            refresh.authenticate(self.worker_id, self.signer)
            with self._lock:
                self._authenticated_at = utc_now()
                self._last_error = ""

    def _request(
        self, path: str, body: Mapping[str, Any], *, correlation_id: str | None = None
    ) -> dict[str, Any]:
        client = self._active_client()
        _identity, _token, generation = self.client._auth_state.snapshot()
        try:
            return client.request(path, body, authenticated=True, correlation_id=correlation_id)
        except RuntimeError as exc:
            if not self._session_expired(exc):
                raise
            with self._lock:
                self._authenticated_at = ""
            self._reauthenticate(generation)
            self._client_local.client = self.client.fork()
            return self._active_client().request(path, body, authenticated=True, correlation_id=correlation_id)

    def _terminal_request(
        self, path: str, body: Mapping[str, Any], *, correlation_id: str | None = None
    ) -> dict[str, Any]:
        try:
            return self._request(path, body, correlation_id=correlation_id)
        except (OSError, TimeoutError, http.client.HTTPException) as exc:
            if not self._transient_transport_error(exc):
                raise
            self._client_local.client = self.client.fork()
            return self._request(path, body, correlation_id=correlation_id)

    def _new_generation_locked(self) -> _AgentGeneration:
        self._generation_serial += 1
        generation = _AgentGeneration(
            number=self._generation_serial,
            stop=threading.Event(),
            pool=ThreadPoolExecutor(max_workers=self.max_slots,
                thread_name_prefix=f"ArenyxaRemoteWorker-{self._generation_serial}",
            ),
        )
        self._current_generation = generation
        return generation

    def _detach_generation_locked(self, generation: _AgentGeneration) -> None:
        if self._current_generation is generation:
            self._current_generation = None
        self._draining_generations[generation.number] = generation

    def _discard_stale_completed_locked(self, generation: _AgentGeneration) -> None:
        for job_id, future in list(generation.active.items()):
            if not future.done():
                continue
            generation.active.pop(job_id, None)
            generation.active_leases.pop(job_id, None)

    def _prune_draining_locked(self) -> None:
        for number, generation in list(self._draining_generations.items()):
            self._discard_stale_completed_locked(generation)
            thread_done = generation.thread is None or not generation.thread.is_alive()
            handover_done = generation.handover_thread is None or not generation.handover_thread.is_alive()
            if thread_done and handover_done and not generation.active:
                self._draining_generations.pop(number, None)

    def _generation_for_work(self) -> _AgentGeneration:
        stale: _AgentGeneration | None = None
        with self._lock:
            generation = self._current_generation
            if generation is None or generation.stop.is_set() or generation.shutdown_started:
                if generation is not None:
                    generation.stop.set()
                    self._detach_generation_locked(generation)
                    stale = generation
                generation = self._new_generation_locked()
        if stale is not None:
            self._shutdown_generation(stale)
        return generation

    def _shutdown_generation(self, generation: _AgentGeneration) -> None:
        with self._lock:
            if generation.shutdown_started:
                return
            generation.shutdown_started = True
        # shutdown(wait=False) is the only stdlib executor shutdown operation
        # with a bounded caller latency. Running Python callables drain under
        # executor ownership; queued work is cancelled and cannot cross restart.
        shutdown_executor(generation.pool, wait=False, cancel_futures=True)

    def _future_completed(
        self,
        generation: _AgentGeneration,
        job_id: str,
        future: Future[Any],
    ) -> None:
        with self._lock:
            if self._current_generation is generation:
                return
            if generation.active.get(job_id) is future:
                generation.active.pop(job_id, None)
                generation.active_leases.pop(job_id, None)
            self._prune_draining_locked()

    def _submit(self, generation: _AgentGeneration, lease: DistributedLease) -> Future[Any] | None:
        # Admission and stop/detach are one critical section. stop() therefore
        # cannot miss a Future submitted by an in-flight lease response.
        with self._lock:
            if self._current_generation is not generation or generation.stop.is_set():
                return None
            future = generation.pool.submit(self.worker.execute_lease, self.queue, lease)
            generation.active[lease.job_id] = future
            generation.active_leases[lease.job_id] = lease
            self._leases_seen += 1
        future.add_done_callback(
            lambda completed, owner=generation, job_id=lease.job_id: self._future_completed(
                owner, job_id, completed
            )
        )
        return future

    def start(self) -> None:
        generation = self._generation_for_work()
        with self._lock:
            if generation.thread is not None and generation.thread.is_alive():
                return
            thread = threading.Thread(
                target=self._run_in_thread,
                args=(generation,),
                name=f"arenyxa-enterprise-worker-agent-{generation.number}",
                daemon=True,
            )
            generation.thread = thread
            try:
                thread.start()
            except RuntimeError:
                generation.stop.set()
                self._detach_generation_locked(generation)
                generation.thread = None
                raise

    def _run_in_thread(self, generation: _AgentGeneration) -> None:
        try:
            self._run(generation)
        finally:
            with self._lock:
                if generation.thread is threading.current_thread():
                    generation.thread = None
                self._prune_draining_locked()

    def _handover_generation(self, generation: _AgentGeneration, leases: list[DistributedLease]) -> None:
        try:
            for lease in leases:
                try:
                    self.queue.handover(
                        lease.job_id,
                        self.worker_id,
                        lease.lease_token,
                        "WORKER_AGENT_SHUTDOWN",
                    )
                except (ArenyxaError, OSError, RuntimeError, TimeoutError, http.client.HTTPException) as exc:
                    LOGGER.warning("Worker lease handover failed during shutdown for %s: %s", lease.job_id, exc)
        finally:
            with self._lock:
                if generation.handover_thread is threading.current_thread():
                    generation.handover_thread = None
                self._prune_draining_locked()

    def stop(self, *, timeout: float = 15.0, cancel_running: bool = False) -> bool:
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._lock:
            generation = self._current_generation
            if generation is None:
                self._prune_draining_locked()
                return not self._draining_generations
            generation.stop.set()
            self._detach_generation_locked(generation)
            self._discard_stale_completed_locked(generation)
            thread = generation.thread
            futures = list(generation.active.values())
            leases = list(generation.active_leases.values())

        if cancel_running and leases:
            handover = threading.Thread(
                target=self._handover_generation,
                args=(generation, leases),
                name=f"arenyxa-enterprise-worker-handover-{generation.number}",
                daemon=True,
            )
            with self._lock:
                generation.handover_thread = handover
            handover.start()
            for future in futures:
                future.cancel()

        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        remaining = max(0.0, deadline - time.monotonic())
        if futures and remaining > 0.0:
            wait_futures(futures, timeout=remaining)
        for future in futures:
            if not future.done():
                future.cancel()
        self._shutdown_generation(generation)

        with self._lock:
            self._discard_stale_completed_locked(generation)
            thread_done = thread is None or not thread.is_alive()
            futures_done = all(future.done() for future in futures)
            handover_thread = generation.handover_thread
            handover_done = handover_thread is None or not handover_thread.is_alive()
            self._prune_draining_locked()
            all_generations_done = not self._draining_generations
        return bool(thread_done and futures_done and handover_done and all_generations_done)

    def _heartbeat(self, generation: _AgentGeneration, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - generation.last_heartbeat < self.heartbeat_seconds:
            return
        with self._lock:
            active_count = len(generation.active)
            leases_seen = self._leases_seen
        resources = {
            **self.resources,
            "runtime": "shared-control-plane",
            "max_slots": self.max_slots,
            "active_jobs": active_count,
            "leases_seen": leases_seen,
        }
        self._request("/enterprise/v1/worker/heartbeat", {"resources": resources})
        generation.last_heartbeat = now

    def _reap(self, generation: _AgentGeneration) -> None:
        with self._lock:
            completed = [(job_id, future) for job_id, future in generation.active.items() if future.done()]
        for job_id, future in completed:
            try:
                failure = future.exception()
            except CancelledError as exc:
                failure = exc
            if failure is not None:
                LOGGER.error(
                    "Remote Worker job %s failed: %s: %s",
                    job_id,
                    type(failure).__name__,
                    failure,
                )
            with self._lock:
                if generation.active.get(job_id) is not future:
                    continue
                generation.active.pop(job_id, None)
                generation.active_leases.pop(job_id, None)
                if self._current_generation is generation:
                    if failure is not None:
                        self._jobs_failed += 1
                        self._last_error = f"{type(failure).__name__}: {failure}"[:512]
                    else:
                        self._jobs_succeeded += 1

    def run_once(self) -> list[dict[str, Any]]:
        generation = self._generation_for_work()
        if not self._authenticated_at:
            self.authenticate()
        self._heartbeat(generation, force=True)
        response = self._request(
            "/enterprise/v1/worker/lease/batch",
            {"lease_seconds": 60, "max_items": self.max_slots},
        )
        rows = response.get("leases", [])
        if not isinstance(rows, list):
            raise RuntimeError("Enterprise Server returned invalid lease batch")
        submitted: list[tuple[str, Future[Any]]] = []
        for raw in rows[: self.max_slots]:
            if not isinstance(raw, Mapping):
                raise RuntimeError("Enterprise Server returned invalid lease object")
            lease = self._lease_from_dict(raw)
            if not lease.job_id or lease.worker_id != self.worker_id or not lease.lease_token:
                raise RuntimeError("Enterprise Server returned an invalid Worker lease")
            future = self._submit(generation, lease)
            if future is None:
                break
            submitted.append((lease.job_id, future))
        results: list[dict[str, Any]] = []
        for job_id, future in submitted:
            try:
                failure = future.exception()
            except CancelledError as exc:
                failure = exc
            if failure is not None:
                with self._lock:
                    if generation.active.get(job_id) is future:
                        generation.active.pop(job_id, None)
                        generation.active_leases.pop(job_id, None)
                    if self._current_generation is generation:
                        self._jobs_failed += 1
                raise failure
            value = future.result()
            with self._lock:
                if generation.active.get(job_id) is future:
                    generation.active.pop(job_id, None)
                    generation.active_leases.pop(job_id, None)
                if self._current_generation is generation:
                    self._jobs_succeeded += 1
            results.append(dict(value) if isinstance(value, Mapping) else {"result": value})
        return results

    def run_forever(self) -> None:
        generation = self._generation_for_work()
        current_thread = threading.current_thread()
        with self._lock:
            if generation.thread is not None and generation.thread.is_alive():
                raise RuntimeError("Enterprise Worker agent is already running")
            generation.thread = current_thread
        try:
            self._run(generation, propagate_fatal=True)
        finally:
            with self._lock:
                if generation.thread is current_thread:
                    generation.thread = None
                self._prune_draining_locked()

    def _run(self, generation: _AgentGeneration, *, propagate_fatal: bool = False) -> None:
        backoff = max(MIN_RECONNECT_BACKOFF_SECONDS, self.idle_seconds)
        while not generation.stop.is_set():
            try:
                if not self._authenticated_at:
                    self.authenticate()
                self._reap(generation)
                self._heartbeat(generation)
                with self._lock:
                    if self._current_generation is not generation:
                        return
                    free_slots = max(0, self.max_slots - len(generation.active))
                if free_slots <= 0:
                    generation.stop.wait(min(self.idle_seconds, 0.5))
                    continue
                response = self._request(
                    "/enterprise/v1/worker/lease/batch",
                    {"lease_seconds": 60, "max_items": free_slots},
                )
                rows = response.get("leases", [])
                if not isinstance(rows, list):
                    raise RuntimeError("Enterprise Server returned invalid lease batch")
                with self._lock:
                    if self._current_generation is generation:
                        generation.partition_since_monotonic = 0.0
                accepted = 0
                for raw in rows[:free_slots]:
                    if not isinstance(raw, Mapping):
                        continue
                    lease = self._lease_from_dict(raw)
                    if not lease.job_id or lease.worker_id != self.worker_id or not lease.lease_token:
                        raise RuntimeError("Enterprise Server returned an invalid Worker lease")
                    if self._submit(generation, lease) is None:
                        break
                    accepted += 1
                backoff = self.idle_seconds
                if accepted == 0:
                    generation.stop.wait(self.idle_seconds)
            except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, http.client.HTTPException) as exc:
                with self._lock:
                    is_current = self._current_generation is generation
                    if is_current:
                        self._last_error = f"{type(exc).__name__}: {exc}"[:512]
                if not self._recoverable_control_error(exc):
                    generation.stop.set()
                    if propagate_fatal:
                        raise
                    LOGGER.error("Enterprise Worker agent stopped after non-recoverable failure: %s", exc)
                    return
                LOGGER.warning("Enterprise Worker agent control loop degraded: %s", exc)
                if self._transient_transport_error(exc):
                    now_mono = time.monotonic()
                    with self._lock:
                        if self._current_generation is generation and generation.partition_since_monotonic <= 0.0:
                            generation.partition_since_monotonic = now_mono
                            self._partition_events += 1
                if self._session_expired(exc):
                    with self._lock:
                        if self._current_generation is generation:
                            self._authenticated_at = ""
                generation.stop.wait(backoff)
                backoff = min(
                    MAX_RECONNECT_BACKOFF_SECONDS,
                    max(MIN_RECONNECT_BACKOFF_SECONDS, self.idle_seconds, backoff * 2.0),
                )
        self._reap(generation)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            self._prune_draining_locked()
            generation = self._current_generation
            active = sorted(generation.active) if generation is not None else []
            thread = generation.thread if generation is not None else None
            partition_since = generation.partition_since_monotonic if generation is not None else 0.0
            return {
                "schema": "arenyxa.enterprise-worker-agent/v1",
                "worker_id": self.worker_id,
                "running": bool(
                    generation is not None
                    and thread is not None
                    and thread.is_alive()
                    and not generation.stop.is_set()
                ),
                "generation": generation.number if generation is not None else self._generation_serial,
                "draining_generations": sorted(self._draining_generations),
                "max_slots": self.max_slots,
                "active_jobs": active,
                "active_count": len(active),
                "leases_seen": self._leases_seen,
                "jobs_succeeded": self._jobs_succeeded,
                "jobs_failed": self._jobs_failed,
                "authenticated_at": self._authenticated_at,
                "partitioned": partition_since > 0.0,
                "partition_seconds": (
                    0.0 if partition_since <= 0.0 else max(0.0, time.monotonic() - partition_since)
                ),
                "partition_events": self._partition_events,
                "last_error": self._last_error,
            }
