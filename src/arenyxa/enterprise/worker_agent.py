from __future__ import annotations

import http.client
import logging
import ssl
import threading
import time
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
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
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._pool = ThreadPoolExecutor(max_workers=self.max_slots, thread_name_prefix="ArenyxaRemoteWorker")
        self._active: dict[str, Future[Any]] = {}
        self._active_leases: dict[str, DistributedLease] = {}
        self._last_heartbeat = 0.0
        self._partition_since_monotonic = 0.0
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

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            thread = threading.Thread(target=self._run, name="arenyxa-enterprise-worker-agent", daemon=True)
            self._thread = thread
            thread.start()

    def stop(self, *, timeout: float = 15.0, cancel_running: bool = False) -> bool:
        self._stop.set()
        with self._lock:
            thread = self._thread
            futures = list(self._active.values())
            leases = list(self._active_leases.values())
        if cancel_running:
            for lease in leases:
                try:
                    self.queue.handover(lease.job_id, self.worker_id, lease.lease_token, "WORKER_AGENT_SHUTDOWN")
                except (ArenyxaError, OSError, RuntimeError, TimeoutError, http.client.HTTPException) as exc:
                    LOGGER.warning("Worker lease handover failed during shutdown for %s: %s", lease.job_id, exc)
            for future in futures:
                future.cancel()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        shutdown_executor(self._pool, wait=not cancel_running, cancel_futures=cancel_running)
        return thread is None or not thread.is_alive()

    def _heartbeat(self, *, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_heartbeat < self.heartbeat_seconds:
            return
        with self._lock:
            active_count = len(self._active)
            leases_seen = self._leases_seen
        resources = {
            **self.resources,
            "runtime": "shared-control-plane",
            "max_slots": self.max_slots,
            "active_jobs": active_count,
            "leases_seen": leases_seen,
        }
        self._request("/enterprise/v1/worker/heartbeat", {"resources": resources})
        self._last_heartbeat = now

    def _reap(self) -> None:
        with self._lock:
            completed = [(job_id, future) for job_id, future in self._active.items() if future.done()]
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
                    self._jobs_failed += 1
                    self._last_error = f"{type(failure).__name__}: {failure}"[:512]
            else:
                with self._lock:
                    self._jobs_succeeded += 1
            with self._lock:
                self._active.pop(job_id, None)
                self._active_leases.pop(job_id, None)

    def run_once(self) -> list[dict[str, Any]]:
        if not self._authenticated_at:
            self.authenticate()
        self._heartbeat(force=True)
        response = self._request(
            "/enterprise/v1/worker/lease/batch",
            {"lease_seconds": 60, "max_items": self.max_slots},
        )
        rows = response.get("leases", [])
        if not isinstance(rows, list):
            raise RuntimeError("Enterprise Server returned invalid lease batch")
        futures: list[Future[Any]] = []
        for raw in rows[: self.max_slots]:
            if not isinstance(raw, Mapping):
                raise RuntimeError("Enterprise Server returned invalid lease object")
            lease = self._lease_from_dict(raw)
            if not lease.job_id or lease.worker_id != self.worker_id or not lease.lease_token:
                raise RuntimeError("Enterprise Server returned an invalid Worker lease")
            with self._lock:
                self._leases_seen += 1
            futures.append(self._pool.submit(self.worker.execute_lease, self.queue, lease))
        results: list[dict[str, Any]] = []
        for future in futures:
            try:
                failure = future.exception()
            except CancelledError as exc:
                failure = exc
            if failure is not None:
                with self._lock:
                    self._jobs_failed += 1
                raise failure
            value = future.result()
            with self._lock:
                self._jobs_succeeded += 1
            results.append(dict(value) if isinstance(value, Mapping) else {"result": value})
        return results

    def run_forever(self) -> None:
        self._stop.clear()
        self._run(propagate_fatal=True)

    def _run(self, *, propagate_fatal: bool = False) -> None:
        backoff = max(MIN_RECONNECT_BACKOFF_SECONDS, self.idle_seconds)
        while not self._stop.is_set():
            try:
                if not self._authenticated_at:
                    self.authenticate()
                self._reap()
                self._heartbeat()
                with self._lock:
                    free_slots = max(0, self.max_slots - len(self._active))
                if free_slots <= 0:
                    self._stop.wait(min(self.idle_seconds, 0.5))
                    continue
                response = self._request(
                    "/enterprise/v1/worker/lease/batch",
                    {"lease_seconds": 60, "max_items": free_slots},
                )
                rows = response.get("leases", [])
                if not isinstance(rows, list):
                    raise RuntimeError("Enterprise Server returned invalid lease batch")
                with self._lock:
                    self._partition_since_monotonic = 0.0
                accepted = 0
                for raw in rows[:free_slots]:
                    if not isinstance(raw, Mapping):
                        continue
                    lease = self._lease_from_dict(raw)
                    if not lease.job_id or lease.worker_id != self.worker_id or not lease.lease_token:
                        raise RuntimeError("Enterprise Server returned an invalid Worker lease")
                    future = self._pool.submit(self.worker.execute_lease, self.queue, lease)
                    with self._lock:
                        self._active[lease.job_id] = future
                        self._active_leases[lease.job_id] = lease
                        self._leases_seen += 1
                    accepted += 1
                backoff = self.idle_seconds
                if accepted == 0:
                    self._stop.wait(self.idle_seconds)
            except (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, http.client.HTTPException) as exc:
                with self._lock:
                    self._last_error = f"{type(exc).__name__}: {exc}"[:512]
                if not self._recoverable_control_error(exc):
                    if propagate_fatal:
                        raise
                    LOGGER.error("Enterprise Worker agent stopped after non-recoverable failure: %s", exc)
                    self._stop.set()
                    return
                LOGGER.warning("Enterprise Worker agent control loop degraded: %s", exc)
                if self._transient_transport_error(exc):
                    now_mono = time.monotonic()
                    with self._lock:
                        if self._partition_since_monotonic <= 0.0:
                            self._partition_since_monotonic = now_mono
                            self._partition_events += 1
                if self._session_expired(exc):
                    with self._lock:
                        self._authenticated_at = ""
                self._stop.wait(backoff)
                backoff = min(
                    MAX_RECONNECT_BACKOFF_SECONDS,
                    max(MIN_RECONNECT_BACKOFF_SECONDS, self.idle_seconds, backoff * 2.0),
                )
        self._reap()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            active = sorted(self._active)
            thread = self._thread
            return {
                "schema": "arenyxa.enterprise-worker-agent/v1",
                "worker_id": self.worker_id,
                "running": bool(thread is not None and thread.is_alive() and not self._stop.is_set()),
                "max_slots": self.max_slots,
                "active_jobs": active,
                "active_count": len(active),
                "leases_seen": self._leases_seen,
                "jobs_succeeded": self._jobs_succeeded,
                "jobs_failed": self._jobs_failed,
                "authenticated_at": self._authenticated_at,
                "partitioned": self._partition_since_monotonic > 0.0,
                "partition_seconds": (
                    0.0 if self._partition_since_monotonic <= 0.0
                    else max(0.0, time.monotonic() - self._partition_since_monotonic)
                ),
                "partition_events": self._partition_events,
                "last_error": self._last_error,
            }
