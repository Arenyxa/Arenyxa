"""BUG-V82-004: default EnterpriseWorkerAgent.stop must handover leftover leases."""
from __future__ import annotations

import queue
import threading
import time
from typing import Any

from arenyxa.enterprise.worker_agent import EnterpriseWorkerAgent


class _AuthState:
    def snapshot(self) -> tuple[str, str, int]:
        return "worker", "token", 1


def _lease(job_id: str) -> dict[str, Any]:
    return {
        "job_id": job_id,
        "worker_id": "worker-1",
        "lease_token": f"token-{job_id}",
        "lease_expires_at": time.time() + 60.0,
        "kind": "test",
        "payload": {},
        "resource_id": "resource",
        "permission": "execute",
        "attempt": 1,
        "max_attempts": 1,
        "side_effect_mode": "idempotent",
        "checkpoint": {},
        "checkpoint_seq": 0,
        "protocol_version": 1,
    }


class _WorkerClient:
    def __init__(self) -> None:
        self._auth_state = _AuthState()
        self._leases: queue.Queue[dict[str, Any]] = queue.Queue()
        self.handovers: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def add_lease(self, job_id: str) -> None:
        self._leases.put_nowait(_lease(job_id))

    def fork(self) -> "_WorkerClient":
        return self

    def authenticate(self, worker_id: str, signer: Any) -> dict[str, Any]:
        del worker_id, signer
        return {"authenticated": True}

    def request(
        self,
        path: str,
        body: dict[str, Any],
        *,
        authenticated: bool,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        del authenticated, correlation_id
        if path.endswith("/heartbeat"):
            return {"ok": True}
        if path.endswith("/lease/batch"):
            try:
                return {"leases": [self._leases.get_nowait()]}
            except queue.Empty:
                return {"leases": []}
        if path.endswith("/job/handover"):
            with self._lock:
                self.handovers.append((str(body.get("job_id")), str(body.get("reason"))))
            return {"state": "queued"}
        raise AssertionError(path)


class _WorkerRuntime:
    def __init__(self, blocked: dict[str, threading.Event]) -> None:
        self.blocked = blocked
        self.started: dict[str, threading.Event] = {}

    def expect(self, job_id: str) -> threading.Event:
        event = threading.Event()
        self.started[job_id] = event
        return event

    def execute_lease(self, _queue: Any, lease: Any) -> dict[str, Any]:
        self.started[lease.job_id].set()
        assert self.blocked[lease.job_id].wait(5.0)
        return {"job_id": lease.job_id}


def test_default_stop_handovers_leftover_lease_after_timeout() -> None:
    release = threading.Event()
    client = _WorkerClient()
    runtime = _WorkerRuntime({"job-stuck": release})
    started = runtime.expect("job-stuck")
    agent = EnterpriseWorkerAgent(
        client=client,  # type: ignore[arg-type]
        runner=None,
        worker_id="worker-1",
        signer=lambda _message: b"signature",
        max_slots=1,
        worker_runtime=runtime,
        preauthenticated=True,
        idle_seconds=0.05,
        heartbeat_seconds=2.0,
    )
    client.add_lease("job-stuck")
    agent.start()
    assert started.wait(2.0)

    # Default stop (cancel_running=False) must still release the leftover lease.
    assert agent.stop(timeout=0.05, cancel_running=False) is False

    deadline = time.monotonic() + 2.0
    while not client.handovers and time.monotonic() < deadline:
        time.sleep(0.01)
    assert client.handovers == [("job-stuck", "WORKER_AGENT_SHUTDOWN")]

    release.set()
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        with agent._lock:
            agent._prune_draining_locked()
            if not agent._draining_generations:
                break
        time.sleep(0.01)
    with agent._lock:
        assert not agent._draining_generations


def test_graceful_stop_does_not_handover_a_finished_lease() -> None:
    release = threading.Event()
    client = _WorkerClient()
    runtime = _WorkerRuntime({"job-finished": release})
    started = runtime.expect("job-finished")
    agent = EnterpriseWorkerAgent(
        client=client,
        runner=None,
        worker_id="worker-1",
        signer=lambda _message: b"signature",
        worker_runtime=runtime,
        preauthenticated=True,
        idle_seconds=0.05,
    )
    client.add_lease("job-finished")
    agent.start()
    assert started.wait(2.0)
    release.set()
    assert agent.stop(timeout=2.0)
    assert client.handovers == []
