from __future__ import annotations

import json
import queue
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import pytest

from arenyxa.application.windows_conpty import WindowsConPtySession
from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.worker_agent import EnterpriseWorkerAgent
from arenyxa.infrastructure import external_supervisor as supervisor_module


class _SupervisorStream:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.probe_written = threading.Event()
        self.closed = False

    def write(self, value: str) -> int:
        self.lines.append(value)
        if '"component":"probe"' in value:
            self.probe_written.set()
        return len(value)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _SupervisorProcess:
    _next_pid = 9000

    def __init__(self) -> None:
        type(self)._next_pid += 1
        self.pid = type(self)._next_pid
        self.stdin = _SupervisorStream()
        self.alive = True

    def poll(self) -> int | None:
        return None if self.alive else 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.alive = False
        return 0

    def terminate(self) -> None:
        self.alive = False

    def kill(self) -> None:
        self.alive = False


def test_external_supervisor_restart_uses_a_fresh_generation_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    processes: list[_SupervisorProcess] = []

    def popen(*_args: Any, **_kwargs: Any) -> _SupervisorProcess:
        process = _SupervisorProcess()
        processes.append(process)
        return process

    monkeypatch.setattr(supervisor_module.subprocess, "Popen", popen)
    client = supervisor_module.ExternalSupervisorClient(tmp_path / "diagnostics")
    original_sender = client._sender_loop
    first_sender_entered = threading.Event()
    sender_calls = 0
    sender_lock = threading.Lock()

    def controlled_sender(process, stderr_stream, outbound_queue, stop_event) -> None:
        nonlocal sender_calls
        with sender_lock:
            sender_calls += 1
            call = sender_calls
        if call == 1:
            # Stop this generation before it consumes its sentinel. This is the
            # exact stale-token ordering that used to poison the shared queue.
            first_sender_entered.set()
            assert stop_event.wait(2.0)
            stderr_stream.close()
            return
        original_sender(process, stderr_stream, outbound_queue, stop_event)

    monkeypatch.setattr(client, "_sender_loop", controlled_sender)
    client.start()
    assert first_sender_entered.wait(2.0)
    first_queue = client._queue
    client.stop(timeout=0.25)
    assert supervisor_module._SENTINEL in list(first_queue.queue)

    client.start()
    second_queue = client._queue
    assert second_queue is not first_queue
    client.heartbeat("probe", {"generation": 2})
    assert processes[1].stdin.probe_written.wait(2.0)
    payloads = [json.loads(line) for line in processes[1].stdin.lines]
    assert any(item.get("component") == "probe" for item in payloads)
    client.stop(timeout=0.25)


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
        del body, authenticated, correlation_id
        if path.endswith("/heartbeat"):
            return {"ok": True}
        if path.endswith("/lease/batch"):
            try:
                return {"leases": [self._leases.get_nowait()]}
            except queue.Empty:
                return {"leases": []}
        if path.endswith("/job/handover"):
            return {"state": "review_required"}
        raise AssertionError(path)


class _WorkerRuntime:
    def __init__(self, blocked: dict[str, threading.Event] | None = None) -> None:
        self.blocked = dict(blocked or {})
        self.started: dict[str, threading.Event] = {}
        self.executed: list[str] = []
        self._lock = threading.Lock()

    def expect(self, job_id: str) -> threading.Event:
        event = threading.Event()
        self.started[job_id] = event
        return event

    def execute_lease(self, _queue: Any, lease: Any) -> dict[str, Any]:
        with self._lock:
            self.executed.append(lease.job_id)
        self.started[lease.job_id].set()
        blocker = self.blocked.get(lease.job_id)
        if blocker is not None:
            assert blocker.wait(5.0)
        return {"job_id": lease.job_id}


def _worker_agent(client: _WorkerClient, runtime: _WorkerRuntime) -> EnterpriseWorkerAgent:
    return EnterpriseWorkerAgent(
        client=client,  # type: ignore[arg-type]
        runner=None,
        worker_id="worker-1",
        signer=lambda _message: b"signature",
        max_slots=1,
        worker_runtime=runtime,
        preauthenticated=True,
        idle_seconds=0.1,
        heartbeat_seconds=2.0,
    )


def test_enterprise_worker_executor_restarts_for_three_generations() -> None:
    client = _WorkerClient()
    runtime = _WorkerRuntime()
    agent = _worker_agent(client, runtime)

    for cycle in range(1, 4):
        job_id = f"job-{cycle}"
        started = runtime.expect(job_id)
        client.add_lease(job_id)
        agent.start()
        assert started.wait(2.0)
        assert agent.stop(timeout=1.0)

    assert runtime.executed == ["job-1", "job-2", "job-3"]
    assert agent.snapshot()["generation"] == 3


def test_enterprise_worker_stop_deadline_detaches_running_generation_safely() -> None:
    release_old = threading.Event()
    release_new = threading.Event()
    client = _WorkerClient()
    runtime = _WorkerRuntime({"job-old": release_old, "job-new": release_new})
    old_started = runtime.expect("job-old")
    new_started = runtime.expect("job-new")
    agent = _worker_agent(client, runtime)

    client.add_lease("job-old")
    agent.start()
    assert old_started.wait(2.0)
    started_at = time.monotonic()
    assert agent.stop(timeout=0.05) is False
    elapsed = time.monotonic() - started_at
    assert elapsed < 0.5
    with agent._lock:
        old_future = agent._draining_generations[1].active["job-old"]

    client.add_lease("job-new")
    agent.start()
    assert new_started.wait(2.0)
    assert agent.snapshot()["active_jobs"] == ["job-new"]

    release_old.set()
    assert old_future.result(timeout=2.0) == {"job_id": "job-old"}
    assert agent.snapshot()["active_jobs"] == ["job-new"]
    assert agent.snapshot()["jobs_succeeded"] == 0

    release_new.set()
    assert agent.stop(timeout=1.0)


def test_enterprise_worker_generation_capacity_fails_closed_until_physical_drain() -> None:
    release_first = threading.Event()
    release_second = threading.Event()
    client = _WorkerClient()
    runtime = _WorkerRuntime({"job-first": release_first, "job-second": release_second})
    first_started = runtime.expect("job-first")
    second_started = runtime.expect("job-second")
    third_started = runtime.expect("job-third")
    agent = _worker_agent(client, runtime)

    client.add_lease("job-first")
    agent.start()
    assert first_started.wait(2.0)
    assert agent.stop(timeout=0.02) is False

    client.add_lease("job-second")
    agent.start()
    assert second_started.wait(2.0)
    assert agent.stop(timeout=0.02) is False

    client.add_lease("job-third")
    with pytest.raises(ArenyxaError) as captured:
        agent.start()
    assert captured.value.code == "WORKER_GENERATION_CAPACITY_EXHAUSTED"
    with agent._lock:
        assert len(agent._draining_generations) == 2
        draining_futures = [
            future
            for generation in agent._draining_generations.values()
            for future in generation.active.values()
        ]

    release_first.set()
    release_second.set()
    for future in draining_futures:
        future.result(timeout=2.0)

    agent.start()
    assert third_started.wait(2.0)
    assert agent.stop(timeout=1.0)


class _ConPtyApi:
    def __init__(self) -> None:
        self.wait_entered = threading.Event()
        self.release_wait = threading.Event()
        self.closed_handles: list[int] = []
        self.closed_pseudoconsoles: list[int] = []
        self.deleted_attributes = 0
        self.terminate_calls = 0

    def WaitForSingleObject(self, _handle: Any, _timeout: int) -> int:
        self.wait_entered.set()
        assert self.release_wait.wait(2.0)
        return WindowsConPtySession.WAIT_OBJECT_0

    def GetExitCodeProcess(self, _handle: Any, output: Any) -> int:
        output._obj.value = 0
        return 1

    def DeleteProcThreadAttributeList(self, _attribute: Any) -> None:
        self.deleted_attributes += 1

    def CloseHandle(self, handle: Any) -> int:
        self.closed_handles.append(int(handle.value))
        return 1

    def ClosePseudoConsole(self, handle: Any) -> None:
        self.closed_pseudoconsoles.append(int(handle.value))

    def TerminateProcess(self, _handle: Any, _code: int) -> int:
        self.terminate_calls += 1
        return 1


def _handle(value: int) -> wintypes.HANDLE:
    return wintypes.HANDLE(value)


def test_conpty_waiter_cleans_only_its_generation_before_exit_callback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _ConPtyApi()
    monkeypatch.setattr(WindowsConPtySession, "_load_api", staticmethod(lambda: api))
    session = WindowsConPtySession(tmp_path)
    old_handles = {101, 102, 103, 104}
    new_handles = {201, 202, 203, 204}
    with session._lock:
        session._generation = 1
        session._hpc = _handle(100)
        session._process_handle = _handle(101)
        session._thread_handle = _handle(102)
        session._input_write = _handle(103)
        session._output_read = _handle(104)
        session._running = True
        session._started_at = time.monotonic()
        session._finished.clear()

    callback_ran = threading.Event()

    def restart_in_callback(_result: Any) -> None:
        # Mirrors start() committing generation 2 from an exit callback. The old
        # implementation called global cleanup *after* this callback and closed
        # every one of these new handles.
        with session._lock:
            session._generation = 2
            session._hpc = _handle(200)
            session._process_handle = _handle(201)
            session._thread_handle = _handle(202)
            session._input_write = _handle(203)
            session._output_read = _handle(204)
            session._running = True
            session._finished.clear()
        callback_ran.set()

    attribute_buffer = __import__("ctypes").create_string_buffer(8)
    waiter = threading.Thread(
        target=session._wait_loop,
        args=(1, _handle(101), restart_in_callback, attribute_buffer),
    )
    waiter.start()
    assert api.wait_entered.wait(2.0)
    api.release_wait.set()
    waiter.join(2.0)
    assert not waiter.is_alive()
    assert callback_ran.is_set()
    assert old_handles.issubset(set(api.closed_handles))
    assert not new_handles.intersection(api.closed_handles)
    assert session.is_running is True
    assert session._finished.is_set() is False


def test_conpty_close_timeout_leaves_live_handles_waiter_owned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _ConPtyApi()
    monkeypatch.setattr(WindowsConPtySession, "_load_api", staticmethod(lambda: api))
    session = WindowsConPtySession(tmp_path)
    with session._lock:
        session._generation = 1
        session._hpc = _handle(300)
        session._process_handle = _handle(301)
        session._thread_handle = _handle(302)
        session._input_write = _handle(303)
        session._output_read = _handle(304)
        session._running = True
        session._finished.clear()
    monkeypatch.setattr(session, "wait", lambda _timeout: False)

    session.close()

    assert api.terminate_calls == 1
    assert api.closed_handles == []
    assert api.closed_pseudoconsoles == []
    assert session.is_running is True
