from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from concurrent.futures import Future

import pytest

import arenyxa.repair as repair_module
from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.runner import RunHandle
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.enums import CaptureSource, CaptureState, RunStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import (
    CaptureSession,
    DatasetRevision,
    NetworkEvent,
    Run,
    Workflow,
    WorkflowNode,
)
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.capture.filtering import FilterSyntaxError
from arenyxa.infrastructure.http_client import CancellationToken


class _PassiveCaptureAdapter:
    def __init__(self) -> None:
        self.emit = None
        self.start_calls = 0
        self.stop_calls = 0
        self.pause_calls = 0
        self.resume_calls = 0

    def start(self, _session, emit) -> None:
        self.start_calls += 1
        self.emit = emit

    def stop(self) -> None:
        self.stop_calls += 1

    def pause(self) -> None:
        self.pause_calls += 1

    def resume(self) -> None:
        self.resume_calls += 1


@pytest.mark.skipif(os.name != "nt", reason="Windows process-probe contract")
def test_windows_repair_process_probe_never_terminates_observed_child() -> None:
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    release_child = threading.Timer(0.2, child.stdin.close)
    try:
        assert repair_module._process_is_running(child.pid) is True
        assert child.poll() is None
        release_child.start()
        started = time.monotonic()
        repair_module._wait_for_parent(child.pid, timeout_seconds=2.0)
        elapsed = time.monotonic() - started
        release_child.join(timeout=1.0)
        assert child.poll() == 0
        assert elapsed >= 0.05
        assert repair_module._process_is_running(child.pid) is False
    finally:
        release_child.cancel()
        if child.stdin is not None and not child.stdin.closed:
            child.stdin.close()
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=3.0)


@pytest.mark.skipif(os.name != "nt", reason="Windows process-probe contract")
def test_windows_unknown_process_state_fails_closed_without_os_kill(monkeypatch) -> None:
    monkeypatch.setattr(repair_module, "_windows_process_running", lambda *_args: None)

    def forbidden_kill(*_args) -> None:
        raise AssertionError("Windows process probing must never call os.kill")

    monkeypatch.setattr(repair_module.os, "kill", forbidden_kill)
    assert repair_module._process_is_running(2_000_000_000) is True


def test_capture_prepare_failure_does_not_poison_controller(store) -> None:
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    bad = CaptureSession("bad-filter", CaptureSource.SYSTEM)
    bad.filter_expression = "bytes >"

    with pytest.raises(FilterSyntaxError):
        controller.prepare(bad, _PassiveCaptureAdapter())

    assert controller.session is None
    assert bad.state == CaptureState.IDLE

    good = CaptureSession("valid-after-failure", CaptureSource.SYSTEM)
    controller.prepare(good, _PassiveCaptureAdapter())
    assert controller.session is good
    assert good.state == CaptureState.PREPARING
    controller.stop(cancelled=True)


def test_capture_rejects_late_event_from_previous_session(store) -> None:
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    first_adapter = _PassiveCaptureAdapter()
    first = CaptureSession("first", CaptureSource.SYSTEM)
    controller.prepare(first, first_adapter)
    controller.start()
    controller.stop()


def test_capture_rechecks_session_after_inflight_filter_callback(store) -> None:
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    first_adapter = _PassiveCaptureAdapter()
    first = CaptureSession("first-filter-race", CaptureSource.SYSTEM)
    controller.prepare(first, first_adapter)
    controller.start()
    filter_entered = threading.Event()
    release_filter = threading.Event()

    def blocking_filter(_event) -> bool:
        filter_entered.set()
        assert release_filter.wait(timeout=2.0)
        return True

    controller._filter = blocking_filter                                       
    stale_event = NetworkEvent(
        session_id=first.id,
        source_type=CaptureSource.SYSTEM,
        protocol="HTTP",
        direction="out",
        size=9,
    )
    callback = threading.Thread(target=controller.emit, args=(stale_event,))
    callback.start()
    assert filter_entered.wait(timeout=1.0)

    controller.stop()
    second = CaptureSession("second-filter-race", CaptureSource.SYSTEM)
    controller.prepare(second, _PassiveCaptureAdapter())
    controller.start()
    release_filter.set()
    callback.join(timeout=2.0)

    assert not callback.is_alive()
    assert controller._queue.empty()
    assert second.event_count == 0
    controller.stop()

    second_adapter = _PassiveCaptureAdapter()
    second = CaptureSession("second", CaptureSource.SYSTEM)
    controller.prepare(second, second_adapter)
    controller.start()
    assert first_adapter.emit is not None
    first_adapter.emit(
        NetworkEvent(
            session_id=first.id,
            source_type=CaptureSource.SYSTEM,
            protocol="HTTP",
            direction="out",
            size=7,
        )
    )

    assert controller._queue.empty()
    assert second.event_count == 0
    controller.stop()


def test_capture_ignores_late_filter_failure_after_stop(store) -> None:
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    session = CaptureSession("late-filter-failure", CaptureSource.SYSTEM)
    controller.prepare(session, _PassiveCaptureAdapter())
    controller.start()
    filter_entered = threading.Event()
    release_filter = threading.Event()

    def blocking_failure(_event) -> bool:
        filter_entered.set()
        assert release_filter.wait(timeout=2.0)
        raise RuntimeError("late filter failure")

    controller._filter = blocking_failure                                        
    event = NetworkEvent(
        session_id=session.id,
        source_type=CaptureSource.SYSTEM,
        protocol="HTTP",
        direction="out",
        size=3,
    )
    callback = threading.Thread(target=controller.emit, args=(event,))
    callback.start()
    assert filter_entered.wait(timeout=1.0)

    controller.stop()
    release_filter.set()
    callback.join(timeout=2.0)

    assert not callback.is_alive()
    assert controller._source_error is None
    assert session.state is CaptureState.COMPLETED

    replacement = CaptureSession("after-late-filter-failure", CaptureSource.SYSTEM)
    controller.prepare(replacement, _PassiveCaptureAdapter())
    controller.stop(cancelled=True)


def test_capture_serializes_filter_failure_commit_with_stop(store) -> None:
    class BlockingSecondProbe(threading.Event):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0
            self.second_probe = threading.Event()
            self.release_probe = threading.Event()

        def is_set(self) -> bool:
            self.calls += 1
            observed = super().is_set()
            if self.calls == 2:
                self.second_probe.set()
                assert self.release_probe.wait(timeout=2.0)
            return observed

    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    session = CaptureSession("filter-stop-commit-order", CaptureSource.SYSTEM)
    controller.prepare(session, _PassiveCaptureAdapter())
    session.state = CaptureState.CAPTURING
    stopping = BlockingSecondProbe()
    controller._stopping = stopping

    def fail_filter(_event) -> bool:
        raise RuntimeError("filter failed before stop commit")

    controller._filter = fail_filter
    event = NetworkEvent(
        session_id=session.id,
        source_type=CaptureSource.SYSTEM,
        protocol="HTTP",
        direction="out",
        size=5,
    )
    callback = threading.Thread(target=controller.emit, args=(event,))
    callback.start()
    assert stopping.second_probe.wait(timeout=1.0)

    stop_errors: list[ArenyxaError] = []

    def stop_capture() -> None:
        try:
            controller.stop()
        except ArenyxaError as exc:
            stop_errors.append(exc)

    stop_thread = threading.Thread(target=stop_capture)
    stop_thread.start()
    time.sleep(0.05)
                                                                                         
    assert stop_thread.is_alive()

    stopping.release_probe.set()
    callback.join(timeout=2.0)
    stop_thread.join(timeout=2.0)

    assert not callback.is_alive() and not stop_thread.is_alive()
    assert len(stop_errors) == 1
    assert stop_errors[0].code == "CAPTURE_SOURCE_LOST"
    assert session.state is CaptureState.FAILED


def test_capture_writer_start_failure_is_terminal_and_reusable(store, monkeypatch) -> None:
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    adapter = _PassiveCaptureAdapter()
    failed = CaptureSession("thread-start-failure", CaptureSource.SYSTEM)
    controller.prepare(failed, adapter)

    def fail_thread_start(_thread) -> None:
        raise RuntimeError("thread resource exhausted")

    with monkeypatch.context() as patch:
        patch.setattr(threading.Thread, "start", fail_thread_start)
        with pytest.raises(RuntimeError, match="thread resource exhausted"):
            controller.start()

    assert failed.state == CaptureState.FAILED
    assert adapter.start_calls == 0
    assert adapter.stop_calls == 0
    assert controller._writer is None
    persisted = next(item for item in store.list_captures() if item["id"] == failed.id)
    assert persisted["state"] == "failed"

    replacement = CaptureSession("replacement", CaptureSource.SYSTEM)
    controller.prepare(replacement, _PassiveCaptureAdapter())
    assert controller.session is replacement
    controller.stop(cancelled=True)


def test_capture_pause_resume_roll_back_when_persistence_fails(store, monkeypatch) -> None:
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    adapter = _PassiveCaptureAdapter()
    session = CaptureSession("control-persistence", CaptureSource.SYSTEM)
    controller.prepare(session, adapter)
    controller.start()
    real_save = store.save_capture
    fail_state: list[CaptureState] = [CaptureState.PAUSED]

    def fail_selected_state(item) -> None:
        if fail_state and item.state is fail_state[0]:
            fail_state.clear()
            raise OSError("disk unavailable")
        real_save(item)

    monkeypatch.setattr(store, "save_capture", fail_selected_state)
    with pytest.raises(OSError, match="disk unavailable"):
        controller.pause()
    assert session.state is CaptureState.CAPTURING
    assert (adapter.pause_calls, adapter.resume_calls) == (1, 1)

    controller.pause()
    assert session.state is CaptureState.PAUSED
    fail_state.append(CaptureState.CAPTURING)
    with pytest.raises(OSError, match="disk unavailable"):
        controller.resume()
    assert session.state is CaptureState.PAUSED
    assert (adapter.pause_calls, adapter.resume_calls) == (3, 2)
    controller.stop(cancelled=True)


def test_run_handle_serializes_pause_resume_persistence_order() -> None:
    run = Run(task_id="control-order", task_snapshot={})
    run.status = RunStatus.RUNNING
    token = CancellationToken()
    future: Future[Run] = Future()
    pause_persist_entered = threading.Event()
    release_pause_persist = threading.Event()
    persisted: list[RunStatus] = []

    def persist(_run_id: str, status: RunStatus) -> bool:
        if status == RunStatus.PAUSED:
            pause_persist_entered.set()
            assert release_pause_persist.wait(timeout=2.0)
        persisted.append(status)
        return True

    handle = RunHandle(run, token, future, persist_status=persist)
    pause_thread = threading.Thread(target=handle.pause)
    pause_thread.start()
    assert pause_persist_entered.wait(timeout=1.0)

    resume_thread = threading.Thread(target=handle.resume)
    resume_thread.start()
    time.sleep(0.05)
    assert resume_thread.is_alive()
    assert persisted == []

    release_pause_persist.set()
    pause_thread.join(timeout=2.0)
    resume_thread.join(timeout=2.0)
    assert not pause_thread.is_alive() and not resume_thread.is_alive()
    assert persisted == [RunStatus.PAUSED, RunStatus.RUNNING]
    assert run.status == RunStatus.RUNNING
    assert token.paused is False


def test_run_handle_cancel_removes_not_yet_started_future() -> None:
    run = Run(task_id="queued-cancel", task_snapshot={}, status=RunStatus.QUEUED)
    token = CancellationToken()
    future: Future[Run] = Future()
    handle = RunHandle(run, token, future)

    handle.cancel()

    assert token.cancelled is True
    assert future.cancelled() is True


def _workflow(workflow_id: str) -> Workflow:
    return Workflow(
        workflow_id,
        [
            WorkflowNode("source", {}, id="source", next_ids=["sink"]),
            WorkflowNode("sink", {}, id="sink"),
        ],
        id=workflow_id,
        version="1.0.0",
    )


def _source_revision(store) -> DatasetRevision:
    revision = DatasetRevision("shutdown-source", [], {"record": {"value": 1}}, schema={"value": "integer"})
    store.save_revision(revision)
    store.upsert_dataset(
        "shutdown-source",
        "shutdown-source",
        current_revision_id=revision.id,
    )
    return revision


def test_workflow_shutdown_waits_for_preflight_repository_operation(store, monkeypatch) -> None:
    source = _source_revision(store)
    runtime = WorkflowDatasetService(store, WorkflowEngine(), DataLineageService(store))
    original_get_revision = store.get_revision_metadata
    repository_entered = threading.Event()
    release_repository = threading.Event()

    def blocking_get_revision(revision_id: str, *args, **kwargs):
        if revision_id == source.id and not repository_entered.is_set():
            repository_entered.set()
            assert release_repository.wait(timeout=2.0)
        return original_get_revision(revision_id, *args, **kwargs)

    monkeypatch.setattr(store, "get_revision_metadata", blocking_get_revision)
    execution_errors: list[Exception] = []

    def execute() -> None:
        try:
            runtime.execute_revision(_workflow("shutdown-race"), source.id, "shutdown-output")
        except ArenyxaError as exc:                                     
            execution_errors.append(exc)

    execution_thread = threading.Thread(target=execute)
    execution_thread.start()
    assert repository_entered.wait(timeout=1.0)

    shutdown_started = threading.Event()
    shutdown_results: list[bool] = []

    def shutdown() -> None:
        shutdown_started.set()
        shutdown_results.append(runtime.shutdown(wait=True, timeout=2.0))

    shutdown_thread = threading.Thread(target=shutdown)
    shutdown_thread.start()
    assert shutdown_started.wait(timeout=1.0)
    time.sleep(0.05)
    assert shutdown_thread.is_alive()

    release_repository.set()
    execution_thread.join(timeout=2.0)
    shutdown_thread.join(timeout=2.0)
    assert not execution_thread.is_alive() and not shutdown_thread.is_alive()
    assert shutdown_results == [True]
    assert len(execution_errors) == 1
    assert isinstance(execution_errors[0], ArenyxaError)
    assert execution_errors[0].code == "RUN_CANCELLED"
