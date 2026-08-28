from __future__ import annotations

import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.capture.proxy_models import ProxyFlow, ProxySettings
from arenyxa.infrastructure.capture.proxy_persistence import ProxyPersistencePipeline
from arenyxa.infrastructure.capture.proxy_resilience import ProxyResilienceMixin


def _flow(identifier: str, sequence: int = 1) -> ProxyFlow:
    return ProxyFlow(
        id=identifier,
        sequence=sequence,
        started_at=utc_now(),
        client="127.0.0.1",
        scheme="http",
        method="GET",
        host="example.test",
        port=80,
        target=f"/{identifier}",
        completed_at=utc_now(),
    )


class _RecordingSink:
    def __init__(self, gates: dict[str, tuple[threading.Event, threading.Event]] | None = None) -> None:
        self.rows: list[str] = []
        self._lock = threading.Lock()
        self._gates = gates or {}

    def store(self, *args: Any) -> None:
        flow = args[-1]
        gate = self._gates.get(flow.id)
        if gate is not None:
            entered, release = gate
            entered.set()
            if not release.wait(5.0):
                raise AssertionError(f"persistence gate timed out for {flow.id}")
        with self._lock:
            self.rows.append(flow.id)


def _start_call(call: Callable[[], Any]) -> tuple[threading.Thread, threading.Event, dict[str, Any]]:
    completed = threading.Event()
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["result"] = call()
        except Exception as exc:  # noqa: BLE001 - test worker must relay every failure
            outcome["error"] = exc
        finally:
            completed.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, completed, outcome


def _wait_for_closing(pipeline: ProxyPersistencePipeline) -> None:
    lifecycle = getattr(pipeline, "_lifecycle", None)
    if lifecycle is not None:
        with lifecycle:
            assert lifecycle.wait_for(
                lambda: str(getattr(pipeline, "_state", "")).casefold().endswith("closing"),
                timeout=2.0,
            )
        return

    # Compatibility path makes the regression demonstrate the old boolean lifecycle race.
    deadline = time.monotonic() + 2.0
    wake = threading.Event()
    while time.monotonic() < deadline:
        with pipeline._lock:
            if bool(getattr(pipeline, "_closed", False)):
                return
        wake.wait(0.001)
    raise AssertionError("close did not enter its lifecycle gate")


def _assert_cleanly_closed(pipeline: ProxyPersistencePipeline) -> None:
    status = pipeline.status()
    assert status["unfinished"] == 0
    assert status["queue_depth"] == 0
    assert status["writer_alive"] is False
    assert status["closed"] is True


def test_admitted_enqueue_cannot_land_after_stop() -> None:
    history = _RecordingSink()
    archive = _RecordingSink()
    pipeline = ProxyPersistencePipeline(history, archive, capacity=16)
    admitted = threading.Event()
    release_admission = threading.Event()
    original_put_nowait = pipeline._queue.put_nowait

    def gated_put_nowait(item: object) -> None:
        if item is not pipeline._STOP:
            admitted.set()
            if not release_admission.wait(5.0):
                raise AssertionError("enqueue admission gate timed out")
        original_put_nowait(item)

    pipeline._queue.put_nowait = gated_put_nowait  # type: ignore[method-assign]
    enqueue_thread, enqueue_done, enqueue_outcome = _start_call(
        lambda: pipeline.enqueue("session", _flow("accepted-before-close"))
    )
    assert admitted.wait(2.0)
    close_thread, close_done, close_outcome = _start_call(lambda: pipeline.close(3.0))
    _wait_for_closing(pipeline)
    closed_before_admission_finished = close_done.wait(0.1)

    release_admission.set()
    enqueue_thread.join(2.0)
    close_thread.join(3.0)

    assert closed_before_admission_finished is False
    assert enqueue_done.is_set()
    assert close_done.is_set()
    assert "error" not in enqueue_outcome
    assert enqueue_outcome["result"] == "queued"
    assert close_outcome == {"result": True}
    assert history.rows == ["accepted-before-close"]
    assert archive.rows == ["accepted-before-close"]
    _assert_cleanly_closed(pipeline)


def test_close_racing_many_enqueues_persists_every_accepted_flow() -> None:
    history = _RecordingSink()
    archive = _RecordingSink()
    pipeline = ProxyPersistencePipeline(history, archive, capacity=16)
    accepted = ["seed"]
    rejected: list[str] = []
    result_lock = threading.Lock()
    pipeline.enqueue("session", _flow("seed", 0))
    producers = 8
    per_producer = 50
    start = threading.Barrier(producers + 1)

    def produce(worker: int) -> None:
        start.wait()
        for offset in range(per_producer):
            identifier = f"worker-{worker}-{offset}"
            try:
                pipeline.enqueue("session", _flow(identifier, worker * per_producer + offset + 1))
            except RuntimeError:
                with result_lock:
                    rejected.append(identifier)
            else:
                with result_lock:
                    accepted.append(identifier)

    threads = [threading.Thread(target=produce, args=(worker,), daemon=True) for worker in range(producers)]
    for thread in threads:
        thread.start()
    start.wait()
    assert pipeline.close(10.0) is True
    for thread in threads:
        thread.join(2.0)
        assert thread.is_alive() is False

    assert len(accepted) + len(rejected) == 1 + producers * per_producer
    assert Counter(history.rows) == Counter(accepted)
    assert Counter(archive.rows) == Counter(accepted)
    _assert_cleanly_closed(pipeline)


def test_queue_full_fallback_is_part_of_close_lifecycle() -> None:
    writer_entered = threading.Event()
    release_writer = threading.Event()
    history = _RecordingSink({"writer": (writer_entered, release_writer)})
    archive = _RecordingSink()
    pipeline = ProxyPersistencePipeline(history, archive, capacity=16)
    fallback_entered = threading.Event()
    release_fallback = threading.Event()
    original_persist = pipeline._persist

    def gated_persist(session_id: str, flow: ProxyFlow) -> None:
        if flow.id == "fallback":
            fallback_entered.set()
            if not release_fallback.wait(5.0):
                raise AssertionError("synchronous fallback gate timed out")
        original_persist(session_id, flow)

    pipeline._persist = gated_persist  # type: ignore[method-assign]
    pipeline.enqueue("session", _flow("writer", 0))
    assert writer_entered.wait(2.0)
    queued = [f"queued-{index}" for index in range(pipeline.capacity)]
    for index, identifier in enumerate(queued, start=1):
        assert pipeline.enqueue("session", _flow(identifier, index)) == "queued"

    fallback_thread, fallback_done, fallback_outcome = _start_call(
        lambda: pipeline.enqueue("session", _flow("fallback", 1000))
    )
    assert fallback_entered.wait(2.0)
    close_thread, close_done, close_outcome = _start_call(lambda: pipeline.close(5.0))
    _wait_for_closing(pipeline)

    release_writer.set()
    closed_while_fallback_was_in_flight = close_done.wait(0.5)
    release_fallback.set()
    fallback_thread.join(2.0)
    close_thread.join(5.0)

    assert closed_while_fallback_was_in_flight is False
    assert fallback_done.is_set()
    assert fallback_outcome == {"result": "synchronous_fallback"}
    assert close_outcome == {"result": True}
    expected = {"writer", "fallback", *queued}
    assert Counter(history.rows) == Counter(expected)
    assert Counter(archive.rows) == Counter(expected)
    _assert_cleanly_closed(pipeline)


def test_flush_and_close_are_bounded_repeatable_and_leave_no_tasks() -> None:
    persist_entered = threading.Event()
    release_persist = threading.Event()
    history = _RecordingSink({"blocked": (persist_entered, release_persist)})
    archive = _RecordingSink()
    pipeline = ProxyPersistencePipeline(history, archive, capacity=16)
    pipeline.enqueue("session", _flow("blocked"))
    assert persist_entered.wait(2.0)

    started = time.monotonic()
    assert pipeline.flush(0.05) is False
    assert time.monotonic() - started < 0.5

    flush_thread, flush_done, flush_outcome = _start_call(lambda: pipeline.flush(3.0))
    close_thread, close_done, close_outcome = _start_call(lambda: pipeline.close(3.0))
    _wait_for_closing(pipeline)
    assert flush_done.wait(0.1) is False
    assert close_done.wait(0.1) is False

    release_persist.set()
    flush_thread.join(3.0)
    close_thread.join(3.0)
    assert flush_outcome == {"result": True}
    assert close_outcome == {"result": True}
    assert pipeline.close(0.1) is True
    with pytest.raises(RuntimeError, match="closed"):
        pipeline.enqueue("session", _flow("too-late"))
    _assert_cleanly_closed(pipeline)


@dataclass
class _PersistenceHarness(ProxyResilienceMixin):
    history_store: _RecordingSink
    archive: _RecordingSink

    def __post_init__(self) -> None:
        self._performance_telemetry = None
        self._lock = threading.RLock()
        self.settings = ProxySettings(persistence_queue_capacity=16)
        self.persistence = self._new_persistence_pipeline(16)

    def _emit(self, _kind: str, _value: Any) -> None:
        return


def test_reconfigure_waits_for_old_pipeline_admissions_without_losing_evidence() -> None:
    history = _RecordingSink()
    archive = _RecordingSink()
    harness = _PersistenceHarness(history, archive)
    old_pipeline = harness.persistence
    admitted = threading.Event()
    release_admission = threading.Event()
    original_put_nowait = old_pipeline._queue.put_nowait

    def gated_put_nowait(item: object) -> None:
        if item is not old_pipeline._STOP:
            admitted.set()
            if not release_admission.wait(5.0):
                raise AssertionError("reconfigure admission gate timed out")
        original_put_nowait(item)

    old_pipeline._queue.put_nowait = gated_put_nowait  # type: ignore[method-assign]
    traffic_thread, traffic_done, traffic_outcome = _start_call(
        lambda: harness._persist_completed_flow("session", _flow("old-pipeline", 1))
    )
    assert admitted.wait(2.0)
    replacement_settings = ProxySettings(persistence_queue_capacity=32)

    def reconfigure() -> None:
        harness.settings = replacement_settings
        harness._reconfigure_persistence(16, replacement_settings)

    reconfigure_thread, reconfigure_done, reconfigure_outcome = _start_call(reconfigure)
    _wait_for_closing(old_pipeline)
    replaced_before_old_admission_finished = reconfigure_done.wait(0.1)

    release_admission.set()
    traffic_thread.join(2.0)
    reconfigure_thread.join(3.0)
    assert replaced_before_old_admission_finished is False
    assert traffic_done.is_set()
    assert traffic_outcome == {"result": "queued"}
    assert reconfigure_outcome == {"result": None}
    assert harness.persistence is not old_pipeline
    _assert_cleanly_closed(old_pipeline)

    assert harness._persist_completed_flow("session", _flow("new-pipeline", 2)) == "queued"
    assert harness.persistence.close(3.0) is True
    assert Counter(history.rows) == Counter({"old-pipeline", "new-pipeline"})
    assert Counter(archive.rows) == Counter({"old-pipeline", "new-pipeline"})
    _assert_cleanly_closed(harness.persistence)
