from __future__ import annotations

import time

import pytest

from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.infrastructure.capture.controller import CaptureController


class FailingStore:
    def __init__(self) -> None:
        self.saved = []

    def save_capture(self, session) -> None:
        self.saved.append(session.state)

    def append_network_events(self, _events) -> None:
        raise OSError("disk full")

    def save_capture_chunks(self, _session_id, _chunks) -> None:
        return


class EmitOneAdapter:
    def start(self, session, emit) -> None:
        emit(NetworkEvent(session.id, CaptureSource.BROWSER, "https", "bidirectional", 64, host="example.test"))

    def stop(self) -> None:
        return

    def pause(self) -> None:
        return

    def resume(self) -> None:
        return


def test_writer_persistence_failure_marks_capture_failed() -> None:
    store = FailingStore()
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    session = CaptureSession("failure", CaptureSource.BROWSER)
    controller.prepare(session, EmitOneAdapter())
    controller.start()
    deadline = time.monotonic() + 2
    while controller._writer_error is None and time.monotonic() < deadline:
        time.sleep(0.01)
    with pytest.raises(ArenyxaError) as caught:
        controller.stop()
    assert caught.value.code == "CAPTURE_STORAGE_FAILED"
    assert session.state is CaptureState.FAILED
