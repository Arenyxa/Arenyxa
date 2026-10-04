from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from arenyxa.application.runtime_supervisor import ArenyxaRuntimeSupervisor
from arenyxa.application.survivability import SurvivabilityManager
from arenyxa.application.resilience_scheduler import ResilienceDrillScheduler
from arenyxa.infrastructure.external_supervisor import ExternalSupervisorClient


@pytest.mark.parametrize("owner_type,method", [
    (ArenyxaRuntimeSupervisor, "stop"),
    (SurvivabilityManager, "stop"),
    (ResilienceDrillScheduler, "shutdown"),
])
def test_monitor_timeout_retains_thread_for_retry(owner_type, method):
    owner = object.__new__(owner_type)
    owner._lock = threading.RLock()
    owner._stop = threading.Event()
    owner._external = SimpleNamespace(stop=lambda timeout: True)
    release = threading.Event()
    thread = threading.Thread(target=lambda: release.wait(2.0))
    owner._thread = thread
    thread.start()
    try:
        before = time.monotonic()
        assert getattr(owner, method)(timeout=0.01) is False
        assert time.monotonic() - before < 0.25
        assert owner._thread is thread
        assert getattr(owner, method)(timeout=0.01) is False
    finally:
        release.set()
        thread.join(1.0)
    assert getattr(owner, method)(timeout=1.0) is True
    assert owner._thread is None


def test_external_supervisor_timeout_retains_sender_and_blocks_restart(tmp_path):
    owner = ExternalSupervisorClient(tmp_path)
    release = threading.Event()
    sender = threading.Thread(target=lambda: release.wait(2.0))
    owner._sender_thread = sender
    sender.start()
    try:
        assert owner.stop(timeout=0.01) is False
        assert owner.snapshot()["ipc_sender_alive"] is True
        with pytest.raises(RuntimeError, match="draining"):
            owner.start()
    finally:
        release.set()
        sender.join(1.0)
    assert owner.stop(timeout=1.0) is True
    assert owner.snapshot()["ipc_sender_alive"] is False
