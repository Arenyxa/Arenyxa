from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession
from arenyxa.infrastructure.capture.controller import CaptureController


def test_worker_denied_data_root_does_not_clear_foreign_active_marker(tmp_path, monkeypatch):
    import arenyxa.repair_engine as engine_module
    import arenyxa.repair_executor as executor
    from arenyxa.repair_common import _load_repair_marker, installation_root, source_mode
    from arenyxa.repair_models import RepairPlan, RepairCategory

    data = tmp_path / 'repair-data'
    plan = RepairPlan(str(installation_root()), str(data), [RepairCategory.SETTINGS_UI.value],
                      parent_pid=0, relaunch=False, source_mode=source_mode())
    plan_path = plan.save(data / 'repair' / 'pending_repair_plan.json')
    code = '''
import os, sys
from pathlib import Path
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.repair_common import _write_repair_marker
root = Path(sys.argv[1])
owner = DataRootLease(root)
assert owner.acquire()
try:
    _write_repair_marker(root, os.getpid(), 'foreign-owner-token', 'active')
    (root / 'ready').write_text('ready')
    sys.stdin.readline()
finally:
    owner.release()
'''
    owner = subprocess.Popen([sys.executable, '-B', '-c', code, str(data)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, encoding='utf-8',
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        deadline = time.monotonic() + 3
        while not (data / 'ready').exists() and time.monotonic() < deadline:
            threading.Event().wait(.01)
        assert (data / 'ready').exists() and owner.poll() is None
        assert _load_repair_marker(data)['owner_pid'] != os.getpid()
        monkeypatch.setattr(engine_module, 'REPAIR_LEASE_WAIT_SECONDS', 0)
        monkeypatch.setattr(executor.time, 'sleep', lambda _seconds: None)
        assert executor.run_repair_worker(plan_path) == 1
        assert owner.poll() is None
        assert _load_repair_marker(data) is not None, 'lease-denied worker cleared a marker owned by a different PID'
    finally:
        owner.communicate(input='\n', timeout=3)
        assert owner.returncode == 0


@pytest.mark.parametrize('linger_after_writer_loop', [False, True])
def test_writer_exit_between_timeout_and_terminal_state_notifies_once(monkeypatch, linger_after_writer_loop):
    blocked = threading.Event()
    release = threading.Event()
    loop_done = threading.Event()
    exit_thread = threading.Event()
    notifications = []
    exit_states = []

    class BlockingQueue(queue.Queue):
        def get(self, *args, **kwargs):
            blocked.set()
            assert release.wait(2.0)
            raise queue.Empty

    store = SimpleNamespace(save_capture=lambda _session: None, save_capture_chunks=lambda *_args: None)
    controller = CaptureController(store)
    original_loop = controller._writer_loop

    def delayed_thread_return():
        original_loop()
        exit_states.append(controller.session.state)
        loop_done.set()
        if linger_after_writer_loop:
            assert exit_thread.wait(2.0)

    monkeypatch.setattr(controller, '_writer_loop', delayed_thread_return)

    class Adapter:
        def start(self, *_args):
            pass

        def stop(self):
            pass

        def committed_chunks(self):
            # Stop has observed a timed-out writer. Let it finish before the
            # stop path changes FINALIZING to FAILED and saves the final row.
            release.set()
            assert loop_done.wait(1.0)
            if not linger_after_writer_loop:
                real_join(timeout=1.0)
                assert not controller._writer.is_alive()
            return []

    session = CaptureSession('timeout-race', CaptureSource.SYSTEM)
    controller.add_finalization_listener(lambda current: notifications.append(current.id))
    controller.prepare(session, Adapter())
    controller._queue = BlockingQueue()
    controller.start()
    assert blocked.wait(1.0)
    real_join = controller._writer.join
    monkeypatch.setattr(controller._writer, 'join', lambda timeout=None: real_join(timeout=0.01))
    try:
        with pytest.raises(ArenyxaError):
            controller.stop()
        assert exit_states == [CaptureState.FINALIZING]
        assert session.state is CaptureState.FAILED
        exit_thread.set()
        real_join(timeout=1.0)
        assert notifications == [session.id], 'writer exited and terminal state was persisted, but finalization was never emitted'
    finally:
        release.set()
        exit_thread.set()
        real_join(timeout=1.0)


def _plan(tmp_path):
    from arenyxa.repair_common import installation_root, source_mode
    from arenyxa.repair_models import RepairPlan, RepairCategory

    data = tmp_path / 'data'
    plan = RepairPlan(str(installation_root()), str(data), [RepairCategory.SETTINGS_UI.value],
                      relaunch=False, source_mode=source_mode())
    return plan, plan.save(data / 'repair' / 'pending_repair_plan.json')


def test_launch_passes_its_fresh_marker_token_to_child_environment(tmp_path, monkeypatch):
    import arenyxa.repair_executor as executor
    from arenyxa.repair_common import _load_repair_marker
    from pathlib import Path

    plan, path = _plan(tmp_path)
    monkeypatch.setenv('ARENYXA_REPAIR_MARKER_TOKEN', 'unrelated-inherited-token')
    captured = {}

    def spawn(_command, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(pid=os.getpid() + 1000000)

    executor.launch_repair_worker(path, popen=spawn)
    marker = _load_repair_marker(Path(plan.data_root))
    assert captured['env']['ARENYXA_REPAIR_MARKER_TOKEN'] == marker['token']
    assert marker['token'] != 'unrelated-inherited-token'
    assert marker['state'] == 'active'


@pytest.mark.parametrize('same_pid, inherited, should_clear', [
    (True, '', True), (False, '', False),
    (False, 'owned-token', True), (False, 'different-token', False),
])
@pytest.mark.parametrize('fatal', [False, True])
def test_worker_marker_cleanup_requires_current_pid_or_handed_off_token(tmp_path, monkeypatch, same_pid, inherited, should_clear, fatal):
    import arenyxa.repair_executor as executor
    from arenyxa.repair_common import _write_repair_marker, _load_repair_marker
    from arenyxa.repair_models import RepairResult
    from pathlib import Path

    plan, path = _plan(tmp_path)
    data = Path(plan.data_root)
    owner_pid = os.getpid() if same_pid else os.getpid() + 1000000
    _write_repair_marker(data, owner_pid, 'owned-token', 'active')
    monkeypatch.setenv('ARENYXA_REPAIR_MARKER_TOKEN', inherited)
    monkeypatch.setattr(executor.time, 'sleep', lambda _seconds: None)

    def run(_engine):
        if fatal:
            raise OSError('controlled engine failure')
        return RepairResult('start', 'finish', False, [], '', [], ['controlled failure'])

    monkeypatch.setattr(executor.RepairEngine, 'run', run)
    assert executor.run_repair_worker(path) == 1
    assert (_load_repair_marker(data) is None) is should_clear


def test_worker_preserves_replacement_marker_and_plan(tmp_path, monkeypatch):
    import arenyxa.repair_executor as executor
    from arenyxa.repair_common import _write_repair_marker, _load_repair_marker
    from arenyxa.repair_models import RepairResult
    from pathlib import Path

    plan, path = _plan(tmp_path)
    data = Path(plan.data_root)
    _write_repair_marker(data, os.getpid(), 'first-token', 'active')
    monkeypatch.setenv('ARENYXA_REPAIR_MARKER_TOKEN', 'first-token')
    monkeypatch.setattr(executor.time, 'sleep', lambda _seconds: None)

    def run(_engine):
        plan.created_at = 'replacement-attempt'
        plan.save(path)
        _write_repair_marker(data, os.getpid() + 1000000, 'replacement-token', 'active')
        return RepairResult('start', 'finish', False, [], '', [], ['controlled failure'])

    monkeypatch.setattr(executor.RepairEngine, 'run', run)
    assert executor.run_repair_worker(path) == 1
    assert _load_repair_marker(data)['token'] == 'replacement-token'
    assert path.is_file(), 'older worker deleted the newer pending repair plan'


def test_capture_does_not_notify_during_terminal_persistence(monkeypatch):
    blocked = threading.Event()
    release = threading.Event()
    loop_done = threading.Event()
    notifications = []
    saving_terminal = False

    class BlockingQueue(queue.Queue):
        def get(self, *args, **kwargs):
            blocked.set()
            assert release.wait(2)
            raise queue.Empty

    def save_capture(session):
        nonlocal saving_terminal
        if session.state is CaptureState.FAILED:
            saving_terminal = True
            release.set()
            assert loop_done.wait(1)
            assert notifications == []
            saving_terminal = False

    store = SimpleNamespace(save_capture=save_capture, save_capture_chunks=lambda *_args: None)
    controller = CaptureController(store)
    adapter = SimpleNamespace(start=lambda *_args: None, stop=lambda: None)
    session = CaptureSession('during-save', CaptureSource.SYSTEM)
    controller.prepare(session, adapter)
    controller._queue = BlockingQueue()
    original = controller._writer_loop

    def run():
        original()
        loop_done.set()

    monkeypatch.setattr(controller, '_writer_loop', run)

    def finalized(current):
        assert not saving_terminal
        notifications.append(current.id)

    controller.add_finalization_listener(finalized)
    controller.start()
    assert blocked.wait(1)
    real_join = controller._writer.join
    monkeypatch.setattr(controller._writer, 'join', lambda timeout=None: real_join(timeout=.01))
    try:
        with pytest.raises(ArenyxaError):
            controller.stop()
        real_join(timeout=1)
        assert notifications == [session.id]
    finally:
        release.set()
        real_join(timeout=1)


def test_async_source_failure_notifies_after_its_terminal_save():
    notifications = []
    saved = []
    failed = threading.Event()
    store = SimpleNamespace(save_capture=lambda session: saved.append(session.state))
    controller = CaptureController(store)
    adapter = SimpleNamespace(start=lambda *_args: None, stop=lambda: None,
                              failure=lambda: OSError('controlled source failure') if failed.is_set() else None)
    session = CaptureSession('async-source-failure', CaptureSource.SYSTEM)
    controller.prepare(session, adapter)

    def finalized(current):
        assert saved[-1] is CaptureState.FAILED
        notifications.append(current.id)

    controller.add_finalization_listener(finalized)
    controller.start()
    failed.set()
    controller._writer.join(timeout=2)
    assert not controller._writer.is_alive()
    assert session.state is CaptureState.FAILED
    assert notifications == [session.id]
