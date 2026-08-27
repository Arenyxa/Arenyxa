from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import arenyxa
from arenyxa.application.terminal import TerminalLaunch, TerminalMode, TerminalSession
from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.plugins import PluginSandbox


ROOT = Path(__file__).resolve().parents[1]


class BlockingStartAdapter:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.stop_calls = 0

    def start(self, _session, _emit) -> None:
        self.entered.set()
        assert self.release.wait(3.0)

    def stop(self) -> None:
        self.stop_calls += 1

    def pause(self) -> None:
        return

    def resume(self) -> None:
        return


class PausedTailAdapter:
    def __init__(self) -> None:
        self.session: CaptureSession | None = None
        self.emit = None

    def start(self, session, emit) -> None:
        self.session = session
        self.emit = emit

    def stop(self) -> None:
        assert self.session is not None and self.emit is not None
        self.emit(
            NetworkEvent(
                self.session.id,
                CaptureSource.BROWSER,
                "https",
                "bidirectional",
                128,
                host="tail.example",
            )
        )

    def pause(self) -> None:
        return

    def resume(self) -> None:
        return


def test_capture_start_stop_lifecycle_is_serialized(store) -> None:
    adapter = BlockingStartAdapter()
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    session = CaptureSession("serialized-start-stop", CaptureSource.BROWSER)
    controller.prepare(session, adapter)

    start_errors: list[BaseException] = []
    stop_errors: list[BaseException] = []
    stop_finished = threading.Event()

    def run_start() -> None:
        try:
            controller.start()
        except BaseException as exc:                                         
            start_errors.append(exc)

    def run_stop() -> None:
        try:
            controller.stop(cancelled=True)
        except BaseException as exc:                                         
            stop_errors.append(exc)
        finally:
            stop_finished.set()

    start_thread = threading.Thread(target=run_start)
    start_thread.start()
    assert adapter.entered.wait(1.5)

    stop_thread = threading.Thread(target=run_stop)
    stop_thread.start()
    time.sleep(0.08)
    assert not stop_finished.is_set(), "stop() must not finalize while adapter.start() still owns lifecycle"

    adapter.release.set()
    start_thread.join(2.0)
    stop_thread.join(2.0)
    assert not start_thread.is_alive() and not stop_thread.is_alive()
    assert start_errors == []
    assert stop_errors == []
    assert adapter.stop_calls == 1
    assert session.state is CaptureState.CANCELLED


def test_paused_capture_stop_commits_synchronous_tail_event(store) -> None:
    adapter = PausedTailAdapter()
    controller = CaptureController(store, queue_capacity=8, flush_size=1)
    session = CaptureSession("paused-tail", CaptureSource.BROWSER)
    controller.prepare(session, adapter)
    controller.start()
    controller.pause()
    assert session.state is CaptureState.PAUSED

    result = controller.stop()
    assert result.state is CaptureState.COMPLETED
    assert result.event_count == 1
    assert result.bytes_captured == 128


def test_terminal_does_not_reuse_slot_before_reader_cleanup(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects")
                                                                                              
    session._process = SimpleNamespace(poll=lambda: 0, pid=4242)                            
    launch = TerminalLaunch(
        mode=TerminalMode.DIRECT,
        executable=sys.executable,
        arguments=("-c", "print('new')"),
        cwd=session.root,
        display="python",
        encoding="utf-8",
    )
    with pytest.raises(RuntimeError, match="cleanup is still finishing"):
        session.start(launch, lambda _text: None, lambda _result: None)


def test_plugin_sandbox_supports_sibling_modules_under_isolated_python(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "helper.py").write_text("VALUE = 73\n", encoding="utf-8")
    (plugin / "main.py").write_text(
        "import helper\n\ndef handle(request):\n    return {'value': helper.VALUE, 'echo': request.get('echo')}\n",
        encoding="utf-8",
    )
    (plugin / "plugin.json").write_text(
        json.dumps(
            {
                "id": "beta2.sibling-import",
                "name": "Sibling Import",
                "version": "1.0.0",
                "entry": "main.py",
                "api_version": "1",
                "min_app_version": "6.0.0",
                "permissions": {},
            }
        ),
        encoding="utf-8",
    )
    response = PluginSandbox().invoke(plugin, {"echo": "ok"}, {})
    assert response == {"value": 73, "echo": "ok"}


def test_application_quit_orders_context_shutdown_before_data_root_release() -> None:
    source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    assert "application.aboutToQuit.connect(data_root_lease.release)" not in source
    assert "application.aboutToQuit.connect(finalize_runtime)" in source
    finalizer = source[source.index("    def finalize_runtime()") : source.index("    application.aboutToQuit.connect(finalize_runtime)")]
    assert finalizer.index("context.shutdown()") < finalizer.index("data_root_lease.release()")


def test_v66_final_version_identity_is_consistent_and_package_safe() -> None:
    assert arenyxa.__version__ == "8.1"
    assert arenyxa.__package_version__ == "8.1.0"
    assert arenyxa.__compat_version__ == "6.8.0"
    assert 'version = "8.1.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version_info = (ROOT / "packaging" / "version_info.txt").read_text(encoding="utf-8")
    assert "filevers=(8,1,0,0)" in version_info
    assert "ProductVersion', '8.1'" in version_info
    installer = (ROOT / "packaging" / "installer.iss").read_text(encoding="utf-8")
    assert '#define MyAppVersion "8.1"' in installer
    assert "OutputBaseFilename=Arenyxa_V8.1_Setup_x64" in installer


def test_repair_worker_refuses_to_mutate_when_data_root_is_owned(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.repair as repair_module
    from arenyxa.infrastructure.data_root_lock import DataRootLease
    from arenyxa.repair import RepairEngine, RepairPlan

    data_root = tmp_path / "data"
    blocker = DataRootLease(data_root)
    assert blocker.acquire() is True
    try:
        monkeypatch.setattr(repair_module, "REPAIR_LEASE_WAIT_SECONDS", 0.01)
        plan = RepairPlan(
            install_root=str(ROOT),
            data_root=str(data_root),
            categories=["cache_temp"],
            parent_pid=0,
            relaunch=False,
            source_mode=True,
        )
        result = RepairEngine(plan).run()
        assert result.success is False
        assert result.actions == []
        assert any("数据目录仍被另一个" in item for item in result.unresolved)
        assert not (data_root / "repair" / "logs").exists()
    finally:
        blocker.release()


def test_process_network_attribution_access_denied_is_nonfatal(monkeypatch) -> None:
    import psutil
    from arenyxa.infrastructure.capture.adapters import ProcessNetworkMonitor

    sentinel = [{"pid": 7, "process": "", "local": "127.0.0.1:1", "remote": "", "status": "", "family": "", "type": "TCP"}]
    monkeypatch.setattr(psutil, "net_connections", lambda **_kwargs: (_ for _ in ()).throw(psutil.AccessDenied(pid=1)))
    monkeypatch.setattr(ProcessNetworkMonitor, "_netstat_snapshot", staticmethod(lambda: sentinel))
    assert ProcessNetworkMonitor().snapshot() == sentinel


def test_process_network_attribution_netstat_failure_returns_empty(monkeypatch) -> None:
    import subprocess
    from arenyxa.infrastructure.capture.adapters import ProcessNetworkMonitor

    def fail(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("netstat", 5)

    monkeypatch.setattr(subprocess, "run", fail)
    assert ProcessNetworkMonitor._netstat_snapshot() == []


def test_repair_marker_blocks_live_worker_and_cleans_stale_marker(tmp_path: Path) -> None:
    import os
    import arenyxa.repair as repair_module

    token = "live-token"
    marker_path = repair_module._write_repair_marker(tmp_path, os.getpid(), token, "active")
    assert repair_module.repair_worker_active(tmp_path) is True
    repair_module.clear_repair_marker(tmp_path, token)
    assert not marker_path.exists()

    marker_path = repair_module._write_repair_marker(tmp_path, 999_999_999, "stale-token", "active")
    assert repair_module.repair_worker_active(tmp_path) is False
    assert not marker_path.exists()


def test_fresh_repair_handoff_fails_closed_if_parent_disappears(tmp_path: Path) -> None:
    import arenyxa.repair as repair_module

    marker_path = repair_module._write_repair_marker(tmp_path, 999_999_999, "handoff-token", "handoff")
    assert repair_module.repair_worker_active(tmp_path) is True
    repair_module.clear_repair_marker(tmp_path, "handoff-token")
    assert not marker_path.exists()


def test_launch_repair_worker_publishes_marker_before_child_spawn(tmp_path: Path, monkeypatch) -> None:
    import os
    import arenyxa.repair as repair_module
    from arenyxa.repair import RepairPlan

    data_root = tmp_path / "data"
    plan_path = data_root / "repair" / "pending_repair_plan.json"
    plan = RepairPlan(
        install_root=str(ROOT),
        data_root=str(data_root),
        categories=["cache_temp"],
        parent_pid=os.getpid(),
        relaunch=False,
        source_mode=True,
    )
    plan.save(plan_path)
    observed: dict[str, object] = {}

    def fake_popen(*_args, **_kwargs):
        observed.update(json.loads((data_root / "repair" / repair_module.REPAIR_MARKER_NAME).read_text(encoding="utf-8")))
        return SimpleNamespace(pid=543210)

    monkeypatch.setattr(repair_module.subprocess, "Popen", fake_popen)
    process = repair_module.launch_repair_worker(plan_path)
    assert process.pid == 543210
    assert observed["state"] == "handoff"
    assert observed["owner_pid"] == os.getpid()
    active_marker = json.loads((data_root / "repair" / repair_module.REPAIR_MARKER_NAME).read_text(encoding="utf-8"))
    assert active_marker["state"] == "active"
    assert active_marker["owner_pid"] == 543210
    repair_module.clear_repair_marker(data_root)


def test_desktop_and_server_both_gate_startup_on_repair_marker() -> None:
    app_source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    server_source = (ROOT / "src" / "arenyxa" / "infrastructure" / "server.py").read_text(encoding="utf-8")
    assert "if repair_worker_active(paths.root):" in app_source
    assert "if repair_worker_active(paths.root):" in server_source


def test_repair_dependency_subprocesses_have_bounded_timeouts() -> None:
    source = (ROOT / "src" / "arenyxa" / "repair_engine.py").read_text(encoding="utf-8")
    assert "timeout=REPAIR_PIP_TIMEOUT_SECONDS" in source
    assert "timeout=REPAIR_OPTIONAL_PIP_TIMEOUT_SECONDS" in source


def test_tshark_start_rolls_back_dumpcap_if_tshark_spawn_fails(tmp_path: Path, monkeypatch) -> None:
    from arenyxa.infrastructure.capture.adapters import TsharkPacketAdapter
    import arenyxa.infrastructure.capture.adapters as adapters_module

    class FakeProcess:
        def __init__(self) -> None:
            self.stderr = None
            self.terminated = False
            self.killed = False
            self.wait_calls = 0

        def poll(self):
            return None if not self.terminated and not self.killed else 0

        def terminate(self) -> None:
            self.terminated = True

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout=None):
            self.wait_calls += 1
            return 0

    dumpcap_process = FakeProcess()
    calls = 0

    def fake_popen(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return dumpcap_process
        raise OSError("tshark spawn failed")

    monkeypatch.setattr(adapters_module.shutil, "which", lambda name: f"/fake/{name}")
    monkeypatch.setattr(TsharkPacketAdapter, "_supported_fields", classmethod(lambda cls, executable: cls.FIELDS))
    monkeypatch.setattr(adapters_module.subprocess, "Popen", fake_popen)
    adapter = TsharkPacketAdapter(raw_dir=tmp_path / "raw")
    session = CaptureSession("spawn-rollback", CaptureSource.SYSTEM)

    with pytest.raises(OSError, match="tshark spawn failed"):
        adapter.start(session, lambda _event: None)
    assert dumpcap_process.terminated is True
    assert dumpcap_process.wait_calls >= 1
    assert adapter._dumpcap is None
    assert adapter._process is None


def test_launch_repair_worker_terminates_child_if_marker_handoff_fails(tmp_path: Path, monkeypatch) -> None:
    import os
    import arenyxa.repair as repair_module
    from arenyxa.repair import RepairPlan

    data_root = tmp_path / "data"
    plan_path = data_root / "repair" / "pending_repair_plan.json"
    RepairPlan(
        install_root=str(ROOT),
        data_root=str(data_root),
        categories=["cache_temp"],
        parent_pid=os.getpid(),
        relaunch=False,
        source_mode=True,
    ).save(plan_path)

    class FakeProcess:
        pid = 654321
        def __init__(self) -> None:
            self.terminated = False
        def poll(self):
            return None if not self.terminated else 0
        def terminate(self) -> None:
            self.terminated = True
        def wait(self, timeout=None):
            return 0
        def kill(self) -> None:
            self.terminated = True

    process = FakeProcess()
    monkeypatch.setattr(repair_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    real_write = repair_module._write_repair_marker
    calls = 0

    def flaky_write(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("marker handoff failed")
        return real_write(*args, **kwargs)

    monkeypatch.setattr(repair_module, "_write_repair_marker", flaky_write)
    with pytest.raises(OSError, match="marker handoff failed"):
        repair_module.launch_repair_worker(plan_path)
    assert process.terminated is True
    assert not (data_root / "repair" / repair_module.REPAIR_MARKER_NAME).exists()


def test_source_manifest_builder_excludes_ephemeral_audit_state() -> None:
    source = (ROOT / "scripts" / "build_source_manifest.py").read_text(encoding="utf-8")
    assert '".coverage"' in source
    assert 'relative.name.startswith(".coverage.")' in source
    assert '"htmlcov"' in source
    assert 'part.endswith(".egg-info")' in source
