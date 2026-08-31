from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

from arenyxa.infrastructure.capture.mitm_engine import MitmEngine, MitmSettings



def _load_bridge_module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    package = types.ModuleType("mitmproxy")
    package.__path__ = []
    flowfilter = types.ModuleType("mitmproxy.flowfilter")
    flowfilter.parse = lambda source: source
    flowfilter.match = lambda _compiled, _flow: False
    monkeypatch.setitem(sys.modules, "mitmproxy", package)
    monkeypatch.setitem(sys.modules, "mitmproxy.flowfilter", flowfilter)
    monkeypatch.setenv("ARENYXA_MITM_EVENT_FILE", str(tmp_path / "events.jsonl"))
    monkeypatch.setenv("ARENYXA_MITM_PENDING_DIR", str(tmp_path / "pending"))
    monkeypatch.setenv("ARENYXA_MITM_CONTROL_DIR", str(tmp_path / "control"))
    bridge = Path(__file__).parents[1] / "src" / "arenyxa" / "infrastructure" / "capture" / "mitm_bridge.py"
    spec = importlib.util.spec_from_file_location("arenyxa_test_mitm_bridge", bridge)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def _fake_executable(tmp_path: Path) -> Path:
    path = tmp_path / ("mitmdump.exe" if __import__("os").name == "nt" else "mitmdump")
    path.write_text("", encoding="utf-8")
    return path


def test_mitm_runtime_settings_reject_remote_listener_without_opt_in():
    with pytest.raises(ValueError):
        MitmSettings(bind_host="0.0.0.0").validate()


def test_mitm_runtime_reverse_and_upstream_require_target():
    with pytest.raises(ValueError):
        MitmSettings(mode="reverse").validate()
    with pytest.raises(ValueError):
        MitmSettings(mode="upstream").validate()


def test_mitm_runtime_command_covers_professional_modes_and_rules(tmp_path: Path):
    executable = _fake_executable(tmp_path)
    settings = MitmSettings(
        executable=str(executable),
        bind_port=9090,
        mode="reverse",
        mode_spec="https://example.com",
        intercept_filter="~q & ~u example\\.com",
        map_local=["|example.com/app.js|/tmp/app.js"],
        map_remote=["|//example.com/|//localhost/"],
        modify_headers=["/~q/X-Test/1"],
        modify_body=["/~s/foo/bar"],
        block_list=[":~d tracker.example:404"],
        ignore_hosts=["ignore.example"],
        allow_hosts=["example.com"],
        http2=True,
        http3=True,
        websocket=True,
        rawtcp=True,
        anticache=True,
        anticomp=True,
    )
    engine = MitmEngine(tmp_path / "runtime", settings)
    command = engine.build_command(str(executable))
    joined = "\n".join(command)
    assert "reverse:https://example.com" in joined
    assert "map_local=|example.com/app.js|/tmp/app.js" in joined
    assert "map_remote=|//example.com/|//localhost/" in joined
    assert "modify_headers=/~q/X-Test/1" in joined
    assert "modify_body=/~s/foo/bar" in joined
    assert "block_list=:~d tracker.example:404" in joined
    assert "ignore_hosts=ignore.example" in joined
    assert "allow_hosts=example.com" in joined
    assert "http3=true" in joined
    assert str(engine.bridge_path) in command


def test_mitm_runtime_modes_build_expected_specs(tmp_path: Path):
    executable = _fake_executable(tmp_path)
    cases = [
        ("regular", "", "regular"),
        ("local", "curl", "local:curl"),
        ("wireguard", "wg.conf", "wireguard:wg.conf"),
        ("tun", "arenyxa-tun", "tun:arenyxa-tun"),
        ("socks5", "", "socks5"),
        ("dns", "", "dns"),
        ("transparent", "", "transparent"),
        ("upstream", "http://127.0.0.1:8888", "upstream:http://127.0.0.1:8888"),
    ]
    for mode, spec, expected in cases:
        engine = MitmEngine(tmp_path / mode, MitmSettings(executable=str(executable), mode=mode, mode_spec=spec))
        command = engine.build_command(str(executable))
        index = command.index("--mode")
        assert command[index + 1] == expected


def test_mitm_runtime_event_ingestion_and_filtering(tmp_path: Path):
    engine = MitmEngine(tmp_path / "mitm")
    payloads = [
        {"sequence": 1, "timestamp": 1, "event": "http.request", "flow_id": "a", "protocol": "http", "phase": "request", "method": "GET", "url": "https://example.com/a", "host": "example.com", "size": 0, "payload": {}},
        {"sequence": 2, "timestamp": 2, "event": "websocket.message", "flow_id": "b", "protocol": "websocket", "phase": "message", "direction": "client", "size": 7, "payload": {"content": {"encoding": "utf-8", "data": "hello"}}},
    ]
    engine.events_path.write_text("\n".join(json.dumps(row) for row in payloads) + "\n", encoding="utf-8")
    rows = engine.poll_events()
    assert len(rows) == 2
    assert engine.events(query="example")[0].flow_id == "a"
    assert engine.events(protocol="websocket")[0].flow_id == "b"


def test_mitm_runtime_intercept_control_channel_is_atomic(tmp_path: Path):
    engine = MitmEngine(tmp_path / "mitm")
    token = "11111111-1111-1111-1111-111111111111"
    pending = engine.pending_dir / f"{token}.json"
    pending.write_text(json.dumps({"phase": "request", "payload": {"method": "GET"}}), encoding="utf-8")
    assert engine.resolve(token, "forward", {"method": "POST"}) is True
    command = json.loads((engine.control_dir / f"{token}.json").read_text(encoding="utf-8"))
    assert command["action"] == "forward"
    assert command["edited"]["method"] == "POST"
    with pytest.raises(ValueError):
        engine.resolve(token, "resume")


def test_mitm_runtime_replay_command_uses_native_archive(tmp_path: Path):
    executable = _fake_executable(tmp_path)
    flow_file = tmp_path / "flows.mitm"
    flow_file.write_bytes(b"flow")
    engine = MitmEngine(tmp_path / "mitm", MitmSettings(executable=str(executable)))
    client = engine.replay_command(flow_file, "client")
    server = engine.replay_command(flow_file, "server")
    assert f"client_replay={flow_file}" in client
    assert f"server_replay={flow_file}" in server


def test_mitm_runtime_bridge_compiles_without_importing_dependency():
    bridge = Path(__file__).parents[1] / "src" / "arenyxa" / "infrastructure" / "capture" / "mitm_bridge.py"
    compile(bridge.read_text(encoding="utf-8"), str(bridge), "exec")



def test_mitm_bridge_background_tasks_have_strong_ownership_until_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_bridge_module(tmp_path, monkeypatch)

    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def blocked() -> None:
            started.set()
            await release.wait()

        task = module._spawn_background(blocked())
        await asyncio.wait_for(started.wait(), 1.0)
        assert task in module._BACKGROUND_TASKS

        release.set()
        await asyncio.wait_for(task, 1.0)
        await asyncio.sleep(0)
        assert task not in module._BACKGROUND_TASKS

    asyncio.run(scenario())


def test_mitm_bridge_background_task_exceptions_are_observed_and_retired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _load_bridge_module(tmp_path, monkeypatch)
    observed: list[tuple[str, str]] = []
    monkeypatch.setattr(
        module,
        "record_current_exception",
        lambda module_name, operation: observed.append((module_name, operation)),
    )

    async def scenario() -> None:
        async def fail() -> None:
            raise RuntimeError("simulated bridge task failure")

        task = module._spawn_background(fail())
        for _ in range(5):
            await asyncio.sleep(0)
            if task.done() and task not in module._BACKGROUND_TASKS:
                break
        assert task.done()
        assert task not in module._BACKGROUND_TASKS

    asyncio.run(scenario())
    assert observed == [(module.__name__, "mitm_bridge.background_task")]

def test_mitm_runtime_is_integrated_into_professional_suite():
    root = Path(__file__).parents[1]
    source = (root / "src" / "arenyxa" / "presentation" / "main_window_registry.py").read_text(encoding="utf-8")
    suite = (root / "src" / "arenyxa" / "presentation" / "pages" / "professional_suite.py").read_text(encoding="utf-8")
    assert '("network", "◫", "nav.network", NetworkPage, "core")' in source
    assert '("proxy", "⇄", "nav.proxy", ProxyPage, "core")' in source
    assert '("mitm", "⇌", "nav.mitm_proxy", MitmInterceptionPage, "core")' in source
    assert 'self.mitm_page = MitmInterceptionPage(context, theme, motion, self)' in suite
    assert 'self.tabs.addTab(self.mitm_page, "MITM Proxy")' in suite
    assert 'from arenyxa.presentation.pages.mitm_proxy import MitmInterceptionPage' in source
