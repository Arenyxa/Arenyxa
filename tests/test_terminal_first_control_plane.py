from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from arenyxa.application.command_runtime import ArenyxaCommandRuntime, CommandRuntimeError
from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION
from arenyxa.application.terminal import TerminalMode, TerminalSession
from arenyxa.bootstrap import bootstrap
from arenyxa.domain.models import RequestSpec, Task


@pytest.fixture()
def context(tmp_path: Path):
    value = bootstrap(tmp_path / "runtime", start_scheduler=False)
    value.settings.developer_mode = True
    value.settings.developer_terms_version = DEVELOPER_TERMS_VERSION
    value.settings.developer_terms_accepted_at = "2026-08-18T12:00:00+00:00"
    value.settings.developer_direct_shell_enabled = True
    value.settings.save(value.paths.root / "settings.json")
    try:
        yield value
    finally:
        value.shutdown()


def test_command_runtime_requires_developer_mode_for_operational_commands(tmp_path: Path) -> None:
    context = bootstrap(tmp_path / "locked", start_scheduler=False)
    try:
        runtime = context.command_runtime or ArenyxaCommandRuntime(context)
        assert runtime.execute("version")["ok"] is True
        assert runtime.execute("help")["ok"] is True
        with pytest.raises(CommandRuntimeError) as captured:
            runtime.execute("status")
        assert captured.value.code == "DEVELOPER_MODE_REQUIRED"
    finally:
        context.shutdown()


def test_command_runtime_help_completion_and_json(context) -> None:
    runtime = context.command_runtime
    result = runtime.execute("help")
    assert result["data"]["groups"]["proxy"][:5] == ["status", "start", "stop", "history", "inspect"]
    assert {"pending", "resolve", "export-har", "autoresponder-list", "match-list"}.issubset(
        set(result["data"]["groups"]["proxy"])
    )
    assert runtime.complete("fl") == ["fleet", "flow"]
    assert "workers" in runtime.complete("fleet w")
    json_result = runtime.execute("status --json")
    assert json_result["format"] == "json"
    assert '"developer_authorized": true' in runtime.render(json_result).lower()


def test_command_runtime_task_run_and_run_control(context) -> None:
    task = Task(name="terminal-control", requests=[RequestSpec(url="http://127.0.0.1:9/")])
    context.store.save_task(task)
    runtime = context.command_runtime

    listed = runtime.execute("task list --limit 10")["data"]
    assert any(row["id"] == task.id for row in listed)
    shown = runtime.execute(f"task show {task.id}")["data"]
    assert shown["name"] == "terminal-control"

    started = runtime.execute(f"task run {task.id}")["data"]
    assert started["task_id"] == task.id
    run_id = started["run_id"]
    assert run_id.startswith("run_")
    runtime.execute(f"run cancel {run_id}")
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        row = context.store.get_run(run_id)
        if row and str(row.get("status")) in {"cancelled", "failed", "completed", "partial"}:
            break
        time.sleep(0.05)
    assert context.store.get_run(run_id) is not None


def test_command_runtime_dataset_flow_and_fleet_queries(context) -> None:
    runtime = context.command_runtime
    assert runtime.execute("dataset list")["data"] == []
    assert isinstance(runtime.execute("flow list")["data"], list)
    with pytest.raises(CommandRuntimeError) as fleet_error:
        runtime.execute("fleet status")
    assert fleet_error.value.code == "ENTERPRISE_VAULT_LOCKED"


def test_command_runtime_uses_shared_proxy_and_mitm_engines(context) -> None:
    runtime = context.command_runtime
    assert context.proxy_engine is not None
    assert context.mitm_engine is not None
    proxy = runtime.execute("proxy status")["data"]
    assert proxy["running"] is False
    assert proxy["host"] == "127.0.0.1"
    mitm = runtime.execute("mitm status")["data"]
    assert mitm["running"] is False


def test_terminal_capabilities_expose_persistent_shells(context) -> None:
    payload = context.command_runtime.execute("terminal capabilities")["data"]
    assert "powershell-session" in payload["persistent_shell_modes"]
    assert "cmd-session" in payload["persistent_shell_modes"]
    assert payload["direct_shell_enabled"] is True


def test_python_persistent_session_preserves_state_and_has_no_command_timeout(tmp_path: Path) -> None:
    session = TerminalSession(tmp_path / "projects", default_timeout_seconds=1)
    launch = session.build_launch("x = 41", TerminalMode.PYTHON_SESSION)
    assert launch.persistent is True
    chunks: list[str] = []
    results = []
    session.start(launch, chunks.append, results.append)
    time.sleep(0.2)
    assert session.active_persistent is True
    assert session.active_mode == TerminalMode.PYTHON_SESSION
    assert session.send_input("x = 41") is True
    assert session.send_input("print(x + 1)") is True
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and "42" not in "".join(chunks):
        time.sleep(0.05)
    assert "42" in "".join(chunks)
    time.sleep(1.1)
    assert session.is_running is True
    assert session.stop() is True
    assert session.wait(5)
    assert results and results[0].cancelled is True


def test_shell_session_launch_contracts_are_persistent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = TerminalSession(tmp_path / "projects")
    monkeypatch.setattr(session, "_find_powershell", lambda: os.sys.executable)
    powershell = session.build_launch("Write-Output hi", TerminalMode.POWERSHELL_SESSION)
    assert powershell.persistent is True
    assert "-NoExit" in powershell.arguments
    if os.name == "nt":
        cmd = session.build_launch("dir", TerminalMode.CMD_SESSION)
        assert cmd.persistent is True
        assert "/K" in cmd.arguments
    else:
        with pytest.raises(OSError):
            session.build_launch("dir", TerminalMode.CMD_SESSION)


def test_internal_pipeline_filters_selects_and_limits(context) -> None:
    for index in range(3):
        context.store.save_task(Task(name=f"pipe-{index}", requests=[RequestSpec(url=f"http://127.0.0.1:{10000 + index}/")]))
    runtime = context.command_runtime
    result = runtime.execute("task list --limit 20 | where name=pipe-1 | select id,name | take 1")
    assert len(result["data"]) == 1
    assert result["data"][0]["name"] == "pipe-1"
    assert set(result["data"][0]) == {"id", "name"}


def test_packet_and_extraction_command_groups_are_discoverable(context) -> None:
    runtime = context.command_runtime
    assert runtime.complete("pa") == ["packet"]
    assert runtime.complete("ex") == ["export", "extraction"]
    assert runtime.execute("packet sessions")["data"] == []
    preview = runtime.execute("extraction dry-run missing-session --field title:css:h1")["data"]
    assert preview["records"] == []
    assert preview["warnings"]


def test_web_autopilot_validation_and_automation_list(context) -> None:
    runtime = context.command_runtime
    status = runtime.execute("web autopilot-status")["data"]
    assert status["available"] is True
    validation = runtime.execute("web autopilot-validate --samples 80")["data"]
    assert validation["stable"] is True
    assert runtime.execute("automation list")["data"] == []


def test_proxy_professional_cli_rules_and_export_are_bounded(context) -> None:
    runtime = context.command_runtime
    added = runtime.execute(
        'proxy autoresponder-add --host example.test --path /api/* --method GET --status 200 --body {"ok":true}'
    )["data"]
    rule_id = added["id"]
    listed = runtime.execute("proxy autoresponder-list")["data"]
    assert any(row["id"] == rule_id for row in listed)
    removed = runtime.execute(f"proxy autoresponder-remove {rule_id}")["data"]
    assert removed["removed"] is True

    match = runtime.execute(
        'proxy match-add --phase request --scope header --match old --replace new --host example.test --header X-Test'
    )["data"]
    match_id = match["id"]
    assert any(row["id"] == match_id for row in runtime.execute("proxy match-list")["data"])
    assert runtime.execute(f"proxy match-remove {match_id}")["data"]["removed"] is True

    exported = runtime.execute("proxy export-har terminal/session.har")["data"]
    exported_path = Path(exported["path"])
    assert exported_path.is_file()
    assert exported_path.is_relative_to(context.paths.exports)
    with pytest.raises(CommandRuntimeError) as denied:
        runtime.execute("proxy export-har ../../outside.har")
    assert denied.value.code == "EXPORT_PATH_DENIED"


def test_proxy_resolve_missing_intercept_is_explicit(context) -> None:
    with pytest.raises(CommandRuntimeError) as captured:
        context.command_runtime.execute("proxy resolve missing forward")
    assert captured.value.code == "INTERCEPT_NOT_FOUND"


def test_flow_cli_exposes_execution_contract(context) -> None:
    assert "run" in context.command_runtime.help("flow")["commands"]
    with pytest.raises(CommandRuntimeError) as captured:
        context.command_runtime.execute("flow run only-one-id")
    assert captured.value.code == "USAGE"


def test_external_terminal_source_requires_valid_developer_authorization() -> None:
    source = Path("src/arenyxa/presentation/pages/tools_terminal_execution.py").read_text(encoding="utf-8")
    marker = "def _execute_external(self, command: str, mode: TerminalMode) -> None:"
    block = source.split(marker, 1)[1].split("def ", 1)[0]
    assert "authorization_from_settings(self.context.settings)" in block
    assert "authorization.valid" in block
    assert "developer_mode or self._root_workstation_active()" not in block


def test_headless_external_terminal_run_requires_confirmation_and_is_bounded(context) -> None:
    runtime = context.command_runtime
    with pytest.raises(CommandRuntimeError) as captured:
        runtime.execute('terminal run python --command "print(42)"')
    assert captured.value.code == "EXTERNAL_CONFIRMATION_REQUIRED"

    result = runtime.execute('terminal run python --confirm-external --command "print(42)"')["data"]
    assert result["exit_code"] == 0
    assert result["timed_out"] is False
    assert "42" in result["output"]
    assert result["mode"] == "python"


def test_automation_cli_full_lifecycle(context) -> None:
    task = Task(name="scheduled-cli", requests=[RequestSpec(url="http://127.0.0.1:9/")])
    context.store.save_task(task)
    runtime = context.command_runtime
    created = runtime.execute(
        f"automation add --task {task.id} --kind interval --minutes 15 --timezone UTC --disabled"
    )["data"]
    schedule_id = created["id"]
    assert created["task_id"] == task.id
    assert created["enabled"] is False
    assert runtime.execute(f"automation show {schedule_id}")["data"]["id"] == schedule_id

    enabled = runtime.execute(f"automation enable {schedule_id}")["data"]
    assert enabled["enabled"] is True
    disabled = runtime.execute(f"automation disable {schedule_id}")["data"]
    assert disabled["enabled"] is False

    started = runtime.execute(f"automation run-now {schedule_id}")["data"]
    assert started["schedule_id"] == schedule_id
    assert started["task_id"] == task.id
    assert started["run_id"].startswith("run_")
    handle = next(item for item in context.runner.active_handles() if item.run.id == started["run_id"])
    handle.cancel()

    removed = runtime.execute(f"automation remove {schedule_id}")["data"]
    assert removed == {"schedule_id": schedule_id, "removed": True}
    with pytest.raises(CommandRuntimeError) as missing:
        runtime.execute(f"automation show {schedule_id}")
    assert missing.value.code == "SCHEDULE_NOT_FOUND"


def test_run_export_is_confined_and_machine_readable(context) -> None:
    from arenyxa.domain.models import ResultRecord, Run

    task = Task(name="export-cli", requests=[RequestSpec(url="http://127.0.0.1/")])
    context.store.save_task(task)
    run = Run(task_id=task.id, task_snapshot=task.to_dict())
    context.store.save_run(run)
    context.store.append_results([
        ResultRecord(task.id, run.id, "http://127.0.0.1/", {"value": 7, "label": "terminal"})
    ])
    exported = context.command_runtime.execute(f"run export {run.id} cli/run.jsonl --format jsonl")["data"]
    path = Path(exported["path"])
    assert exported["records"] == 1
    assert path.is_relative_to(context.paths.exports)
    assert '"value": 7' in path.read_text(encoding="utf-8")
    with pytest.raises(CommandRuntimeError) as denied:
        context.command_runtime.execute(f"run export {run.id} ../../escape.jsonl --format jsonl")
    assert denied.value.code == "EXPORT_PATH_DENIED"


def test_fleet_snapshot_export_is_bounded_and_confined(context) -> None:
    class FakeFleet:
        def remote_ops_snapshot(self):
            return {
                "queue": {"database_integrity": "ok"},
                "workers": [{"worker_id": "worker-1", "state": "healthy"}],
                "jobs": [{"job_id": "job-1", "state": "queued"}],
            }

    original = context.enterprise_server
    context.enterprise_server = FakeFleet()
    try:
        result = context.command_runtime.execute("fleet export-snapshot cli/fleet.json")["data"]
        path = Path(result["path"])
        assert path.is_relative_to(context.paths.exports)
        assert result["workers"] == 1
        assert result["jobs"] == 1
        assert json.loads(path.read_text(encoding="utf-8"))["workers"][0]["worker_id"] == "worker-1"
    finally:
        context.enterprise_server = original


def test_pipeline_count_and_unique(context) -> None:
    for name in ("same", "same", "other"):
        context.store.save_task(Task(name=name, requests=[RequestSpec(url="http://127.0.0.1/")]))
    counted = context.command_runtime.execute("task list --limit 20 | count")["data"]
    assert counted["count"] >= 3
    unique = context.command_runtime.execute("task list --limit 20 | unique name | select name")['data']
    names = [row["name"] for row in unique]
    assert names.count("same") == 1
    assert "other" in names


def test_terminal_network_diagnostics_are_first_class_commands(context) -> None:
    runtime = context.command_runtime
    capabilities = runtime.execute("terminal net-capabilities")["data"]
    assert capabilities["resolver"] is True
    assert capabilities["tcp_probe"] is True
    assert capabilities["tls_probe"] is True
    protocol = runtime.execute("terminal net-protocol tcp")["data"]
    assert protocol["number"] == 6
    service = runtime.execute("terminal net-service --port 80 --protocol tcp")["data"]
    assert service["port"] == 80
    terminal_capabilities = runtime.execute("terminal capabilities")["data"]
    assert terminal_capabilities["network_diagnostics"]["resolver"] is True


def test_terminal_packet_protocol_catalog_and_native_decode(context) -> None:
    runtime = context.command_runtime
    protocols = runtime.execute("terminal packet-protocols --contains dns --limit 20")["data"]
    assert protocols["count"] >= 1
    assert any(row.get("protocol") in {"dns", "mdns"} for row in protocols["protocols"])
    capabilities = runtime.execute("terminal packet-capabilities")["data"]
    assert capabilities["native_protocol_count"] >= 40
    assert capabilities["coverage"]["native_protocol_count"] >= 40
    ethernet_arp = "ffffffffffff00112233445508060001080006040001001122334455c0a80101000000000000c0a80102"
    decoded = runtime.execute(f"terminal packet-decode --hex {ethernet_arp}")["data"]
    assert decoded["protocols"][:2] == ("ethernet", "arp") or decoded["protocols"][:2] == ["ethernet", "arp"]


def test_terminal_can_inspect_capture_info_frames_summaries_and_stats(context, tmp_path: Path) -> None:
    import struct

    dns_name = b"\x05stats\x07example\x00"
    dns = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + dns_name + struct.pack("!HH", 1, 1)
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0x4000, 64, 17, 0,
        b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08",
    ) + udp
    frame = bytes.fromhex("00112233445566778899aabb0800") + ip
    capture = tmp_path / "terminal-native.pcap"
    capture.write_bytes(
        b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1_700_000_000, 0, len(frame), len(frame)) + frame
    )
    runtime = context.command_runtime
    info = runtime.execute(f"terminal packet-info {capture}")["data"]
    assert "pcap" in info["info"].casefold()
    summary = runtime.execute(f"terminal packet-summary {capture} --limit 10")["data"]
    assert summary["count"] == 1
    assert summary["packets"][0]["protocol"] == "dns"
    decoded = runtime.execute(f"terminal packet-frame {capture} --number 1 --no-raw")["data"]
    assert decoded["application_protocol"] == "dns"
    stats = runtime.execute(f"terminal packet-stats {capture}")["data"]
    assert "dns" in stats["protocol_hierarchy"].casefold()
