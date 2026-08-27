from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SCHEMA = "arenyxa.windows-native-qualification/v2"
OPERATOR_CHECKS = (
    "startup_frozen_visual",
    "welcome_center_motion",
    "multi_monitor_window_placement",
    "dpi_100_125_150_200",
    "refresh_60_120_144_165",
    "theme_crossfade",
    "professional_navigation_transitions",
    "reduce_motion",
    "system_tray",
    "taskbar_progress",
    "terminal_split_panes",
    "terminal_ansi_rendering",
    "terminal_fullscreen_tui",
    "extraction_picker_visible_overlay",
)
AUTOMATED_CHECKS = (
    "runtime_deep_probe",
    "npcap_enumeration",
    "etw_round_trip",
    "wfp_engine_round_trip",
    "dpapi_round_trip",
    "tpm_cng_probe",
    "event_log_round_trip",
    "named_pipe_capability",
    "conpty_api",
    "conpty_powershell_session",
    "conpty_cmd_session",
    "conpty_resize",
    "playwright_chromium_launch",
)
OPTIONAL_DESTRUCTIVE_CHECKS = (
    "windows_service_install_start_stop_remove",
)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _wait_for_output(workspace: Any, session_id: str, needle: str, timeout: float = 8.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in workspace.output(session_id, tail_chars=100000):
            return True
        time.sleep(0.05)
    return False


def _terminal_checks() -> tuple[list[str], dict[str, str]]:
    passed: list[str] = []
    diagnostics: dict[str, str] = {}
    try:
        from arenyxa.application.windows_conpty import WindowsConPtySession
        from arenyxa.application.terminal_workspace import TerminalWorkspaceManager
    except (ImportError, RuntimeError) as exc:
        return passed, {"imports": f"{type(exc).__name__}: {exc}"}
    if WindowsConPtySession.supported():
        passed.append("conpty_api")
    else:
        diagnostics["conpty_api"] = "Windows runtime does not expose a supported ConPTY API"
        return passed, diagnostics
    with tempfile.TemporaryDirectory(prefix="arenyxa-native-") as raw_root:
        workspace = TerminalWorkspaceManager(Path(raw_root))
        try:
            power = workspace.create(title="qualification-powershell", mode="powershell-session")
            if power.get("backend") != "windows-conpty":
                diagnostics["conpty_powershell_session"] = f"unexpected backend: {power.get('backend')}"
            else:
                workspace.start(power["id"])
                workspace.send(power["id"], "Write-Output ARENYXA_CONPTY_POWERSHELL_OK")
                if _wait_for_output(workspace, power["id"], "ARENYXA_CONPTY_POWERSHELL_OK"):
                    passed.append("conpty_powershell_session")
                else:
                    diagnostics["conpty_powershell_session"] = "PowerShell marker was not observed"
                try:
                    resized = workspace.resize(power["id"], 140, 44)
                    if resized.get("columns") == 140 and resized.get("rows") == 44:
                        passed.append("conpty_resize")
                    else:
                        diagnostics["conpty_resize"] = f"unexpected geometry: {resized}"
                except (OSError, RuntimeError, ValueError) as exc:
                    diagnostics["conpty_resize"] = f"{type(exc).__name__}: {exc}"
            cmd = workspace.create(title="qualification-cmd", mode="cmd-session")
            if cmd.get("backend") != "windows-conpty":
                diagnostics["conpty_cmd_session"] = f"unexpected backend: {cmd.get('backend')}"
            else:
                workspace.start(cmd["id"])
                workspace.send(cmd["id"], "echo ARENYXA_CONPTY_CMD_OK")
                if _wait_for_output(workspace, cmd["id"], "ARENYXA_CONPTY_CMD_OK"):
                    passed.append("conpty_cmd_session")
                else:
                    diagnostics["conpty_cmd_session"] = "CMD marker was not observed"
        except (FileNotFoundError, KeyError, OSError, RuntimeError, ValueError) as exc:
            diagnostics.setdefault("conpty_session", f"{type(exc).__name__}: {exc}")
        finally:
            workspace.close_all()
    return passed, diagnostics


def _browser_check() -> tuple[bool, str]:
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    try:
        with sync_playwright() as runtime:
            browser = runtime.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_content("<html><body><button id='probe'>Arenyxa</button></body></html>")
            ok = page.locator("#probe").inner_text() == "Arenyxa"
            browser.close()
            return ok, "ok" if ok else "DOM marker mismatch"
    except (OSError, RuntimeError, PlaywrightError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _service_lifecycle(runtime: Any) -> tuple[bool, dict[str, Any]]:
    service_name = f"ArenyxaQualification{os.getpid()}"
    data_root = Path(tempfile.mkdtemp(prefix="arenyxa-service-qualification-"))
    evidence: dict[str, Any] = {"service": service_name, "data_dir": str(data_root)}
    try:
        installed = runtime.service_install(data_root, service_name=service_name, start="demand")
        evidence["install"] = installed
        started = runtime.service_control("start", service_name=service_name)
        evidence["start"] = started
        deadline = time.time() + 20.0
        running = False
        while time.time() < deadline:
            status = runtime.service_status(service_name=service_name)
            evidence["status_after_start"] = status
            if status.get("service_state") == "running":
                running = True
                break
            time.sleep(0.25)
        stopped = runtime.service_control("stop", service_name=service_name)
        evidence["stop"] = stopped
        removed = runtime.service_remove(service_name=service_name)
        evidence["remove"] = removed
        return bool(running and removed.get("removed")), evidence
    except Exception as exc:  # qualification must retain the complete native error
        evidence["error"] = f"{type(exc).__name__}: {exc}"[:2048]
        try:
            runtime.service_remove(service_name=service_name)
        except Exception as cleanup_exc:
            evidence["cleanup_error"] = f"{type(cleanup_exc).__name__}: {cleanup_exc}"[:1024]
        return False, evidence
    finally:
        shutil.rmtree(data_root, ignore_errors=True)


def _automated_checks(*, service_lifecycle: bool) -> tuple[list[str], dict[str, Any]]:
    from arenyxa.application.windows_runtime import WindowsRuntimeControl

    passed: list[str] = []
    diagnostics: dict[str, Any] = {}
    runtime = WindowsRuntimeControl()
    deep = runtime.status(deep=True)
    diagnostics["runtime"] = deep
    if deep.get("windows") is True:
        passed.append("runtime_deep_probe")
    if (deep.get("npcap_enumeration") or {}).get("state") == "available":
        passed.append("npcap_enumeration")
    if (deep.get("etw_round_trip") or {}).get("written") is True:
        passed.append("etw_round_trip")
    if (deep.get("wfp_engine_round_trip") or {}).get("opened") is True:
        passed.append("wfp_engine_round_trip")
    if (deep.get("dpapi") or {}).get("round_trip") is True:
        passed.append("dpapi_round_trip")
    if (deep.get("tpm_cng") or {}).get("state") == "available":
        passed.append("tpm_cng_probe")
    if (deep.get("named_pipe") or {}).get("state") == "available":
        passed.append("named_pipe_capability")
    try:
        event = runtime.write_event("Arenyxa v8.1 native qualification", level="INFORMATION")
        diagnostics["event_log"] = event
        if event.get("written") is True:
            passed.append("event_log_round_trip")
    except Exception as exc:
        diagnostics["event_log"] = f"{type(exc).__name__}: {exc}"[:1024]

    terminal_passed, terminal_diag = _terminal_checks()
    passed.extend(terminal_passed)
    diagnostics["terminal"] = terminal_diag
    browser_ok, browser_diag = _browser_check()
    diagnostics["browser"] = browser_diag
    if browser_ok:
        passed.append("playwright_chromium_launch")

    if service_lifecycle:
        ok, service_diag = _service_lifecycle(runtime)
        diagnostics["service_lifecycle"] = service_diag
        if ok:
            passed.append("windows_service_install_start_stop_remove")
    return sorted(set(passed)), diagnostics


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Record real Windows-native Arenyxa v8.1 qualification evidence")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--check", action="append", default=[], help="mark an operator-observed visual check as passed")
    parser.add_argument("--skip-automated", action="store_true", help="record operator evidence only")
    parser.add_argument("--service-lifecycle", action="store_true", help="install/start/stop/remove a temporary Arenyxa service (admin required)")
    args = parser.parse_args(argv)

    if os.name != "nt":
        payload = {
            "schema": SCHEMA,
            "status": "NOT_EXECUTED",
            "complete": False,
            "reason": "Windows native qualification requires a real Windows host or Windows VM.",
            "host": platform.node(),
            "platform": platform.platform(),
            "python": sys.version,
            "required_automated_checks": list(AUTOMATED_CHECKS),
            "optional_destructive_checks": list(OPTIONAL_DESTRUCTIVE_CHECKS),
        }
        _atomic_json(args.report, payload)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 2

    operator_passed = sorted(set(args.check) & set(OPERATOR_CHECKS))
    operator_missing = [item for item in OPERATOR_CHECKS if item not in operator_passed]
    automated_passed: list[str] = []
    automated_diagnostics: dict[str, Any] = {}
    if not args.skip_automated:
        automated_passed, automated_diagnostics = _automated_checks(service_lifecycle=bool(args.service_lifecycle))
    automated_missing = [item for item in AUTOMATED_CHECKS if item not in automated_passed]
    required_service = bool(args.service_lifecycle)
    service_ok = (not required_service) or "windows_service_install_start_stop_remove" in automated_passed
    complete = not operator_missing and not automated_missing and not args.skip_automated and service_ok
    payload = {
        "schema": SCHEMA,
        "status": "PASS" if complete else "PARTIAL",
        "timestamp_epoch": time.time(),
        "host": platform.node(),
        "windows": platform.platform(),
        "python": sys.version,
        "operator_checks": {"required": list(OPERATOR_CHECKS), "passed": operator_passed, "missing": operator_missing},
        "automated_checks": {
            "required": list(AUTOMATED_CHECKS),
            "passed": automated_passed,
            "missing": automated_missing,
            "diagnostics": automated_diagnostics,
            "skipped": bool(args.skip_automated),
        },
        "service_lifecycle_requested": required_service,
        "complete": complete,
        "operator_attested": True,
    }
    _atomic_json(args.report, payload)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
