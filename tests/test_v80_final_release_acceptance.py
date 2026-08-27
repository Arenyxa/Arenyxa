from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from arenyxa import __package_version__, __version__
from arenyxa.application.windows_runtime import WindowsRuntimeControl

ROOT = Path(__file__).resolve().parents[1]


def test_v80_stable_release_identity() -> None:
    assert __version__ == "8.1"
    assert __package_version__ == "8.1.0"


def test_windows_native_deep_probe_is_honest_off_windows() -> None:
    if os.name == "nt":
        return
    runtime = WindowsRuntimeControl()
    report = runtime.status(deep=True)
    assert report["windows"] is False
    assert report["npcap_enumeration"]["state"] == "not_available"
    assert report["etw_round_trip"]["state"] == "not_available"
    assert report["wfp_engine_round_trip"]["state"] == "not_available"
    assert report["dpapi"]["state"] == "not_available"
    assert report["tpm_cng"]["state"] == "not_available"


def test_windows_qualification_records_not_executed_off_windows(tmp_path: Path) -> None:
    if os.name == "nt":
        return
    report = tmp_path / "windows.json"
    completed = subprocess.run(
        [sys.executable, "scripts/windows_native_qualification.py", "--report", str(report)],
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
    )
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert completed.returncode == 2
    assert payload["status"] == "NOT_EXECUTED"
    assert payload["complete"] is False
    assert "Windows" in payload["reason"]


def test_v80_acceptance_gate_contains_full_pdf_gate_surface() -> None:
    source = (ROOT / "scripts/v8_acceptance_gate.py").read_text(encoding="utf-8")
    for marker in (
        "NO_STUB",
        "NO_PLACEHOLDER",
        "NO_FAKE_SUCCESS",
        "NO_FAKE_TEST",
        "NO_FAKE_PROTOCOL_SUPPORT",
        "NO_SILENT_EXCEPTION",
        "NO_UNBOUNDED_CRITICAL_QUEUE",
        "NO_KNOWN_P0",
        "NO_UNJUSTIFIED_P1",
        "NO_FEATURE_REGRESSION",
        "GUI_CONNECTED",
        "CLI_CONNECTED",
        "CORE_CONNECTED",
        "SECURITY_CONNECTED",
        "STORAGE_CONNECTED",
        "AUDIT_CONNECTED",
        "JOB_SYSTEM_CONNECTED",
        "HEALTH_CONNECTED",
        "RECOVERY_CONNECTED",
        "WINDOWS_VALIDATED_WHERE_AVAILABLE",
        "PACKAGING_CHECKED",
        "TESTED",
        "REGRESSION_CHECKED",
        "PERFORMANCE_BASELINE_CHECKED",
        "SECURITY_BASELINE_CHECKED",
        "SURVIVABILITY_DRILLS_EXECUTED",
    ):
        assert marker in source


def test_phase7_validation_never_promotes_unavailable_external_gate() -> None:
    source = (ROOT / "scripts/v8_final_release_validation.py").read_text(encoding="utf-8")
    assert '"status": "NOT_EXECUTED"' in source
    assert "external_certification_complete" in source
    assert "windows_vm_attempt" in source
