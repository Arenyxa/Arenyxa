from __future__ import annotations

import os
from pathlib import Path

import pytest

from arenyxa.application.autopilot_validation import AutopilotProductionValidator

ROOT = Path(__file__).resolve().parents[1]


def test_release_static_gate_is_mandatory_in_final_quality() -> None:
    source = (ROOT / "scripts/final_quality_gate.py").read_text(encoding="utf-8")
    assert "scripts/static_quality_gate.py" in source
    static = (ROOT / "scripts/static_quality_gate.py").read_text(encoding="utf-8")
    assert 'REQUIRED_TOOLS = ("ruff", "mypy")' in static
    assert "src/arenyxa/enterprise" in static
    assert "src/arenyxa/presentation/pages/proxy.py" in static


def test_windows_legacy_no_longer_controls_modern_mypy() -> None:
    config = (ROOT / "scripts/mypy-release.ini").read_text(encoding="utf-8")
    assert "python_version = 3.11" in config
    assert "exclude = ^src/arenyxa/" not in config
    assert "[mypy-arenyxa.presentation.glass]" in config


def test_plugin_worker_posix_hardening_contract() -> None:
    source = (ROOT / "src/arenyxa/infrastructure/plugin_worker.py").read_text(encoding="utf-8")
    assert "RLIMIT_AS" in source
    assert "RLIMIT_NPROC" in source
    assert "PR_SET_NO_NEW_PRIVS" in source
    assert "POSIX plugin memory limit could not be enforced" in source
    parent = (ROOT / "src/arenyxa/infrastructure/plugins.py").read_text(encoding="utf-8")
    assert 'start_new_session=os.name != "nt"' in parent
    assert "os.killpg" in parent


def test_autopilot_production_validator_passes_local_stability_cases() -> None:
    report = AutopilotProductionValidator(samples=80).run()
    assert report.stable, report.to_dict()
    assert report.contamination_shift <= 0.20
    assert report.recovery_shift >= 0.04


def test_windows_native_qualification_is_real_host_only() -> None:
    source = (ROOT / "scripts/windows_native_qualification.py").read_text(encoding="utf-8")
    assert 'if os.name != "nt"' in source
    assert "dpi_100_125_150_200" in source
    assert "refresh_60_120_144_165" in source
