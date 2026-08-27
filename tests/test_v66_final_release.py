from __future__ import annotations

from pathlib import Path

import arenyxa
ROOT = Path(__file__).resolve().parents[1]


def test_v66_final_public_and_package_identity() -> None:
    assert arenyxa.__version__ == "8.1"
    assert arenyxa.__package_version__ == "8.1.0"
    assert arenyxa.__compat_version__ == "6.8.0"
    assert 'version = "8.1.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_release_test_gate_scopes_qt_offscreen_environment() -> None:
    script = (ROOT / "scripts" / "test.ps1").read_text(encoding="utf-8")
    assert "$PreviousQtQpaPlatform" in script
    assert "$env:QT_QPA_PLATFORM = 'offscreen'" in script
    assert "Remove-Item Env:QT_QPA_PLATFORM" in script
    assert "finally" in script
                                                                                            
    assert script.index("$env:QT_QPA_PLATFORM = 'offscreen'") > script.index("[4/5] Running release-blocking pytest")


def test_final_source_has_no_packaged_startup_trace_instrumentation() -> None:
    app_source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    window_source = (ROOT / "src" / "arenyxa" / "presentation" / "main_window.py").read_text(encoding="utf-8")
    assert "ARENYXA_STARTUP_TRACE" not in app_source
    assert "packaged_startup_trace" not in app_source
    assert "ARENYXA_STARTUP_TRACE" not in window_source
