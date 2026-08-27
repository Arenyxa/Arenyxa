from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_gate():
    spec = importlib.util.spec_from_file_location(
        "verify_main_window_import_contract",
        SCRIPTS / "verify_main_window_import_contract.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_v71_main_window_split_has_no_implicit_globals() -> None:
    gate = _load_gate()
    gate.verify_static_contract()


def test_v71_main_window_imports_when_qt_is_available() -> None:
    from arenyxa.qt_compat import binding_available

    if not binding_available():
        pytest.skip("Qt binding unavailable in this validation environment")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    gate = _load_gate()
    assert gate.verify_runtime_import_when_qt_available() == "PASS"
