from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_page_runtime_contract.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("verify_page_runtime_contract", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_v71_lazy_page_static_contract() -> None:
    _load_gate().verify_static_contract()


def test_v71_lazy_pages_construct_when_qt_is_available() -> None:
    from arenyxa.qt_compat import binding_available

    if not binding_available():
        pytest.skip("Qt binding unavailable in this validation environment")
    assert _load_gate().verify_runtime_pages_when_qt_available() == "PASS"
