from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import importlib.util
import pytest


def _gate():
    path = Path(__file__).resolve().parents[1] / "scripts/architecture_debt_gate.py"
    spec = importlib.util.spec_from_file_location("release_architecture_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_ownership_classification_does_not_allow_a_sibling_catch() -> None:
    gate = _gate()
    source = "def bootstrap():\n    try: pass\n    except Exception: raise\ndef other():\n    try: pass\n    except Exception: raise\n"
    assert gate.ownership_boundary_catches("bootstrap.py", source) == 1
    assert gate.ownership_boundary_catches("unregistered.py", source) == 0


def test_ownership_classification_rejects_growth_inside_an_approved_function() -> None:
    gate = _gate()
    source = "def bootstrap():\n    try: pass\n    except Exception: raise\n    try: pass\n    except Exception: raise\n"
    with pytest.raises(SystemExit, match="ownership exception boundary grew"):
        gate.ownership_boundary_catches("bootstrap.py", source)


def test_ordinary_exception_ratchets_remain_unchanged() -> None:
    gate = _gate()
    assert gate.MAX_BROAD_EXCEPTION_CATCHES == 284
    assert gate.MAX_ENTERPRISE_BROAD_EXCEPTION_CATCHES == 50
    assert gate.MAX_PROXY_BROAD_EXCEPTION_CATCHES == 1


def test_architecture_debt_gate_passes() -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run([sys.executable, str(root / "scripts" / "architecture_debt_gate.py")], cwd=root, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "architecture debt gate: PASS" in completed.stdout
