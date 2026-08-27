from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_architecture_debt_gate_passes() -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run([sys.executable, str(root / "scripts" / "architecture_debt_gate.py")], cwd=root, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "architecture debt gate: PASS" in completed.stdout
