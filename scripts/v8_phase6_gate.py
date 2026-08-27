from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _run(root: Path, command: list[str]) -> int:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.call(command, cwd=root, env=env)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    tests = [
        "tests/test_v80_phase6_survivability.py",
        "tests/test_reliability_stability_hardening.py",
        "tests/test_deep_runtime_resilience.py",
        "tests/test_proxy_capture.py",
        "tests/test_proxy_transport_hardening.py",
        "tests/test_crawler_engine.py",
    ]
    if _run(root, [sys.executable, "-m", "pytest", "-q", *tests]) != 0:
        return 1
    return _run(root, [sys.executable, "scripts/v8_phase6_performance_validation.py"])


if __name__ == "__main__":
    raise SystemExit(main())
