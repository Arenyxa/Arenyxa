from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--disable-warnings",
        "--maxfail=1",
        "tests/test_v80_platform_control_plane.py",
        "tests/test_v656_stability_compatibility_hardening.py",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=env,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=360,
        )
        payload = {
            "schema": "arenyxa.reliability-test-gate/v2",
            "healthy": completed.returncode == 0,
            "returncode": completed.returncode,
            "command": command,
            "output": completed.stdout[-12_000:],
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", "replace")
        payload = {
            "schema": "arenyxa.reliability-test-gate/v2",
            "healthy": False,
            "returncode": 124,
            "command": command,
            "output": output[-12_000:] + "\nTIMEOUT",
        }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["healthy"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
