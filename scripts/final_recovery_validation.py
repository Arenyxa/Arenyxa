"""Execute the real startup/runtime recovery regression set used for release validation."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "tests/test_v654_self_healing_runtime_recovery.py",
    "tests/test_v655_recovery_health_resume.py",
)


def main() -> int:
    started = time.monotonic()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *TARGETS],
        cwd=ROOT,
        env=env,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
    )
    passed = completed.returncode == 0
    payload = {
        "schema": "arenyxa.final-recovery-validation/v2",
        "recovery_validation": "passed" if passed else "failed",
        "passed": passed,
        "duration_seconds": round(time.monotonic() - started, 3),
        "targets": list(TARGETS),
        "returncode": completed.returncode,
        "output_tail": completed.stdout[-8000:],
    }
    (ROOT / "FINAL_RECOVERY_VALIDATION.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if passed else completed.returncode or 1


if __name__ == "__main__":
    raise SystemExit(main())
