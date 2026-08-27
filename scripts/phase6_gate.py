from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
                                                                                         
                                                                                        
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    tests = [
        "tests/test_phase6_developer_access.py",
        "tests/test_phase4_security_foundation.py",
        "tests/test_phase45_experience_and_security_integration.py",
    ]
    return subprocess.call([sys.executable, "-m", "pytest", "-q", *tests], cwd=root, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
