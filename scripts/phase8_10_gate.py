from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def run(label: str, command: list[str], root: Path, env: dict[str, str]) -> None:
    print("\n=== " + label + " ===", flush=True)
    result = subprocess.run(command, cwd=root, env=env, check=False)
    if result.returncode:
        raise SystemExit(result.returncode)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    run("compileall", [sys.executable, "-m", "compileall", "-q", "src", "scripts", "tests"], root, env)
    run("Frozen startup visual baseline", [sys.executable, "scripts/verify_startup_visual_baseline.py"], root, env)
    run("Configuration parse", [sys.executable, "scripts/phase12_config_gate.py"], root, env)
    run("Targeted static security scan", [sys.executable, "scripts/phase12_static_security_scan.py"], root, env)
    run("Independent Welcome window contract", [sys.executable, "scripts/verify_welcome_window_contract.py"], root, env)
    # Run heavy regression files in isolated pytest processes.  The enterprise gate mixes
    # multiprocessing, Qt compatibility probes, and whole-tree AST scans; keeping all of
    # those in one pytest interpreter can leave non-daemon lifecycle helpers alive long
    # enough to look like a product hang in CI.  Isolation makes the gate stricter: every
    # file must pass on its own, and one stuck file cannot hide the rest of the matrix.
    for test_file in (
        "tests/test_phase7_local_enterprise_identity.py",
        "tests/test_phase8_10_enterprise_platform.py",
        "tests/test_phase4_security_foundation.py",
        "tests/test_phase6_developer_access.py",
        "tests/test_phase45_experience_and_security_integration.py",
        "tests/test_v653_startup_motion_i18n_contracts.py",
        "tests/test_v661_windows7_legacy_compat.py",
    ):
        run(
            f"Phase 7-10 regression: {test_file}",
            [sys.executable, "-m", "pytest", "-q", test_file],
            root,
            env,
        )
    print("\nPhase 7-10 automated enterprise platform gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
