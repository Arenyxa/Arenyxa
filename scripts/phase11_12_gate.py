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
    run("Phase 1-12 static security scan", [sys.executable, "scripts/phase12_static_security_scan.py"], root, env)
    run("Independent Welcome window contract", [sys.executable, "scripts/verify_welcome_window_contract.py"], root, env)
    run("UI button connection contract", [sys.executable, "scripts/verify_ui_button_connections.py"], root, env)
    run(
        "Phase 11 distributed runtime / Phase 12 release hardening",
        [sys.executable, "-m", "pytest", "-q", "tests/test_phase11_distributed_runtime.py", "tests/test_phase12_release_hardening.py", "tests/test_phase11_12_root_ui_hardening.py"],
        root, env,
    )
    run(
        "Phase 7-10 prerequisite enterprise regression",
        [sys.executable, "-m", "pytest", "-q", "tests/test_phase7_local_enterprise_identity.py", "tests/test_phase8_10_enterprise_platform.py", "tests/test_phase4_security_foundation.py", "tests/test_phase6_developer_access.py", "tests/test_phase45_experience_and_security_integration.py"],
        root, env,
    )
    print("\nPhase 11-12 automated server/distributed/release gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
