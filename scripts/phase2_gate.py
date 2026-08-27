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
    run(
        "Phase 2 Web Intelligence + compatibility regression",
        [sys.executable, "-m", "pytest", "-q",
         "tests/test_phase2_web_intelligence.py",
         "tests/test_nextgen_intelligence_studio.py",
         "tests/test_competitive_edge.py",
         "tests/test_replay_api_map_v63.py",
         "tests/test_network_capture_v62.py"],
        root, env,
    )
    print("\nPhase 2 automated Web Intelligence gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
