from __future__ import annotations

"""Run the automatable portion of the Roadmap Phase 0 release gate.

Native Windows UX checks remain deliberately separate: this script cannot
pretend that offscreen/headless Qt proves compositor, multi-monitor, Capture or
Repair behavior on a real Windows desktop.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def run(label: str, command: list[str], *, root: Path, env: dict[str, str]) -> None:
    print(f"\n=== {label} ===", flush=True)
    completed = subprocess.run(command, cwd=root, env=env, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)




def cleanup_ephemeral(root: Path) -> None:
    directory_names = {"__pycache__", ".pytest_cache", ".ruff_cache", ".mypy_cache"}
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir() and (path.name in directory_names or path.name.endswith(".egg-info")):
            shutil.rmtree(path, ignore_errors=True)
    for path in root.rglob("*"):
        if path.is_file() and (path.suffix in {".pyc", ".pyo"} or path.name.startswith(".coverage")):
            try:
                path.unlink()
            except FileNotFoundError:
                continue

def main() -> int:
    parser = argparse.ArgumentParser(description="Run Arenyxa release baseline automated gates")
    parser.add_argument("--skip-pytest", action="store_true")
    parser.add_argument("--skip-static", action="store_true", help="developer-only: skip release-blocking Ruff/Mypy gate")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(root / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env.setdefault("QT_QPA_PLATFORM", "offscreen")

    run("Python compileall", [sys.executable, "-m", "compileall", "-q", "src", "scripts", "tests"], root=root, env=env)
    if not args.skip_static:
        run("Release static quality", [sys.executable, "scripts/static_quality_gate.py"], root=root, env=env)
    if not args.skip_pytest:
        run("Historical regression", [sys.executable, "-m", "pytest", "-q"], root=root, env=env)
    cleanup_ephemeral(root)
    run(
        "Phase 0 integrity",
        [sys.executable, "scripts/verify_phase0_baseline.py", "--allow-local-artifacts"],
        root=root,
        env=env,
    )
    print("\nAutomated Phase 0 gates passed. Native Windows verification is still a separate hard gate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
