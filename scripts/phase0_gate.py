from __future__ import annotations

"""Run the automatable portion of the Roadmap Phase 0 release gate.

Native Windows UX checks remain deliberately separate: this script cannot
pretend that offscreen/headless Qt proves compositor, multi-monitor, Capture or
Repair behavior on a real Windows desktop.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

try:
    from scripts.build_source_manifest import is_generated_or_ephemeral, is_preserved_local_artifact
except ModuleNotFoundError:
    from build_source_manifest import is_generated_or_ephemeral, is_preserved_local_artifact

def run(label: str, command: list[str], *, root: Path, env: dict[str, str]) -> None:
    print(f"\n=== {label} ===", flush=True)
    completed = subprocess.run(command, cwd=root, env=env, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)




def cleanup_ephemeral(root: Path) -> None:
    """Remove gate bytecode only within the roots passed to compileall.

    Dependency metadata and local evidence are never cleanup targets. Unknown
    cache contents remain intact; only empty bytecode directories are removed.
    """
    root = root.resolve()
    protected_names = {".env", "env", "venv", "tool", "tools", "backup", "backups"}
    for name in ("src", "scripts", "tests"):
        source = root / name
        if not source.is_dir() or source.is_symlink() or source.resolve() != source:
            continue
        caches: list[Path] = []
        for directory, names, files in os.walk(source, followlinks=False):
            parent = Path(directory)
            names[:] = [name for name in names
                        if not (parent / name).is_symlink()
                        and (parent / name).resolve() == parent / name
                        and name.casefold() not in protected_names
                        and (name == "__pycache__" or not is_generated_or_ephemeral(Path(name)))]
            if parent.name == "__pycache__":
                caches.append(parent)
            for filename in files:
                path = parent / filename
                ephemeral = path.suffix in {".pyc", ".pyo"} or filename == ".coverage" or filename.startswith(".coverage.")
                if not ephemeral or is_preserved_local_artifact(Path(filename)) or path.is_symlink():
                    continue
                resolved = path.resolve()
                if resolved != path or not resolved.is_relative_to(source):
                    continue
                path.unlink(missing_ok=True)
        for cache in reversed(caches):
            if cache.resolve() == cache and cache.is_relative_to(source):
                try:
                    cache.rmdir()
                except OSError:
                    pass

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
