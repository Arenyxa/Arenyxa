from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_TOOLS = ("ruff", "mypy")
CRITICAL_RUFF_RULES = "E9,F63,F7,F82"
MYPY_TARGETS = (
    "src/arenyxa/domain",
    "src/arenyxa/application",
    "src/arenyxa/infrastructure",
    "src/arenyxa/enterprise",
    "src/arenyxa/presentation/main_window.py",
    "src/arenyxa/presentation/pages/network.py",
    "src/arenyxa/presentation/pages/proxy.py",
    "src/arenyxa/presentation/pages/mitm_proxy.py",
    "src/arenyxa/presentation/pages/extraction.py",
    "src/arenyxa/presentation/pages/server_ops.py",
    "src/arenyxa/presentation/pages/data.py",
    "src/arenyxa/presentation/pages/tasks.py",
)


def _require_module(name: str) -> None:
    if importlib.util.find_spec(name) is None:
        raise SystemExit(
            f"Release-blocking static analysis tool is missing: {name}. "
            "Install Arenyxa development dependencies with: python -m pip install -e .[dev]"
        )


def _environment() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    return env


def _run_blocking(label: str, command: list[str]) -> None:
    print(f"\n=== {label} ===", flush=True)
    completed = subprocess.run(command, cwd=ROOT, env=_environment(), check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def _run_advisory(label: str, command: list[str], report_name: str) -> None:
    print(f"\n=== {label} (advisory) ===", flush=True)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=_environment(),
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    audit_root = ROOT / "dist" / "audit"
    audit_root.mkdir(parents=True, exist_ok=True)
    report = audit_root / report_name
    report.write_text(completed.stdout, encoding="utf-8")
    nonempty = [line for line in completed.stdout.splitlines() if line.strip()]
    summary = nonempty[-1] if nonempty else "no findings"
    print(f"exit={completed.returncode}; {summary}; report={report}", flush=True)


def main() -> int:
    for tool in REQUIRED_TOOLS:
        _require_module(tool)
    _run_blocking(
        "Ruff critical runtime safety",
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--select",
            CRITICAL_RUFF_RULES,
            "src/arenyxa",
            "scripts",
            "tests",
        ],
    )
    _run_advisory(
        "Ruff full repository audit",
        [sys.executable, "-m", "ruff", "check", "src/arenyxa", "scripts", "tests"],
        "ruff-full.txt",
    )
    _run_advisory(
        "Mypy strict modern runtime",
        [
            sys.executable,
            "-m",
            "mypy",
            "--config-file",
            "scripts/mypy-release.ini",
            *MYPY_TARGETS,
        ],
        "mypy-full.txt",
    )
    print("\nRelease-blocking critical Ruff gate passed; full Ruff and Mypy reports were retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
