"""Repair recovery/relaunch policy.

Source-tree relaunch intentionally uses the active ``python.exe -m arenyxa`` path rather than
preferring ``pythonw.exe`` so startup diagnostics, exit status, and stderr remain observable.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from arenyxa.branding import DATA_DIR_ENV, LEGACY_DATA_DIR_ENV
from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.repair_models import RepairPlan


def source_python_executable() -> str:
    return str(sys.executable)


def relaunch_arenyxa(plan: RepairPlan) -> None:
    environment = os.environ.copy()
    environment[DATA_DIR_ENV] = plan.data_root
    environment[LEGACY_DATA_DIR_ENV] = plan.data_root
    if plan.source_mode:
        src = str(Path(plan.install_root) / "src")
        existing = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = src + (os.pathsep + existing if existing else "")
        command = [source_python_executable(), "-m", "arenyxa", "--post-repair"]
        cwd = plan.install_root
    else:
        command = [sys.executable, "--post-repair"]
        cwd = plan.install_root
    popen_kwargs: dict[str, Any] = {"cwd": cwd, "env": environment, "close_fds": True}
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if plan.source_mode:
            creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
        else:
            creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
        popen_kwargs.update(
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    subprocess.Popen(validated_argv(command), **popen_kwargs)
