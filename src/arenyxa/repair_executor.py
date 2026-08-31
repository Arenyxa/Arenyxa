"""Repair worker process lifecycle and execution orchestration."""
from __future__ import annotations

import logging
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

from arenyxa.console_io import console_write
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.repair_common import clear_repair_marker, repair_resource, _write_repair_marker
from arenyxa.repair_engine import RepairEngine
from arenyxa.repair_models import RepairActionResult, RepairPlan, RepairResult, _utc_now
from arenyxa.repair_planner import validate_repair_plan_origin
from arenyxa.repair_recovery import relaunch_arenyxa

LOGGER = logging.getLogger(__name__)
PopenFactory = Callable[..., subprocess.Popen[Any]]
MarkerWriter = Callable[[Path, int, str, str], Path]
MarkerClearer = Callable[[Path, str | None], None]


def _terminal_failure_result(
    engine: RepairEngine,
    plan: RepairPlan,
    error: Exception,
) -> RepairResult:
    detail = f"Repair engine terminated unexpectedly: {type(error).__name__}: {error}"
    result = RepairResult(
        started_at=engine.started_at,
        finished_at=_utc_now(),
        success=False,
        categories=list(plan.categories),
        backup_dir=str(engine.backup_root),
        actions=list(engine.actions)
        + [RepairActionResult("Repair worker terminalization", "failed", detail)],
        unresolved=list(engine.unresolved) + [detail],
    )
    try:
        atomic_write_json(
            Path(plan.data_root) / "repair" / "last_repair_report.json",
            result.to_dict(),
        )
    except Exception:
        LOGGER.exception("Unable to persist unexpected Repair Worker failure report")
    return result


def launch_repair_worker(
    plan_path: Path,
    *,
    popen: PopenFactory = subprocess.Popen,
    write_marker: MarkerWriter = _write_repair_marker,
    clear_marker: MarkerClearer = clear_repair_marker,
) -> subprocess.Popen[Any]:
    plan = RepairPlan.load(plan_path)
    validate_repair_plan_origin(plan, plan_path)
    environment = os.environ.copy()
    data_root = Path(plan.data_root).resolve()
    marker_token = secrets.token_hex(16)

    # Publish handoff before spawning the child: desktop/server startup sees a closed gate even
    # in the short parent->child ownership transition.
    write_marker(data_root, os.getpid(), marker_token, "handoff")
    process: subprocess.Popen[Any] | None = None
    try:
        if os.name == "nt" and not plan.source_mode:
            repair_dir = data_root / "repair"
            repair_dir.mkdir(parents=True, exist_ok=True)
            script_source = repair_resource("repair/repair_worker.ps1")
            if not script_source.is_file():
                raise FileNotFoundError(f"Repair worker resource missing: {script_source}")
            script_copy = repair_dir / "repair_worker.ps1"
            shutil.copy2(script_source, script_copy)
            command = [
                "powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script_copy),
                "-InstallRoot", plan.install_root,
                "-DataRoot", plan.data_root,
                "-PlanPath", str(plan_path),
                "-WaitPid", str(plan.parent_pid or os.getpid()),
            ]
            process = popen(
                validated_argv(command),
                cwd=plan.data_root,
                env=environment,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
            )
        else:
            if plan.source_mode:
                src = str(Path(plan.install_root) / "src")
                existing = environment.get("PYTHONPATH", "")
                environment["PYTHONPATH"] = src + (os.pathsep + existing if existing else "")
                command = [sys.executable, "-m", "arenyxa", "--repair-worker", str(plan_path)]
            else:
                command = [sys.executable, "--repair-worker", str(plan_path)]
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0) if os.name == "nt" else 0
            process = popen(
                validated_argv(command),
                cwd=plan.install_root,
                env=environment,
                close_fds=True,
                creationflags=creationflags,
            )
        write_marker(data_root, int(process.pid), marker_token, "active")
        return process
    except Exception:
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5.0)
            except (AttributeError, OSError, subprocess.SubprocessError) as cleanup_exc:
                LOGGER.error("Repair child cleanup after launch failure also failed: %s", cleanup_exc)
        clear_marker(data_root, marker_token)
        raise


def run_repair_worker(plan_path: Path) -> int:
    try:
        plan = RepairPlan.load(plan_path)
        validate_repair_plan_origin(plan, plan_path)
    except Exception as exc:
        console_write(f"Arenyxa Repair Center: 无法读取修复计划: {exc}", flush=True)
        return 2
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleTitleW("Arenyxa Repair Center · 自动修复")
        except (AttributeError, OSError) as exc:
            LOGGER.debug("Unable to set Repair Center console title: %s", exc)
    engine = RepairEngine(plan)
    try:
        result = engine.run()
    except Exception as exc:
        LOGGER.exception("Repair Worker terminated unexpectedly")
        result = _terminal_failure_result(engine, plan, exc)
    try:
        plan_path.unlink(missing_ok=True)
    except OSError as exc:
        engine.log(f"清理修复计划失败（保留取证文件）: {exc}")
    clear_repair_marker(Path(plan.data_root))
    if plan.relaunch:
        try:
            relaunch_arenyxa(plan)
            engine.log("已重新启动 Arenyxa，修复终端将在 1 秒后自动退出。")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            engine.log(f"重新启动 Arenyxa 失败: {exc}")
    time.sleep(1.0)
    return 0 if result.success else 1
