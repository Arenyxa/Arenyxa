"""Repair worker process lifecycle and execution orchestration."""
from __future__ import annotations

import logging
import os
import secrets
import shutil
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from arenyxa.console_io import console_write
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.repair_common import clear_repair_marker, repair_resource, _write_repair_marker, _load_repair_marker
from arenyxa.repair_engine import RepairEngine
from arenyxa.repair_models import RepairPlan, RepairResult, _utc_now
from arenyxa.repair_planner import validate_repair_plan_origin
from arenyxa.repair_recovery import relaunch_arenyxa

LOGGER = logging.getLogger(__name__)
PopenFactory = Callable[..., subprocess.Popen[Any]]
MarkerWriter = Callable[[Path, int, str, str], Path]
MarkerClearer = Callable[[Path, str | None], None]


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
    environment["ARENYXA_REPAIR_MARKER_TOKEN"] = marker_token

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
    marker = _load_repair_marker(Path(plan.data_root))
    plan_payload = asdict(plan)
    marker_token = None
    if marker:
        observed_token = str(marker.get("token", ""))
        handed_off_token = os.environ.get("ARENYXA_REPAIR_MARKER_TOKEN", "")
        if marker.get("owner_pid") == os.getpid() or (
            handed_off_token and secrets.compare_digest(observed_token, handed_off_token)
        ):
            marker_token = observed_token
    engine = RepairEngine(plan)
    try:
        result = engine.run()
    except Exception as exc:
        LOGGER.exception("Repair worker failed")
        result = RepairResult(
            started_at=engine.started_at,
            finished_at=_utc_now(),
            success=False,
            categories=list(plan.categories),
            backup_dir=str(engine.backup_root),
            actions=list(engine.actions),
            unresolved=[*engine.unresolved, f"Repair worker failed: {exc}"],
        )
        # A fatal engine failure must be auditable without overwriting another owner's report.
        audit_lease = DataRootLease(Path(plan.data_root))
        try:
            if audit_lease.acquire():
                atomic_write_json(engine.repair_root / "last_repair_report.json", result.to_dict())
                engine.log(result.unresolved[-1])
            else:
                LOGGER.error("Cannot persist repair failure: data root is owned by another process")
        except OSError:
            LOGGER.exception("Unable to persist repair failure report")
        finally:
            audit_lease.release()
    try:
        current_marker = _load_repair_marker(Path(plan.data_root))
        owns_marker = (
            marker_token is not None
            and current_marker is not None
            and current_marker.get("token") == marker_token
        ) or (marker is None and current_marker is None)
        # Old callers may still use a shared filename. Never remove a replacement
        # plan or one whose ownership has moved to another repair attempt.
        if owns_marker and plan_path.exists() and asdict(RepairPlan.load(plan_path)) == plan_payload:
            plan_path.unlink(missing_ok=True)
    except (OSError, ValueError, TypeError) as exc:
        engine.log(f"清理修复计划失败（保留取证文件）: {exc}")
    if marker_token is not None:
        clear_repair_marker(Path(plan.data_root), marker_token)
    if plan.relaunch:
        try:
            relaunch_arenyxa(plan)
            engine.log("已重新启动 Arenyxa，修复终端将在 1 秒后自动退出。")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            engine.log(f"重新启动 Arenyxa 失败: {exc}")
    time.sleep(1.0)
    return 0 if result.success else 1
