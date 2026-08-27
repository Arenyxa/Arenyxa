"""Arenyxa Repair Center public facade.

The implementation is split by responsibility: models, diagnostics, scanner, planner, executor,
recovery, and engine.  This module intentionally preserves the historical import surface used by
UI, CLI, service startup, plugins, and existing automation.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
from pathlib import Path
from typing import Any

from arenyxa.repair_common import (
    REPAIR_LEASE_WAIT_SECONDS,
    REPAIR_MARKER_NAME,
    REPAIR_HANDOFF_GRACE_SECONDS,
    REPAIR_PIP_TIMEOUT_SECONDS,
    REPAIR_OPTIONAL_PIP_TIMEOUT_SECONDS,
    _repair_marker_path,
    _windows_process_running,
    _process_is_running as _common_process_is_running,
    _load_repair_marker,
    repair_worker_active,
    _write_repair_marker,
    clear_repair_marker,
    installation_root,
    source_mode,
    repair_resource,
    _packaged_repair_artifacts,
    _validate_packaged_recovery,
    ensure_known_good_seed,
    _sha256,
    _safe_relative,
    _directory_size,
    _wait_for_parent,
)
from arenyxa.repair_diagnostics import append_feature_integration_findings
from arenyxa.repair_engine import RepairEngine
from arenyxa.repair_executor import launch_repair_worker as _launch_repair_worker_impl
from arenyxa.repair_executor import run_repair_worker
from arenyxa.repair_models import (
    CATEGORY_LABELS,
    HealthReport,
    RepairActionResult,
    RepairCategory,
    RepairFinding,
    RepairPlan,
    RepairResult,
    _utc_now,
    fault_fingerprint,
)
from arenyxa.repair_planner import create_repair_plan
from arenyxa.repair_planner import validate_repair_plan_origin as _validate_repair_plan_origin
from arenyxa.repair_recovery import relaunch_arenyxa as _relaunch_arenyxa
from arenyxa.repair_recovery import source_python_executable as _source_gui_python_executable
from arenyxa.repair_scanner import StartupHealthScanner

# Historical compatibility constant retained for external Repair Center integrations.
FEATURE_INTEGRATION = "feature_integration"
if FEATURE_INTEGRATION != RepairCategory.FEATURE_INTEGRATION.value:
    raise RuntimeError("RepairCategory FEATURE_INTEGRATION contract drift")


def _process_is_running(pid: int) -> bool:
    if os.name != "nt":
        return bool(_common_process_is_running(pid))
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    state = _windows_process_running(pid)
    return True if state is None else state


def launch_repair_worker(plan_path: Path) -> subprocess.Popen[Any]:
    # Preserve the historical monkeypatch seam while delegating all lifecycle logic to the
    # executor layer.  Production still uses the real subprocess/marker functions.
    return _launch_repair_worker_impl(
        plan_path,
        popen=subprocess.Popen,
        write_marker=_write_repair_marker,
        clear_marker=clear_repair_marker,
    )
