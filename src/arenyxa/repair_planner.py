"""Repair plan construction and trust-boundary validation."""
from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from arenyxa.config import AppPaths
from arenyxa.repair_common import installation_root, source_mode
from arenyxa.repair_models import HealthReport, RepairCategory, RepairPlan


def create_repair_plan(
    paths: AppPaths,
    report: HealthReport,
    categories: Iterable[RepairCategory],
    *,
    parent_pid: int | None = None,
    relaunch: bool = True,
) -> Path:
    repair_dir = paths.root / "repair"
    repair_dir.mkdir(parents=True, exist_ok=True)
    plan = RepairPlan(
        install_root=str(installation_root()),
        data_root=str(paths.root),
        categories=[item.value for item in categories],
        detected_findings=[item.to_dict() for item in report.findings],
        parent_pid=parent_pid or os.getpid(),
        relaunch=relaunch,
        source_mode=source_mode(),
    )
    return plan.save(repair_dir / "pending_repair_plan.json")


def validate_repair_plan_origin(plan: RepairPlan, plan_path: Path) -> None:
    expected_install = installation_root().resolve()
    declared_install = Path(plan.install_root).expanduser().resolve()
    if declared_install != expected_install:
        raise ValueError("Repair plan install_root does not match the running Arenyxa installation")
    declared_data = Path(plan.data_root).expanduser().resolve()
    expected_plan_dir = (declared_data / "repair").resolve()
    resolved_plan = plan_path.expanduser().resolve()
    if resolved_plan.parent != expected_plan_dir:
        raise ValueError("Repair plan must reside in the declared Arenyxa data repair directory")
    if plan.source_mode != source_mode():
        raise ValueError("Repair plan source/install mode does not match the running Arenyxa mode")
