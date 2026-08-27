"""Responsive bootstrap and in-shell recovery orchestration."""

from __future__ import annotations

import os
import queue
import time
from pathlib import Path
from typing import Any

from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited

MINIMUM_BOOTSTRAP_PRESENTATION_SECONDS = 1.0


def bootstrap_with_animation(
    *,
    shell_window: Any,
    data_dir: Path | None,
    safe_mode: bool,
) -> Any:
    """Run non-Qt bootstrap work in the global pool while the shell event loop stays live."""
    from arenyxa.bootstrap import bootstrap
    from arenyxa.presentation.background import run_background
    from arenyxa.qt_compat.QtCore import QEventLoop, QTimer

    updates: queue.SimpleQueue[tuple[int, str]] = queue.SimpleQueue()
    outcome: dict[str, Any] = {}
    loop = QEventLoop(shell_window)
    timer = QTimer(shell_window)
    timer.setInterval(16)
    started = time.monotonic()

    def report(value: int, label: str) -> None:
        updates.put((int(value), str(label)))

    def drain() -> None:
        while True:
            try:
                value, label = updates.get_nowait()
            except queue.Empty:
                break
            shell_window.show_splash(f"{value}% {label}", progress=value)

    def completed(context: object) -> None:
        outcome["context"] = context
        drain()
        shell_window.show_splash("100% Ready", progress=100)
        remaining = max(
            0,
            int((MINIMUM_BOOTSTRAP_PRESENTATION_SECONDS - (time.monotonic() - started)) * 1000),
        )
        QTimer.singleShot(remaining, loop.quit)

    def failed(message: str) -> None:
        outcome["error"] = RuntimeError(message)
        loop.quit()

    timer.timeout.connect(drain)
    timer.start()
    run_background(
        lambda: bootstrap(data_dir, safe_mode, progress_callback=report),
        completed,
        failed,
    )
    loop.exec()
    timer.stop()
    drain()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["context"]


def _latest_startup_log(paths: Any) -> str:
    try:
        candidates = sorted(
            paths.logs.glob("*"), key=lambda item: item.stat().st_mtime, reverse=True
        )
        if candidates:
            return read_text_limited(candidates[0], 256 * 1024, encoding="utf-8")
    except (OSError, UnicodeError, ValueError):
        return "Startup log could not be read."
    return "No startup log is available."


def show_shell_bootstrap_recovery(
    *,
    paths: Any,
    failure_report: Any,
    locale: str,
    error: Exception,
    shell_window: Any,
    data_root_lease: Any,
) -> int:
    """Keep fatal startup recovery inside the branded shell until the user chooses an action."""
    from arenyxa.presentation.repair_dialog import RepairSelectionDialog
    from arenyxa.qt_compat.QtCore import QEventLoop
    from arenyxa.repair import create_repair_plan, launch_repair_worker

    latest_log = _latest_startup_log(paths)
    shell_window.show_recovery(
        f"Bootstrap failed: {type(error).__name__}: {error}",
        runtime_status="Runtime Supervisor: unavailable · Security/Database initialization incomplete",
        logs=latest_log,
    )
    shell_window.show()
    shell_window.raise_()
    result = {"code": 1}
    loop = QEventLoop(shell_window)

    def repair() -> None:
        selector = RepairSelectionDialog(failure_report, locale, shell_window)
        if selector.exec() != selector.DialogCode.Accepted:
            return
        plan_path = create_repair_plan(
            paths,
            failure_report,
            selector.selected_categories(),
            parent_pid=os.getpid(),
            relaunch=True,
        )
        launch_repair_worker(plan_path)
        result["code"] = 0
        loop.quit()

    def export() -> None:
        target = paths.exports / f"Arenyxa_Bootstrap_Diagnostics_{int(time.time())}.json"
        atomic_write_json(
            target,
            {
                "schema": "arenyxa.bootstrap-diagnostics/v1",
                "error": {"type": type(error).__name__, "message": str(error)},
                "runtime_status": "bootstrap_incomplete",
                "health_report": failure_report.to_dict(),
                "latest_log": latest_log[-200000:],
            },
            ensure_ascii=False,
            indent=2,
        )
        shell_window.recovery_page.show_export_result(str(target))

    shell_window.recovery_page.autoRepairRequested.connect(repair)
    shell_window.recovery_page.exportDiagnosticsRequested.connect(export)
    shell_window.recovery_page.continueRequested.connect(loop.quit)
    shell_window.closeRequested.connect(loop.quit)
    loop.exec()
    data_root_lease.release()
    return int(result["code"])
