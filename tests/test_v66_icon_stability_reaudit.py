from __future__ import annotations

import logging
import struct
from pathlib import Path

import pytest

from arenyxa import branding
from arenyxa import app as app_module


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_new_icon_resources_are_canonical_and_packaging_consistent() -> None:
    png = branding.application_icon_png_path()
    ico = branding.application_icon_ico_path()
    assert png == SRC / "resources" / "icons" / "arenyxa.png"
    assert ico == SRC / "resources" / "icons" / "arenyxa.ico"
    assert png.is_file() and ico.is_file()

    raw = png.read_bytes()
    assert raw[:8] == b"\x89PNG\r\n\x1a\n"
    width, height, bit_depth, color_type = struct.unpack(">IIBB", raw[16:26])
    assert (width, height, bit_depth, color_type) == (1024, 1024, 8, 6)

    for relative in (
        "packaging/arenyxa.spec",
        "packaging/arenyxa_win7.spec",
        "packaging/installer.iss",
        "packaging/installer_win7.iss",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "arenyxa.ico" in source


def test_runtime_icon_is_applied_before_instance_and_bootstrap_boundaries() -> None:
    source = (SRC / "app.py").read_text(encoding="utf-8")
    set_icon = source.index("application.setWindowIcon")
    single_instance = source.index("single_instance = SingleInstance")
    bootstrap = source.index("context = bootstrap(")
    assert set_icon < single_instance < bootstrap
    assert "preferred_window_icon_path" in source


def test_icon_path_falls_back_to_ico_if_png_is_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(branding, "_ICON_DIR", tmp_path)
    ico = tmp_path / "arenyxa.ico"
    ico.write_bytes(b"ico")
    assert branding.preferred_window_icon_path() == ico


def test_crash_marker_failure_is_diagnostic_but_nonfatal(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise OSError("simulated marker write failure")

    monkeypatch.setattr(app_module, "atomic_write_json", fail)
    with caplog.at_level(logging.WARNING):
        app_module._write_crash_marker(tmp_path / "crash.marker", "bootstrap")
    assert "Unable to write crash marker" in caplog.text


def test_stale_progress_save_cannot_reverse_pause_resume_control_state(tmp_path: Path) -> None:
    from arenyxa.domain.enums import RunStatus
    from arenyxa.domain.models import Run
    from arenyxa.infrastructure.database import SQLiteStore

    store = SQLiteStore(tmp_path / "control-race.db")
    store.initialize()
                                                                          
    from arenyxa.domain.enums import TaskStatus
    from arenyxa.domain.models import RequestSpec, Task

    task = Task("control-race", [RequestSpec("http://127.0.0.1/")], status=TaskStatus.READY)
    store.save_task(task)
    run = Run(task.id, task.to_dict(), status=RunStatus.RUNNING)
    store.save_run(run)

    assert store.update_run_control_status(run.id, RunStatus.PAUSED)
    run.status = RunStatus.RUNNING                                              
    store.save_run(run)
    row = next(item for item in store.list_runs(task.id) if item["id"] == run.id)
    assert row["status"] == RunStatus.PAUSED.value

    assert store.update_run_control_status(run.id, RunStatus.RUNNING)
    run.status = RunStatus.PAUSED                                               
    store.save_run(run)
    row = next(item for item in store.list_runs(task.id) if item["id"] == run.id)
    assert row["status"] == RunStatus.RUNNING.value


def test_stale_active_progress_cannot_reopen_terminal_run(tmp_path: Path) -> None:
    from arenyxa.domain.enums import RunStatus, TaskStatus
    from arenyxa.domain.models import RequestSpec, Run, Task
    from arenyxa.infrastructure.database import SQLiteStore

    store = SQLiteStore(tmp_path / "terminal-race.db")
    store.initialize()
    task = Task("terminal-race", [RequestSpec("http://127.0.0.1/")], status=TaskStatus.READY)
    store.save_task(task)
    run = Run(task.id, task.to_dict(), status=RunStatus.RUNNING)
    store.save_run(run)

    run.status = RunStatus.COMPLETED
    run.stage = "completed"
    store.save_run(run)
    run.status = RunStatus.RUNNING                           
    run.stage = "fetch"
    store.save_run(run)

    row = next(item for item in store.list_runs(task.id) if item["id"] == run.id)
    assert row["status"] == RunStatus.COMPLETED.value
