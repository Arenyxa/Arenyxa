from __future__ import annotations

import io
from datetime import datetime
from pathlib import Path

import arenyxa.repair_engine as repair_engine
from arenyxa.console_io import console_write
from arenyxa.repair import RepairCategory, RepairEngine, RepairPlan


def _engine(tmp_path: Path) -> RepairEngine:
    return RepairEngine(RepairPlan(str(tmp_path), str(tmp_path / "data"), [RepairCategory.SETTINGS_UI.value], source_mode=False))


def test_repeated_engine_runs_have_independent_results_and_backups(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    for method in ("_repair_settings", "_archive_pre_repair_logs", "_final_verify"):
        monkeypatch.setattr(engine, method, lambda: "ok")
    first = engine.run()
    first_log = engine.log_path
    second = engine.run()
    assert first.success and second.success
    assert len(first.actions) == len(second.actions) == 3
    assert first.backup_dir != second.backup_dir
    assert first_log != engine.log_path
    assert first_log.is_file() and engine.log_path.is_file()


def test_same_clock_tick_engines_do_not_share_backup_locations(tmp_path, monkeypatch):
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 1, 1, tzinfo=tz)

    monkeypatch.setattr(repair_engine, "datetime", FrozenDateTime)
    first, second = _engine(tmp_path), _engine(tmp_path)
    assert first.backup_root != second.backup_root
    assert first.log_path != second.log_path


def test_backup_collision_never_overwrites_a_prior_image(tmp_path):
    engine = _engine(tmp_path)
    source = tmp_path / "settings.json"
    source.write_text("first", encoding="utf-8")
    engine._backup(source, "settings")
    source.write_text("second", encoding="utf-8")
    engine._backup(source, "settings")
    images = list((engine.backup_root / "settings").iterdir())
    assert sorted(p.read_text(encoding="utf-8") for p in images) == ["first", "second"]


def test_redirected_cp936_console_keeps_repair_diagnostics(monkeypatch):
    import arenyxa.console_io as console

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp936", errors="strict")
    monkeypatch.setattr(console.sys, "stdout", stream)
    console_write("\u25b6 repair diagnostic", flush=True)
    assert b"repair diagnostic" in raw.getvalue()


def test_windowed_console_without_stdout_is_safe(monkeypatch):
    import arenyxa.console_io as console

    monkeypatch.setattr(console.sys, "stdout", None)
    console_write("repair diagnostic", flush=True)


def test_planning_twice_preserves_both_pending_attempts(tmp_path):
    from types import SimpleNamespace
    from arenyxa.repair_planner import create_repair_plan

    paths = SimpleNamespace(root=tmp_path)
    report = SimpleNamespace(findings=[])
    first = create_repair_plan(paths, report, [RepairCategory.SETTINGS_UI], relaunch=False)
    first_bytes = first.read_bytes()
    second = create_repair_plan(paths, report, [RepairCategory.CACHE_TEMP], relaunch=False)
    assert first != second
    assert first.read_bytes() == first_bytes
    assert RepairPlan.load(first).categories == [RepairCategory.SETTINGS_UI.value]
    assert RepairPlan.load(second).categories == [RepairCategory.CACHE_TEMP.value]
