from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from arenyxa.config import AppPaths
from arenyxa.repair import RepairCategory, RepairEngine, RepairPlan, StartupHealthScanner


def _paths(tmp_path: Path) -> AppPaths:
    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    return paths


def _scanner(paths: AppPaths, tmp_path: Path) -> StartupHealthScanner:
    scanner = StartupHealthScanner(paths, tmp_path)
    scanner.source_mode = False                                                                               
    scanner.REQUIRED_MODULES = {}
    return scanner


def test_scanner_detects_invalid_settings_and_previous_crash(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    (paths.root / "settings.json").write_text("{broken", encoding="utf-8")
    (paths.root / "crash.marker").write_text("startup", encoding="utf-8")
    report = _scanner(paths, tmp_path).scan()
    codes = {item.code for item in report.findings}
    assert "SETTINGS_JSON_INVALID" in codes
    assert "PREVIOUS_UNCLEAN_EXIT" in codes


def test_scanner_detects_corrupt_database(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.database.write_bytes(b"not a sqlite database")
    report = _scanner(paths, tmp_path).scan()
    assert any(item.category == RepairCategory.DATABASE_INDEX for item in report.findings)


def test_settings_repair_normalizes_without_touching_user_data(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    settings = paths.root / "settings.json"
    settings.write_text(json.dumps({"locale": "broken", "theme": "missing", "max_workers": 7}), encoding="utf-8")
    project = paths.projects / "keep.arenyxa"
    capture = paths.captures / "keep.har"
    export = paths.exports / "keep.csv"
    project.write_text("project", encoding="utf-8")
    capture.write_text("capture", encoding="utf-8")
    export.write_text("export", encoding="utf-8")
    plan = RepairPlan(str(tmp_path), str(paths.root), [RepairCategory.SETTINGS_UI.value], source_mode=False)
    engine = RepairEngine(plan)
    engine._repair_settings()
    repaired = json.loads(settings.read_text(encoding="utf-8"))
    assert repaired["locale"] == "system"
    assert repaired["theme"] == "modern_dark"
    assert repaired["max_workers"] == 7
    assert project.read_text(encoding="utf-8") == "project"
    assert capture.read_text(encoding="utf-8") == "capture"
    assert export.read_text(encoding="utf-8") == "export"


def test_settings_repair_preserves_completed_welcome_profile(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    settings = paths.root / "settings.json"
    settings.write_text(
        json.dumps({
            "experience_profile": "professional",
            "experience_setup_completed": True,
            "theme": "terminal_green",
        }),
        encoding="utf-8",
    )
    plan = RepairPlan(str(tmp_path), str(paths.root), [RepairCategory.SETTINGS_UI.value], source_mode=False)
    RepairEngine(plan)._repair_settings()
    repaired = json.loads(settings.read_text(encoding="utf-8"))
    assert repaired["experience_profile"] == "professional"
    assert repaired["experience_setup_completed"] is True
    assert repaired["theme"] == "terminal_green"


def test_cache_repair_preserves_projects_captures_and_exports(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    (paths.cache / "throwaway.bin").write_bytes(b"x" * 64)
    (paths.projects / "keep.txt").write_text("p", encoding="utf-8")
    (paths.captures / "keep.txt").write_text("c", encoding="utf-8")
    (paths.exports / "keep.txt").write_text("e", encoding="utf-8")
    plan = RepairPlan(str(tmp_path), str(paths.root), [RepairCategory.CACHE_TEMP.value], source_mode=False)
    engine = RepairEngine(plan)
    engine._repair_cache()
    assert not (paths.cache / "throwaway.bin").exists()
    assert (paths.projects / "keep.txt").exists()
    assert (paths.captures / "keep.txt").exists()
    assert (paths.exports / "keep.txt").exists()


def test_database_repair_keeps_valid_database(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    connection = sqlite3.connect(paths.database)
    connection.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
    connection.execute("INSERT INTO sample(value) VALUES ('ok')")
    connection.commit()
    connection.close()
    plan = RepairPlan(str(tmp_path), str(paths.root), [RepairCategory.DATABASE_INDEX.value], source_mode=False)
    engine = RepairEngine(plan)
    detail = engine._repair_database()
    assert "quick_check=ok" in detail
    connection = sqlite3.connect(paths.database)
    try:
        assert connection.execute("SELECT value FROM sample").fetchone()[0] == "ok"
    finally:
        connection.close()


def test_database_rebuild_streams_and_keeps_unique_preserved_copies(tmp_path: Path, monkeypatch) -> None:
    paths = _paths(tmp_path)
    connection = sqlite3.connect(paths.database)
    connection.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
    connection.executemany("INSERT INTO sample(value) VALUES (?)", [("one",), ("two",)])
    connection.commit()
    connection.close()

    plan = RepairPlan(str(tmp_path), str(paths.root), [RepairCategory.DATABASE_INDEX.value], source_mode=False)
    engine = RepairEngine(plan)
    original_check = engine._database_quick_check
    calls = 0

    def force_first_check_to_fail(path: Path) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return "failed"
        return original_check(path)

    monkeypatch.setattr(engine, "_database_quick_check", force_first_check_to_fail)
    detail = engine._repair_database()
    assert "流式" in detail
    connection = sqlite3.connect(paths.database)
    try:
        assert connection.execute("SELECT value FROM sample ORDER BY id").fetchall() == [("one",), ("two",)]
    finally:
        connection.close()
    preserved = sorted(paths.database.parent.glob(f"{paths.database.stem}.corrupt-preserved-*{paths.database.suffix}"))
    assert len(preserved) == 1
    assert not list(paths.database.parent.glob(f".{paths.database.name}.recovered-*.tmp"))

                                                                                           
    calls = 0
    detail = engine._repair_database()
    assert "流式" in detail
    preserved_after = sorted(paths.database.parent.glob(f"{paths.database.stem}.corrupt-preserved-*{paths.database.suffix}"))
    assert len(preserved_after) == 2
    assert preserved_after[0] != preserved_after[1]


def test_bundled_source_repair_seed_matches_manifest() -> None:
    import hashlib
    import zipfile

    project = Path(__file__).resolve().parents[1]
    manifest_path = project / "src" / "arenyxa" / "resources" / "repair_manifest.json"
    seed_path = project / "src" / "arenyxa" / "resources" / "repair_seed.zip"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert hashlib.sha256(seed_path.read_bytes()).hexdigest() == manifest["seed_sha256"]
    with zipfile.ZipFile(seed_path, "r") as archive:
        assert archive.testzip() is None
        internal = json.loads(archive.read("MANIFEST.json").decode("utf-8"))
        assert internal["files"] == manifest["files"]
        for relative, expected in internal["files"].items():
            data = (project / relative).read_bytes()
            assert hashlib.sha256(data).hexdigest() == expected


def test_windows_repair_worker_is_non_interactive() -> None:
    project = Path(__file__).resolve().parents[1]
    script = (project / "src" / "arenyxa" / "resources" / "repair" / "repair_worker.ps1").read_text(encoding="utf-8")
    assert "Read-Host" not in script
    assert "--repair-worker" in script
    assert "CREATE_NEW_CONSOLE" not in script                                               


def test_scanner_handles_non_object_settings_without_crashing(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    (paths.root / "settings.json").write_text("[]", encoding="utf-8")
    report = _scanner(paths, tmp_path).scan()
    assert any(item.code == "SETTINGS_ROOT_INVALID" for item in report.findings)


def test_app_settings_load_safely_normalizes_invalid_types(tmp_path: Path) -> None:
    from arenyxa.config import AppSettings

    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "max_workers": "abc",
                "default_timeout_seconds": float("inf"),
                "glass_strength": -7,
                "motion_strength": 99,
                "blur_strength": "bad",
                "reduce_motion": "yes",
                "performance_mode": "turbo",
                "locale": ["zh_CN"],
                "theme": {"name": "modern_dark"},
            }
        ),
        encoding="utf-8",
    )
    settings = AppSettings.load(path)
    defaults = AppSettings()
    assert settings.max_workers == defaults.max_workers
    assert settings.default_timeout_seconds == defaults.default_timeout_seconds
    assert settings.glass_strength == 0.0
    assert settings.motion_strength == 1.0
    assert settings.blur_strength == defaults.blur_strength
    assert settings.reduce_motion is defaults.reduce_motion
    assert settings.performance_mode == defaults.performance_mode
    assert settings.locale == defaults.locale
    assert settings.theme == defaults.theme


def test_windows_repair_worker_forces_trusted_known_good_on_invalid_attestation() -> None:
    project = Path(__file__).resolve().parents[1]
    script = (project / "src" / "arenyxa" / "resources" / "repair" / "repair_worker.ps1").read_text(encoding="utf-8")
    assert "RELEASE_ATTESTATION_INVALID" in script
    assert "$script:ForceKnownGood = $true" in script
    assert "release_attestation.json" in script
    assert "manifest_sha256" in script


def test_repair_plan_rejects_unknown_categories_and_extra_fields(tmp_path: Path) -> None:
    from arenyxa.repair import RepairPlan

    path = tmp_path / "plan.json"
    path.write_text(
        json.dumps(
            {
                "install_root": str(tmp_path),
                "data_root": str(tmp_path / "data"),
                "categories": ["not-a-category"],
                "unexpected": "value",
            }
        ),
        encoding="utf-8",
    )
    try:
        RepairPlan.load(path)
    except ValueError:
        pass
    else:
        raise AssertionError("malformed repair plan must be rejected")


def test_repair_plan_save_is_validated_and_atomic(tmp_path: Path) -> None:
    from arenyxa.repair import RepairPlan

    plan = RepairPlan(str(tmp_path), str(tmp_path / "data"), [RepairCategory.OTHER.value])
    path = tmp_path / "repair" / "pending_repair_plan.json"
    plan.save(path)
    loaded = RepairPlan.load(path)
    assert loaded.categories == [RepairCategory.OTHER.value]
    assert not path.with_suffix(path.suffix + ".tmp").exists()


def test_app_settings_load_invalid_json_returns_safe_defaults_without_overwrite(tmp_path: Path) -> None:
    from arenyxa.config import AppSettings

    path = tmp_path / "settings.json"
    original = "{broken"
    path.write_text(original, encoding="utf-8")
    settings = AppSettings.load(path)
    assert settings == AppSettings()
    assert path.read_text(encoding="utf-8") == original


def test_runtime_diagnostics_ignore_current_running_crash_marker(tmp_path, monkeypatch) -> None:
    import os
    from arenyxa.config import AppPaths
    from arenyxa.repair import StartupHealthScanner

    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    (paths.root / "crash.marker").write_text(
        json.dumps({"pid": os.getpid(), "phase": "running"}), encoding="utf-8"
    )
    scanner = StartupHealthScanner(paths, tmp_path, ignore_current_session=True)
    monkeypatch.setenv("ARENYXA_ENFORCE_SOURCE_INTEGRITY", "0")
    report = scanner.scan()
    assert all(item.code != "PREVIOUS_UNCLEAN_EXIT" for item in report.findings)


def test_language_repair_does_not_restore_source_tree_implicitly(tmp_path, monkeypatch) -> None:
    from arenyxa.repair import RepairCategory, RepairEngine, RepairPlan

    data = tmp_path / "data"
    data.mkdir()
    plan = RepairPlan(
        str(tmp_path),
        str(data),
        [RepairCategory.ENCODING_UI.value],
        source_mode=True,
        relaunch=False,
    )
    engine = RepairEngine(plan)
    called = False

    def forbidden_restore() -> str:
        nonlocal called
        called = True
        return "unexpected"

    monkeypatch.setattr(engine, "_repair_program_files", forbidden_restore)
    engine._repair_language()
    assert called is False


def test_health_scanner_reports_invalid_navigation_setting_types(tmp_path, monkeypatch) -> None:
    from arenyxa.config import AppPaths
    from arenyxa.repair import StartupHealthScanner

    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    (paths.root / "settings.json").write_text(
        json.dumps(
            {
                "developer_mode": False,
                "developer_nav_expanded": True,
                "advanced_nav_expanded": "yes",
                "performance_mode": "turbo",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARENYXA_ENFORCE_SOURCE_INTEGRITY", "0")
    report = StartupHealthScanner(paths, tmp_path, ignore_current_session=True).scan()
    codes = {item.code for item in report.findings}
    assert "SETTING_BOOL_ADVANCED_NAV_EXPANDED" in codes
    assert "SETTING_PERFORMANCE_MODE_INVALID" in codes
    assert "DEVELOPER_NAV_STATE_INCONSISTENT" in codes


def test_health_scanner_reports_concurrency_budget_inconsistency(tmp_path, monkeypatch) -> None:
    from arenyxa.config import AppPaths
    from arenyxa.repair import StartupHealthScanner

    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    (paths.root / "settings.json").write_text(
        json.dumps({"request_concurrency": 2, "per_host_concurrency": 8}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARENYXA_ENFORCE_SOURCE_INTEGRITY", "0")
    report = StartupHealthScanner(paths, tmp_path, ignore_current_session=True).scan()
    codes = {item.code for item in report.findings}
    assert "PER_HOST_CONCURRENCY_EXCEEDS_GLOBAL" in codes


def test_settings_repair_normalizes_concurrency_without_disabling_feature(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    settings = paths.root / "settings.json"
    settings.write_text(
        json.dumps({"request_concurrency": 3, "per_host_concurrency": 20}),
        encoding="utf-8",
    )
    plan = RepairPlan(
        str(tmp_path), str(paths.root), [RepairCategory.SETTINGS_UI.value], source_mode=False
    )
    RepairEngine(plan)._repair_settings()
    repaired = json.loads(settings.read_text(encoding="utf-8"))
    assert repaired["request_concurrency"] == 3
    assert repaired["per_host_concurrency"] == 3


def test_plugin_repair_quarantines_non_object_manifest_without_deleting_old_evidence(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    old_evidence = paths.plugins / "quarantine" / "older-run" / "broken" / "evidence.txt"
    old_evidence.parent.mkdir(parents=True, exist_ok=True)
    old_evidence.write_text("keep", encoding="utf-8")

    broken = paths.plugins / "broken"
    broken.mkdir(parents=True, exist_ok=True)
    (broken / "plugin.json").write_text("[]", encoding="utf-8")

    plan = RepairPlan(str(tmp_path), str(paths.root), [RepairCategory.PLUGINS.value], source_mode=False)
    engine = RepairEngine(plan)
    detail = engine._repair_plugins()

    assert "隔离 1 个" in detail
    assert not broken.exists()
    assert old_evidence.read_text(encoding="utf-8") == "keep"
    quarantined_manifests = list((paths.plugins / "quarantine").glob("*/*/plugin.json"))
    assert any(item.read_text(encoding="utf-8") == "[]" for item in quarantined_manifests)
