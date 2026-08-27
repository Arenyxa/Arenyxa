from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from arenyxa.release_hardening import (
    ReleaseChannel, ReleaseGateReport, ReleasePolicy, UpgradeTransaction, compatibility_matrix, default_migration_registry,
)


def test_release_channels_lts_and_protocol_window_are_explicit() -> None:
    policy = ReleasePolicy()
    assert {item.value for item in ReleaseChannel} == {"stable", "beta", "developer", "enterprise"}
    assert policy.lts_support_months >= 24
    assert policy.deprecation_window_months >= 12
    matrix = compatibility_matrix()
    assert matrix["enterprise_protocol"]["current"] == 2
    assert matrix["enterprise_protocol"]["minimum"] == 1
    assert matrix["runtime_compatibility_identity"] == "6.8.0"


def test_settings_workflow_and_plugin_migrations_are_reversible() -> None:
    registry = default_migration_registry()
    settings = {"schema_version": 8, "language": "zh-CN"}
    migrated, steps = registry.migrate("settings", settings, 8, 9)
    assert migrated["schema_version"] == 9
    assert registry.rollback(migrated, steps)["schema_version"] == 8

    workflow = {"schema": "arenyxa.workflow/v0", "name": "Legacy", "nodes": [], "edges": []}
    migrated, steps = registry.migrate("workflow_definition", workflow, 0, 1)
    assert migrated["schema"] == "arenyxa.workflow/v1"
    assert len(migrated["sha256"]) == 64
    assert registry.rollback(migrated, steps)["schema"] == "arenyxa.workflow/v0"

    plugin = {"id": "sample", "name": "Sample", "version": "1.0"}
    migrated, steps = registry.migrate("plugin_api", plugin, 0, 1)
    assert migrated["api_version"] == "1"
    assert "api_version" not in registry.rollback(migrated, steps)


def test_release_hardening_does_not_invent_unknown_old_enterprise_vault_migration() -> None:
    registry = default_migration_registry()
    with pytest.raises(Exception) as unsupported:
        registry.plan("enterprise_vault", 0, 1)
    assert getattr(unsupported.value, "code", "") in {"MIGRATION_VERSION_UNSUPPORTED", "MIGRATION_PATH_MISSING"}


def _create_db(path: Path, value: str) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS state(value TEXT NOT NULL)")
        connection.execute("DELETE FROM state")
        connection.execute("INSERT INTO state(value) VALUES(?)", (value,))
        connection.commit()
    finally:
        connection.close()


def _db_value(path: Path) -> str:
    connection = sqlite3.connect(path)
    try:
        return str(connection.execute("SELECT value FROM state").fetchone()[0])
    finally:
        connection.close()


def test_upgrade_preflight_backup_and_failure_restore_control_files_and_sqlite(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    control = data / "settings.json"
    control.write_text(json.dumps({"schema_version": 8, "value": "old"}), encoding="utf-8")
    database = data / "arenyxa.sqlite"
    _create_db(database, "old-db")
    tx = UpgradeTransaction(data, tmp_path / "upgrade-backup")
    preflight = tx.preflight([control], database)
    assert preflight.allowed is True and preflight.database_integrity.casefold() == "ok"
    manifest = tx.backup([control], database_paths=[database])
    assert len(manifest["files"]) == 1 and len(manifest["databases"]) == 1
    tx.verify_backup()

    def failing_upgrade() -> None:
        control.write_text(json.dumps({"schema_version": 9, "value": "new"}), encoding="utf-8")
        _create_db(database, "new-db")
        raise RuntimeError("injected upgrade failure")

    with pytest.raises(RuntimeError):
        tx.execute(failing_upgrade)
    assert json.loads(control.read_text(encoding="utf-8"))["value"] == "old"
    assert _db_value(database) == "old-db"


def test_tampered_upgrade_backup_blocks_execution(tmp_path: Path) -> None:
    data = tmp_path / "data"; data.mkdir()
    control = data / "settings.json"; control.write_text('{"schema_version":8}', encoding="utf-8")
    tx = UpgradeTransaction(data, tmp_path / "backup")
    tx.backup([control])
    backed = tx.backup_root / "files" / "settings.json"
    backed.write_bytes(backed.read_bytes() + b"tamper")
    with pytest.raises(Exception) as invalid:
        tx.verify_backup()
    assert getattr(invalid.value, "code", "") == "UPGRADE_BACKUP_INVALID"


def test_phase12_release_artifacts_exist() -> None:
    root = Path(__file__).resolve().parents[1]
    required = [
        root / "docs/release/LTS_POLICY.md",
        root / "docs/release/COMPATIBILITY_MATRIX.json",
        root / "docs/release/INDEPENDENT_SECURITY_AUDIT_CHECKLIST.md",
        root / "docs/roadmap/PHASE11_12_IMPLEMENTATION.md",
        root / "scripts/release_hardening.py",
        root / "scripts/upgrade_manager.py",
        root / "scripts/enterprise_migration.py",
    ]
    assert all(path.is_file() and path.stat().st_size > 100 for path in required)


def test_corrupted_existing_migration_journal_fails_closed(tmp_path: Path) -> None:
    data = tmp_path / "data"; data.mkdir()
    control = data / "settings.json"; control.write_text('{"schema_version":8}', encoding="utf-8")
    tx = UpgradeTransaction(data, tmp_path / "backup")
    tx.backup([control])
    tx.journal_path.write_text("{broken", encoding="utf-8")
    with pytest.raises(Exception) as invalid:
        tx.execute(lambda: None)
    assert getattr(invalid.value, "code", "") == "MIGRATION_JOURNAL_INVALID"


def test_release_channel_gate_cannot_substitute_automated_tests_for_native_windows() -> None:
    report = ReleaseGateReport(
        regression=True, integrity=True, migration_rollback=True, security_review=True,
        native_windows=False, distributed_failure_drill=True,
    )
    assert report.can_promote(ReleaseChannel.BETA) is True
    assert report.can_promote(ReleaseChannel.STABLE) is False
    assert report.can_promote(ReleaseChannel.ENTERPRISE) is False
    assert report.missing(ReleaseChannel.ENTERPRISE) == ["native_windows"]


def test_migration_journal_malformed_event_fails_closed(tmp_path: Path) -> None:
    data = tmp_path / "data"; data.mkdir()
    control = data / "settings.json"; control.write_text('{"schema_version":8}', encoding="utf-8")
    tx = UpgradeTransaction(data, tmp_path / "backup")
    tx.backup([control])
    tx.journal_path.write_text(
        json.dumps({"schema": "arenyxa.migration-journal/v1", "events": [{"at": "now", "state": "ok", "details": {}}, "corrupt"]}),
        encoding="utf-8",
    )
    with pytest.raises(Exception) as invalid:
        tx.execute(lambda: None)
    assert getattr(invalid.value, "code", "") == "MIGRATION_JOURNAL_INVALID"


def test_upgrade_backup_rejects_symlink_even_without_preflight(tmp_path: Path) -> None:
    data = tmp_path / "data"; data.mkdir()
    target = data / "settings-real.json"; target.write_text('{"schema_version":8}', encoding="utf-8")
    link = data / "settings.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")
    tx = UpgradeTransaction(data, tmp_path / "backup")
    with pytest.raises(Exception) as unsafe:
        tx.backup([link])
    assert getattr(unsafe.value, "code", "") == "UPGRADE_PATH_UNSAFE"


def test_failed_backup_does_not_leave_partial_destination(tmp_path: Path) -> None:
    data = tmp_path / "data"; data.mkdir()
    first = data / "first.json"; first.write_text('{"schema_version":8}', encoding="utf-8")
    missing = data / "missing.json"
    backup = tmp_path / "backup"
    tx = UpgradeTransaction(data, backup)
    with pytest.raises(Exception):
        tx.backup([first, missing])
    assert not backup.exists() or not any(backup.iterdir())
                                                                                   
    tx2 = UpgradeTransaction(data, backup)
    tx2.backup([first])
    tx2.verify_backup()


def test_upgrade_preflight_rejects_explicit_missing_database(tmp_path: Path) -> None:
    data = tmp_path / "data"; data.mkdir()
    control = data / "settings.json"; control.write_text('{"schema_version":8}', encoding="utf-8")
    tx = UpgradeTransaction(data, tmp_path / "backup")
    result = tx.preflight([control], database_path=data / "missing.sqlite")
    assert result.allowed is False
    assert "database_path_missing" in result.reasons
def test_release_private_key_generator_uses_exclusive_restrictive_creation() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts/generate_release_key.py").read_text(encoding="utf-8")
    assert "os.O_EXCL" in source
    assert "0o600" in source
    assert "os.fsync(fd)" in source
    assert "private_key.write_bytes" not in source

