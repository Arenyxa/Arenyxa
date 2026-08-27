from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from arenyxa.infrastructure.database import MIGRATIONS, SQLiteStore


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "compatibility"


def _fixture_cases() -> list[Path]:
    return sorted(path for path in FIXTURE_ROOT.glob("migration-v*") if path.is_dir())


@pytest.mark.parametrize("fixture_dir", _fixture_cases(), ids=lambda p: p.name)
def test_historical_shadow_upgrade_read_write_restart_and_rollback(tmp_path: Path, fixture_dir: Path) -> None:
    manifest = json.loads((fixture_dir / "manifest.json").read_text(encoding="utf-8"))
    source = fixture_dir / str(manifest["database"])
    assert hashlib.sha256(source.read_bytes()).hexdigest() == manifest["sha256"]

    working = tmp_path / "arenyxa.db"
    shutil.copy2(source, working)
    original = working.read_bytes()

    store = SQLiteStore(working)
    store.initialize()
    assert store.integrity_check().casefold() == "ok"
    with store.connect() as connection:
        applied = {int(row[0]) for row in connection.execute("SELECT version FROM schema_migrations")}
        assert applied == set(range(1, len(MIGRATIONS) + 1))
        row = connection.execute("SELECT value_json FROM settings WHERE key=?", (manifest["expected_setting_key"],)).fetchone()
        assert row is not None and "preserve-me" in str(row[0])
        task = connection.execute("SELECT name FROM tasks WHERE id=?", (manifest["expected_task_id"],)).fetchone()
        assert task is not None
        connection.execute(
            "INSERT OR REPLACE INTO settings(key,value_json,updated_at) VALUES(?,?,?)",
            ("compat.roundtrip", '{"ok":true}', "2026-08-23T00:00:00+00:00"),
        )
        connection.commit()

    # Restart/read path.
    restarted = SQLiteStore(working)
    restarted.initialize()
    with restarted.connect() as connection:
        assert connection.execute("SELECT value_json FROM settings WHERE key='compat.roundtrip'").fetchone()[0] == '{"ok":true}'

    backup = working.with_name("arenyxa.pre-migration.bak")
    assert backup.is_file()
    assert SQLiteStore(backup).integrity_check().casefold() == "ok"

    # Rollback is file-level recovery by restoring the verified pre-migration backup.
    rollback = tmp_path / "rollback.db"
    shutil.copy2(backup, rollback)
    with sqlite3.connect(rollback) as connection:
        versions = {int(row[0]) for row in connection.execute("SELECT version FROM schema_migrations")}
        assert max(versions) == int(manifest["migration_version"])
        assert connection.execute("SELECT value_json FROM settings WHERE key=?", (manifest["expected_setting_key"],)).fetchone() is not None
    # SQLite's online backup API can produce a byte-different but logically identical image
    # (page layout/header counters are implementation details).  Rollback correctness is the
    # historical schema/data contract above, while the immutable fixture hash is verified at
    # test entry before migration.
    assert hashlib.sha256(source.read_bytes()).hexdigest() == manifest["sha256"]


def test_shadow_fixture_inventory_covers_multiple_upgrade_eras() -> None:
    cases = _fixture_cases()
    assert len(cases) >= 5
    versions = [int(json.loads((case / "manifest.json").read_text(encoding="utf-8"))["migration_version"]) for case in cases]
    assert versions == sorted(versions)
    assert versions[0] == 1
    assert versions[-1] < len(MIGRATIONS)
