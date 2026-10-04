from __future__ import annotations

from pathlib import Path

from psycopg.conninfo import make_conninfo

from arenyxa.enterprise.runtime_storage import (
    PostgreSQLDistributedRuntimeStorage,
    SQLiteDistributedRuntimeStorage,
    storage_backend_for,
)


def test_make_conninfo_keyword_dsn_selects_postgresql_backend() -> None:
    keyword_dsn = make_conninfo(
        "postgresql://postgres@127.0.0.1:55432/postgres",
        options="-c search_path=arenyxa_test",
    )
    backend = storage_backend_for(keyword_dsn)
    assert isinstance(backend, PostgreSQLDistributedRuntimeStorage)
    assert backend.capabilities.backend == "postgresql"


def test_sqlite_path_containing_equals_remains_sqlite(tmp_path: Path) -> None:
    backend = storage_backend_for(tmp_path / "cache=user.db")
    assert isinstance(backend, SQLiteDistributedRuntimeStorage)
    assert backend.capabilities.backend == "sqlite"
