from __future__ import annotations

import select
from contextlib import contextmanager

from arenyxa.enterprise import runtime_storage
from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage


class _Cursor:
    def fetchone(self):
        return {"arenyxa_pool_health": 1}


class _HealthConnection:
    def __init__(self) -> None:
        self.executed: list[str] = []
        self.closed = False
        self.broken = False

    def execute(self, sql: str):
        self.executed.append(str(sql))
        return _Cursor()

    def fileno(self) -> int:
        return 123

    def rollback(self) -> None:
        pass

class _FakePsycopg:
    Error = RuntimeError


class _Pool:
    created: list["_Pool"] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.closed = False
        type(self).created.append(self)

    def open(self, *, wait: bool, timeout: float) -> None:
        assert wait is True
        assert timeout == 15.0

    @contextmanager
    def connection(self, *, timeout: float):
        assert timeout == 15.0
        yield _HealthConnection()

    def close(self) -> None:
        self.closed = True


def test_reconstructed_a_pool_is_fixed_8_by_8(monkeypatch) -> None:
    _Pool.created.clear()
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    monkeypatch.setattr(backend, "_driver", lambda: (_FakePsycopg, object(), _Pool))

    with backend.connection():
        pass

    pool = _Pool.created[0]
    assert pool.kwargs["min_size"] == 8
    assert pool.kwargs["max_size"] == 8
    assert pool.kwargs["timeout"] == 15.0
    assert pool.kwargs["max_idle"] == 300.0
    assert pool.kwargs["max_lifetime"] == 1800.0
    assert pool.kwargs["reconnect_timeout"] == 30.0
    backend.close()


def test_reconstructed_b_removes_only_fast_path_trim() -> None:
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")

    for sql in (
        backend.lease_next_fast_sql(),
        backend.start_job_fast_sql(),
        backend.complete_fast_sql(),
    ):
        assert "INSERT INTO distributed_job_events" in sql
        assert "trimmed AS" not in sql
        assert "DELETE FROM distributed_job_events" not in sql

    class _Recording:
        def __init__(self) -> None:
            self.sql = ""
            self.params = ()

        def execute(self, sql, params=()):
            self.sql = str(sql)
            self.params = tuple(params)
            return _Cursor()

    connection = _Recording()
    backend.record_event(
        connection,
        ("job", "event", "a", "b", "worker", "", "{}", "now"),
        128,
    )
    assert "DELETE FROM distributed_job_events" in connection.sql
    assert "LIMIT ?" in connection.sql


def test_reconstructed_c_is_absent_start_keeps_baseline_for_update() -> None:
    sql = PostgreSQLDistributedRuntimeStorage(
        "postgresql://user:pass@db/arenyxa"
    ).start_job_fast_sql()
    assert "WITH worker_locked AS MATERIALIZED" in sql
    assert "candidate AS MATERIALIZED" in sql
    assert sql.index("worker_locked AS MATERIALIZED") < sql.index("candidate AS MATERIALIZED")
    assert "FOR UPDATE OF j" in sql
    assert "UPDATE distributed_jobs AS j" in sql
    assert "lease_expires_at>EXTRACT(EPOCH FROM clock_timestamp())" in sql


def test_reconstructed_g_skips_roundtrip_before_five_second_idle(monkeypatch) -> None:
    now = [100.0]
    monkeypatch.setattr(runtime_storage.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(select, "select", lambda r, w, x, timeout: ([], [], []))
    conn = _HealthConnection()

    PostgreSQLDistributedRuntimeStorage._mark_pool_connection_idle(conn)
    now[0] = 104.999
    PostgreSQLDistributedRuntimeStorage._check_pool_connection(conn)
    assert conn.executed == []

    now[0] = 105.0
    PostgreSQLDistributedRuntimeStorage._check_pool_connection(conn)
    assert conn.executed == ["SELECT 1 AS arenyxa_pool_health"]


def test_reconstructed_g_fd_readiness_forces_immediate_probe(monkeypatch) -> None:
    now = [200.0]
    monkeypatch.setattr(runtime_storage.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(select, "select", lambda r, w, x, timeout: ([r[0]], [], []))
    conn = _HealthConnection()

    PostgreSQLDistributedRuntimeStorage._mark_pool_connection_idle(conn)
    now[0] = 200.1
    PostgreSQLDistributedRuntimeStorage._check_pool_connection(conn)
    assert conn.executed == ["SELECT 1 AS arenyxa_pool_health"]


def test_reconstructed_g_unknown_idle_age_is_probed(monkeypatch) -> None:
    monkeypatch.setattr(select, "select", lambda r, w, x, timeout: ([], [], []))
    conn = _HealthConnection()
    PostgreSQLDistributedRuntimeStorage._check_pool_connection(conn)
    assert conn.executed == ["SELECT 1 AS arenyxa_pool_health"]
