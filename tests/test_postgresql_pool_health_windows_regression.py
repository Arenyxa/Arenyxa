from __future__ import annotations

import time

from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage


class _Cursor:
    def fetchone(self):
        return (1,)


class _ProbeConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self._arenyxa_pool_idle_since = time.monotonic() - 10.0

    def execute(self, sql: str):
        self.statements.append(sql)
        return _Cursor()


def test_pool_health_check_falls_back_to_sql_without_crashing() -> None:
    connection = _ProbeConnection()
    PostgreSQLDistributedRuntimeStorage._check_pool_connection(connection)
    assert connection.statements == ["SELECT 1 AS arenyxa_pool_health"]
