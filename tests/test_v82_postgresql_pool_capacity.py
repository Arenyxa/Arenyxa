from __future__ import annotations

from typing import Any

from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage


class _DriverError(Exception):
    pass


class _FakePsycopg:
    Error = _DriverError


class _FakePool:
    captured: dict[str, Any] = {}

    def __init__(self, **kwargs: Any) -> None:
        type(self).captured = dict(kwargs)
        self.closed = False

    def open(self, *, wait: bool, timeout: float) -> None:
        assert wait is True
        assert timeout == 15.0

    def close(self) -> None:
        self.closed = True


def test_postgresql_worker_pool_prewarms_full_bounded_capacity(monkeypatch) -> None:
    """The eight-slot worker-client pool must be ready before timed work starts."""
    storage = PostgreSQLDistributedRuntimeStorage(
        "postgresql://arenyxa:arenyxa_ci@127.0.0.1:5432/arenyxa_ci"
    )
    monkeypatch.setattr(
        storage,
        "_driver",
        lambda: (_FakePsycopg, object(), _FakePool),
    )

    pool = storage._connection_pool_locked()

    assert pool is storage._pool
    assert _FakePool.captured["max_size"] == 8
    assert _FakePool.captured["min_size"] == _FakePool.captured["max_size"]
