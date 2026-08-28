from __future__ import annotations

from contextlib import contextmanager

from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage


class _DriverError(Exception):
    pass


class _FakePsycopg:
    Error = _DriverError


class _Cursor:
    rowcount = 1

    def fetchone(self):
        return {"healthy": 1}

    def fetchall(self):
        return []


class _Raw:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.rollbacks = 0

    def execute(self, sql: str, params=()):
        self.executed.append((str(sql), tuple(params)))
        return _Cursor()

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        self.rollbacks += 1


class _Pool:
    created: list["_Pool"] = []

    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        self.opens: list[tuple[bool, float]] = []
        self.connection_calls: list[float] = []
        self.closed = False
        self.raws: list[_Raw] = []
        type(self).created.append(self)

    def open(self, *, wait: bool, timeout: float) -> None:
        self.opens.append((wait, timeout))

    @contextmanager
    def connection(self, *, timeout: float):
        self.connection_calls.append(timeout)
        raw = _Raw()
        self.raws.append(raw)
        yield raw

    def close(self) -> None:
        self.closed = True


def test_postgresql_runtime_reuses_one_bounded_connection_pool(monkeypatch) -> None:
    _Pool.created.clear()
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    monkeypatch.setattr(backend, "_driver", lambda: (_FakePsycopg, object(), _Pool))

    with backend.connection() as connection:
        connection.execute("SELECT ? AS value", (1,))
    with backend.connection() as connection:
        connection.execute("SELECT ? AS value", (2,))

    assert len(_Pool.created) == 1
    pool = _Pool.created[0]
    assert pool.kwargs["min_size"] == 4
    assert pool.kwargs["max_size"] == 8
    assert pool.kwargs["open"] is False
    assert pool.opens == [(True, 15.0)]
    assert pool.connection_calls == [15.0, 15.0]
    assert pool.raws[0].executed[-1] == ("SELECT %s AS value", (1,))
    assert pool.raws[1].executed[-1] == ("SELECT %s AS value", (2,))

    backend.close()
    assert pool.closed is True
    assert backend._pool is None


def test_postgresql_runtime_connection_failure_rolls_back_and_preserves_driver_error(monkeypatch) -> None:
    _Pool.created.clear()
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    monkeypatch.setattr(backend, "_driver", lambda: (_FakePsycopg, object(), _Pool))

    try:
        with backend.connection() as connection:
            raw = connection.raw
            raise _DriverError("boom")
    except _DriverError:
        pass
    else:
        raise AssertionError("driver error should propagate")

    assert raw.rollbacks == 1
    backend.close()
