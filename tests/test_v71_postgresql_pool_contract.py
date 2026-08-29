from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import ClassVar

import pytest

from arenyxa.domain.errors import ArenyxaError
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
    created: ClassVar[list[_Pool]] = []

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
    assert pool.kwargs["check"] == backend._check_pool_connection
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


def test_postgresql_write_transaction_overrides_stale_server_snapshot_isolation(monkeypatch) -> None:
    _Pool.created.clear()
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    monkeypatch.setattr(backend, "_driver", lambda: (_FakePsycopg, object(), _Pool))

    with backend.connection() as connection:
        backend.begin_write(connection)

    assert _Pool.created[0].raws[0].executed == [
        ("BEGIN ISOLATION LEVEL READ COMMITTED", ()),
    ]
    backend.close()


class _CloseBlockingPool(_Pool):
    close_entered = threading.Event()
    allow_close = threading.Event()

    def close(self) -> None:
        type(self).close_entered.set()
        if not type(self).allow_close.wait(5.0):
            raise AssertionError("test did not release pool close")
        super().close()


def test_postgresql_runtime_close_is_terminal_while_pool_close_is_in_flight(monkeypatch) -> None:
    _CloseBlockingPool.created.clear()
    _CloseBlockingPool.close_entered.clear()
    _CloseBlockingPool.allow_close.clear()
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    monkeypatch.setattr(backend, "_driver", lambda: (_FakePsycopg, object(), _CloseBlockingPool))

    with backend.connection():
        pass

    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="postgres-runtime-close") as executor:
        close_future = executor.submit(backend.close)
        assert _CloseBlockingPool.close_entered.wait(5.0)

        with pytest.raises(ArenyxaError) as caught, backend.connection():
            pass
        assert caught.value.code == "DISTRIBUTED_STORAGE_CLOSED"
        assert len(_CloseBlockingPool.created) == 1
        assert backend.pool_metrics()["lifecycle_state"] == "closing"

        _CloseBlockingPool.allow_close.set()
        close_future.result(timeout=5.0)
    assert backend.pool_metrics()["lifecycle_state"] == "closed"

    # CLOSED is terminal and idempotent: neither connection() nor close()
    # can resurrect or replace the retired pool.
    backend.close()
    with pytest.raises(ArenyxaError), backend.connection():
        pass
    assert len(_CloseBlockingPool.created) == 1


class _RetryClosePool(_Pool):
    close_calls = 0

    def close(self) -> None:
        type(self).close_calls += 1
        if type(self).close_calls == 1:
            raise _DriverError("close interrupted")
        super().close()


def test_postgresql_runtime_close_failure_stays_non_admitting_and_is_retryable(monkeypatch) -> None:
    _RetryClosePool.created.clear()
    _RetryClosePool.close_calls = 0
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    monkeypatch.setattr(backend, "_driver", lambda: (_FakePsycopg, object(), _RetryClosePool))

    with backend.connection():
        pass
    with pytest.raises(_DriverError, match="close interrupted"):
        backend.close()

    assert backend.pool_metrics()["lifecycle_state"] == "closing"
    with pytest.raises(ArenyxaError), backend.connection():
        pass

    backend.close()
    assert _RetryClosePool.close_calls == 2
    assert backend.pool_metrics()["lifecycle_state"] == "closed"


class _CreationAndConnectionBlockingPool(_Pool):
    open_entered = threading.Event()
    allow_open = threading.Event()
    connection_entered = threading.Event()
    allow_connection_exit = threading.Event()
    connection_returned = threading.Event()

    def open(self, *, wait: bool, timeout: float) -> None:
        type(self).open_entered.set()
        if not type(self).allow_open.wait(5.0):
            raise AssertionError("test did not release pool creation")
        super().open(wait=wait, timeout=timeout)

    @contextmanager
    def connection(self, *, timeout: float):
        self.connection_calls.append(timeout)
        raw = _Raw()
        self.raws.append(raw)
        type(self).connection_entered.set()
        try:
            if not type(self).allow_connection_exit.wait(5.0):
                raise AssertionError("test did not release active connection")
            yield raw
        finally:
            type(self).connection_returned.set()

    def close(self) -> None:
        if not type(self).connection_returned.is_set():
            raise AssertionError("pool closed before the admitted connection drained")
        super().close()


def test_postgresql_runtime_close_drains_pool_creation_and_active_admission(monkeypatch) -> None:
    pool_type = _CreationAndConnectionBlockingPool
    pool_type.created.clear()
    for event in (
        pool_type.open_entered,
        pool_type.allow_open,
        pool_type.connection_entered,
        pool_type.allow_connection_exit,
        pool_type.connection_returned,
    ):
        event.clear()
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    monkeypatch.setattr(backend, "_driver", lambda: (_FakePsycopg, object(), pool_type))
    close_invoked = threading.Event()

    def use_connection() -> None:
        with backend.connection():
            pass

    def close_backend() -> None:
        close_invoked.set()
        backend.close()

    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="postgres-runtime-race") as executor:
        connection_future = executor.submit(use_connection)
        assert pool_type.open_entered.wait(5.0)
        close_future = executor.submit(close_backend)
        assert close_invoked.wait(5.0)
        pool_type.allow_open.set()
        assert pool_type.connection_entered.wait(5.0)

        deadline = time.monotonic() + 5.0
        while backend.pool_metrics()["lifecycle_state"] != "closing":
            assert time.monotonic() < deadline
            threading.Event().wait(0.001)
        assert not close_future.done()

        pool_type.allow_connection_exit.set()
        connection_future.result(timeout=5.0)
        close_future.result(timeout=5.0)

    assert pool_type.connection_returned.is_set()
    assert len(pool_type.created) == 1
    assert backend.pool_metrics()["lifecycle_state"] == "closed"
