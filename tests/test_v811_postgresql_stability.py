from __future__ import annotations

import base64
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage


def _postgres_test_dsn() -> str:
    dsn = os.environ.get("ARENYXA_POSTGRES_TEST_DSN", "").strip()
    if not dsn:
        pytest.skip("PostgreSQL integration DSN is not configured")
    return dsn


@pytest.fixture()
def isolated_postgres_dsn():
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    base_dsn = _postgres_test_dsn()
    schema = f"arenyxa_v811_{uuid.uuid4().hex}"
    with psycopg.connect(base_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        yield base_dsn, make_conninfo(base_dsn, options=f"-c search_path={schema}")
    finally:
        with psycopg.connect(base_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def _worker_public_key() -> str:
    raw = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class _GatedCursor:
    def __init__(
        self,
        cursor,
        candidate_selected: threading.Event,
        heartbeat_committed: threading.Event,
    ) -> None:
        self._cursor = cursor
        self._candidate_selected = candidate_selected
        self._heartbeat_committed = heartbeat_committed

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        rows = self._cursor.fetchall()
        self._candidate_selected.set()
        if not self._heartbeat_committed.wait(10.0):
            raise AssertionError("heartbeat connection did not commit")
        return rows


class _GatedConnection:
    def __init__(
        self,
        connection,
        candidate_selected: threading.Event,
        heartbeat_committed: threading.Event,
    ) -> None:
        self._connection = connection
        self._candidate_selected = candidate_selected
        self._heartbeat_committed = heartbeat_committed

    def execute(self, statement: str, params=()):
        cursor = self._connection.execute(statement, params)
        normalized = " ".join(str(statement).split())
        if "JOIN distributed_workers w" in normalized and "w.heartbeat_at<=?" in normalized:
            return _GatedCursor(cursor, self._candidate_selected, self._heartbeat_committed)
        return cursor

    def __getattr__(self, name: str):
        return getattr(self._connection, name)


def test_postgresql_stale_recovery_rechecks_heartbeat_after_candidate_selection(
    isolated_postgres_dsn,
) -> None:
    import psycopg

    _base_dsn, dsn = isolated_postgres_dsn
    recovery_queue = DurableDistributedQueue(dsn)
    heartbeat_queue = DurableDistributedQueue(dsn)
    worker_id = f"worker-{uuid.uuid4().hex}"
    job_id = ""
    candidate_selected = threading.Event()
    heartbeat_committed = threading.Event()
    original_connection = recovery_queue._connection

    try:
        recovery_queue.register_worker(worker_id, _worker_public_key(), {"slots": 1}, max_slots=1)
        job_id = recovery_queue.enqueue(
            "task.run",
            {"task": {"name": "heartbeat-toctou"}},
            resource_id="postgresql-heartbeat-toctou",
            permission="workflow.execute",
            idempotency_key=f"heartbeat-toctou-{uuid.uuid4().hex}",
        )
        lease = recovery_queue.lease_next(worker_id, lease_seconds=60)
        assert lease is not None and lease.job_id == job_id
        recovery_now = time.time()
        stale_heartbeat = recovery_now - recovery_queue._worker_heartbeat_timeout_seconds - 1.0
        with psycopg.connect(dsn, autocommit=True) as independent:
            independent.execute(
                "UPDATE distributed_workers SET heartbeat_at=%s WHERE worker_id=%s",
                (stale_heartbeat, worker_id),
            )

        @contextmanager
        def gated_connection():
            with original_connection() as connection:
                yield _GatedConnection(connection, candidate_selected, heartbeat_committed)

        recovery_queue._connection = gated_connection

        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="postgres-stale-recovery") as executor:
            recovery_future = executor.submit(
                recovery_queue.recover_stale_worker_leases,
                recovery_now,
            )
            assert candidate_selected.wait(10.0)
            try:
                # This is a different DurableDistributedQueue and pool, so its
                # heartbeat uses an independent PostgreSQL connection.
                heartbeat_queue.heartbeat(worker_id)
            finally:
                heartbeat_committed.set()
            assert recovery_future.result(timeout=10.0) == 0

        current = heartbeat_queue.job(job_id)
        assert current is not None and current["state"] == "leased"
        worker = heartbeat_queue.worker(worker_id)
        assert worker is not None and worker["active_leases"] == 1
        assert all(
            event["event_type"] != "worker_heartbeat_lost"
            for event in heartbeat_queue.job_events(job_id)
        )
    finally:
        recovery_queue._connection = original_connection
        heartbeat_queue.close()
        recovery_queue.close()


def test_postgresql_pool_discards_server_terminated_idle_connections(
    isolated_postgres_dsn,
) -> None:
    import psycopg

    base_dsn, dsn = isolated_postgres_dsn
    backend = PostgreSQLDistributedRuntimeStorage(dsn)
    contexts = []
    leased_connections = []
    terminated_pids: set[int] = set()
    try:
        # Hold the complete warm pool so every physical connection PID is
        # known, then return all four sockets to the idle pool.
        for _index in range(4):
            context = backend.connection()
            connection = context.__enter__()
            contexts.append(context)
            leased_connections.append(connection)
            terminated_pids.add(int(connection.execute("SELECT pg_backend_pid()").fetchone()[0]))
        assert len(terminated_pids) == 4
        while contexts:
            contexts.pop().__exit__(None, None, None)

        with psycopg.connect(base_dsn, autocommit=True) as admin:
            for pid in terminated_pids:
                assert bool(admin.execute("SELECT pg_terminate_backend(%s)", (pid,)).fetchone()[0])

        # The checkout health callback must reject the stale idle sockets and
        # let psycopg_pool replace them before this first business query.
        with backend.connection() as connection:
            replacement_pid = int(connection.execute("SELECT pg_backend_pid()").fetchone()[0])
            assert int(connection.execute("SELECT 1").fetchone()[0]) == 1
        assert replacement_pid not in terminated_pids
    finally:
        while contexts:
            contexts.pop().__exit__(None, None, None)
        backend.close()
