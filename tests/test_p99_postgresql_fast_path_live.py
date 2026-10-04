from __future__ import annotations

import os
import uuid
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql

from arenyxa.enterprise.distributed import DurableDistributedQueue
from scripts.postgresql_32_worker_gate import _public_key


def _live_dsn() -> str:
    dsn = os.environ.get("ARENYXA_POSTGRES_TEST_DSN", "").strip()
    if not dsn:
        pytest.skip("PostgreSQL integration DSN is not configured")
    return dsn


def _replace_database(dsn: str, database: str) -> str:
    parts = urlsplit(dsn)
    assert parts.scheme in {"postgresql", "postgres"}
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", parts.query, parts.fragment))


def test_live_postgresql_lease_fast_path_parameter_contract() -> None:
    admin_dsn = _live_dsn()
    database = f"arenyxa_p99_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    queue = DurableDistributedQueue(_replace_database(admin_dsn, database))
    try:
        queue.register_worker("worker-0", _public_key(), {"slots": 2}, max_slots=2)
        job_id = queue.enqueue(
            "benchmark.noop",
            {},
            resource_id="p99:live-contract",
            permission="workflow.execute",
            idempotency_key=f"p99-live-{uuid.uuid4().hex}",
        )
        lease = queue.lease_next("worker-0", lease_seconds=60)
        assert lease is not None and lease.job_id == job_id
    finally:
        queue.close()
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s", (database,))
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))


def test_live_postgresql_complete_fast_path_parameter_contract() -> None:
    admin_dsn = _live_dsn()
    database = f"arenyxa_p99_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    queue = DurableDistributedQueue(_replace_database(admin_dsn, database))
    try:
        queue.register_worker("worker-0", _public_key(), {"slots": 2}, max_slots=2)
        job_id = queue.enqueue("benchmark.noop", {}, resource_id="p99:complete",
                               permission="workflow.execute", idempotency_key=f"p99-complete-{uuid.uuid4().hex}")
        lease = queue.lease_next("worker-0", lease_seconds=60)
        assert lease is not None and lease.job_id == job_id
        queue.start_job(job_id, "worker-0", lease.lease_token)
        queue.complete(job_id, "worker-0", lease.lease_token, {"status": "ok"})
        assert queue.job(job_id)["state"] == "completed"
        assert queue.worker("worker-0")["active_leases"] == 0
    finally:
        queue.close()
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s", (database,))
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))
