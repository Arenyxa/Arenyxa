from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise.runtime_storage import (
    _POSTGRES_SCHEMA,
    PostgreSQLDistributedRuntimeStorage,
)
from scripts.postgresql_32_worker_gate import _lease_failure_diagnostic, _public_key


class _Rows:
    def __init__(self, rows: list[tuple[str, str, str]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[str, str, str]]:
        return list(self._rows)


class _RecordingConnection:
    def __init__(self, rows: list[tuple[str, str, str]]) -> None:
        self.rows = rows
        self.statements: list[str] = []

    def execute(self, sql: str, _parameters: Any = None) -> _Rows:
        self.statements.append(sql)
        return _Rows(self.rows)


def test_postgresql_epoch_columns_use_float8_for_new_schemas() -> None:
    assert "heartbeat_at DOUBLE PRECISION NOT NULL" in _POSTGRES_SCHEMA
    assert "lease_expires_at DOUBLE PRECISION NOT NULL DEFAULT 0" in _POSTGRES_SCHEMA
    assert "heartbeat_at REAL" not in _POSTGRES_SCHEMA
    assert "lease_expires_at REAL" not in _POSTGRES_SCHEMA


def test_postgresql_legacy_float4_epoch_columns_are_migrated() -> None:
    connection = _RecordingConnection(
        [
            ("distributed_workers", "heartbeat_at", "real"),
            ("distributed_jobs", "lease_expires_at", "real"),
        ]
    )

    PostgreSQLDistributedRuntimeStorage._migrate_epoch_columns_to_float8(connection)  # type: ignore[arg-type]

    migrations = [statement for statement in connection.statements if statement.startswith("ALTER TABLE")]
    assert migrations == [
        (
            "ALTER TABLE distributed_workers ALTER COLUMN heartbeat_at TYPE DOUBLE PRECISION "
            "USING heartbeat_at::DOUBLE PRECISION"
        ),
        (
            "ALTER TABLE distributed_jobs ALTER COLUMN lease_expires_at TYPE DOUBLE PRECISION "
            "USING lease_expires_at::DOUBLE PRECISION"
        ),
    ]


def test_postgresql_float8_epoch_columns_do_not_repeat_migration() -> None:
    connection = _RecordingConnection(
        [
            ("distributed_workers", "heartbeat_at", "double precision"),
            ("distributed_jobs", "lease_expires_at", "double precision"),
        ]
    )

    PostgreSQLDistributedRuntimeStorage._migrate_epoch_columns_to_float8(connection)  # type: ignore[arg-type]

    assert not any(statement.startswith("ALTER TABLE") for statement in connection.statements)


def test_postgresql_hot_paths_use_atomic_admission_and_one_event_statement() -> None:
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:pass@db/arenyxa")
    assert "RETURNING protocol_min,protocol_max" in backend.claim_worker_slot_for_lease_sql()
    assert "WITH eligible_worker AS" in backend.lease_next_fast_sql()
    assert "FOR UPDATE OF j SKIP LOCKED" in backend.lease_next_fast_sql()
    assert "w.active_leases<w.max_slots" in backend.lease_next_fast_sql()
    assert "WITH candidate AS" in backend.start_job_fast_sql()
    assert "WITH candidate AS" in backend.complete_fast_sql()
    assert "worker_updated AS" in backend.complete_fast_sql()

    connection = _RecordingConnection([])
    backend.record_event(
        connection,
        ("job-1", "completed", "running", "completed", "worker-1", "", "{}", "now"),
        128,
    )
    assert len(connection.statements) == 1
    assert connection.statements[0].lstrip().startswith("WITH inserted AS")
    assert "LIMIT ?" in connection.statements[0]


def test_postgresql_gate_diagnostic_is_structured_without_exposing_lease_token(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "gate-diagnostic.sqlite")
    queue.register_worker("worker-a", _public_key(), {"diagnostic": True}, max_slots=1)
    job_id = queue.enqueue(
        "diagnostic.noop",
        {},
        resource_id="diagnostic:test",
        permission="workflow.execute",
        idempotency_key="diagnostic-job",
    )
    started = queue._clock.snapshot()
    started_perf = time.perf_counter()
    lease = queue.lease_next("worker-a", lease_seconds=60)
    assert lease is not None and lease.job_id == job_id
    finished = queue._clock.snapshot()
    diagnostic = _lease_failure_diagnostic(
        queue,
        "worker-a",
        "start_job",
        ArenyxaError(
            "DISTRIBUTED_LEASE_EXPIRED",
            "Distributed job lease has expired",
            domain="ENTERPRISE_DISTRIBUTED",
        ),
        lease,
        {
            "lease_next_started_perf": started_perf,
            "lease_next_finished_perf": time.perf_counter(),
            "lease_next_started_wall": started.wall_epoch,
            "lease_next_finished_wall": finished.wall_epoch,
            "lease_next_started_stable": started.stable_epoch,
            "lease_next_finished_stable": finished.stable_epoch,
            "start_job_started_wall": finished.wall_epoch,
            "start_job_started_stable": finished.stable_epoch,
        },
    )

    assert diagnostic["phase"] == "start_job"
    assert diagnostic["error_code"] == "DISTRIBUTED_LEASE_EXPIRED"
    assert diagnostic["database_job_state"] == "leased"
    assert diagnostic["database_lease_token_hash_state"] == "matches_presented"
    assert diagnostic["lease_remaining_at_start_job_seconds"] > 0
    assert lease.lease_token not in json.dumps(diagnostic, sort_keys=True)
