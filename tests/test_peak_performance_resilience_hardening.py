from __future__ import annotations

import base64
import json
import logging
import threading
import time
from pathlib import Path

from arenyxa.application.runner import RunOrchestrator
from arenyxa.domain.enums import TaskStatus
from arenyxa.domain.models import FetchResponse, FieldSpec, Project, RequestSpec, Task
from arenyxa.enterprise import distributed as distributed_module
from arenyxa.enterprise import distributed_queue as distributed_queue_module
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.observability import JsonFormatter, Redactor


class _ConnectionCountingStore(SQLiteStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.connection_count = 0

    def connect(self):
        self.connection_count += 1
        return super().connect()


class _FlushTrackingStore(SQLiteStore):
    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.first_result_flush = threading.Event()

    def append_results(self, records, batch_size: int = 500):
        written = super().append_results(records, batch_size=batch_size)
        self.first_result_flush.set()
        return written


class _RecoveryCountingQueue(DurableDistributedQueue):
    def __init__(self, path: Path) -> None:
        self.recovery_calls = 0
        super().__init__(path)

    def recover_expired_leases(self, now: float | None = None) -> int:
        self.recovery_calls += 1
        return super().recover_expired_leases(now=now)


def _worker_key() -> str:
    return base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")


def test_project_catalogue_is_materialized_from_one_sqlite_snapshot(tmp_path: Path) -> None:
    store = _ConnectionCountingStore(tmp_path / "projects.db")
    store.initialize()
    for index in range(120):
        store.save_project(
            Project(
                f"Project {index}",
                id=f"project-{index:03d}",
                description=f"description-{index}",
                tags=["peak", str(index)],
            )
        )

    store.connection_count = 0
    projects = store.list_projects(limit=120)

    assert len(projects) == 120
    assert store.connection_count == 1
    assert {project.id for project in projects} == {f"project-{index:03d}" for index in range(120)}
    assert all(project.tags[0] == "peak" for project in projects)


def test_negative_catalogue_limits_cannot_expand_to_unbounded_sqlite_reads(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "limits.db")
    store.initialize()
    for index in range(3):
        store.save_task(
            Task(
                f"Task {index}",
                [RequestSpec(f"https://example.test/{index}")],
                id=f"task-{index}",
                status=TaskStatus.READY,
            )
        )
    assert len(store.list_tasks(limit=-1)) == 1


def test_slow_run_flushes_results_by_age_before_large_batch_fills(tmp_path: Path) -> None:
    store = _FlushTrackingStore(tmp_path / "timed-flush.db")
    store.initialize()
    release_tail = threading.Event()
    task = Task(
        "timed flush",
        [RequestSpec(f"https://same.example/{index}") for index in range(2)],
        fields=[FieldSpec("value", "value", data_type="integer")],
        status=TaskStatus.READY,
        parser_hint="json",
    )
    store.save_task(task)
    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=2,
        per_host_workers=1,
        result_write_batch_size=100,
        result_flush_interval_ms=50,
        adaptive_request_concurrency=False,
    )

    def fetch(spec, token, on_attempt=None):
        del token, on_attempt
        index = int(spec.url.rsplit("/", 1)[1])
        if index >= 1:
            assert release_tail.wait(timeout=3.0)
        time.sleep(0.03)
        payload = json.dumps({"value": index}).encode("utf-8")
        return FetchResponse(
            spec.url, spec.url, 200, {}, payload, 0.1, "utf-8", "application/json"
        )

    runner.fetcher.fetch = fetch
    handle = runner.submit(task)
    try:
        assert store.first_result_flush.wait(timeout=2.0)
        assert not handle.future.done()
    finally:
        release_tail.set()
        completed = handle.future.result(timeout=5.0)
        runner.shutdown(wait_for_runs=True)
    assert completed.result_count == 2


def test_empty_worker_poll_burst_coalesces_expiry_recovery_scans(tmp_path: Path) -> None:
    queue = _RecoveryCountingQueue(tmp_path / "distributed.db")
    queue.register_worker("worker-a", _worker_key(), {"cpu": 8})
    initial_calls = queue.recovery_calls
    queue._expiry_scan_interval_seconds = 60.0
    queue._last_expiry_scan_monotonic = time.monotonic()

    for _ in range(100):
        assert queue.lease_next("worker-a") is None

    assert queue.recovery_calls == initial_calls


def test_distributed_connections_keep_full_durability_and_busy_contract(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "distributed-pragmas.db")
    with queue._connect() as connection:
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
        assert int(connection.execute("PRAGMA busy_timeout").fetchone()[0]) == 10_000
        assert int(connection.execute("PRAGMA synchronous").fetchone()[0]) == 2
        assert str(connection.execute("PRAGMA journal_mode").fetchone()[0]).casefold() == "wal"


def test_health_runs_integrity_and_journal_snapshot_even_during_early_boot(
    tmp_path: Path, monkeypatch,
) -> None:
    queue = DurableDistributedQueue(tmp_path / "early-boot-health.db")
    queue.enqueue(
        "task.run",
        {"task": "health"},
        resource_id="resource-a",
        permission="workflow.execute",
        idempotency_key="early-boot-health",
    )
    monkeypatch.setattr(distributed_queue_module.time, "monotonic", lambda: 1.0)

    health = queue.health()

    assert health["database_integrity"] == "ok"
    assert health["state_invariants"]["journal_events"] == 1


def test_redactor_handles_cycles_without_losing_secret_fail_closed_behavior() -> None:
    payload: dict[str, object] = {"authorization": "Bearer private-value"}
    payload["self"] = payload
    redacted = Redactor().redact(payload)

    assert redacted["authorization"] == "••••••••"
    assert redacted["self"] == "[circular reference]"


def test_redactor_bounds_adversarial_depth_and_scrubs_object_text() -> None:
    nested: object = {"password": "never-visible"}
    for _ in range(40):
        nested = {"child": nested}

    class SecretText:
        def __str__(self) -> str:
            return "password=private-value"

    redacted = Redactor().redact({"nested": nested, "object": SecretText()})
    rendered = repr(redacted)

    assert "never-visible" not in rendered
    assert "private-value" not in rendered
    assert "[redaction depth limit]" in rendered


def test_json_log_formatter_emits_compact_parseable_redacted_json() -> None:
    formatter = JsonFormatter(Redactor())
    record = logging.LogRecord(
        "arenyxa.test", logging.INFO, __file__, 1, "token=private-value", (), None
    )
    rendered = formatter.format(record)
    parsed = json.loads(rendered)

    assert ": " not in rendered
    assert "private-value" not in rendered
    assert parsed["message"] == "token=••••••••"
