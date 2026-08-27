from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from arenyxa.application.runner import RunOrchestrator
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.models import FetchResponse, FieldSpec, RequestSpec, Run, Task
from arenyxa.infrastructure import database as database_module
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import HttpFetcher


def test_tls_contexts_are_created_once_per_verification_mode(monkeypatch) -> None:
    fetcher = HttpFetcher()
    import ssl

    real_factory = ssl.create_default_context
    calls = 0

    def counted_factory():
        nonlocal calls
        calls += 1
        return real_factory()

    monkeypatch.setattr(ssl, "create_default_context", counted_factory)
    with ThreadPoolExecutor(max_workers=8) as executor:
        verified = list(executor.map(lambda _index: fetcher._tls_context(True), range(16)))
        unverified = list(executor.map(lambda _index: fetcher._tls_context(False), range(16)))

    assert calls == 2
    assert all(context is verified[0] for context in verified)
    assert all(context is unverified[0] for context in unverified)
    assert verified[0] is not unverified[0]
    assert unverified[0].check_hostname is False
    assert unverified[0].verify_mode == ssl.CERT_NONE


def test_task_write_reuses_canonical_payload_for_exact_snapshot_hash(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "task-hash.db")
    store.initialize()
    task = Task(
        "large-task",
        [RequestSpec(f"https://example.test/{index}") for index in range(128)],
        status=TaskStatus.READY,
    )
    store.save_task(task)

    with store.connect() as connection:
        row = connection.execute(
            "SELECT definition_json,snapshot_hash FROM tasks WHERE id=?", (task.id,)
        ).fetchone()
    assert row is not None
    assert json.loads(row["definition_json"])["id"] == task.id
    assert row["snapshot_hash"] == task.snapshot_hash()


def test_existing_run_progress_does_not_reserialize_immutable_snapshot(
    tmp_path: Path, monkeypatch
) -> None:
    store = SQLiteStore(tmp_path / "run-progress.db")
    store.initialize()
    task = Task("run-task", [RequestSpec("https://example.test")], status=TaskStatus.READY)
    store.save_task(task)
    run = Run(task.id, task.to_dict(), status=RunStatus.RUNNING, total_units=10)
    store.save_run(run)

    def unexpected_dumps(*_args, **_kwargs):
        raise AssertionError("an existing Run must not reserialize its immutable task snapshot")

    monkeypatch.setattr(database_module.json, "dumps", unexpected_dumps)
    run.completed_units = 7
    run.success_count = 7
    run.stage = "fetch"
    store.save_run(run)

    with store.connect() as connection:
        row = connection.execute(
            "SELECT status,completed_units,success_count,stage FROM runs WHERE id=?", (run.id,)
        ).fetchone()
    assert row is not None
    assert dict(row) == {
        "status": "running",
        "completed_units": 7,
        "success_count": 7,
        "stage": "fetch",
    }


def test_same_host_backlog_is_classified_once_not_rescanned_quadratically(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "host-buckets.db")
    store.initialize()
    request_count = 800
    task = Task(
        "same-host",
        [RequestSpec(f"https://same.example/{index}") for index in range(request_count)],
        fields=[FieldSpec("value", "value", data_type="integer")],
        status=TaskStatus.READY,
        parser_hint="json",
    )
    store.save_task(task)
    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=4,
        per_host_workers=1,
        progress_interval_ms=500,
        result_write_batch_size=64,
        adaptive_request_concurrency=False,
    )
    host_calls = 0
    original_host_key = runner._host_key

    def counted_host_key(url: str) -> str:
        nonlocal host_calls
        host_calls += 1
        return original_host_key(url)

    def fetch(spec, token, on_attempt=None):
        del token, on_attempt
        value = int(spec.url.rsplit("/", 1)[1])
        payload = json.dumps({"value": value}).encode("utf-8")
        return FetchResponse(
            spec.url, spec.url, 200, {}, payload, 0.1, "utf-8", "application/json"
        )

    runner._host_key = counted_host_key                               
    runner.fetcher.fetch = fetch
    try:
        completed = runner.submit(task).future.result(timeout=15.0)
    finally:
        runner.shutdown(wait_for_runs=True)

    assert completed.status == RunStatus.COMPLETED
    assert completed.success_count == request_count
    assert host_calls <= request_count + runner.request_workers


def test_deferred_host_refills_all_available_per_host_permits(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "host-refill.db")
    store.initialize()
    task = Task(
        "same-host-refill",
        [RequestSpec(f"https://same.example/{index}") for index in range(12)],
        status=TaskStatus.READY,
        parser_hint="json",
    )
    store.save_task(task)
    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=4,
        per_host_workers=4,
        progress_interval_ms=500,
        result_write_batch_size=32,
        adaptive_request_concurrency=False,
    )
    permits = threading.Semaphore(0)
    state_lock = threading.Lock()
    started = 0
    active = 0

    def fetch(spec, token, on_attempt=None):
        nonlocal active, started
        del token, on_attempt
        with state_lock:
            started += 1
            active += 1
        try:
            assert permits.acquire(timeout=5.0)
            return FetchResponse(
                spec.url,
                spec.url,
                200,
                {},
                b"{}",
                0.1,
                "utf-8",
                "application/json",
            )
        finally:
            with state_lock:
                active -= 1

    runner.fetcher.fetch = fetch
    handle = runner.submit(task)
    try:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            with state_lock:
                if started >= 4 and active == 4:
                    break
            time.sleep(0.005)
        with state_lock:
            assert (started, active) == (4, 4)

        for _ in range(4):
            permits.release()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            with state_lock:
                if started >= 8 and active == 4:
                    break
            time.sleep(0.005)
        with state_lock:
            assert started >= 8
            assert active == 4
    finally:
        for _ in range(16):
            permits.release()
        handle.future.result(timeout=10.0)
        runner.shutdown(wait_for_runs=True)


def test_connection_pragmas_keep_busy_and_durability_contract(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "pragmas.db")
    store.initialize()
    with store.connect() as connection:
        assert int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) == 1
        assert int(connection.execute("PRAGMA busy_timeout").fetchone()[0]) == 30_000
        assert int(connection.execute("PRAGMA synchronous").fetchone()[0]) == 1
        assert int(connection.execute("PRAGMA wal_autocheckpoint").fetchone()[0]) == 4096
        assert int(connection.execute("PRAGMA cache_size").fetchone()[0]) == -8192
        assert int(connection.execute("PRAGMA temp_store").fetchone()[0]) == 2
