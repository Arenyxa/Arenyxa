from __future__ import annotations

import json
import socket
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest

from arenyxa.application.nextgen import (
    DistributedWorker,
    DistributedWorkerService,
    HttpRequestWorkbench,
    ProjectEnvironmentService,
    ProjectPythonEnvironmentService,
    RequestCodeGenerator,
    SecretVault,
)
from arenyxa.application.scheduler import ScheduleRule
from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent, RequestSpec, RetryPolicy
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher


def test_request_validation_preserves_query_grammar_but_rejects_bad_headers() -> None:
    spec = RequestSpec(
        "https://example.test/search",
        query={"filters[]": "a", "x y": "z"},
        cookies={"session.id": "ok"},
    )
    assert spec.validate() == []
    bad = RequestSpec("https://example.test", headers={"Bad Header": "x"})
    assert any("HTTP 字段名称" in item for item in bad.validate())


def test_http_read_polling_survives_short_socket_timeouts_and_honors_cancel() -> None:
    class FlakyResponse:
        def __init__(self) -> None:
            self.calls = 0

        def read(self, _size: int) -> bytes:
            self.calls += 1
            if self.calls <= 2:
                raise socket.timeout("poll")
            if self.calls == 3:
                return b"payload"
            return b""

    fetcher = HttpFetcher(1024)
    assert fetcher._read_limited(FlakyResponse(), CancellationToken(), read_timeout=1.0) == b"payload"

    token = CancellationToken()

    class CancellingResponse:
        def read(self, _size: int) -> bytes:
            token.cancel()
            raise socket.timeout("poll")

    with pytest.raises(ArenyxaError) as exc:
        fetcher._read_limited(CancellingResponse(), token, read_timeout=30.0)
    assert exc.value.code == "RUN_CANCELLED"


def test_request_codegen_matches_fetch_url_and_content_type() -> None:
    spec = RequestSpec(
        "https://example.test/items?a=1&a=2",
        query={"b": "3"},
        method="POST",
        content_type="application/json",
        body="{}",
    )
    assert RequestCodeGenerator._url(spec) == HttpFetcher._build_url(spec)
    assert RequestCodeGenerator._url(spec).endswith("?a=1&a=2&b=3")
    generated = RequestCodeGenerator().generate(spec, "curl")
    assert "Content-Type: application/json" in generated


def test_http_workbench_reconstructs_retry_policy_from_json_payload() -> None:
    spec = HttpRequestWorkbench.from_payload(
        {
            "url": "https://example.test",
            "retry": {
                "attempts": 4,
                "initial_backoff_seconds": 0.1,
                "max_backoff_seconds": 2.0,
                "retry_statuses": [429, 503],
                "allow_non_idempotent": True,
            },
        }
    )
    assert isinstance(spec.retry, RetryPolicy)
    assert spec.retry.attempts == 4
    assert spec.retry.retry_statuses == (429, 503)
    assert spec.validate() == []


def test_secret_vault_recovers_last_known_good_encrypted_revision(tmp_path: Path) -> None:
    vault = SecretVault(tmp_path / "vault")
    vault.set("alpha", "one")
    vault.set("beta", "two")
    assert vault.backup_path.exists()
    vault.vault_path.write_bytes(b"torn-write")

                                                                                           
                                                  
    assert vault.get("alpha") == "one"
    assert vault.get("beta") is None
    assert vault.vault_path.read_bytes() == vault.backup_path.read_bytes()


def test_secret_vault_reports_invalid_key_stably(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    root.mkdir()
    (root / "secrets.key").write_bytes(b"not-a-fernet-key")
    with pytest.raises(ArenyxaError) as exc:
        SecretVault(root)
    assert exc.value.code == "VAULT_KEY_INVALID"


def test_corrupt_worker_registry_is_never_silently_overwritten(tmp_path: Path) -> None:
    vault = SecretVault(tmp_path / "secrets")
    service = DistributedWorkerService(tmp_path / "workers", vault)
    service.path.write_text('{"broken": true}', encoding="utf-8")
    original = service.path.read_bytes()

    worker = DistributedWorker("w1", "local", "http://127.0.0.1:8080", "worker.token")
    with pytest.raises(ArenyxaError) as exc:
        service.upsert(worker, token="new-secret")
    assert exc.value.code == "WORKER_REGISTRY_CORRUPT"
    assert service.path.read_bytes() == original
    assert vault.get("worker.token") is None


def test_failed_python_venv_rebuild_restores_previous_environment(tmp_path: Path, monkeypatch) -> None:
    projects = ProjectEnvironmentService(tmp_path / "projects")
    service = ProjectPythonEnvironmentService(projects)
    old = service.venv_path("demo")
    old.mkdir(parents=True)
    (old / "marker.txt").write_text("old-good-env", encoding="utf-8")

    monkeypatch.setattr(service, "_discover_python", lambda: ["python"])
    monkeypatch.setattr(
        "arenyxa.application.nextgen.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="venv failed"),
    )
    with pytest.raises(RuntimeError, match="venv failed"):
        service.create("demo", clear=True)
    assert (old / "marker.txt").read_text(encoding="utf-8") == "old-good-env"
    assert not list(old.parent.glob(".venv.backup-*"))


def test_sqlite_backup_is_verified_and_corrupt_optional_setting_is_quarantined(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "arenyxa.db")
    store.initialize()
    store.set_setting("good", {"ok": True})
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)",
            ("bad", "{", "now"),
        )
    assert store.get_setting("bad", "fallback") == "fallback"

    backup = store.backup_to(tmp_path / "backups" / "snapshot.db")
    connection = sqlite3.connect(backup)
    try:
        assert connection.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
        assert json.loads(connection.execute("SELECT value_json FROM settings WHERE key='good'").fetchone()[0]) == {"ok": True}
    finally:
        connection.close()
    with pytest.raises(ValueError):
        store.backup_to(store.path)


def test_daily_scheduler_normalizes_dst_gap_and_does_not_double_run_fold() -> None:
    ny = ZoneInfo("America/New_York")
    spring = ScheduleRule(kind="daily", hour=2, minute=30, timezone="America/New_York")
    next_run = spring.next_after(datetime(2026, 3, 8, 6, 0, tzinfo=UTC))
    assert next_run.date().isoformat() == "2026-03-08"
    assert (next_run.hour, next_run.minute) == (3, 30)

    fall = ScheduleRule(kind="daily", hour=1, minute=30, timezone="America/New_York")
    first = fall.next_after(datetime(2026, 11, 1, 5, 0, tzinfo=UTC))
    assert first.astimezone(UTC) == datetime(2026, 11, 1, 5, 30, tzinfo=UTC)
                                                                                              
    after_first = fall.next_after(datetime(2026, 11, 1, 5, 45, tzinfo=UTC))
    assert after_first.date().isoformat() == "2026-11-02"
    assert (after_first.hour, after_first.minute) == (1, 30)
    assert after_first.tzinfo == ny


def test_capture_source_failure_drains_already_emitted_tail_event(store) -> None:
    event_ready = False

    class TailThenFailAdapter:
        def __init__(self) -> None:
            self.error: Exception | None = None

        def start(self, session: CaptureSession, emit) -> None:
            nonlocal event_ready
            emit(
                NetworkEvent(
                    session_id=session.id,
                    source_type=CaptureSource.SYSTEM,
                    protocol="tcp",
                    direction="inbound",
                    size=42,
                    host="example.test",
                )
            )
            event_ready = True
            self.error = RuntimeError("source died after tail event")

        def failure(self):
            return self.error

        def stop(self) -> None:
            return None

        def pause(self) -> None:
            return None

        def resume(self) -> None:
            return None

    controller = CaptureController(store, queue_capacity=8, flush_size=50)
    session = CaptureSession("tail", CaptureSource.SYSTEM)
    adapter = TailThenFailAdapter()
    controller.prepare(session, adapter)
    controller.start()
    assert event_ready
    deadline = time.monotonic() + 2
    while session.state != CaptureState.FAILED and time.monotonic() < deadline:
        time.sleep(0.01)
    with pytest.raises(ArenyxaError) as exc:
        controller.stop()
    assert exc.value.code == "CAPTURE_SOURCE_LOST"
    rows = list(store.iter_network_events(session.id))
    assert len(rows) == 1
    assert rows[0]["size"] == 42


def test_database_migration_version_is_atomic_on_statement_failure(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.infrastructure.database as database_module

    monkeypatch.setattr(
        database_module,
        "MIGRATIONS",
        ("CREATE TABLE should_rollback(id INTEGER); THIS IS NOT SQL;",),
    )
    store = SQLiteStore(tmp_path / "broken-migration.db")
    with pytest.raises(sqlite3.DatabaseError):
        store.initialize()
    connection = sqlite3.connect(store.path)
    try:
        assert connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='should_rollback'"
        ).fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 0
    finally:
        connection.close()


def test_existing_database_gets_verified_pre_migration_backup(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.infrastructure.database as database_module

    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        connection.execute("INSERT INTO schema_migrations VALUES(1, 'old')")
        connection.execute("CREATE TABLE legacy_data(value TEXT)")
        connection.execute("INSERT INTO legacy_data VALUES('keep-me')")
        connection.commit()
    finally:
        connection.close()

    monkeypatch.setattr(
        database_module,
        "MIGRATIONS",
        (
            "CREATE TABLE IF NOT EXISTS legacy_data(value TEXT);",
            "CREATE TABLE new_schema(value INTEGER);",
        ),
    )
    store = SQLiteStore(path)
    store.initialize()
    backup = path.with_name("legacy.pre-migration.bak")
    assert backup.exists()
    copied = sqlite3.connect(backup)
    try:
        assert copied.execute("PRAGMA quick_check(1)").fetchone()[0] == "ok"
        assert copied.execute("SELECT value FROM legacy_data").fetchone()[0] == "keep-me"
        assert copied.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='new_schema'"
        ).fetchone()[0] == 0
    finally:
        copied.close()


def test_oversized_settings_file_falls_back_without_unbounded_read(tmp_path: Path) -> None:
    from arenyxa.config import AppSettings

    path = tmp_path / "settings.json"
    path.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    loaded = AppSettings.load(path)
    assert loaded == AppSettings()


def test_run_worker_turns_midflight_storage_failure_into_stable_terminal_state(tmp_path: Path) -> None:
    from arenyxa.application.runner import RunOrchestrator
    from arenyxa.domain.enums import RunStatus
    from arenyxa.domain.models import Run, Task

    class FailingStore:
        def save_run(self, _run) -> None:
            raise OSError("disk full")

    task = Task("storage-failure", [RequestSpec("https://example.test")])
    orchestrator = RunOrchestrator(FailingStore(), max_workers=1, request_workers=1)                          
    orchestrator.fetcher.fetch = lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network must not start"))                               
    run = Run(task_id=task.id, task_snapshot=task.to_dict(), total_units=1)
    try:
        result = orchestrator._execute(task, run, CancellationToken(), None, False)
    finally:
        orchestrator.shutdown(wait_for_runs=True)
    assert result.status == RunStatus.FAILED
    assert result.error_code == "RUN_STORAGE_FAILED"
    assert result.request_count == 0


def test_run_submit_reports_storage_failure_before_enqueue(tmp_path: Path) -> None:
    from arenyxa.application.runner import RunOrchestrator
    from arenyxa.domain.models import Task

    class FailingStore:
        def save_run(self, _run) -> None:
            raise OSError("read-only")

    task = Task("submit-storage-failure", [RequestSpec("https://example.test")])
    orchestrator = RunOrchestrator(FailingStore(), max_workers=1, request_workers=1)                          
    try:
        with pytest.raises(ArenyxaError) as exc:
            orchestrator.submit(task)
        assert exc.value.code == "RUN_STORAGE_FAILED"
        assert orchestrator.active_handles() == []
    finally:
        orchestrator.shutdown(wait_for_runs=True)


def test_multiple_vault_instances_share_transaction_lock(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    root = tmp_path / "shared-vault"
    first = SecretVault(root)
    second = SecretVault(root)

    def write(index: int) -> None:
        (first if index % 2 == 0 else second).set(f"key{index}", f"value{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(40)))
    names = first.names()
    assert names == sorted(f"key{index}" for index in range(40))
    assert all(first.get(f"key{index}") == f"value{index}" for index in range(40))


def test_concurrent_settings_writers_leave_one_complete_json_document(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from arenyxa.config import AppSettings

    path = tmp_path / "settings.json"

    def save(index: int) -> None:
        AppSettings(max_workers=(index % 32) + 1, developer_mode=bool(index % 2)).save(path)

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(save, range(80)))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert 1 <= int(data["max_workers"]) <= 32
    assert not list(tmp_path.glob(".settings.json.*.tmp"))


def test_distributed_worker_quotes_remote_task_identifier(tmp_path: Path, monkeypatch) -> None:
    vault = SecretVault(tmp_path / "vault")
    service = DistributedWorkerService(tmp_path / "workers", vault)
    worker = DistributedWorker(
        id="local",
        name="Local",
        base_url="http://127.0.0.1:8787",
        token_secret="worker-token",
    )
    captured: dict[str, object] = {}
    monkeypatch.setattr(service, "_worker", lambda _worker_id: worker)

    def fake_request(_worker, path: str, **kwargs):
        captured["path"] = path
        captured.update(kwargs)
        return {"id": "run1"}

    monkeypatch.setattr(service, "_request", fake_request)
    assert service.run_task("local", "task/../unsafe ?#") == {"id": "run1"}
    assert captured["path"] == "/api/v1/tasks/task%2F..%2Funsafe%20%3F%23/runs"


def test_har_import_is_bounded_and_tolerates_noncritical_malformed_fields(tmp_path: Path) -> None:
    from arenyxa.infrastructure.capture.har import HarAnalyzer

    path = tmp_path / "weird.har"
    path.write_text(
        json.dumps(
            {
                "log": {
                    "pages": [],
                    "entries": [
                        {
                            "time": "NaN",
                            "request": {
                                "method": "GET",
                                "url": "https://example.test/",
                                "headers": [None, {"name": "X-Test", "value": "ok"}],
                            },
                            "response": {
                                "status": "not-a-status",
                                "headers": None,
                                "bodySize": "bad",
                                "content": None,
                            },
                            "timings": {"wait": "NaN", "receive": "12.5"},
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    events, summary = HarAnalyzer.load(path, CaptureSession("HAR", CaptureSource.HAR_IMPORT))
    assert len(events) == 1
    assert events[0].status == 0
    assert events[0].request_headers == {"X-Test": "ok"}
    assert events[0].response_headers == {}
    assert events[0].timing["wait"] == 0.0
    assert events[0].timing["receive"] == 12.5
    assert summary.request_count == 1

    oversized = tmp_path / "oversized.har"
    with oversized.open("wb") as stream:
        stream.truncate(256 * 1024 * 1024 + 1)
    with pytest.raises(ArenyxaError) as exc:
        HarAnalyzer.load(oversized, CaptureSession("HAR", CaptureSource.HAR_IMPORT))
    assert exc.value.code == "HAR_IMPORT_TOO_LARGE"


def test_repair_plan_control_file_has_bounded_read(tmp_path: Path) -> None:
    from arenyxa.repair import RepairPlan

    path = tmp_path / "plan.json"
    with path.open("wb") as stream:
        stream.truncate(4 * 1024 * 1024 + 1)
    with pytest.raises(ValueError):
        RepairPlan.load(path)


def test_legacy_database_backup_is_taken_before_migration_metadata_changes(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.infrastructure.database as database_module

    path = tmp_path / "legacy-no-migrations.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute("CREATE TABLE legacy_only(value TEXT)")
        connection.execute("INSERT INTO legacy_only VALUES('original')")
        connection.commit()
    finally:
        connection.close()

    monkeypatch.setattr(database_module, "MIGRATIONS", ("CREATE TABLE new_table(value INTEGER);",))
    store = SQLiteStore(path)
    store.initialize()

    backup = path.with_name("legacy-no-migrations.pre-migration.bak")
    copied = sqlite3.connect(backup)
    try:
        assert copied.execute("SELECT value FROM legacy_only").fetchone()[0] == "original"
        assert copied.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchone()[0] == 0
    finally:
        copied.close()


def test_sqlite_store_connect_closes_handle_if_connection_setup_fails(tmp_path: Path, monkeypatch) -> None:
    

    class BrokenConnection:
        def __init__(self) -> None:
            self.row_factory = None
            self.closed = False

        def executescript(self, _sql: str):
            raise sqlite3.DatabaseError("corrupt during connection setup")

        def close(self) -> None:
            self.closed = True

    broken = BrokenConnection()
    monkeypatch.setattr(
        "arenyxa.infrastructure.database.sqlite3.connect",
        lambda *args, **kwargs: broken,
    )
    store = SQLiteStore(tmp_path / "broken.db")
    with pytest.raises(sqlite3.DatabaseError, match="corrupt during connection setup"):
        store.connect()
    assert broken.closed is True
