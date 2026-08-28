from __future__ import annotations

import json
import threading
import time
import urllib.error
from concurrent.futures import CancelledError
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from arenyxa.application.export import ExportService
from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.scheduler import ScheduleRule, SchedulerService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.enums import CaptureSource, CaptureState, RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, FetchResponse, FieldSpec, RequestSpec, RetryPolicy, Task, Workflow, WorkflowNode
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.observability import Redactor
from arenyxa.infrastructure.plugins import PluginSandbox


class HostAwareFetcher:
    def __init__(self, *, block_shared: bool = False) -> None:
        self.shared_started = threading.Event()
        self.shared_release = threading.Event()
        self.unrelated_started = threading.Event()
        self.block_shared = block_shared

    def fetch(self, spec, token, on_attempt=None):
        if on_attempt:
            on_attempt(0)
        if "shared.example" in spec.url:
            self.shared_started.set()
            if self.block_shared:
                while not self.shared_release.is_set():
                    token.checkpoint()
                    time.sleep(0.003)
                delay = 0.0
            else:
                delay = 0.28
        else:
            self.unrelated_started.set()
            delay = 0.01
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline:
            token.checkpoint()
            time.sleep(0.003)
        return FetchResponse(
            url=spec.url,
            final_url=spec.url,
            status=200,
            headers={"Content-Type": "application/json"},
            body=json.dumps({"value": spec.url}).encode(),
            elapsed_ms=delay * 1000,
            encoding="utf-8",
            content_type="application/json",
        )


def _task(name: str, url: str) -> Task:
    return Task(
        name,
        [RequestSpec(url)],
        fields=[FieldSpec("value", "value")],
        parser_hint="json",
        status=TaskStatus.READY,
    )


def test_cross_run_host_waiters_do_not_starve_unrelated_hosts(store) -> None:
    runner = RunOrchestrator(store, max_workers=3, request_workers=2, per_host_workers=1, progress_interval_ms=50)
    fetcher = HostAwareFetcher(block_shared=True)
    runner.fetcher = fetcher
    first = _task("first", "https://shared.example/a")
    second = _task("second", "https://shared.example/b")
    unrelated = _task("unrelated", "https://other.example/fast")
    for task in (first, second, unrelated):
        store.save_task(task)
    try:
        h1 = runner.submit(first)
        assert fetcher.shared_started.wait(1.0)
        h2 = runner.submit(second)
        h3 = runner.submit(unrelated)
        assert fetcher.unrelated_started.wait(1.0)
        assert h3.future.result(timeout=2).status == RunStatus.COMPLETED
        assert not fetcher.shared_release.is_set()
        fetcher.shared_release.set()
        assert h1.future.result(timeout=2).status == RunStatus.COMPLETED
        assert h2.future.result(timeout=2).status == RunStatus.COMPLETED
    finally:
        runner.shutdown(wait=True)


def test_nonblocking_runner_shutdown_marks_queued_run_cancelled(store) -> None:
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    runner.fetcher = HostAwareFetcher()
    first = _task("active", "https://shared.example/a")
    second = _task("queued", "https://other.example/b")
    store.save_task(first)
    store.save_task(second)
    first_handle = runner.submit(first)
    assert runner.fetcher.shared_started.wait(1.0)
    second_handle = runner.submit(second)
    runner.shutdown(wait_for_runs=False)
    with pytest.raises(CancelledError):
        second_handle.future.result(timeout=1)
    deadline = time.monotonic() + 1
    while second_handle.run.status != RunStatus.CANCELLED and time.monotonic() < deadline:
        time.sleep(0.01)
    assert second_handle.run.status == RunStatus.CANCELLED
    first_result = first_handle.future.result(timeout=1)
    assert first_result.status == RunStatus.CANCELLED


def test_scheduler_reenable_recalculates_stale_deadline() -> None:
    persisted: list[datetime] = []
    scheduler = SchedulerService(lambda _sid, when: persisted.append(when))
    rule = ScheduleRule(kind="interval", interval_minutes=5, timezone="UTC")
    scheduler.add("job", rule, lambda: None, enabled=False, next_run=datetime.now(UTC) - timedelta(days=1))
    scheduler.set_enabled("job", True)
    try:
        assert persisted
        assert persisted[-1] > datetime.now(UTC) + timedelta(minutes=4)
    finally:
        scheduler.stop()


def test_scheduler_callback_pool_is_bounded() -> None:
    lock = threading.Lock()
    active = 0
    peak = 0
    release = threading.Event()
    entered = threading.Event()

    def callback() -> None:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if peak >= 2:
                entered.set()
        release.wait(1.0)
        with lock:
            active -= 1

    scheduler = SchedulerService(max_callback_workers=2)
    past = datetime.now(UTC) - timedelta(seconds=1)
    for index in range(8):
        scheduler.add(f"job-{index}", ScheduleRule(interval_minutes=60, timezone="UTC"), callback, next_run=past)
    scheduler.start()
    assert entered.wait(1.0)
    time.sleep(0.05)
    assert peak == 2
    release.set()
    scheduler.stop()


def test_deleted_task_is_removed_from_fts_atomically(store) -> None:
    task = _task("UniqueSearchNeedle", "https://example.test")
    store.save_task(task)
    assert any(row["object_id"] == task.id for row in store.search("UniqueSearchNeedle"))
    task.status = TaskStatus.DELETED
    store.save_task(task)
    assert all(row["object_id"] != task.id for row in store.search("UniqueSearchNeedle"))


def test_http_query_is_inserted_before_fragment() -> None:
    spec = RequestSpec("https://example.test/path?old=1#section", query={"new": "2"})
    assert HttpFetcher._build_url(spec) == "https://example.test/path?old=1&new=2#section"


def test_non_timeout_url_error_has_network_error_code(monkeypatch) -> None:
    fetcher = HttpFetcher()
    monkeypatch.setattr(fetcher, "_fetch_once", lambda _spec, _token: (_ for _ in ()).throw(
        urllib.error.URLError(ConnectionRefusedError("refused"))
    ))
    spec = RequestSpec("https://example.test", retry=RetryPolicy(attempts=0))
    with pytest.raises(ArenyxaError) as exc:
        fetcher.fetch(spec)
    assert exc.value.code == "FETCH_NETWORK_ERROR"


def test_request_validation_rejects_header_injection_and_bad_task_types() -> None:
    spec = RequestSpec("https://example.test", headers={"X-Test": "ok\r\nInjected: yes"})
    assert any("CR/LF" in message for message in spec.validate())
    task = Task("valid", [spec])
    task.name = 42                            
    errors = task.validate()
    assert errors and any("任务名称" in message for message in errors)


class FakeExportStore:
    def iter_results(self, _run_id: str):
        yield {"value": 1}
        yield {"value": 2}


def test_export_cancel_keeps_previous_destination(tmp_path: Path) -> None:
    destination = tmp_path / "data.json"
    destination.write_text("known-good", encoding="utf-8")
    cancel = threading.Event()
    cancel.set()
    service = ExportService(FakeExportStore())                          
    with pytest.raises(ArenyxaError) as exc:
        service.export_run("run", destination, "json", cancel=cancel)
    assert exc.value.code == "EXPORT_CANCELLED"
    assert destination.read_text(encoding="utf-8") == "known-good"


def test_workflow_rejects_duplicate_ids_and_disconnected_cycle() -> None:
    duplicate = Workflow("dup", [WorkflowNode("source", {}, id="x"), WorkflowNode("sink", {}, id="x")])
    with pytest.raises(ArenyxaError) as exc:
        WorkflowEngine().execute(duplicate, [{}])
    assert exc.value.code == "WORKFLOW_NODE_DUPLICATE"

    cyclic = Workflow(
        "cycle",
        [
            WorkflowNode("source", {}, id="root"),
            WorkflowNode("map", {}, id="b", next_ids=["c"]),
            WorkflowNode("map", {}, id="c", next_ids=["b"]),
        ],
    )
    with pytest.raises(ArenyxaError) as exc:
        WorkflowEngine().execute(cyclic, [{}])
    assert exc.value.code == "WORKFLOW_CYCLE"


def test_plugin_without_storage_cannot_delete_arbitrary_file(tmp_path: Path) -> None:
    valuable = tmp_path / "valuable.txt"
    valuable.write_text("keep", encoding="utf-8")
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "plugin.json").write_text(json.dumps({
        "id": "safe.plugin", "name": "Safe", "version": "1.0", "entry": "main.py", "permissions": {}
    }), encoding="utf-8")
    (plugin / "main.py").write_text(
        "import os\ndef handle(request):\n    os.remove(request['path'])\n    return {'ok': True}\n",
        encoding="utf-8",
    )
    with pytest.raises(ArenyxaError) as exc:
        PluginSandbox().invoke(plugin, {"path": str(valuable)}, {})
    assert exc.value.code == "PLUGIN_EXECUTION_FAILED"
    assert valuable.read_text(encoding="utf-8") == "keep"


def test_redactor_covers_inline_token_secret_cookie_and_authorization() -> None:
    text = "token=abc123&x=1 secret:xyz Cookie: sid=topsecret\nAuthorization: Basic dXNlcjpwYXNz"
    redacted = Redactor().redact(text)
    for secret in ("abc123", "xyz", "topsecret", "dXNlcjpwYXNz"):
        assert secret not in redacted


class FailingCaptureAdapter:
    def __init__(self) -> None:
        self.started = False

    def start(self, _session, _emit) -> None:
        self.started = True

    def stop(self) -> None:
        return None

    def pause(self) -> None:
        return None

    def resume(self) -> None:
        return None

    def failure(self):
        return RuntimeError("source died") if self.started else None


def test_capture_controller_detects_async_adapter_failure(store) -> None:
    controller = CaptureController(store, queue_capacity=10, flush_size=2)
    session = CaptureSession("failing", CaptureSource.SYSTEM)
    adapter = FailingCaptureAdapter()
    controller.prepare(session, adapter)
    controller.start()
    deadline = time.monotonic() + 1.5
    while session.state != CaptureState.FAILED and time.monotonic() < deadline:
        time.sleep(0.02)
    assert session.state == CaptureState.FAILED
    with pytest.raises(ArenyxaError) as exc:
        controller.stop()
    assert exc.value.code == "CAPTURE_SOURCE_LOST"


def test_sqlite_database_adapter_rejects_ddl_type_injection(tmp_path: Path) -> None:
    from arenyxa.infrastructure.database_adapters import SQLiteDatabaseAdapter

    adapter = SQLiteDatabaseAdapter()
    adapter.open({"path": str(tmp_path / "adapter.db")}, {})
    try:
        with pytest.raises(ValueError):
            adapter.ensure_schema("safe_table", {"value": "TEXT); DROP TABLE safe_table; --"})
        adapter.ensure_schema("safe_table", {"value": "string"})
        assert adapter.bulk_write("safe_table", [{"value": "ok"}], batch_size=1) == 1
    finally:
        adapter.close()


def test_project_rejects_casefold_portability_collision(tmp_path: Path) -> None:
    import zipfile
    from arenyxa.application.project_format import ArenyxaProjectService

    package = tmp_path / "collision.arenyxa"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("manifest.json", '{"name":"demo","files":{}}')
        archive.writestr("scripts/A.py", "a")
        archive.writestr("scripts/a.py", "b")
    with pytest.raises(ArenyxaError) as exc:
        ArenyxaProjectService().validate(package)
    assert exc.value.code == "PROJECT_PATH_COLLISION"


def test_plugin_without_network_cannot_create_socket(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin-net"
    plugin.mkdir()
    (plugin / "plugin.json").write_text(json.dumps({
        "id": "no.network", "name": "No Network", "version": "1.0", "entry": "main.py", "permissions": {}
    }), encoding="utf-8")
    (plugin / "main.py").write_text(
        "import socket\ndef handle(request):\n    socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n    return {'ok': True}\n",
        encoding="utf-8",
    )
    with pytest.raises(ArenyxaError) as exc:
        PluginSandbox().invoke(plugin, {}, {})
    assert exc.value.code == "PLUGIN_EXECUTION_FAILED"


def test_recover_interrupted_runs_and_captures_after_crash(store) -> None:
    from arenyxa.domain.models import Run

    task = _task("interrupted", "https://example.test")
    store.save_task(task)
    run = Run(task_id=task.id, task_snapshot=task.to_dict(), status=RunStatus.RUNNING)
    run.stage = "fetch"
    store.save_run(run)
    capture = CaptureSession("interrupted-capture", CaptureSource.SYSTEM)
    capture.state = CaptureState.CAPTURING
    store.save_capture(capture)

    recovered = store.recover_interrupted_state()
    assert recovered == {"runs": 1, "captures": 1}
    persisted_run = next(row for row in store.list_runs() if row["id"] == run.id)
    assert persisted_run["status"] == "failed"
    assert persisted_run["error_code"] == "RUN_INTERRUPTED"
    persisted_capture = next(row for row in store.list_captures() if row["id"] == capture.id)
    assert persisted_capture["state"] == "failed"


def test_disabling_schedule_cancels_callback_waiting_in_pool() -> None:
    first_started = threading.Event()
    release_first = threading.Event()
    second_fired = threading.Event()

    def first() -> None:
        first_started.set()
        release_first.wait(1.0)

    scheduler = SchedulerService(max_callback_workers=1)
    past = datetime.now(UTC) - timedelta(seconds=1)
    scheduler.add("first", ScheduleRule(interval_minutes=60, timezone="UTC"), first, next_run=past)
    scheduler.add(
        "second",
        ScheduleRule(interval_minutes=60, timezone="UTC"),
        second_fired.set,
        next_run=past,
    )
    scheduler.start()
    try:
        assert first_started.wait(1.0)
        deadline = time.monotonic() + 1.0
        while "second" not in scheduler._callback_futures and time.monotonic() < deadline:                
            time.sleep(0.01)
        scheduler.set_enabled("second", False)
        release_first.set()
        time.sleep(0.15)
        assert not second_fired.is_set()
    finally:
        release_first.set()
        scheduler.stop()


def test_plugin_output_budget_is_enforced_while_child_is_running(tmp_path: Path) -> None:
    from arenyxa.infrastructure.plugins import SandboxBudget

    plugin = tmp_path / "plugin-output"
    plugin.mkdir()
    (plugin / "plugin.json").write_text(
        json.dumps({
            "id": "output.limit",
            "name": "Output Limit",
            "version": "1.0",
            "entry": "main.py",
            "permissions": {},
        }),
        encoding="utf-8",
    )
    (plugin / "main.py").write_text(
        "def handle(request):\n"
        "    print('X' * 50000)\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )
    with pytest.raises(ArenyxaError) as exc:
        PluginSandbox().invoke(
            plugin,
            {},
            {},
                                                                                  
                                                                              
                                                                          
                                                                         
                                                                              
                                                                             
        SandboxBudget(timeout_seconds=2.0, max_output_bytes=1024, max_memory_mb=256),
        )
    assert exc.value.code == "PLUGIN_BUDGET_EXCEEDED"


def test_field_validation_rejects_invalid_builtins_before_run() -> None:
    from arenyxa.domain.models import CleanerStep, ValidationRule

    field = FieldSpec(
        "value",
        "div",
        selector_type="typo",
        cleaners=[CleanerStep("regex_extract", {"pattern": "("})],
        validators=[ValidationRule("regex", {"pattern": "["})],
    )
    errors = field.validate()
    assert any("selector_type" in error for error in errors)
    assert sum("正则表达式无效" in error for error in errors) == 2


def test_non_idempotent_requests_do_not_retry_without_explicit_opt_in(monkeypatch) -> None:
    calls = 0
    fetcher = HttpFetcher()

    def fail(_spec, _token):
        nonlocal calls
        calls += 1
        raise urllib.error.URLError(ConnectionResetError("lost after send"))

    monkeypatch.setattr(fetcher, "_fetch_once", fail)
    spec = RequestSpec(
        "https://example.test/submit",
        method="POST",
        retry=RetryPolicy(attempts=3),
    )
    with pytest.raises(ArenyxaError):
        fetcher.fetch(spec)
    assert calls == 1

    calls = 0
    spec.retry.allow_non_idempotent = True
    with pytest.raises(ArenyxaError):
        fetcher.fetch(spec)
    assert calls == 4


def test_invalid_server_charset_falls_back_to_utf8() -> None:
    content_type, charset = HttpFetcher._content_type(
        {"Content-Type": "text/html; charset=definitely-not-a-codec"}
    )
    assert content_type == "text/html"
    assert charset == "utf-8"


def test_database_adapter_rejects_schema_drift_in_bulk_rows(tmp_path: Path) -> None:
    from arenyxa.infrastructure.database_adapters import SQLiteDatabaseAdapter

    adapter = SQLiteDatabaseAdapter()
    adapter.open({"path": str(tmp_path / "adapter.db")}, {})
    try:
        adapter.ensure_schema("records", {"id": "integer", "value": "text"})
        with pytest.raises(ValueError, match="identical columns"):
            adapter.bulk_write(
                "records",
                [
                    {"id": 1, "value": "ok"},
                    {"id": 2, "value": "ok", "unexpected": "must-not-be-dropped"},
                ],
            )
    finally:
        adapter.close()


def test_settings_save_uses_atomic_unique_temp_file(tmp_path: Path) -> None:
    from arenyxa.config import AppSettings

    destination = tmp_path / "settings.json"
    settings = AppSettings()
    settings.save(destination)
    parsed = json.loads(destination.read_text(encoding="utf-8"))
    assert parsed["theme"] == settings.theme
    assert not list(tmp_path.glob(".settings.json.*.tmp"))


def test_settings_load_does_not_treat_booleans_as_numeric_values(tmp_path: Path) -> None:
    from arenyxa.config import AppSettings

    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({
            "max_workers": True,
            "request_concurrency": False,
            "default_timeout_seconds": True,
        }),
        encoding="utf-8",
    )
    loaded = AppSettings.load(path)
    defaults = AppSettings()
    assert loaded.max_workers == defaults.max_workers
    assert loaded.request_concurrency == defaults.request_concurrency
    assert loaded.default_timeout_seconds == defaults.default_timeout_seconds


def test_replacing_schedule_cancels_queued_old_callback() -> None:
    first_started = threading.Event()
    release_first = threading.Event()
    old_fired = threading.Event()
    new_fired = threading.Event()

    def blocker() -> None:
        first_started.set()
        release_first.wait(1.0)

    scheduler = SchedulerService(max_callback_workers=1)
    past = datetime.now(UTC) - timedelta(seconds=1)
    scheduler.add("blocker", ScheduleRule(interval_minutes=60, timezone="UTC"), blocker, next_run=past)
    scheduler.add("replace", ScheduleRule(interval_minutes=60, timezone="UTC"), old_fired.set, next_run=past)
    scheduler.start()
    try:
        assert first_started.wait(1.0)
        deadline = time.monotonic() + 1.0
        while "replace" not in scheduler._callback_futures and time.monotonic() < deadline:                
            time.sleep(0.01)
        scheduler.add(
            "replace",
            ScheduleRule(interval_minutes=60, timezone="UTC"),
            new_fired.set,
            next_run=datetime.now(UTC) + timedelta(hours=1),
        )
        release_first.set()
        time.sleep(0.15)
        assert not old_fired.is_set()
        assert not new_fired.is_set()
    finally:
        release_first.set()
        scheduler.stop()


def test_result_deduplication_is_durable_and_transactional(store) -> None:
    from arenyxa.domain.models import ResultRecord, Run

    task = _task("dedupe", "https://example.test/a")
    store.save_task(task)
    run = Run(task_id=task.id, task_snapshot=task.to_dict(), total_units=2)
    store.save_run(run)
    first = ResultRecord(task.id, run.id, "https://example.test/a", {"value": 1})
    duplicate = ResultRecord(task.id, run.id, "https://example.test/b", {"value": 1})
    assert first.content_hash == duplicate.content_hash
    assert store.append_results([first]) == 1
    assert store.append_results([duplicate]) == 0
    assert store.count_results(run.id) == 1


def test_data_root_lease_blocks_second_runtime_and_recovers_after_release(tmp_path: Path) -> None:
    from arenyxa.infrastructure.data_root_lock import DataRootLease

    first = DataRootLease(tmp_path / "shared-data")
    second = DataRootLease(tmp_path / "shared-data")
    assert first.acquire() is True
    try:
        assert second.acquire() is False
    finally:
        first.release()
    assert second.acquire() is True
    second.release()


def test_running_old_schedule_generation_cannot_overwrite_replacement() -> None:
    persisted: list[tuple[str, datetime]] = []
    executed: list[tuple[str, datetime]] = []
    old_started = threading.Event()
    release_old = threading.Event()

    def old_callback() -> None:
        old_started.set()
        release_old.wait(1.0)

    scheduler = SchedulerService(
        lambda sid, when: persisted.append((sid, when)),
        on_executed=lambda sid, when: executed.append((sid, when)),
        max_callback_workers=1,
    )
    past = datetime.now(UTC) - timedelta(seconds=1)
    scheduler.add(
        "replace-running",
        ScheduleRule(interval_minutes=60, timezone="UTC"),
        old_callback,
        next_run=past,
    )
    scheduler.start()
    try:
        assert old_started.wait(1.0)
        replacement_due = datetime.now(UTC) + timedelta(hours=3)
        scheduler.add(
            "replace-running",
            ScheduleRule(interval_minutes=90, timezone="UTC"),
            lambda: None,
            next_run=replacement_due,
        )
        release_old.set()
        deadline = time.monotonic() + 1.0
        while "replace-running" in scheduler._running and time.monotonic() < deadline:                
            time.sleep(0.01)
        assert persisted
        assert persisted[-1] == ("replace-running", replacement_due)
                                                                                           
                                        
        assert executed == []
    finally:
        release_old.set()
        scheduler.stop()


def test_running_schedule_completion_cannot_overwrite_disable_reenable_deadline() -> None:
    persisted: list[datetime] = []
    executed: list[datetime] = []
    started = threading.Event()
    release = threading.Event()

    def callback() -> None:
        started.set()
        release.wait(1.0)

    scheduler = SchedulerService(
        lambda _sid, when: persisted.append(when),
        on_executed=lambda _sid, when: executed.append(when),
        max_callback_workers=1,
    )
    scheduler.add(
        "toggle-running",
        ScheduleRule(interval_minutes=60, timezone="UTC"),
        callback,
        next_run=datetime.now(UTC) - timedelta(seconds=1),
    )
    scheduler.start()
    try:
        assert started.wait(1.0)
        scheduler.set_enabled("toggle-running", False)
        scheduler.set_enabled("toggle-running", True)
        assert persisted
        reenabled_due = persisted[-1]
        release.set()
        deadline = time.monotonic() + 1.0
        while "toggle-running" in scheduler._running and time.monotonic() < deadline:                
            time.sleep(0.01)
        assert persisted[-1] == reenabled_due
        assert executed == []
    finally:
        release.set()
        scheduler.stop()


def test_long_schedule_completion_persists_latest_overlap_advanced_deadline() -> None:
    persisted: list[datetime] = []
    started = threading.Event()
    release = threading.Event()

    def callback() -> None:
        started.set()
        release.wait(1.0)

    scheduler = SchedulerService(lambda _sid, when: persisted.append(when))
    original_next = datetime.now(UTC) + timedelta(minutes=1)
    scheduler.add(
        "long-overlap",
        ScheduleRule(interval_minutes=60, timezone="UTC"),
        callback,
        next_run=original_next,
    )
    with scheduler._condition:                                                             
        generation = scheduler._job_generations["long-overlap"]                
    worker = threading.Thread(
        target=scheduler._execute_callback,                
        args=("long-overlap", callback, original_next, generation),
        daemon=True,
    )
    worker.start()
    try:
        assert started.wait(1.0)
        overlap_advanced = original_next + timedelta(hours=2)
        with scheduler._condition:                
            rule, _due, current_callback, enabled = scheduler._jobs["long-overlap"]                
            scheduler._jobs["long-overlap"] = (                
                rule,
                overlap_advanced,
                current_callback,
                enabled,
            )
        release.set()
        worker.join(timeout=1.0)
        assert not worker.is_alive()
        assert persisted == [overlap_advanced]
    finally:
        release.set()
        worker.join(timeout=1.0)
        scheduler.stop()


def test_request_executor_shutdown_race_is_cancelled_not_failed(store, monkeypatch) -> None:
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    task = _task("shutdown-submit-race", "https://example.test/a")
    store.save_task(task)

    def reject_during_shutdown(*_args, **_kwargs):
        with runner._lock:                                               
            runner._closed = True                
        raise RuntimeError("cannot schedule new futures after shutdown")

    monkeypatch.setattr(runner.request_executor, "submit", reject_during_shutdown)
    try:
        handle = runner.submit(task)
        result = handle.future.result(timeout=1.0)
        assert result.status == RunStatus.CANCELLED
        assert result.error_code is None
    finally:
        runner.shutdown(wait_for_runs=True)




def test_plugin_worker_command_uses_base_interpreter_for_windows_venv(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.infrastructure.plugins as plugins_module

    venv_python = tmp_path / "venv-python.exe"
    base_python = tmp_path / "base-python.exe"
    venv_python.write_bytes(b"launcher")
    base_python.write_bytes(b"python")
    worker = tmp_path / "plugin_worker.py"
    manifest = tmp_path / "plugin.json"

    monkeypatch.setattr(plugins_module.sys, "platform", "win32")
    monkeypatch.setattr(plugins_module.sys, "prefix", str(tmp_path / "venv"))
    monkeypatch.setattr(plugins_module.sys, "base_prefix", str(tmp_path / "base"))
    monkeypatch.setattr(plugins_module.sys, "executable", str(venv_python))
    monkeypatch.setattr(plugins_module.sys, "_base_executable", str(base_python), raising=False)
    monkeypatch.delattr(plugins_module.sys, "frozen", raising=False)

    command = plugins_module._plugin_worker_command(worker, manifest, "{}")                
    assert command == [str(base_python), "-I", str(worker), str(manifest), "{}"]


def test_plugin_worker_command_reenters_frozen_app_without_python_launcher(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.infrastructure.plugins as plugins_module

    app = tmp_path / "Arenyxa.exe"
    app.write_bytes(b"app")
    worker_script = tmp_path / "plugin_worker.py"
    manifest = tmp_path / "plugin.json"

    monkeypatch.setattr(plugins_module.sys, "executable", str(app))
    monkeypatch.setattr(plugins_module.sys, "frozen", True, raising=False)

    command = plugins_module._plugin_worker_command(worker_script, manifest, "{}")                
    assert command == [str(app), "--internal-plugin-worker", str(manifest), "{}"]


def test_app_has_pre_gui_internal_plugin_worker_dispatch() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/app.py").read_text(encoding="utf-8")
    main_body = source.split("def main(", 1)[1]
    assert 'effective_argv[0] == "--internal-plugin-worker"' in main_body
    assert main_body.index('effective_argv[0] == "--internal-plugin-worker"') < main_body.index("faulthandler")


def test_app_has_pre_gui_frozen_external_supervisor_dispatch() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/app.py").read_text(encoding="utf-8")
    main_body = source.split("def main(", 1)[1]
    assert 'effective_argv[0] == "--internal-external-supervisor-child"' in main_body
    assert main_body.index('effective_argv[0] == "--internal-external-supervisor-child"') < main_body.index("faulthandler")


def test_external_supervisor_uses_frozen_reentry_command(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.infrastructure.external_supervisor as supervisor_module

    commands: list[list[str]] = []

    class FakeProcess:
        stdin = None

        def poll(self):
            return None

    def fake_popen(command, **kwargs):
        commands.append(list(command))
        return FakeProcess()

    monkeypatch.setattr(supervisor_module.sys, "executable", str(tmp_path / "Arenyxa.exe"))
    monkeypatch.setattr(supervisor_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(supervisor_module.subprocess, "Popen", fake_popen)

    client = supervisor_module.ExternalSupervisorClient(tmp_path / "diagnostics")
    client.start()
    assert commands
    assert commands[0][1] == "--internal-external-supervisor-child"
    assert "-m" not in commands[0]
