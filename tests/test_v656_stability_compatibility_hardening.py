from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.bootstrap import ApplicationContext
from arenyxa.config import AppPaths
from arenyxa.domain.enums import CaptureSource, CaptureState, RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import (
    CaptureSession,
    DatasetRevision,
    FetchResponse,
    FieldSpec,
    RequestSpec,
    Run,
    Task,
    Workflow,
    WorkflowNode,
)
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.plugins import PluginManager
from arenyxa.infrastructure.http_client import CancellationToken
from arenyxa.repair import RepairCategory, RepairEngine, RepairPlan, StartupHealthScanner


def _workflow(workflow_id: str) -> Workflow:
    return Workflow(
        workflow_id,
        [WorkflowNode("source", {}, id="source", next_ids=["sink"]), WorkflowNode("sink", {}, id="sink")],
        id=workflow_id,
        version="1.0.0",
    )


def _source(store, dataset_id: str, payload: dict[str, object]) -> DatasetRevision:
    revision = DatasetRevision(dataset_id, [], {"record": dict(payload)}, schema={key: "string" for key in payload})
    store.save_revision(revision)
    store.upsert_dataset(dataset_id, dataset_id, current_revision_id=revision.id)
    return revision


def test_application_context_shutdown_is_thread_safe(tmp_path: Path) -> None:
    class Counter:
        def __init__(self) -> None:
            self.count = 0
            self.lock = threading.Lock()

        def hit(self, delay: float = 0.0) -> None:
            with self.lock:
                self.count += 1
            if delay:
                time.sleep(delay)

    scheduler_count = Counter()
    workflow_count = Counter()
    runner_count = Counter()
    terminal_count = Counter()
    settings_count = Counter()
    checkpoint_count = Counter()
    optimize_count = Counter()

    scheduler = SimpleNamespace(
        begin_shutdown=lambda: None,
        drain=lambda _timeout: True,
        stop=lambda *, timeout: scheduler_count.hit(0.04) or True,
        shutdown_snapshot=lambda: {},
    )
    workflow_runtime = SimpleNamespace(shutdown=lambda **_kwargs: workflow_count.hit() or True)
    runner = SimpleNamespace(
        begin_shutdown=lambda: None,
        drain=lambda _timeout: True,
        shutdown=lambda **_kwargs: runner_count.hit() or True,
        shutdown_snapshot=lambda: {},
    )
    terminal = SimpleNamespace(close=lambda: terminal_count.hit())
    settings = SimpleNamespace(save=lambda _path: settings_count.hit())
    store = SimpleNamespace(checkpoint=lambda _mode: checkpoint_count.hit(), optimize=lambda: optimize_count.hit())
    capture = SimpleNamespace(session=None)

    context = ApplicationContext(
        paths=SimpleNamespace(root=tmp_path),
        settings=settings,
        store=store,
        runner=runner,
        scheduler=scheduler,
        exporter=object(),
        capture=capture,
        versioning=object(),
        workflows=object(),
        lineage=object(),
        workflow_runtime=workflow_runtime,
        projects=object(),
        plugins=object(),
        plugin_sandbox=object(),
        performance=object(),
        terminal=terminal,
        nextgen=object(),
        runtime_recovery=object(),
    )
    results: list[bool] = []
    errors: list[BaseException] = []
    outcome_lock = threading.Lock()

    def shutdown() -> None:
        try:
            result = context.shutdown()
        except BaseException as exc:  # noqa: BLE001 - relay worker failures to pytest
            with outcome_lock:
                errors.append(exc)
        else:
            with outcome_lock:
                results.append(result)

    threads = [threading.Thread(target=shutdown) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    assert len(results) == 12
    assert any(results)
    assert scheduler_count.count == 1
    assert workflow_count.count == 3
    assert runner_count.count == 1
    assert terminal_count.count == 1
    assert settings_count.count == 1
    assert checkpoint_count.count == 1
    assert optimize_count.count == 1


def test_capture_failed_start_cleans_partial_adapter(store) -> None:
    class BrokenAdapter:
        def __init__(self) -> None:
            self.stop_calls = 0

        def start(self, _session, _emit) -> None:
            raise RuntimeError("spawned-then-failed")

        def stop(self) -> None:
            self.stop_calls += 1

        def pause(self) -> None:                                            
            pass

        def resume(self) -> None:                                            
            pass

    controller = CaptureController(store, queue_capacity=8, flush_size=2)
    adapter = BrokenAdapter()
    session = CaptureSession("broken", CaptureSource.SYSTEM)
    controller.prepare(session, adapter)
    with pytest.raises(RuntimeError, match="spawned-then-failed"):
        controller.start()
    assert adapter.stop_calls == 1
    assert session.state == CaptureState.FAILED
    assert controller._writer is not None and not controller._writer.is_alive()


def test_concurrent_capture_stop_finalizes_once(store) -> None:
    class Adapter:
        def __init__(self) -> None:
            self.stop_calls = 0
            self.lock = threading.Lock()

        def start(self, _session, _emit) -> None:
            return None

        def stop(self) -> None:
            with self.lock:
                self.stop_calls += 1
            time.sleep(0.04)

        def pause(self) -> None:
            return None

        def resume(self) -> None:
            return None

    controller = CaptureController(store, queue_capacity=8, flush_size=2)
    adapter = Adapter()
    session = CaptureSession("race", CaptureSource.SYSTEM)
    controller.prepare(session, adapter)
    controller.start()
    errors: list[Exception] = []

    def stop() -> None:
        try:
            controller.stop(cancelled=True)
        except Exception as exc:                                                 
            errors.append(exc)

    threads = [threading.Thread(target=stop) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert errors == []
    assert adapter.stop_calls == 1
    assert session.state == CaptureState.CANCELLED


def test_data_root_lease_metadata_failure_does_not_cache_false_ownership(tmp_path: Path, monkeypatch) -> None:
    lease = DataRootLease(tmp_path / "data")
    original = DataRootLease._write_owner_metadata

    def fail(_self) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(DataRootLease, "_write_owner_metadata", fail)
    with pytest.raises(OSError, match="disk full"):
        lease.acquire()
    assert lease._stream is None

    monkeypatch.setattr(DataRootLease, "_write_owner_metadata", original)
    assert lease.acquire()
    lease.release()
    assert lease._stream is None


def test_incompatible_plugin_is_disabled_not_quarantined(tmp_path: Path, monkeypatch) -> None:
    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    plugin = paths.plugins / "future-plugin"
    plugin.mkdir()
    (plugin / "main.py").write_text("def handle(request): return {'ok': True}\n", encoding="utf-8")
    (plugin / "plugin.json").write_text(
        json.dumps(
            {
                "id": "future.plugin",
                "name": "Future Plugin",
                "version": "1.0.0",
                "entry": "main.py",
                "api_version": "999",
                "min_app_version": "6.0.0",
                "permissions": {},
            }
        ),
        encoding="utf-8",
    )
    manager = PluginManager(paths.plugins)
    assert manager.discover() == []
    with pytest.raises(ArenyxaError) as caught:
        manager.inspect_install(plugin)
    assert caught.value.code == "PLUGIN_API_UNSUPPORTED"

    monkeypatch.setenv("ARENYXA_ENFORCE_SOURCE_INTEGRITY", "0")
    report = StartupHealthScanner(paths, tmp_path, ignore_current_session=True).scan()
    assert "PLUGIN_INCOMPATIBLE" in {item.code for item in report.findings}

    plan = RepairPlan(
        install_root=str(tmp_path),
        data_root=str(paths.root),
        categories=[RepairCategory.PLUGINS.value],
        relaunch=False,
        source_mode=True,
    )
    detail = RepairEngine(plan)._repair_plugins()
    assert "保留 1" in detail
    assert plugin.is_dir()
    quarantine = paths.plugins / "quarantine"
    assert not quarantine.exists() or not any(path.name == "future-plugin" for path in quarantine.rglob("future-plugin"))


def test_workflow_shutdown_tracks_two_operations_sharing_one_token(store) -> None:
    slow_started = threading.Event()
    fast_started = threading.Event()

    class DelayedCancellationEngine(WorkflowEngine):
        def execute(self, workflow, inputs, token=None, **kwargs):                          
            assert token is not None
            item = next(iter(inputs))
            kind = str(item.get("kind"))
            (slow_started if kind == "slow" else fast_started).set()
            while True:
                try:
                    token.checkpoint()
                except ArenyxaError:
                    if kind == "slow":
                        time.sleep(0.30)
                    raise
                time.sleep(0.005)

    slow = _source(store, "slow-source", {"kind": "slow"})
    fast = _source(store, "fast-source", {"kind": "fast"})
    runtime = WorkflowDatasetService(
        store, DelayedCancellationEngine(), DataLineageService(store), checkpoint_every=1
    )
    shared = CancellationToken()
    errors: list[Exception] = []

    def run(source_id: str, output_id: str, workflow_id: str) -> None:
        try:
            runtime.execute_revision(_workflow(workflow_id), source_id, output_id, token=shared)
        except Exception as exc:
            errors.append(exc)

    slow_thread = threading.Thread(target=run, args=(slow.id, "slow-out", "slow-wf"))
    fast_thread = threading.Thread(target=run, args=(fast.id, "fast-out", "fast-wf"))
    slow_thread.start()
    assert slow_started.wait(timeout=2)
    fast_thread.start()
    assert fast_started.wait(timeout=2)
    started = time.monotonic()
    assert runtime.shutdown(wait=True, timeout=2)
    elapsed = time.monotonic() - started
    slow_thread.join(timeout=2)
    fast_thread.join(timeout=2)
    assert not slow_thread.is_alive() and not fast_thread.is_alive()
                                                                                           
                                                           
    assert elapsed >= 0.22
    assert len(errors) == 2
    assert all(isinstance(exc, ArenyxaError) and exc.code == "RUN_CANCELLED" for exc in errors)


def test_runner_pause_resume_race_cannot_overwrite_terminal_state(store) -> None:
    class FastFetcher:
        def fetch(self, spec, token=None, on_attempt=None):
            if on_attempt:
                on_attempt(0)
            if token:
                token.checkpoint()
            time.sleep(0.003)
            if token:
                token.checkpoint()
            return FetchResponse(
                url=spec.url,
                final_url=spec.url,
                status=200,
                headers={"Content-Type": "application/json"},
                body=b'{"value": 1}',
                elapsed_ms=3.0,
                encoding="utf-8",
                content_type="application/json",
            )

    runner = RunOrchestrator(store, max_workers=2, request_workers=2, per_host_workers=2)
    runner.fetcher = FastFetcher()
    try:
        for index in range(20):
            task = Task(
                f"race-{index}",
                [RequestSpec(f"https://example.test/{index}")],
                fields=[FieldSpec("value", "value")],
                parser_hint="json",
                status=TaskStatus.READY,
            )
            store.save_task(task)
            handle = runner.submit(task)
            stop = threading.Event()

            def toggler() -> None:
                while not stop.is_set() and not handle.future.done():
                    handle.pause()
                    handle.resume()

            thread = threading.Thread(target=toggler)
            thread.start()
            result = handle.future.result(timeout=3)
            stop.set()
            thread.join(timeout=1)
            assert result.status in {RunStatus.COMPLETED, RunStatus.PARTIAL, RunStatus.FAILED, RunStatus.CANCELLED}
            assert result.status != RunStatus.PAUSED
    finally:
        runner.shutdown(wait=True)


def test_headless_server_reconciles_stale_runtime_state(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from arenyxa.infrastructure.database import SQLiteStore
    from arenyxa.infrastructure.server import create_app

    paths = AppPaths.discover(tmp_path / "server-data")
    paths.initialize()
    store = SQLiteStore(paths.database)
    store.initialize()
    task = Task("stale", [RequestSpec("https://example.test")], status=TaskStatus.READY)
    store.save_task(task)
    run = Run(task.id, task.to_dict(), status=RunStatus.RUNNING, stage="fetch")
    store.save_run(run)

    app = create_app(paths.root, {})
    try:
        recovered = next(row for row in SQLiteStore(paths.database).list_runs(task.id) if row["id"] == run.id)
        assert recovered["status"] == RunStatus.FAILED.value
        assert recovered["error_code"] == "RUN_INTERRUPTED"
    finally:
        app.state.data_root_lease.release()


def test_python_311_syntax_contract() -> None:
    import ast

    root = Path(__file__).resolve().parents[1] / "src" / "arenyxa"
    failures: list[str] = []
    for path in root.rglob("*.py"):
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 11))
        except SyntaxError:
            failures.append(str(path.relative_to(root)))
    assert failures == []


def test_plugin_version_metadata_is_bounded_and_never_leaks_raw_value_error(tmp_path: Path) -> None:
    import json

    from arenyxa.domain.errors import ArenyxaError
    from arenyxa.infrastructure.plugins import PluginManifest

    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "main.py").write_text("def handle(request):\n    return request\n", encoding="utf-8")
    manifest_path = plugin / "plugin.json"
    payload = {
        "id": "version.boundary",
        "name": "Version Boundary",
        "version": "1.0.0",
        "entry": "main.py",
        "api_version": "1",
        "permissions": {},
        "capabilities": [],
        "min_app_version": "9" * 10000,
    }
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ArenyxaError) as caught:
        PluginManifest.load(manifest_path)
    assert caught.value.code == "PLUGIN_APP_VERSION_INVALID"
