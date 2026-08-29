from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.nextgen import DistributedWorker, DistributedWorkerService, SecretVault
from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.config import AppPaths
from arenyxa.domain.enums import RunStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, RequestSpec, ResultRecord, Run, Task, Workflow, WorkflowNode, utc_now
from arenyxa.infrastructure.plugins import PluginSandbox
from arenyxa.repair import RepairCategory, RepairEngine, RepairPlan, StartupHealthScanner


def _workflow(*, workflow_id: str = "wf-v656", version: str = "1.0.0") -> Workflow:
    return Workflow(
        "v656",
        [
            WorkflowNode("source", {}, id="source", next_ids=["sink"]),
            WorkflowNode("sink", {}, id="sink"),
        ],
        id=workflow_id,
        version=version,
    )


def _source(store, dataset_id: str = "source-v656", count: int = 3) -> DatasetRevision:
    revision = DatasetRevision(
        dataset_id,
        [],
        {f"r{index}": {"id": index} for index in range(count)},
        schema={"id": "integer"},
    )
    store.save_revision(revision)
    store.upsert_dataset(dataset_id, dataset_id, current_revision_id=revision.id)
    return revision


def test_plugin_os_open_write_flags_cannot_bypass_storage_permission(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "plugin.json").write_text(
        json.dumps({
            "id": "audit.osopen",
            "name": "Audit os.open",
            "version": "1.0.0",
            "entry": "main.py",
            "permissions": {},
        }),
        encoding="utf-8",
    )
    (plugin / "main.py").write_text(
        "import os\n"
        "def handle(request):\n"
        "    target=os.path.join(os.path.dirname(__file__), 'unauthorized.bin')\n"
        "    fd=os.open(target, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)\n"
        "    try:\n"
        "        os.write(fd, b'BYPASS')\n"
        "    finally:\n"
        "        os.close(fd)\n"
        "    return {'ok': True}\n",
        encoding="utf-8",
    )

    with pytest.raises(ArenyxaError) as caught:
        PluginSandbox().invoke(plugin, {}, {})
    assert caught.value.code == "PLUGIN_EXECUTION_FAILED"
    assert not (plugin / "unauthorized.bin").exists()


def test_repair_plugin_validation_matches_runtime_manifest_contract(tmp_path: Path, monkeypatch) -> None:
    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    plugin = paths.plugins / "bad-permission"
    plugin.mkdir()
    (plugin / "main.py").write_text("def handle(request): return {}\n", encoding="utf-8")
    (plugin / "plugin.json").write_text(
        json.dumps({
            "id": "bad.permission",
            "name": "Bad Permission",
            "version": "1.0.0",
            "entry": "main.py",
            "permissions": {"made_up_permission": True},
        }),
        encoding="utf-8",
    )

    monkeypatch.setenv("ARENYXA_ENFORCE_SOURCE_INTEGRITY", "0")
    report = StartupHealthScanner(paths, tmp_path, ignore_current_session=True).scan()
    assert "PLUGIN_MANIFEST_INVALID" in {item.code for item in report.findings}

    plan = RepairPlan(
        install_root=str(tmp_path),
        data_root=str(paths.root),
        categories=[RepairCategory.PLUGINS.value],
        relaunch=False,
        source_mode=True,
    )
    detail = RepairEngine(plan)._repair_plugins()
    assert "隔离 1" in detail
    assert not plugin.exists()
    assert any(path.name == "bad-permission" for path in (paths.plugins / "quarantine").rglob("bad-permission"))


def test_dependency_repair_uses_scanner_single_source_of_truth(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text("cryptography>=44,<46\n", encoding="utf-8")
    data = tmp_path / "data"
    plan = RepairPlan(
        install_root=str(tmp_path),
        data_root=str(data),
        categories=[RepairCategory.DEPENDENCIES.value],
        relaunch=False,
        source_mode=True,
    )
    engine = RepairEngine(plan)
    monkeypatch.setattr(StartupHealthScanner, "REQUIRED_MODULES", {"sentinel_missing": "cryptography"})
    real_find_spec = __import__("importlib.util", fromlist=["find_spec"]).find_spec

    def fake_find_spec(name: str):
        if name == "sentinel_missing":
            return None
        return real_find_spec(name)

    commands: list[list[str]] = []
    monkeypatch.setattr("arenyxa.repair.importlib.util.find_spec", fake_find_spec)
    monkeypatch.setattr(
        "arenyxa.repair.subprocess.run",
        lambda command, **kwargs: commands.append(list(command)) or SimpleNamespace(returncode=0),
    )
    assert "自动恢复" in engine._repair_dependencies()
    assert commands and "requirements.txt" in " ".join(commands[0])


def test_same_dataset_workflow_parent_is_actual_source_revision(store) -> None:
    first = _source(store, "history", 1)
    second = DatasetRevision(
        "history", [], {"head": {"id": 99}}, parent_revision=first.id, schema={"id": "integer"}
    )
    store.save_revision(second)
    store.upsert_dataset("history", "History", current_revision_id=second.id)

    runtime = WorkflowDatasetService(store, WorkflowEngine(), DataLineageService(store), checkpoint_every=1)
    result = runtime.execute_revision(_workflow(), first.id, "history")
    output = store.get_revision_metadata(result.output_revision_id)
    assert output is not None
    assert output["parent_revision"] == first.id
    assert output["parent_revision"] != second.id


def test_execution_snapshot_allows_resume_after_saved_workflow_changes(store) -> None:
    source = _source(store)
    runtime = WorkflowDatasetService(store, WorkflowEngine(), DataLineageService(store), checkpoint_every=1)
    workflow = _workflow(workflow_id="snapshot-resume")

    class CancelSoon:
        def __init__(self) -> None:
            from arenyxa.infrastructure.http_client import CancellationToken
            self.inner = CancellationToken()
            self.calls = 0

        def checkpoint(self) -> None:
            self.calls += 1
            if self.calls >= 4:
                self.inner.cancel()
            self.inner.checkpoint()

        def cancel(self) -> None:
            self.inner.cancel()

    token = CancelSoon()
    with pytest.raises(ArenyxaError) as caught:
        runtime.execute_revision(workflow, source.id, "snapshot-output", token=token)                          
    assert caught.value.code == "RUN_CANCELLED"
    execution = store.list_workflow_executions("snapshot-resume", limit=1)[0]
    assert execution["state"] == "cancelled"
    assert str(execution.get("definition_json") or "") not in {"", "{}"}

    changed = _workflow(workflow_id="snapshot-resume", version="99.0.0")
    changed.nodes.insert(1, WorkflowNode("map", {"constants": {"changed": True}}, id="changed", next_ids=["sink"]))
    changed.nodes[0].next_ids = ["changed"]
    store.save_workflow(asdict(changed))

    resumed = runtime.resume_execution(str(execution["id"]), workflow=None)
    assert resumed.state == "completed"
    assert len(list(store.iter_revision_records(resumed.output_revision_id))) == 3


def test_ready_output_is_reconciled_as_completed_after_commit_window_crash(store) -> None:
    source = _source(store, "crash-source", 1)
    workflow = _workflow(workflow_id="crash-window")
    store.save_workflow(asdict(workflow))
    output = DatasetRevision("crash-output", [], {}, schema={})
    store.begin_revision_build(output)
    store.begin_workflow_execution(
        {
            "id": "exec-crash-window",
            "workflow_id": workflow.id,
            "source_revision_id": source.id,
            "output_dataset_id": "crash-output",
            "output_revision_id": output.id,
            "definition_hash": WorkflowDatasetService.definition_hash(workflow),
            "definition_json": json.dumps(asdict(workflow), ensure_ascii=False, default=str),
            "started_at": utc_now(),
        },
        [node.id for node in workflow.nodes],
    )
    store.append_revision_records(output.id, [("result", {"ok": True})])
    store.finalize_revision_build(output.id, schema={"ok": "boolean"}, dataset_name="Crash Output")
                                                                                             
                                        
    assert store.get_workflow_execution("exec-crash-window")["state"] == "running"                       

    recovered = RuntimeRecoveryService(store).recover()
    assert recovered.reconciled_completed_workflows == 1
    execution = store.get_workflow_execution("exec-crash-window")
    assert execution is not None and execution["state"] == "completed"
    assert recovered.failed_broken_workflows == 0
    assert store.get_revision_metadata(output.id)["build_state"] == "ready"                       
    assert output.id not in {
        str(item["id"]) for item in store.list_ready_dataset_revisions_missing_lineage()
    }

    runtime = WorkflowDatasetService(store, WorkflowEngine(), DataLineageService(store))
    assert runtime.reconcile_completed_lineage() >= 1
    assert runtime.reconcile_completed_lineage() == 0
    graph = runtime.lineage.graph("workflow_execution", "exec-crash-window", max_depth=2)
    assert any(edge["relation"] == "produced" for edge in graph.edges)


def test_workflow_runtime_shutdown_cancels_background_execution(store) -> None:
    source = _source(store, "shutdown-source", 1)
    started = threading.Event()

    class SlowEngine(WorkflowEngine):
        def execute(self, workflow, records, token=None, **kwargs):                          
            assert token is not None
            started.set()
            for _ in range(300):
                time.sleep(0.005)
                token.checkpoint()
            return super().execute(workflow, records, token, **kwargs)

    runtime = WorkflowDatasetService(store, SlowEngine(), DataLineageService(store), checkpoint_every=1)
    errors: list[Exception] = []

    def run() -> None:
        try:
            runtime.execute_revision(_workflow(workflow_id="shutdown-wf"), source.id, "shutdown-output")
        except Exception as exc:                                                   
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert started.wait(timeout=2)
    assert runtime.shutdown(wait=True, timeout=3)
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert errors and isinstance(errors[0], ArenyxaError) and errors[0].code == "RUN_CANCELLED"
    execution = store.list_workflow_executions("shutdown-wf", limit=1)[0]
    assert execution["state"] == "cancelled"
    with pytest.raises(ArenyxaError) as caught:
        runtime.execute_revision(_workflow(workflow_id="new-after-shutdown"), source.id, "x")
    assert caught.value.code == "WORKFLOW_RUNTIME_SHUTDOWN"


def test_worker_registry_rejects_duplicate_ids_and_invalid_secret_names(tmp_path: Path) -> None:
    vault = SecretVault(tmp_path / "vault")
    service = DistributedWorkerService(tmp_path / "workers", vault)
    with pytest.raises(ValueError):
        service.upsert(DistributedWorker("a", "Worker", "http://127.0.0.1:8787", "not valid secret!"))

    service.path.write_text(
        json.dumps([
            {"id": "dup", "name": "One", "base_url": "http://127.0.0.1:8787", "token_secret": "worker.token", "enabled": True, "weight": 1},
            {"id": "dup", "name": "Two", "base_url": "http://127.0.0.1:8788", "token_secret": "worker.token2", "enabled": True, "weight": 1},
        ]),
        encoding="utf-8",
    )
    with pytest.raises(ArenyxaError) as caught:
        service.list()
    assert caught.value.code == "WORKER_REGISTRY_CORRUPT"


def test_ready_non_workflow_revision_lineage_can_be_reconciled(store) -> None:
    revision = DatasetRevision("plain-dataset", [], {"x": {"id": 1}}, schema={"id": "integer"})
    store.save_revision(revision)
    store.upsert_dataset("plain-dataset", "Plain", current_revision_id=revision.id)
    service = DataLineageService(store)
    missing = {str(item["id"]) for item in store.list_ready_dataset_revisions_missing_lineage()}
    assert revision.id in missing
    assert service.reconcile_ready_revision_lineage() >= 1
    assert service.reconcile_ready_revision_lineage() == 0
    graph = service.graph("revision", revision.id, max_depth=1)
    assert any(edge["relation"] == "version_of" for edge in graph.edges)


def test_dataset_commit_survives_post_commit_lineage_failure(store, monkeypatch) -> None:
    task = Task("lineage-commit", [RequestSpec("https://example.test")])
    store.save_task(task)
    run = Run(task.id, task.to_dict(), status=RunStatus.COMPLETED, stage="completed")
    store.save_run(run)
    store.append_results([ResultRecord(task.id, run.id, "https://example.test", {"id": 1})])
    service = DataLineageService(store)
    service.create_dataset("Committed", dataset_id="committed-dataset")

    def fail_lineage(*args, **kwargs):
        raise RuntimeError("simulated lineage failure")

    monkeypatch.setattr(service, "_record_run_revision_lineage", fail_lineage)
    result = service.materialize_from_runs("committed-dataset", [run.id])
    revision = store.get_revision_metadata(result.revision_id)
    assert revision is not None and revision["build_state"] == "ready"
    assert store.get_dataset("committed-dataset")["current_revision_id"] == result.revision_id                       


def test_v656_runtime_and_packaging_versions_are_consistent() -> None:
    import ast
    import tomllib

    import arenyxa

    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    current = str(project["project"]["version"])
    assert current == arenyxa.__distribution_version__ == "8.1.1"
    assert arenyxa.__package_version__ == "8.1.0"
    assert arenyxa.__version__ == "8.1"
    assert arenyxa.__compat_version__ == "6.8.0"
    version_info = (root / "packaging" / "version_info.txt").read_text(encoding="utf-8")
    installer = (root / "packaging" / "installer.iss").read_text(encoding="utf-8")
    assert "filevers=(8,1,1,0)" in version_info
    assert "ProductVersion', '8.1.1'" in version_info
    assert '#define MyAppVersion "8.1.1"' in installer

                                                                                             
                                                                      
    stale_runtime_literals: list[str] = []
    for path in (root / "src" / "arenyxa").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(isinstance(node, ast.Constant) and isinstance(node.value, str) and "6.5.5" in node.value for node in ast.walk(tree)):
            stale_runtime_literals.append(str(path.relative_to(root)))
    assert stale_runtime_literals == []


def test_lineage_write_failure_does_not_downgrade_committed_workflow(store) -> None:
    source = _source(store, "lineage-failure-source", 1)

    class BrokenLineage(DataLineageService):
        def record_derivation(self, *args, **kwargs):                          
            raise RuntimeError("simulated lineage storage failure")

    runtime = WorkflowDatasetService(store, WorkflowEngine(), BrokenLineage(store), checkpoint_every=1)
    result = runtime.execute_revision(_workflow(workflow_id="lineage-failure"), source.id, "lineage-output")
    assert result.state == "completed"
    execution = store.get_workflow_execution(result.execution_id)
    assert execution is not None and execution["state"] == "completed"
    output = store.get_revision_metadata(result.output_revision_id)
    assert output is not None and output["build_state"] == "ready"


def test_workflow_engine_buffer_size_is_a_real_memory_boundary() -> None:
    engine = WorkflowEngine(buffer_size=4)
    workflow = Workflow("bounded", [WorkflowNode("source", {}, id="source")], id="bounded")
    with pytest.raises(ArenyxaError) as caught:
        engine.execute(workflow, ({"id": index} for index in range(5)))
    assert caught.value.code == "WORKFLOW_BUFFER_LIMIT"

    expanding = WorkflowEngine(buffer_size=4)
    expanding.register("explode", lambda item, config: ({"n": n} for n in range(10)))
    fanout = Workflow("fanout", [WorkflowNode("explode", {}, id="explode")], id="fanout")
    with pytest.raises(ArenyxaError) as caught:
        expanding.execute(fanout, [{"id": 1}])
    assert caught.value.code == "WORKFLOW_BUFFER_LIMIT"

                                                                                         
                                                                                  
    failing = WorkflowEngine(buffer_size=2)
    chain = Workflow(
        "error-chain",
        [
            WorkflowNode("validate", {"required": ["a"]}, id="a", failure_ids=["b"]),
            WorkflowNode("validate", {"required": ["b"]}, id="b", failure_ids=["c"]),
            WorkflowNode("validate", {"required": ["c"]}, id="c"),
        ],
        id="error-chain",
    )
    with pytest.raises(ArenyxaError) as caught:
        failing.execute(chain, [{}])
    assert caught.value.code == "WORKFLOW_BUFFER_LIMIT"
    assert caught.value.context["area"] == "errors"


def test_v656_schema_migration_adds_execution_snapshot_with_backup(tmp_path: Path) -> None:
    import sqlite3

    from arenyxa.infrastructure.database import MIGRATIONS, SQLiteStore

    path = tmp_path / "legacy-v655.db"
    connection = sqlite3.connect(path)
    try:
        for version, script in enumerate(MIGRATIONS[:10], start=1):
            connection.executescript(script)
            connection.execute(
                "INSERT OR REPLACE INTO schema_migrations(version,applied_at) VALUES(?,?)",
                (version, utc_now()),
            )
        connection.commit()
    finally:
        connection.close()

    SQLiteStore(path).initialize()
    upgraded = sqlite3.connect(path)
    try:
        columns = {row[1] for row in upgraded.execute("PRAGMA table_info(workflow_executions)")}
        latest = upgraded.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
    finally:
        upgraded.close()
    assert "definition_json" in columns
                                                                                          
                                                                                           
                                                                                             
    assert latest == len(MIGRATIONS)
    assert len(MIGRATIONS) >= 11
    assert (tmp_path / "legacy-v655.pre-migration.bak").is_file()
