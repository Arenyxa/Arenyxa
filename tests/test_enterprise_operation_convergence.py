from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.enums import CaptureSource, CaptureState, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, DatasetRevision, RequestSpec, Task, Workflow, WorkflowNode
from arenyxa.enterprise import EnterpriseGovernanceService, LocalEnterpriseIdentityService
from arenyxa.enterprise.operations import EnterpriseOperationGuard
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.security import SecurityKernel

ADMIN_PASSWORD = "Convergence-Admin-Password!"
VAULT_PASSWORD = "Convergence-Vault-Passphrase!"


def _stack(tmp_path: Path, store):
    identity = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    identity.create_enterprise("Convergence Enterprise", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    identity.login("root", ADMIN_PASSWORD)
    identity.step_up(ADMIN_PASSWORD)
    governance = EnterpriseGovernanceService(identity)
    guard = EnterpriseOperationGuard(store, identity, governance)
    workspace = governance.create_workspace("Operations")
    return identity, governance, guard, workspace


def test_bound_resource_fails_closed_after_enterprise_logout(tmp_path: Path, store) -> None:
    identity, _governance, guard, workspace = _stack(tmp_path, store)
    resource_id = guard.register_and_bind_resource("workflow", "task-bound", workspace)
    assert resource_id == "workflow:task-bound"
    assert guard.authorize_if_bound("workflow", "task-bound", "workflow.execute").governed is True

    identity.logout()
    with pytest.raises(ArenyxaError) as caught:
        guard.authorize_if_bound("workflow", "task-bound", "workflow.execute")
    assert caught.value.code == "ENTERPRISE_BOUND_RESOURCE_LOCKED"
    assert guard.authorize_if_bound("workflow", "personal-task", "workflow.execute").governed is False


def test_registration_binding_compensates_when_governance_write_fails(tmp_path: Path, store, monkeypatch) -> None:
    _identity, governance, guard, workspace = _stack(tmp_path, store)

    def fail_register(*_args, **_kwargs):
        raise ArenyxaError("TEST_REGISTER_FAILED", "forced", domain="TEST")

    monkeypatch.setattr(governance, "register_resource", fail_register)
    with pytest.raises(ArenyxaError) as caught:
        guard.register_and_bind_resource("dataset", "dataset-failed", workspace)
    assert caught.value.code == "TEST_REGISTER_FAILED"
    assert store.enterprise_resource_binding("dataset", "dataset-failed") is None


def test_runner_cannot_bypass_bound_enterprise_workflow(tmp_path: Path, store) -> None:
    identity, _governance, guard, workspace = _stack(tmp_path, store)
    guard.register_and_bind_resource("workflow", "task-runner", workspace)
    identity.logout()

    runner = RunOrchestrator(store, max_workers=1, request_workers=1, enterprise_operations=guard)
    task = Task(
        "Bound Task",
        [RequestSpec("http://127.0.0.1:9/")],
        id="task-runner",
        status=TaskStatus.READY,
    )
    store.save_task(task)
    try:
        with pytest.raises(ArenyxaError) as caught:
            runner.submit(task)
        assert caught.value.code == "ENTERPRISE_BOUND_RESOURCE_LOCKED"
        assert store.list_runs(task.id) == []
    finally:
        runner.shutdown(wait=True)


def test_workflow_dataset_denial_occurs_before_partial_output_state(tmp_path: Path, store) -> None:
    identity, governance, guard, workspace = _stack(tmp_path, store)
    workflow_id = "workflow-governed"
    source_dataset_id = "source-governed"
    output_dataset_id = "output-governed"
    wf_resource = guard.register_and_bind_resource("workflow", workflow_id, workspace)
    source_resource = guard.register_and_bind_resource("dataset", source_dataset_id, workspace)
    output_resource = guard.register_and_bind_resource("dataset", output_dataset_id, workspace)
    identity.step_up(ADMIN_PASSWORD)
    governance.grant_role(wf_resource, "analyst", ["workflow.execute"])
    identity.step_up(ADMIN_PASSWORD)
    governance.grant_role(source_resource, "analyst", ["dataset.read"])
                                                             

    analyst_id = identity.create_account("analyst2", "Analyst", "Analyst-Password-456!", ["analyst"])
    assert analyst_id
    identity.logout()
    identity.login("analyst2", "Analyst-Password-456!")

    source = DatasetRevision(
        source_dataset_id,
        [],
        {"a": {"id": 1}},
        schema={"id": "integer"},
    )
    store.save_revision(source)
    store.upsert_dataset(source_dataset_id, "Source", current_revision_id=source.id)
    store.upsert_dataset(output_dataset_id, "Output")
    workflow = Workflow(
        "governed",
        [WorkflowNode("source", {}, id="source", next_ids=["sink"]), WorkflowNode("sink", {}, id="sink")],
        id=workflow_id,
    )
    runtime = WorkflowDatasetService(
        store,
        WorkflowEngine(),
        DataLineageService(store),
        enterprise_operations=guard,
    )

    before_revisions = list(store.list_revisions(output_dataset_id, include_incomplete=True))
    with pytest.raises(ArenyxaError):
        runtime.execute_revision(workflow, source.id, output_dataset_id)
    after_revisions = list(store.list_revisions(output_dataset_id, include_incomplete=True))
    assert after_revisions == before_revisions
    assert store.list_workflow_executions(workflow_id, limit=20) == []


def test_capture_bound_resource_is_denied_before_adapter_start(tmp_path: Path, store) -> None:
    identity, _governance, guard, workspace = _stack(tmp_path, store)
    session = CaptureSession("Bound Capture", CaptureSource.BROWSER, id="capture-bound")
    guard.register_and_bind_resource("capture", session.id, workspace)
    identity.logout()

    class Adapter:
        started = False
        def start(self, _session, _emit):
            self.started = True
        def stop(self):
            pass
        def pause(self):
            pass
        def resume(self):
            pass

    adapter = Adapter()
    capture = CaptureController(store, queue_capacity=16, flush_size=4, enterprise_operations=guard)
    capture.prepare(session, adapter)
    with pytest.raises(ArenyxaError) as caught:
        capture.start()
    assert caught.value.code == "ENTERPRISE_BOUND_RESOURCE_LOCKED"
    assert adapter.started is False
    assert session.state is CaptureState.PREPARING


def test_store_aware_governance_direct_registration_also_binds(tmp_path: Path, store) -> None:
    identity = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    identity.create_enterprise("Direct Enterprise", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    identity.login("root", ADMIN_PASSWORD)
    governance = EnterpriseGovernanceService(identity, store)
    workspace = governance.create_workspace("Direct")
    resource_id = governance.register_resource("workflow", "direct-workflow", workspace)
    binding = store.enterprise_resource_binding("workflow", "direct-workflow")
    assert binding is not None
    assert binding["resource_id"] == resource_id
    assert binding["enterprise_id"] == identity.status().enterprise_id
    snapshot = governance.operations_snapshot()
    assert snapshot["bound_local_resources"] == 1
    assert snapshot["orphaned_local_bindings"] == 0


def test_migration_12_adds_enterprise_binding_index_to_existing_schema(tmp_path: Path) -> None:
    import sqlite3
    from arenyxa.infrastructure.database import MIGRATIONS, SQLiteStore

    path = tmp_path / "pre-convergence.db"
    connection = sqlite3.connect(path)
    try:
        for version, script in enumerate(MIGRATIONS[:-1], start=1):
            connection.executescript(script)
            connection.execute(
                "INSERT OR REPLACE INTO schema_migrations(version,applied_at) VALUES(?,?)",
                (version, "2026-08-17T00:00:00+00:00"),
            )
        connection.commit()
    finally:
        connection.close()

    SQLiteStore(path).initialize()
    connection = sqlite3.connect(path)
    try:
        table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='enterprise_resource_bindings'"
        ).fetchone()
        latest = connection.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
    finally:
        connection.close()
    assert table == ("enterprise_resource_bindings",)
    assert latest == len(MIGRATIONS) == 13
