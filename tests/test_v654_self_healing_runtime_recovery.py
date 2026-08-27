from __future__ import annotations

import json
from pathlib import Path

from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.domain.enums import CaptureSource, CaptureState, RunStatus
from arenyxa.domain.models import CaptureSession, DatasetRevision, RequestSpec, Run, Task, utc_now
from arenyxa.repair import RepairCategory, RepairFinding, StartupHealthScanner, fault_fingerprint


def _task() -> Task:
    return Task("runtime-recovery", [RequestSpec("https://example.test")])


def test_fault_fingerprint_is_stable_and_excludes_evidence() -> None:
    first = RepairFinding(
        "WORKFLOW_RECOVERY_STATE_INVALID",
        RepairCategory.RUNTIME_STATE,
        "warning",
        "x",
        "y",
        "C:/private/path/one",
    )
    second = RepairFinding(
        "WORKFLOW_RECOVERY_STATE_INVALID",
        RepairCategory.RUNTIME_STATE,
        "critical",
        "changed title",
        "changed detail",
        "D:/another/private/path",
    )
    assert first.fingerprint == second.fingerprint
    assert first.fingerprint == fault_fingerprint(first.code, first.category)
    assert first.fingerprint.startswith("NXF-")
    assert "private" not in first.fingerprint.casefold()


def test_runtime_recovery_closes_stale_state_and_preserves_resumable_workflow(store) -> None:
    task = _task()
    store.save_task(task)
    run = Run(task_id=task.id, task_snapshot=task.to_dict(), status=RunStatus.RUNNING)
    run.stage = "fetch"
    store.save_run(run)

    capture = CaptureSession("runtime", CaptureSource.SYSTEM)
    capture.state = CaptureState.CAPTURING
    store.save_capture(capture)

    source = DatasetRevision("source", [], {"a": {"id": 1}}, schema={"id": "integer"})
    store.save_revision(source)
    store.upsert_dataset("source", "Source", current_revision_id=source.id)
    workflow_payload = {
        "id": "wf-resumable",
        "name": "resumable",
        "version": "1.0.0",
        "nodes": [{"id": "source", "kind": "source", "config": {}, "next_ids": [], "failure_ids": []}],
        "schema_version": 6,
    }
    store.save_workflow(workflow_payload)
    workflow = WorkflowDatasetService.workflow_from_payload(workflow_payload)
    output = DatasetRevision("derived", [], {}, schema={})
    store.begin_revision_build(output)
    store.begin_workflow_execution(
        {
            "id": "exec-resumable",
            "workflow_id": "wf-resumable",
            "source_revision_id": source.id,
            "output_dataset_id": "derived",
            "output_revision_id": output.id,
            "definition_hash": WorkflowDatasetService.definition_hash(workflow),
            "definition_json": json.dumps(workflow_payload),
            "started_at": utc_now(),
        },
        ["source"],
    )

    with store.connect() as connection:
        connection.execute(
            "INSERT INTO schedules(id,task_id,rule_json,timezone,enabled,next_run_at,last_run_at,created_at,updated_at) "
            "VALUES(?,?,?,?,1,NULL,NULL,?,?)",
            ("bad-schedule", task.id, "[]", "UTC", utc_now(), utc_now()),
        )

    service = RuntimeRecoveryService(store)
    before = service.audit()
    assert run.id in before.active_runs
    assert capture.id in before.active_captures
    assert "exec-resumable" in before.active_workflows
    assert output.id in before.building_revisions
    assert "bad-schedule" in before.invalid_schedules

    recovered = service.recover()
    assert recovered.recovered_runs == 1
    assert recovered.recovered_captures == 1
    assert recovered.interrupted_workflows == 1
    assert recovered.interrupted_revisions == 1
    assert recovered.disabled_invalid_schedules == 1
    assert recovered.resumable_workflows == 1

    execution = store.get_workflow_execution("exec-resumable")
    assert execution is not None and execution["state"] == "interrupted"
    revision = store.get_revision_metadata(output.id, include_incomplete=True)
    assert revision is not None and revision["build_state"] == "interrupted"
    with store.connect() as connection:
        enabled = connection.execute("SELECT enabled FROM schedules WHERE id='bad-schedule'").fetchone()[0]
    assert enabled == 0


def test_runtime_recovery_fails_broken_resume_chain_without_deleting_output(store) -> None:
    source = DatasetRevision("source", [], {"a": {"id": 1}}, schema={"id": "integer"})
    store.save_revision(source)
    output = DatasetRevision("derived", [], {}, schema={})
    store.begin_revision_build(output)
                                                                                             
                                                              
    store.begin_workflow_execution(
        {
            "id": "exec-broken",
            "workflow_id": "missing-workflow",
            "source_revision_id": source.id,
            "output_dataset_id": "derived",
            "output_revision_id": output.id,
            "definition_hash": "1" * 64,
            "started_at": utc_now(),
        },
        ["source"],
    )
    store.append_revision_records(output.id, [("kept", {"value": 7})])

    result = RuntimeRecoveryService(store).recover()
    assert result.failed_broken_workflows == 1
    execution = store.get_workflow_execution("exec-broken")
    assert execution is not None
    assert execution["state"] == "failed"
    assert execution["error_code"] == "WORKFLOW_RESUME_INVALID"
    revision = store.get_revision_metadata(output.id, include_incomplete=True)
    assert revision is not None and revision["build_state"] == "failed"
    assert store.count_revision_records(output.id) == 1


def test_health_scanner_reports_invalid_schedule_and_plugin_manifest(tmp_path: Path, monkeypatch) -> None:
    from arenyxa.config import AppPaths
    from arenyxa.infrastructure.database import SQLiteStore

    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    store = SQLiteStore(paths.database)
    store.initialize()
    task = _task()
    store.save_task(task)
    with store.connect() as connection:
        connection.execute(
            "INSERT INTO schedules(id,task_id,rule_json,timezone,enabled,next_run_at,last_run_at,created_at,updated_at) "
            "VALUES(?,?,?,?,1,NULL,NULL,?,?)",
            ("invalid", task.id, json.dumps({"kind": "weekly", "weekdays": []}), "UTC", utc_now(), utc_now()),
        )
    plugin = paths.plugins / "broken"
    plugin.mkdir(parents=True)
    (plugin / "plugin.json").write_text("[]", encoding="utf-8")

    monkeypatch.setenv("ARENYXA_ENFORCE_SOURCE_INTEGRITY", "0")
    report = StartupHealthScanner(paths, tmp_path, ignore_current_session=True).scan()
    codes = {item.code for item in report.findings}
    assert "INVALID_PERSISTED_SCHEDULE" in codes
    assert "PLUGIN_MANIFEST_INVALID" in codes
    assert all(item.fingerprint.startswith("NXF-") for item in report.findings)
