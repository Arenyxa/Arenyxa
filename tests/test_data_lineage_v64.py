from __future__ import annotations

from arenyxa.application.data_lineage import DataLineageService
from arenyxa.domain.enums import RunStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec, ResultRecord, Run, Task


def _completed_run(store, task: Task, rows: list[dict]) -> Run:
    run = Run(task.id, task.to_dict(), status=RunStatus.COMPLETED, stage="completed")
    store.save_run(run)
    store.append_results(
        ResultRecord(task.id, run.id, "https://example.test", row) for row in rows
    )
    return run


def test_v64_materializes_runs_with_stable_identity_and_lineage(store) -> None:
    task = Task("items", [RequestSpec("https://example.test/items")])
    store.save_task(task)
    first = _completed_run(store, task, [{"id": 1, "name": "A"}, {"id": 2, "name": "B"}])
    second = _completed_run(store, task, [{"id": 1, "name": "A2"}, {"id": 3, "name": "C"}])

    service = DataLineageService(store, write_batch_size=50)
    dataset_id = service.create_dataset("Products", dataset_id="dataset_products")
    result = service.materialize_from_runs(
        dataset_id,
        [first.id, second.id],
        identity_fields=["id"],
        label="merged",
    )

    assert result.record_count == 3
    rows = dict(store.iter_revision_records(result.revision_id))
    assert sorted(row["id"] for row in rows.values()) == [1, 2, 3]
    assert next(row for row in rows.values() if row["id"] == 1)["name"] == "A2"
    assert result.schema == {"id": "integer", "name": "string"}
    assert store.get_dataset(dataset_id)["current_revision_id"] == result.revision_id

    graph = service.graph("revision", result.revision_id, max_depth=3)
    kinds = {node["kind"] for node in graph.nodes}
    assert {"revision", "dataset", "run", "task"} <= kinds
    assert any(edge["relation"] == "materialized_into" for edge in graph.edges)


def test_v64_failed_build_is_hidden_from_normal_revision_history(store) -> None:
    task = Task("cap", [RequestSpec("https://example.test")])
    store.save_task(task)
    run = _completed_run(store, task, [{"id": 1}, {"id": 2}])
    service = DataLineageService(store, max_records=1000)
    service.create_dataset("Cap", dataset_id="dataset_cap")

    try:
        service.materialize_from_runs("dataset_cap", [run.id], max_records=1)
    except ArenyxaError as exc:
        assert exc.code == "DATASET_RECORD_LIMIT"
    else:
        raise AssertionError("expected record limit failure")

    assert store.list_revisions("dataset_cap") == []
    incomplete = store.list_revisions("dataset_cap", include_incomplete=True)
    assert len(incomplete) == 1
    assert incomplete[0]["build_state"] == "failed"
