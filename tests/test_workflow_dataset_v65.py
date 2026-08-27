from __future__ import annotations

import pytest

from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, Workflow, WorkflowNode
from arenyxa.infrastructure.http_client import CancellationToken


def _source_revision(store) -> DatasetRevision:
    revision = DatasetRevision(
        "source_dataset",
        [],
        {
            "a": {"id": 1, "name": "Alpha"},
            "b": {"id": 2, "name": "Beta"},
            "c": {"id": 3, "name": "Gamma"},
        },
        schema={"id": "integer", "name": "string"},
    )
    store.save_revision(revision)
    store.upsert_dataset("source_dataset", "Source", current_revision_id=revision.id)
    return revision


def _workflow() -> Workflow:
    return Workflow(
        "enrich",
        [
            WorkflowNode("source", {}, id="source", next_ids=["map"]),
            WorkflowNode("map", {"constants": {"kind": "product"}}, id="map", next_ids=["sink"]),
            WorkflowNode("sink", {}, id="sink"),
        ],
        id="workflow_enrich",
        version="2.0.0",
    )


def test_v65_workflow_revision_pipeline_persists_output_and_lineage(store) -> None:
    source = _source_revision(store)
    lineage = DataLineageService(store)
    runtime = WorkflowDatasetService(store, WorkflowEngine(), lineage, checkpoint_every=1)

    result = runtime.execute_revision(
        _workflow(), source.id, "derived_dataset", output_dataset_name="Derived"
    )
    assert result.state == "completed"
    assert result.processed_inputs == 3
    assert result.output_count == 3
    output = store.get_revision_metadata(result.output_revision_id)
    assert output is not None and output["build_state"] == "ready"
    records = list(store.iter_revision_records(result.output_revision_id))
    assert len(records) == 3
    assert all(record["kind"] == "product" for _, record in records)

    nodes = store.get_workflow_node_executions(result.execution_id)
    assert {row["node_id"] for row in nodes} == {"source", "map", "sink"}
    graph = lineage.graph("workflow_execution", result.execution_id, max_depth=2)
    assert any(edge["relation"] == "input_to" for edge in graph.edges)
    assert any(edge["relation"] == "produced" for edge in graph.edges)


class _AutoCancelToken(CancellationToken):
    def __init__(self, cancel_after: int) -> None:
        super().__init__()
        self.calls = 0
        self.cancel_after = cancel_after

    def checkpoint(self) -> None:
        self.calls += 1
        if self.calls >= self.cancel_after:
            self.cancel()
        super().checkpoint()


def test_v65_cancelled_execution_can_resume_without_duplicate_outputs(store) -> None:
    source = _source_revision(store)
    lineage = DataLineageService(store)
    runtime = WorkflowDatasetService(store, WorkflowEngine(), lineage, checkpoint_every=1)
    token = _AutoCancelToken(cancel_after=8)

    with pytest.raises(ArenyxaError) as caught:
        runtime.execute_revision(_workflow(), source.id, "resume_dataset", token=token)
    assert caught.value.code == "RUN_CANCELLED"
    execution = store.list_workflow_executions("workflow_enrich", limit=1)[0]
    assert execution["state"] == "cancelled"

    resumed = runtime.resume_execution(execution["id"], _workflow(), token=CancellationToken())
    assert resumed.state == "completed"
    assert resumed.processed_inputs == 3
    rows = list(store.iter_revision_records(resumed.output_revision_id))
    assert len(rows) == 3
