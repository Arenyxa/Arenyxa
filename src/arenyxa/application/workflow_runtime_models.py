from __future__ import annotations

from arenyxa.compat import dataclass


@dataclass(slots=True)
class WorkflowExecutionResult:
    execution_id: str
    workflow_id: str
    source_revision_id: str
    output_revision_id: str
    output_dataset_id: str
    state: str
    processed_inputs: int
    output_count: int
    error_count: int
    resumed: bool = False
