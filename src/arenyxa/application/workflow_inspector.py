from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class WorkflowNodeInspection:
    node_id: str
    kind: str
    state: str
    input_count: int
    output_count: int
    error_count: int
    expansion_ratio: float
    error_rate: float
    configuration: dict[str, Any]


@dataclass(slots=True)
class WorkflowExecutionInspection:
    execution_id: str
    workflow_id: str
    state: str
    started_at: str
    updated_at: str
    finished_at: str | None
    processed_inputs: int
    staged_outputs: int
    error_count: int
    output_ratio: float
    error_rate: float
    checkpoint: dict[str, Any]
    error: dict[str, Any] | None
    nodes: list[WorkflowNodeInspection]
    bottleneck_nodes: list[str]
    error_nodes: list[str]
    warnings: list[str]

    def snapshot(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["nodes"] = [asdict(item) for item in self.nodes]
        return payload


class WorkflowExecutionInspector:
    def __init__(self, store: Any) -> None:
        self.store = store

    def inspect(self, execution_id: str) -> WorkflowExecutionInspection:
        execution = self.store.get_workflow_execution(str(execution_id))
        if execution is None:
            raise KeyError(f"Workflow execution was not found: {execution_id}")
        definition = self._json_object(execution.get("definition_json"))
        node_definitions = {
            str(item.get("id")): dict(item)
            for item in list(definition.get("nodes") or [])
            if isinstance(item, dict) and item.get("id")
        }
        persisted_nodes = {
            str(item.get("node_id")): dict(item)
            for item in self.store.get_workflow_node_executions(str(execution_id))
            if item.get("node_id")
        }
        node_ids = list(dict.fromkeys([*node_definitions, *persisted_nodes]))[:2000]
        nodes: list[WorkflowNodeInspection] = []
        warnings: list[str] = []
        for node_id in node_ids:
            definition_row = node_definitions.get(node_id, {})
            metrics = persisted_nodes.get(node_id, {})
            inputs = max(0, int(metrics.get("input_count") or 0))
            outputs = max(0, int(metrics.get("output_count") or 0))
            errors = max(0, int(metrics.get("error_count") or 0))
            nodes.append(
                WorkflowNodeInspection(
                    node_id=node_id,
                    kind=str(definition_row.get("kind") or "unknown"),
                    state=str(metrics.get("state") or "pending"),
                    input_count=inputs,
                    output_count=outputs,
                    error_count=errors,
                    expansion_ratio=round(outputs / max(1, inputs), 4),
                    error_rate=round(errors / max(1, inputs), 4),
                    configuration=self._bounded_config(definition_row.get("config")),
                )
            )
        processed = max(0, int(execution.get("processed_inputs") or 0))
        staged = max(0, int(execution.get("staged_outputs") or 0))
        errors_total = max(0, int(execution.get("error_count") or 0))
        error_nodes = [item.node_id for item in nodes if item.error_count > 0 or item.state.casefold() in {"failed", "error"}]
        ranked = sorted(
            nodes,
            key=lambda item: (item.error_count, item.input_count + item.output_count),
            reverse=True,
        )
        bottlenecks = [item.node_id for item in ranked[:5] if item.input_count or item.output_count or item.error_count]
        if processed and staged == 0:
            warnings.append("Execution processed input records but staged no outputs")
        if errors_total:
            warnings.append(f"Execution recorded {errors_total} errors")
        if any(item.expansion_ratio > 20 for item in nodes):
            warnings.append("At least one node expanded records by more than 20x; verify bounded fan-out")
        if any(item.error_rate > 0.25 and item.input_count >= 4 for item in nodes):
            warnings.append("At least one node has an error rate above 25%")
        state = str(execution.get("state") or "")
        if state in {"queued", "running"} and not execution.get("checkpoint_json"):
            warnings.append("Active execution has no persisted checkpoint payload")
        error = None
        if execution.get("error_code") or execution.get("error_message"):
            error = {
                "code": str(execution.get("error_code") or ""),
                "message": str(execution.get("error_message") or "")[:4000],
            }
        return WorkflowExecutionInspection(
            execution_id=str(execution.get("id") or execution_id),
            workflow_id=str(execution.get("workflow_id") or ""),
            state=state,
            started_at=str(execution.get("started_at") or ""),
            updated_at=str(execution.get("updated_at") or ""),
            finished_at=None if not execution.get("finished_at") else str(execution.get("finished_at")),
            processed_inputs=processed,
            staged_outputs=staged,
            error_count=errors_total,
            output_ratio=round(staged / max(1, processed), 4),
            error_rate=round(errors_total / max(1, processed), 4),
            checkpoint=self._json_object(execution.get("checkpoint_json")),
            error=error,
            nodes=nodes,
            bottleneck_nodes=bottlenecks,
            error_nodes=error_nodes,
            warnings=warnings,
        )

    @staticmethod
    def _json_object(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        if not value:
            return {}
        try:
            parsed = json.loads(str(value))
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}

    @staticmethod
    def _bounded_config(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        output: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 64:
                break
            name = str(key)[:128]
            if isinstance(item, (str, int, float, bool)) or item is None:
                output[name] = str(item)[:1000] if isinstance(item, str) else item
            elif isinstance(item, list):
                output[name] = item[:32]
            elif isinstance(item, dict):
                output[name] = dict(list(item.items())[:32])
            else:
                output[name] = str(item)[:1000]
        return output
