from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from arenyxa.application.workflow_inspector import WorkflowExecutionInspector


@dataclass(slots=True)
class WorkflowTraceNode:
    node_id: str
    kind: str
    state: str
    lane: int
    order: int
    input_count: int
    output_count: int
    error_count: int
    pressure: float
    health: str


class WorkflowRuntimeTrace:
    MAX_NODES = 2000

    def __init__(self, store: Any) -> None:
        self.store = store
        self.inspector = WorkflowExecutionInspector(store)

    def trace(self, execution_id: str) -> dict[str, Any]:
        inspection = self.inspector.inspect(execution_id)
        definition = self._definition(execution_id)
        node_defs = {str(row.get("id")): dict(row) for row in list(definition.get("nodes") or []) if isinstance(row, dict) and row.get("id")}
        levels = self._levels(node_defs)
        rows: list[WorkflowTraceNode] = []
        for order, node in enumerate(inspection.nodes[: self.MAX_NODES]):
            pressure = round((node.input_count + node.output_count + node.error_count * 5) / max(1, inspection.processed_inputs), 4)
            health = "error" if node.error_count else "warning" if node.error_rate > 0.1 or node.expansion_ratio > 10 else "ok"
            rows.append(WorkflowTraceNode(
                node_id=node.node_id,
                kind=node.kind,
                state=node.state,
                lane=int(levels.get(node.node_id, 0)),
                order=order,
                input_count=node.input_count,
                output_count=node.output_count,
                error_count=node.error_count,
                pressure=pressure,
                health=health,
            ))
        return {
            "execution_id": inspection.execution_id,
            "workflow_id": inspection.workflow_id,
            "state": inspection.state,
            "processed_inputs": inspection.processed_inputs,
            "staged_outputs": inspection.staged_outputs,
            "error_count": inspection.error_count,
            "bottleneck_nodes": inspection.bottleneck_nodes,
            "error_nodes": inspection.error_nodes,
            "warnings": inspection.warnings,
            "nodes": [asdict(row) for row in rows],
            "lanes": max([row.lane for row in rows], default=-1) + 1,
        }

    def step_plan(self, execution_id: str) -> dict[str, Any]:
        trace = self.trace(execution_id)
        nodes = list(trace["nodes"])
        actionable = [row for row in nodes if str(row.get("state")) not in {"completed", "skipped"}]
        return {
            "execution_id": execution_id,
            "state": trace["state"],
            "next_nodes": actionable[:32],
            "can_retry": bool(trace["error_nodes"]),
            "can_continue": str(trace["state"]) in {"paused", "running", "queued"},
            "warnings": trace["warnings"],
        }

    def _definition(self, execution_id: str) -> dict[str, Any]:
        execution = self.store.get_workflow_execution(str(execution_id))
        if execution is None:
            raise KeyError(f"Workflow execution was not found: {execution_id}")
        import json
        value = execution.get("definition_json")
        if isinstance(value, dict):
            return dict(value)
        try:
            decoded = json.loads(str(value or "{}"))
        except (ValueError, TypeError, json.JSONDecodeError):
            return {}
        return dict(decoded) if isinstance(decoded, dict) else {}

    def _levels(self, definitions: dict[str, dict[str, Any]]) -> dict[str, int]:
        incoming: dict[str, set[str]] = {node_id: set() for node_id in definitions}
        outgoing: dict[str, list[str]] = {node_id: [] for node_id in definitions}
        for node_id, definition in definitions.items():
            for target in list(definition.get("next_ids") or [])[:256]:
                target_id = str(target)
                if target_id in definitions:
                    outgoing[node_id].append(target_id)
                    incoming[target_id].add(node_id)
        queue = [node_id for node_id, parents in incoming.items() if not parents]
        levels = {node_id: 0 for node_id in queue}
        seen = 0
        while queue and seen < self.MAX_NODES * 2:
            node_id = queue.pop(0)
            seen += 1
            for target in outgoing[node_id]:
                levels[target] = max(levels.get(target, 0), levels.get(node_id, 0) + 1)
                incoming[target].discard(node_id)
                if not incoming[target]:
                    queue.append(target)
        for node_id in definitions:
            levels.setdefault(node_id, 0)
        return levels
