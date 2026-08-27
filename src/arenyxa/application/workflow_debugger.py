"""Bounded, side-effect-free workflow simulation with node breakpoints."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Mapping, Sequence

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Workflow
from arenyxa.application.workflows import WorkflowEngine


@dataclass(slots=True)
class WorkflowDebugStep:
    """One completed or paused node in a deterministic debug simulation."""

    sequence: int
    node_id: str
    kind: str
    state: str
    input_count: int
    output_count: int
    error_count: int
    input_preview: list[dict[str, Any]] = field(default_factory=list)
    output_preview: list[dict[str, Any]] = field(default_factory=list)
    error_preview: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class WorkflowDebugReport:
    """Serializable bounded debugger result."""

    workflow_id: str
    state: str
    breakpoint: str | None
    steps_executed: int
    traces: list[WorkflowDebugStep]
    outputs: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    pending_nodes: list[dict[str, Any]]
    blocked_nodes: list[str]
    warnings: list[str]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class WorkflowSafeDebugger:
    """Simulate local deterministic workflow nodes without external side effects."""

    SAFE_KINDS = frozenset({"source", "filter", "map", "validate", "sink"})
    MAX_INPUTS = 10_000
    MAX_STEPS = 20_000
    MAX_PREVIEW = 20

    def __init__(self, engine: WorkflowEngine) -> None:
        self.engine = engine

    def simulate(
        self,
        workflow: Workflow,
        inputs: Sequence[dict[str, Any]],
        *,
        breakpoints: Sequence[str] = (),
        max_steps: int = 5000,
        scopes: Mapping[str, Mapping[str, Any]] | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
    ) -> WorkflowDebugReport:
        if len(inputs) > self.MAX_INPUTS:
            raise ArenyxaError(
                "WORKFLOW_DEBUG_INPUT_LIMIT",
                f"Workflow debugger input exceeds {self.MAX_INPUTS} records.",
                domain="WORKFLOW",
            )
        step_budget = max(1, min(int(max_steps), self.MAX_STEPS))
        nodes = {node.id: node for node in workflow.nodes}
        if not nodes:
            raise ArenyxaError("WORKFLOW_EMPTY", "Workflow requires at least one node.", domain="WORKFLOW")
        if len(nodes) != len(workflow.nodes) or any(not node_id for node_id in nodes):
            raise ArenyxaError("WORKFLOW_NODE_DUPLICATE", "Workflow contains invalid or duplicate node IDs.", domain="WORKFLOW")

        incoming: defaultdict[str, int] = defaultdict(int)
        for node in workflow.nodes:
            for target in [*node.next_ids, *node.failure_ids]:
                if target not in nodes:
                    raise ArenyxaError(
                        "WORKFLOW_NODE_MISSING",
                        f"Workflow edge targets a missing node: {target}",
                        domain="WORKFLOW",
                    )
                incoming[target] += 1
        roots = [node.id for node in workflow.nodes if incoming[node.id] == 0]
        if not roots:
            raise ArenyxaError("WORKFLOW_CYCLE", "Workflow has no root node.", domain="WORKFLOW")

        queues: dict[str, deque[dict[str, Any]]] = {node_id: deque() for node_id in nodes}
        for raw in inputs:
            if not isinstance(raw, dict):
                raise ArenyxaError("WORKFLOW_INPUT_INVALID", "Debugger inputs must be objects.", domain="WORKFLOW")
            for root in roots:
                self._append(queues[root], dict(raw), root)
        ready = deque(roots)
        remaining = dict(incoming)
        visited: set[str] = set()
        breakpoint_set = {str(item).strip() for item in breakpoints if str(item).strip()}
        traces: list[WorkflowDebugStep] = []
        outputs: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        blocked: list[str] = []
        warnings: list[str] = []
        sequence = 0

        while ready:
            node_id = ready.popleft()
            node = nodes[node_id]
            if node_id in breakpoint_set:
                traces.append(
                    WorkflowDebugStep(
                        sequence=sequence,
                        node_id=node_id,
                        kind=node.kind,
                        state="breakpoint",
                        input_count=len(queues[node_id]),
                        output_count=0,
                        error_count=0,
                        input_preview=self._preview(queues[node_id]),
                    )
                )
                return self._report(
                    workflow.id, "paused", node_id, sequence, traces, outputs, errors,
                    queues, ready, nodes, blocked, warnings,
                )
            if sequence >= step_budget:
                warnings.append(f"Debugger stopped at the {step_budget}-step safety budget")
                return self._report(
                    workflow.id, "budget-exhausted", None, sequence, traces, outputs, errors,
                    queues, ready, nodes, blocked, warnings,
                )
            sequence += 1
            input_preview = self._preview(queues[node_id])
            local_outputs: list[dict[str, Any]] = []
            local_errors: list[dict[str, Any]] = []
            if node.kind not in self.SAFE_KINDS:
                blocked.append(node_id)
                warnings.append(f"Node {node_id} ({node.kind}) was blocked by safe debugger policy")
                traces.append(
                    WorkflowDebugStep(
                        sequence=sequence,
                        node_id=node_id,
                        kind=node.kind,
                        state="blocked",
                        input_count=len(queues[node_id]),
                        output_count=0,
                        error_count=0,
                        input_preview=input_preview,
                    )
                )
                return self._report(
                    workflow.id, "blocked", node_id, sequence, traces, outputs, errors,
                    queues, ready, nodes, blocked, warnings,
                )

            handler = self.engine.handlers.get(node.kind)
            if handler is None:
                raise ArenyxaError(
                    "WORKFLOW_HANDLER_MISSING",
                    f"Workflow debugger has no handler for node kind: {node.kind}",
                    domain="WORKFLOW",
                )
            input_count = 0
            error_count = 0
            while queues[node_id]:
                item = queues[node_id].popleft()
                input_count += 1
                try:
                    config = self.engine._resolve_variables(node.config, scopes or {}, secret_resolver)
                    generated = handler(item, config)
                    for output in generated:
                        if not isinstance(output, dict):
                            raise TypeError("workflow node output must be a dict")
                        clean = dict(output)
                        local_outputs.append(clean)
                        if node.next_ids:
                            for child_id in node.next_ids:
                                self._append(queues[child_id], dict(clean), child_id)
                        else:
                            self._append_output(outputs, clean)
                except (ArenyxaError, KeyError, TypeError, ValueError) as exc:
                    error_count += 1
                    row = {"node_id": node_id, "error": str(exc), "item": self._bounded_record(item)}
                    local_errors.append(row)
                    self._append_error(errors, row)
                    for child_id in node.failure_ids:
                        self._append(queues[child_id], {**item, "_error": str(exc)}, child_id)
            traces.append(
                WorkflowDebugStep(
                    sequence=sequence,
                    node_id=node_id,
                    kind=node.kind,
                    state="completed" if error_count == 0 else "partial",
                    input_count=input_count,
                    output_count=len(local_outputs),
                    error_count=error_count,
                    input_preview=input_preview,
                    output_preview=[self._bounded_record(item) for item in local_outputs[: self.MAX_PREVIEW]],
                    error_preview=local_errors[: self.MAX_PREVIEW],
                )
            )
            visited.add(node_id)
            for child_id in [*node.next_ids, *node.failure_ids]:
                remaining[child_id] = remaining.get(child_id, 0) - 1
                if remaining[child_id] == 0 and child_id not in visited:
                    ready.append(child_id)

        if len(visited) != len(nodes):
            blocked_graph = sorted(set(nodes) - visited)
            raise ArenyxaError(
                "WORKFLOW_CYCLE",
                "Workflow debugger could not complete the graph topology.",
                domain="WORKFLOW",
                context={"blocked_nodes": blocked_graph[:50]},
            )
        return self._report(
            workflow.id, "completed", None, sequence, traces, outputs, errors,
            queues, ready, nodes, blocked, warnings,
        )

    def _append(self, queue: deque[dict[str, Any]], value: dict[str, Any], node_id: str) -> None:
        if len(queue) >= self.engine.buffer_size:
            raise ArenyxaError(
                "WORKFLOW_BUFFER_LIMIT",
                "Workflow debugger node buffer reached the safety limit.",
                domain="WORKFLOW",
                context={"node_id": node_id, "limit": self.engine.buffer_size},
            )
        queue.append(value)

    def _append_output(self, outputs: list[dict[str, Any]], value: dict[str, Any]) -> None:
        if len(outputs) >= self.engine.buffer_size:
            raise ArenyxaError(
                "WORKFLOW_BUFFER_LIMIT",
                "Workflow debugger output reached the safety limit.",
                domain="WORKFLOW",
                context={"limit": self.engine.buffer_size},
            )
        outputs.append(self._bounded_record(value))

    def _append_error(self, errors: list[dict[str, Any]], value: dict[str, Any]) -> None:
        if len(errors) >= self.engine.buffer_size:
            raise ArenyxaError(
                "WORKFLOW_BUFFER_LIMIT",
                "Workflow debugger error buffer reached the safety limit.",
                domain="WORKFLOW",
                context={"limit": self.engine.buffer_size},
            )
        errors.append(value)

    def _report(
        self,
        workflow_id: str,
        state: str,
        breakpoint: str | None,
        steps: int,
        traces: list[WorkflowDebugStep],
        outputs: list[dict[str, Any]],
        errors: list[dict[str, Any]],
        queues: Mapping[str, deque[dict[str, Any]]],
        ready: deque[str],
        nodes: Mapping[str, Any],
        blocked: list[str],
        warnings: list[str],
    ) -> WorkflowDebugReport:
        ready_order = list(ready)
        pending = []
        for node_id, queue in queues.items():
            if queue or node_id in ready_order:
                pending.append({
                    "node_id": node_id,
                    "kind": str(nodes[node_id].kind),
                    "queued_records": len(queue),
                    "preview": self._preview(queue),
                })
        return WorkflowDebugReport(
            workflow_id=workflow_id,
            state=state,
            breakpoint=breakpoint,
            steps_executed=steps,
            traces=traces[: self.MAX_STEPS],
            outputs=outputs[: self.engine.buffer_size],
            errors=errors[: self.engine.buffer_size],
            pending_nodes=pending[:256],
            blocked_nodes=list(dict.fromkeys(blocked))[:256],
            warnings=warnings[:256],
        )

    @classmethod
    def _preview(cls, queue: Sequence[dict[str, Any]] | deque[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = list(queue)[: cls.MAX_PREVIEW]
        return [cls._bounded_record(item) for item in rows]

    @staticmethod
    def _bounded_record(value: Mapping[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 64:
                result["_truncated_fields"] = True
                break
            text = item if isinstance(item, (bool, int, float)) or item is None else str(item)
            if isinstance(text, str) and len(text) > 2000:
                text = text[:2000] + "…"
            result[str(key)[:256]] = text
        return result
