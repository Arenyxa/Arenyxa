from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import field
from arenyxa.compat import dataclass
import re
from typing import Any, Callable, Dict, Iterable

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Workflow
from arenyxa.application.workflow_contract import validate_workflow_contract
from arenyxa.infrastructure.http_client import CancellationToken

NodeHandler = Callable[[Dict[str, Any], Dict[str, Any]], Iterable[Dict[str, Any]]]


@dataclass(slots=True)
class NodeExecution:
    node_id: str
    input_count: int = 0
    output_count: int = 0
    error_count: int = 0
    state: str = "pending"


@dataclass(slots=True)
class WorkflowResult:
    workflow_id: str
    outputs: list[dict[str, Any]] = field(default_factory=list)
    nodes: dict[str, NodeExecution] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)


class WorkflowEngine:
    def __init__(self, buffer_size: int = 1000) -> None:
        if not isinstance(buffer_size, int) or isinstance(buffer_size, bool) or buffer_size <= 0:
            raise ValueError("buffer_size 必须是正整数。")
        self.buffer_size = buffer_size
        self.handlers: dict[str, NodeHandler] = {}
        self.register("source", lambda item, config: [item])
        self.register("filter", self._filter)
        self.register("map", self._map)
        self.register("validate", self._validate)
        self.register("sink", lambda item, config: [item])
        from arenyxa.application.browser_workflow import BrowserWorkflowActionHandler
        self.register("browser_action", BrowserWorkflowActionHandler())

    def register(self, kind: str, handler: NodeHandler) -> None:
        if not isinstance(kind, str) or not kind:
            raise ValueError("workflow handler kind must be a non-empty string")
        if not callable(handler):
            raise TypeError("workflow handler must be callable")
        self.handlers[kind] = handler

    def configure_browser_runtime(self, browser_pool: Any | None = None, *, headless: bool = True) -> None:
        from arenyxa.application.browser_workflow import BrowserWorkflowActionHandler
        self.register("browser_action", BrowserWorkflowActionHandler(browser_pool, headless=headless))

    def validate_executable(self, workflow: Workflow) -> None:
        validate_workflow_contract(workflow, registered_runtime_kinds=set(self.handlers))
        for kind in {node.kind for node in workflow.nodes}:
            handler = self.handlers[kind]
            runtime_available = getattr(handler, "runtime_available", None)
            if callable(runtime_available) and not bool(runtime_available()):
                raise ArenyxaError(
                    "WORKFLOW_RUNTIME_UNAVAILABLE",
                    f"Workflow node runtime is unavailable: {kind}",
                    domain="WORKFLOW",
                    context={"kind": kind},
                )

    def execute(
        self, workflow: Workflow, inputs: Iterable[dict[str, Any]], token: CancellationToken | None = None,
        *, scopes: Mapping[str, Mapping[str, Any]] | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
    ) -> WorkflowResult:
        token = token or CancellationToken()
        validate_workflow_contract(
            workflow,
            registered_runtime_kinds=set(self.handlers),
            allow_runtime_extensions=True,
        )
        nodes = {node.id: node for node in workflow.nodes}
        lifecycle_handlers: list[Any] = []
        seen_handler_ids: set[int] = set()
        for node in workflow.nodes:
            handler = self.handlers[node.kind]
            identity = id(handler)
            if identity in seen_handler_ids:
                continue
            seen_handler_ids.add(identity)
            if hasattr(handler, "begin_execution") and hasattr(handler, "end_execution"):
                lifecycle_handlers.append(handler)

        result = WorkflowResult(
            workflow.id, nodes={node.id: NodeExecution(node.id) for node in workflow.nodes}
        )

        def append_bounded(queue: deque[dict[str, Any]], value: dict[str, Any], node_id: str) -> None:
            if len(queue) >= self.buffer_size:
                raise ArenyxaError(
                    "WORKFLOW_BUFFER_LIMIT",
                    "工作流单节点缓冲区达到安全上限。",
                    domain="WORKFLOW",
                    context={"node_id": node_id, "limit": self.buffer_size},
                )
            queue.append(value)

        def append_terminal(value: dict[str, Any]) -> None:
            if len(result.outputs) >= self.buffer_size:
                raise ArenyxaError(
                    "WORKFLOW_BUFFER_LIMIT",
                    "工作流单次执行输出达到安全缓冲上限。",
                    domain="WORKFLOW",
                    context={"area": "outputs", "limit": self.buffer_size},
                )
            result.outputs.append(value)

        def append_error(node_id: str, exc: Exception, item: dict[str, Any]) -> None:
                                                                                               
                                                                                           
                                                                    
            if len(result.errors) >= self.buffer_size:
                raise ArenyxaError(
                    "WORKFLOW_BUFFER_LIMIT",
                    "工作流单次执行错误记录达到安全缓冲上限。",
                    domain="WORKFLOW",
                    context={"area": "errors", "node_id": node_id, "limit": self.buffer_size},
                )
            result.errors.append({"node_id": node_id, "error": str(exc), "item": item})

        started_lifecycles: list[Any] = []
        try:
            for lifecycle_handler in lifecycle_handlers:
                lifecycle_handler.begin_execution()
                started_lifecycles.append(lifecycle_handler)
            indegree: defaultdict[str, int] = defaultdict(int)
            for node in workflow.nodes:
                for child_id in node.next_ids + node.failure_ids:
                    if not isinstance(child_id, str):
                        raise ArenyxaError(
                            "WORKFLOW_NODE_INVALID", "工作流连接目标必须是节点 ID 字符串。", domain="WORKFLOW"
                        )
                    if child_id not in nodes:
                        raise ArenyxaError(
                            "WORKFLOW_NODE_MISSING", f"不存在的节点：{child_id}", domain="WORKFLOW"
                        )
                    indegree[child_id] += 1
            roots = [node for node in workflow.nodes if indegree[node.id] == 0]
            if not roots:
                raise ArenyxaError("WORKFLOW_CYCLE", "工作流没有入口节点。", domain="WORKFLOW")
            items_by_node: dict[str, deque[dict[str, Any]]] = {node.id: deque() for node in workflow.nodes}
                                                                                            
                                                                                              
                                                      
            for input_item in inputs:
                if not isinstance(input_item, dict):
                    raise ArenyxaError("WORKFLOW_INPUT_INVALID", "工作流输入必须是对象。", domain="WORKFLOW")
                for root in roots:
                    append_bounded(items_by_node[root.id], dict(input_item), root.id)
            ready = deque(root.id for root in roots)
                                                                                             
                                                                                               
                                                                                      
            remaining_parents = dict(indegree)
            visited = set()
            while ready:
                token.checkpoint()
                node_id = ready.popleft()
                node = nodes[node_id]
                execution = result.nodes[node_id]
                execution.state = "running"
                handler = self.handlers.get(node.kind)
                if not handler:
                    raise ArenyxaError(
                        "WORKFLOW_HANDLER_MISSING", f"不支持节点类型：{node.kind}", domain="WORKFLOW"
                    )
                while items_by_node[node_id]:
                    token.checkpoint()
                    item = items_by_node[node_id].popleft()
                    execution.input_count += 1
                    try:
                                                                                    
                                                                                            
                                                                 
                        config = self._resolve_variables(node.config, scopes or {}, secret_resolver)
                        for output in handler(item, config):
                            if not isinstance(output, dict):
                                raise TypeError("workflow node output must be a dict")
                            execution.output_count += 1
                            if node.next_ids:
                                for child_id in node.next_ids:
                                    append_bounded(items_by_node[child_id], dict(output), child_id)
                            else:
                                append_terminal(output)
                    except ArenyxaError as exc:
                        if exc.code == "WORKFLOW_BUFFER_LIMIT":
                            raise
                        execution.error_count += 1
                        append_error(node_id, exc, item)
                        for child_id in node.failure_ids:
                            append_bounded(items_by_node[child_id], {**item, "_error": str(exc)}, child_id)
                    except Exception as exc:                                                            
                        execution.error_count += 1
                        append_error(node_id, exc, item)
                        for child_id in node.failure_ids:
                            append_bounded(items_by_node[child_id], {**item, "_error": str(exc)}, child_id)
                execution.state = "completed" if execution.error_count == 0 else "partial"
                visited.add(node_id)
                for child_id in node.next_ids + node.failure_ids:
                    remaining = remaining_parents.get(child_id, 0) - 1
                    remaining_parents[child_id] = remaining
                    if remaining == 0 and child_id not in visited:
                        ready.append(child_id)
            if len(visited) != len(nodes):
                blocked = sorted(set(nodes) - visited)
                raise ArenyxaError(
                    "WORKFLOW_CYCLE",
                    "工作流包含无法从入口完成拓扑排序的循环节点。",
                    domain="WORKFLOW",
                    context={"blocked_nodes": blocked[:50]},
                )
            return result
        finally:
            for lifecycle_handler in reversed(started_lifecycles):
                lifecycle_handler.end_execution()


    _VARIABLE = re.compile(r"\$\{([a-zA-Z][\w-]*)\.([\w.-]+)\}")

    @classmethod
    def _resolve_variables(
        cls, value: Any, scopes: Mapping[str, Mapping[str, Any]],
        secret_resolver: Callable[[str], str | None] | None,
    ) -> Any:
        if isinstance(value, str):
            def replace(match: re.Match[str]) -> str:
                scope, key = match.group(1), match.group(2)
                resolved = secret_resolver(key) if scope == "secret" and secret_resolver is not None else scopes.get(scope, {}).get(key)
                if resolved is None:
                    raise KeyError(f"workflow variable not found: {scope}.{key}")
                return str(resolved)
            return cls._VARIABLE.sub(replace, value)
        if isinstance(value, list):
            return [cls._resolve_variables(item, scopes, secret_resolver) for item in value]
        if isinstance(value, tuple):
            return tuple(cls._resolve_variables(item, scopes, secret_resolver) for item in value)
        if isinstance(value, dict):
            return {key: cls._resolve_variables(item, scopes, secret_resolver) for key, item in value.items()}
        return value

    @staticmethod
    def _filter(item: dict[str, Any], config: dict[str, Any]) -> Iterable[dict[str, Any]]:
        field_name = str(config["field"])
        operator = config.get("operator", "equals")
        expected = config.get("value")
        actual = item.get(field_name)
        matched = {
            "equals": actual == expected,
            "not_equals": actual != expected,
            "contains": str(expected) in str(actual or ""),
            "exists": field_name in item,
        }.get(operator, False)
        return [item] if matched else []

    @staticmethod
    def _map(item: dict[str, Any], config: dict[str, Any]) -> Iterable[dict[str, Any]]:
        result = dict(item)
                                                                                              
                                                                                        
                                                                                                
        for destination, source in config.get("fields", {}).items():
            result[destination] = item.get(source) if isinstance(source, str) else source
        for destination, value in config.get("constants", {}).items():
            result[destination] = value
        return [result]

    @staticmethod
    def _validate(item: dict[str, Any], config: dict[str, Any]) -> Iterable[dict[str, Any]]:
        missing = [name for name in config.get("required", []) if item.get(name) in {None, ""}]
        if missing:
            raise ValueError(f"required fields missing: {', '.join(missing)}")
        return [item]
