"""Authoritative workflow node contract shared by producers, storage, migrations and runtime."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable, Mapping

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Workflow, WorkflowNode

ConfigValidator = Callable[[Mapping[str, Any]], None]


def _require_mapping(config: Mapping[str, Any]) -> None:
    if not isinstance(config, Mapping):
        raise ValueError("workflow node config must be an object")


def _validate_filter(config: Mapping[str, Any]) -> None:
    _require_mapping(config)
    field = config.get("field")
    if not isinstance(field, str) or not field:
        raise ValueError("filter.field must be a non-empty string")
    if config.get("operator", "equals") not in {"equals", "not_equals", "contains", "exists"}:
        raise ValueError("filter.operator is unsupported")


def _validate_map(config: Mapping[str, Any]) -> None:
    _require_mapping(config)
    for key in ("fields", "constants"):
        value = config.get(key, {})
        if not isinstance(value, Mapping):
            raise ValueError(f"map.{key} must be an object")


def _validate_validate(config: Mapping[str, Any]) -> None:
    _require_mapping(config)
    required = config.get("required", [])
    if not isinstance(required, list) or any(not isinstance(item, str) or not item for item in required):
        raise ValueError("validate.required must be a list of non-empty strings")


def _validate_browser_action(config: Mapping[str, Any]) -> None:
    _require_mapping(config)
    kind = config.get("kind")
    supported = {
        "goto", "click", "fill", "press", "check", "uncheck", "select",
        "wait", "scroll", "download", "upload", "assert_text",
    }
    if kind not in supported:
        raise ValueError(f"browser_action.kind is unsupported: {kind!r}")
    timeout = config.get("timeout_ms", 30_000)
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 100 <= timeout <= 300_000:
        raise ValueError("browser_action.timeout_ms must be between 100 and 300000")
    selector = config.get("selector", "")
    if not isinstance(selector, str) or len(selector) > 8_192:
        raise ValueError("browser_action.selector must be a bounded string")
    value = config.get("value", "")
    if not isinstance(value, str) or len(value) > 1_000_000:
        raise ValueError("browser_action.value must be a bounded string")
    url = config.get("url", "")
    if not isinstance(url, str) or len(url) > 16_384:
        raise ValueError("browser_action.url must be a bounded string")
    metadata = config.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ValueError("browser_action.metadata must be an object")
    if kind == "goto" and not (url or value):
        raise ValueError("browser_action goto requires url or value")
    if kind in {"click", "fill", "press", "check", "uncheck", "select", "download", "upload", "assert_text"} and not selector:
        raise ValueError(f"browser_action {kind} requires selector")


@dataclass(frozen=True, slots=True)
class WorkflowNodeContract:
    kind: str
    schema_version: int
    serializer_version: int
    migration_version: int
    runtime_required: bool
    validator: ConfigValidator


WORKFLOW_NODE_CONTRACTS: dict[str, WorkflowNodeContract] = {
    "source": WorkflowNodeContract("source", 1, 1, 1, True, _require_mapping),
    "filter": WorkflowNodeContract("filter", 1, 1, 1, True, _validate_filter),
    "map": WorkflowNodeContract("map", 1, 1, 1, True, _validate_map),
    "validate": WorkflowNodeContract("validate", 1, 1, 1, True, _validate_validate),
    "sink": WorkflowNodeContract("sink", 1, 1, 1, True, _require_mapping),
    "browser_action": WorkflowNodeContract("browser_action", 1, 1, 1, True, _validate_browser_action),
}

SUPPORTED_WORKFLOW_NODE_KINDS = frozenset(WORKFLOW_NODE_CONTRACTS)


def validate_workflow_node(
    node: WorkflowNode,
    *,
    registered_runtime_kinds: set[str] | frozenset[str] | None = None,
    allow_runtime_extensions: bool = False,
) -> None:
    if not isinstance(node.id, str) or not node.id:
        raise ArenyxaError("WORKFLOW_NODE_INVALID", "Workflow node ID must be non-empty", domain="WORKFLOW")
    if node.kind not in SUPPORTED_WORKFLOW_NODE_KINDS:
        if allow_runtime_extensions and registered_runtime_kinds is not None and node.kind in registered_runtime_kinds:
            try:
                _require_mapping(node.config)
            except (TypeError, ValueError) as exc:
                raise ArenyxaError(
                    "WORKFLOW_NODE_CONFIG_INVALID",
                    f"Invalid runtime-extension workflow config for {node.kind}: {exc}",
                    domain="WORKFLOW",
                    context={"node_id": node.id, "kind": node.kind},
                ) from exc
            return
        raise ArenyxaError(
            "WORKFLOW_NODE_KIND_UNSUPPORTED",
            f"Unsupported workflow node kind: {node.kind}",
            domain="WORKFLOW",
            context={"kind": str(node.kind)},
        )
    contract = WORKFLOW_NODE_CONTRACTS[node.kind]
    try:
        contract.validator(node.config)
    except (TypeError, ValueError, KeyError) as exc:
        raise ArenyxaError(
            "WORKFLOW_NODE_CONFIG_INVALID",
            f"Invalid workflow node config for {node.kind}: {exc}",
            domain="WORKFLOW",
            context={"node_id": node.id, "kind": node.kind},
        ) from exc
    if registered_runtime_kinds is not None and contract.runtime_required and node.kind not in registered_runtime_kinds:
        raise ArenyxaError(
            "WORKFLOW_HANDLER_MISSING",
            f"Workflow node kind has no runtime handler: {node.kind}",
            domain="WORKFLOW",
            context={"node_id": node.id, "kind": node.kind},
        )


def validate_workflow_contract(
    workflow: Workflow,
    *,
    registered_runtime_kinds: set[str] | frozenset[str] | None = None,
    allow_runtime_extensions: bool = False,
) -> None:
    if not isinstance(workflow.nodes, list) or not workflow.nodes:
        raise ArenyxaError("WORKFLOW_EMPTY", "Workflow must contain at least one node", domain="WORKFLOW")
    ids: set[str] = set()
    for node in workflow.nodes:
        validate_workflow_node(
            node,
            registered_runtime_kinds=registered_runtime_kinds,
            allow_runtime_extensions=allow_runtime_extensions,
        )
        if node.id in ids:
            raise ArenyxaError("WORKFLOW_NODE_DUPLICATE", "Workflow contains duplicate node IDs", domain="WORKFLOW")
        ids.add(node.id)
    for node in workflow.nodes:
        for child_id in [*node.next_ids, *node.failure_ids]:
            if not isinstance(child_id, str) or child_id not in ids:
                raise ArenyxaError(
                    "WORKFLOW_NODE_MISSING",
                    f"Workflow edge references missing node: {child_id}",
                    domain="WORKFLOW",
                    context={"node_id": node.id, "target": str(child_id)},
                )


def serialize_workflow(workflow: Workflow) -> dict[str, Any]:
    """Canonical serializer used by persistence and compatibility fixtures."""
    validate_workflow_contract(workflow)
    return asdict(workflow)


def contract_gate_snapshot() -> dict[str, dict[str, Any]]:
    return {
        kind: {
            "schema_version": contract.schema_version,
            "serializer_version": contract.serializer_version,
            "migration_version": contract.migration_version,
            "runtime_required": contract.runtime_required,
        }
        for kind, contract in sorted(WORKFLOW_NODE_CONTRACTS.items())
    }
