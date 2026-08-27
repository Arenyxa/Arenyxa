from __future__ import annotations

from dataclasses import asdict

import pytest

from arenyxa.application.workflow_contract import (
    SUPPORTED_WORKFLOW_NODE_KINDS,
    WORKFLOW_NODE_CONTRACTS,
    serialize_workflow,
    validate_workflow_contract,
)
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Workflow, WorkflowNode


VALID_CONFIGS = {
    "source": {},
    "filter": {"field": "x", "operator": "exists"},
    "map": {"fields": {}, "constants": {}},
    "validate": {"required": []},
    "sink": {},
    "browser_action": {"kind": "goto", "url": "https://example.com", "timeout_ms": 1000},
}


@pytest.mark.parametrize("kind", sorted(SUPPORTED_WORKFLOW_NODE_KINDS))
def test_every_supported_workflow_kind_has_schema_serializer_migration_runtime_and_test(kind: str) -> None:
    contract = WORKFLOW_NODE_CONTRACTS[kind]
    assert contract.schema_version >= 1
    assert contract.serializer_version >= 1
    assert contract.migration_version >= 1
    assert callable(contract.validator)
    assert kind in WorkflowEngine().handlers
    workflow = Workflow(name=f"contract-{kind}", id=f"contract-{kind}", nodes=[WorkflowNode(kind=kind, config=VALID_CONFIGS[kind], id="n")])
    validate_workflow_contract(workflow)
    payload = serialize_workflow(workflow)
    assert payload["nodes"][0]["kind"] == kind


def test_unknown_producer_kind_fails_contract_instead_of_being_saved() -> None:
    workflow = Workflow(name="unknown", id="unknown", nodes=[WorkflowNode(kind="future_node", config={}, id="n")])
    with pytest.raises(ArenyxaError) as caught:
        validate_workflow_contract(workflow)
    assert caught.value.code == "WORKFLOW_NODE_KIND_UNSUPPORTED"


def test_browser_action_contract_rejects_non_executable_definition() -> None:
    workflow = Workflow(name="bad-browser", id="bad-browser", nodes=[WorkflowNode(kind="browser_action", config={"kind": "click", "selector": ""}, id="n")])
    with pytest.raises(ArenyxaError) as caught:
        validate_workflow_contract(workflow)
    assert caught.value.code == "WORKFLOW_NODE_CONFIG_INVALID"
