"""Release-blocking workflow producer/schema/serializer/migration/runtime contract gate."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from arenyxa.application.workflow_contract import (
    SUPPORTED_WORKFLOW_NODE_KINDS,
    WORKFLOW_NODE_CONTRACTS,
    contract_gate_snapshot,
)
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.models import Workflow, WorkflowNode

SRC = ROOT / "src" / "arenyxa"
TEST_FILE = ROOT / "tests" / "test_workflow_contract_gate.py"


def _literal_workflow_kinds(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    if "WorkflowNode" not in text and "browser_action" not in text:
        return set()
    tree = ast.parse(text, filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ""
            if isinstance(node.func, ast.Name):
                name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                name = node.func.attr
            if name != "WorkflowNode":
                continue
            candidate: ast.AST | None = node.args[0] if node.args else None
            for keyword in node.keywords:
                if keyword.arg == "kind":
                    candidate = keyword.value
            if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
                found.add(candidate.value)
        elif isinstance(node, ast.Dict):
            # Recorder/extraction producers intentionally construct portable node dictionaries
            # before they are turned into WorkflowNode objects.
            pairs = zip(node.keys, node.values)
            values: dict[str, Any] = {}
            for key, value in pairs:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    if isinstance(value, ast.Constant):
                        values[key.value] = value.value
            if values.get("kind") == "browser_action":
                found.add("browser_action")
    return found


def main() -> int:
    producer_kinds: set[str] = set()
    producer_files: dict[str, list[str]] = {}
    for path in SRC.rglob("*.py"):
        kinds = _literal_workflow_kinds(path)
        for kind in kinds:
            producer_kinds.add(kind)
            producer_files.setdefault(kind, []).append(str(path.relative_to(ROOT)))

    errors: list[str] = []
    missing_contract = sorted(producer_kinds - SUPPORTED_WORKFLOW_NODE_KINDS)
    if missing_contract:
        errors.append("producer kinds missing central contract: " + ", ".join(missing_contract))

    engine = WorkflowEngine()
    runtime_kinds = set(engine.handlers)
    for kind, contract in WORKFLOW_NODE_CONTRACTS.items():
        if contract.schema_version <= 0:
            errors.append(f"{kind}: schema version missing")
        if contract.serializer_version <= 0:
            errors.append(f"{kind}: serializer version missing")
        if contract.migration_version <= 0:
            errors.append(f"{kind}: migration version missing")
        if not callable(contract.validator):
            errors.append(f"{kind}: validator missing")
        if contract.runtime_required and kind not in runtime_kinds:
            errors.append(f"{kind}: runtime handler missing")

    if not TEST_FILE.is_file():
        errors.append("workflow contract regression test file is missing")
    else:
        test_text = TEST_FILE.read_text(encoding="utf-8")
        if "SUPPORTED_WORKFLOW_NODE_KINDS" not in test_text:
            errors.append("workflow contract tests do not parameterize the central supported-kind set")

    # Serializer must accept every supported kind in a minimal valid workflow where a canonical
    # minimal config is available. The full behavior matrix lives in the pytest contract test.
    if set(contract_gate_snapshot()) != set(WORKFLOW_NODE_CONTRACTS):
        errors.append("contract snapshot drifted from contract registry")

    report = {
        "schema": "arenyxa.workflow-contract-gate/v1",
        "producer_kinds": sorted(producer_kinds),
        "supported_kinds": sorted(SUPPORTED_WORKFLOW_NODE_KINDS),
        "runtime_kinds": sorted(runtime_kinds),
        "producer_files": {key: sorted(value) for key, value in sorted(producer_files.items())},
        "contracts": contract_gate_snapshot(),
        "errors": errors,
        "passed": not errors,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
