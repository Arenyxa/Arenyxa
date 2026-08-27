from __future__ import annotations

import ast
from dataclasses import fields
from pathlib import Path

from arenyxa.application.feature_audit import ADVANCED_FEATURE_CONTRACTS, audit_advanced_features
from arenyxa.application.nextgen import NextGenFeatureHub
from arenyxa.bootstrap import bootstrap


def test_all_nextgen_hub_services_have_explicit_feature_contracts() -> None:
    hub_fields = {item.name for item in fields(NextGenFeatureHub)}
    contracted = {
        contract.root.split(".", 1)[1]
        for contract in ADVANCED_FEATURE_CONTRACTS
        if contract.root.startswith("nextgen.")
    }
    assert contracted == hub_fields


def test_bootstrapped_advanced_feature_wiring_is_complete(tmp_path: Path) -> None:
    context = bootstrap(tmp_path / "data")
    try:
        report = audit_advanced_features(context)
        assert report.checked == len(ADVANCED_FEATURE_CONTRACTS)
        assert report.implemented == report.checked
        assert report.healthy, report.to_dict()
    finally:
        context.shutdown()


def test_advanced_runtime_modules_do_not_contain_placeholder_implementations() -> None:
    root = Path(__file__).resolve().parents[1] / "src" / "arenyxa" / "application"
    modules = (
        "advanced.py",
        "nextgen.py",
        "autopilot.py",
        "workflows.py",
        "workflow_runtime.py",
        "data_lineage.py",
        "competitive.py",
        "runtime_ecosystem.py",
    )
    violations: list[str] = []
    for name in modules:
        path = root / name
        if not path.exists():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                violations.append(f"{name}:{node.lineno}:{node.name}: pass")
            for child in ast.walk(node):
                if not isinstance(child, ast.Raise) or child.exc is None:
                    continue
                call = child.exc if isinstance(child.exc, ast.Call) else None
                if call is not None and isinstance(call.func, ast.Name) and call.func.id == "NotImplementedError":
                    violations.append(f"{name}:{node.lineno}:{node.name}: NotImplementedError")
    assert violations == []


def test_studio_exposes_expected_advanced_workspaces() -> None:
    root = Path(__file__).resolve().parents[1]
    source = "\n".join((root / rel).read_text(encoding="utf-8") for rel in (
        "src/arenyxa/presentation/pages/studio.py",
        "src/arenyxa/presentation/pages/studio_intelligence.py",
        "src/arenyxa/presentation/pages/studio_operations.py",
    ))
    expected = {
        "SmartPath & Data Sources",
        "Explainable Blueprint",
        "Selector Studio",
        "HTTP Request Builder",
        "Protocol Inspector",
        "Data Quality Studio",
        "Browser Recorder 2.0",
        "Workflow Debugger",
        "Secrets Vault",
        "Templates & Project Environment",
        "Profiles & Marketplace",
        "Distributed Workers",
        "Compatibility Lab",
        "Workflow Portability",
        "Autopilot Learning",
        "Live Run & Activity Center",
    }
    missing = sorted(label for label in expected if label not in source)
    assert missing == []
