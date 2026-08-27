from __future__ import annotations

"""Auditable Phase 1 architecture, lifecycle, dependency and failure contracts.

This module is deliberately descriptive rather than a second runtime.  It gives tests,
review tooling and later phases one canonical place to ask who owns a subsystem, which
layers it may depend on, and what a failure is allowed to do.
"""

import ast
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from arenyxa.compat import dataclass


LIFECYCLE_SEQUENCE = (
    "create",
    "start",
    "pause",
    "resume",
    "terminal",
    "persist",
    "recover",
    "dispose",
)


@dataclass(frozen=True, slots=True)
class ComponentContract:
    key: str
    owner: str
    module_prefixes: tuple[str, ...]
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    lifecycle: tuple[str, ...]
    failure_boundary: str
    may_depend_on: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FailureRule:
    category: str
    disposition: str
    retryable: bool
    rollback_required: bool
    invariant: str


@dataclass(frozen=True, slots=True)
class CompatibilityContract:
    name: str
    kind: str
    contract: str
    compatibility_level: str


CORE_COMPONENTS: tuple[ComponentContract, ...] = (
    ComponentContract(
        "run",
        "RunOrchestrator",
        ("arenyxa.application.runner",),
        ("Task", "RequestSpec", "PerformancePolicy", "CancellationToken"),
        ("Run", "ResultRecord", "progress events", "persisted run state"),
        LIFECYCLE_SEQUENCE,
        "A run may retry idempotent transport work, but state transitions must remain durable and explainable.",
        ("domain", "infrastructure.http_client", "infrastructure.database", "performance"),
    ),
    ComponentContract(
        "workflow",
        "WorkflowEngine / WorkflowDatasetService",
        ("arenyxa.application.workflows", "arenyxa.application.workflow_runtime"),
        ("Workflow", "DatasetRevision", "fixtures/context"),
        ("workflow result", "DatasetRevision", "lineage", "checkpoint state"),
        LIFECYCLE_SEQUENCE,
        "Workflow execution owns checkpoint and output consistency; replay must not duplicate non-idempotent effects.",
        ("domain", "application.data_lineage", "infrastructure.database"),
    ),
    ComponentContract(
        "dataset",
        "DatasetVersionService / DataLineageService",
        ("arenyxa.application.versioning", "arenyxa.application.data_lineage"),
        ("records", "parent revision", "source run ids"),
        ("DatasetRevision", "lineage edges", "schema metadata"),
        LIFECYCLE_SEQUENCE,
        "A revision is either complete and attributable or absent; half-persisted lineage is recoverable evidence debt.",
        ("domain", "infrastructure.database", "infrastructure.atomic_io"),
    ),
    ComponentContract(
        "capture",
        "CaptureController",
        ("arenyxa.infrastructure.capture",),
        ("capture adapter", "CaptureSession", "filters"),
        ("NetworkEvent", "body references", "capture statistics"),
        LIFECYCLE_SEQUENCE,
        "Capture may drop bounded events under explicit pressure, but must finalize state and disclose drops.",
        ("domain", "infrastructure.database", "infrastructure.atomic_io"),
    ),
    ComponentContract(
        "recovery",
        "RuntimeRecoveryService",
        ("arenyxa.application.runtime_recovery",),
        ("durable runtime state", "failure fingerprint"),
        ("recovery decision", "reconciled state", "diagnostic history"),
        ("create", "start", "persist", "recover", "dispose"),
        "Recovery repairs only states with defined invariants; corruption and ambiguity terminate with diagnostics.",
        ("domain", "infrastructure.database", "infrastructure.atomic_io"),
    ),
    ComponentContract(
        "plugin",
        "PluginManager / PluginSandbox",
        ("arenyxa.infrastructure.plugins", "arenyxa.infrastructure.plugin_worker"),
        ("plugin manifest", "declared capability", "isolated request"),
        ("bounded plugin result", "health/failure status"),
        LIFECYCLE_SEQUENCE,
        "Plugin faults are isolated from the host; undeclared filesystem/network access is rejected rather than hidden.",
        ("domain", "infrastructure.atomic_io", "platform_compat"),
    ),
    ComponentContract(
        "storage",
        "SQLiteStore / atomic_io",
        ("arenyxa.infrastructure.database", "arenyxa.infrastructure.atomic_io"),
        ("validated domain data", "transaction intent"),
        ("durable rows/files", "transaction result"),
        ("create", "start", "persist", "recover", "dispose"),
        "Storage owns atomicity and durability. Callers must not report success before durable commit.",
        ("domain", "compat", "platform_compat"),
    ),
    ComponentContract(
        "ui_shell",
        "MainWindow / presentation pages",
        ("arenyxa.presentation",),
        ("ApplicationContext services", "immutable/read-only view models"),
        ("user intent", "presentation state"),
        ("create", "start", "pause", "resume", "terminal", "dispose"),
        "UI is presentation only; hiding a control is never authorization and UI failures must not mutate durable truth silently.",
        ("application", "domain", "presentation", "selected service adapters"),
    ),
)


FAILURE_RULES: tuple[FailureRule, ...] = (
    FailureRule("transient", "retry", True, False, "Retries are bounded, cancellable and idempotency-aware."),
    FailureRule("recoverable", "recover", False, True, "Restore the last durable invariant before exposing success."),
    FailureRule("configuration", "reject", False, False, "Reject before side effects and explain which configuration is invalid."),
    FailureRule("permission", "reject", False, False, "Deny in the backend; UI visibility cannot grant capability."),
    FailureRule("corruption", "terminate", False, True, "Stop mutation, preserve evidence and require a verified recovery path."),
    FailureRule("fatal", "terminate", False, False, "Fail closed, finalize owned resources and preserve diagnostics."),
)


COMPATIBILITY_CONTRACTS: tuple[CompatibilityContract, ...] = (
    CompatibilityContract("arenyxa", "python-package", "Public facade remains importable and re-exports version metadata.", "7.0"),
    CompatibilityContract("arenyxa", "legacy-python-package", "Historical implementation namespace remains importable through v7.0.", "7.0"),
    CompatibilityContract("arenyxa", "cli", "arenyxa -> arenyxa.app:main", "7.0"),
    CompatibilityContract("arenyxa", "legacy-cli", "arenyxa -> arenyxa.app:main", "7.0"),
    CompatibilityContract("arenyxa-server", "cli", "arenyxa-server -> arenyxa.infrastructure.server:main", "7.0"),
    CompatibilityContract("plugin-api", "plugin", "Existing manifest/API compatibility comparator remains at 6.8.0 unless explicitly migrated.", "6.8.0"),
)


                                                                                       
                                                                                        
                                                  
_FORBIDDEN_LAYER_EDGES: Mapping[str, tuple[str, ...]] = {
    "domain": ("arenyxa.application", "arenyxa.infrastructure", "arenyxa.presentation"),
    "application": ("arenyxa.presentation",),
    "infrastructure": ("arenyxa.presentation",),
}

                                                                                              
                                                                                               
_FORBIDDEN_PRESENTATION_IMPORTS = ("arenyxa.infrastructure.database",)


def component(key: str) -> ComponentContract:
    for item in CORE_COMPONENTS:
        if item.key == key:
            return item
    raise KeyError(key)


def failure_rule(category: str) -> FailureRule:
    folded = category.casefold().strip()
    for item in FAILURE_RULES:
        if item.category == folded:
            return item
    raise KeyError(category)


def _imports(path: Path) -> Iterable[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module


def validate_dependency_rules(source_root: Path) -> list[str]:
    

    source_root = Path(source_root)
    package_root = source_root / "arenyxa" if (source_root / "arenyxa").is_dir() else source_root
    violations: list[str] = []
    for path in sorted(package_root.rglob("*.py")):
        rel = path.relative_to(package_root)
        if not rel.parts:
            continue
        layer = rel.parts[0] if rel.parts[0] in _FORBIDDEN_LAYER_EDGES else ""
        try:
            imported = tuple(_imports(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            violations.append(f"{rel}: parse failed: {exc}")
            continue
        for prefix in _FORBIDDEN_LAYER_EDGES.get(layer, ()):
            if any(name == prefix or name.startswith(prefix + ".") for name in imported):
                violations.append(f"{rel}: forbidden dependency {layer} -> {prefix}")
        if layer == "presentation":
            for prefix in _FORBIDDEN_PRESENTATION_IMPORTS:
                if any(name == prefix or name.startswith(prefix + ".") for name in imported):
                    violations.append(f"{rel}: presentation must not import persistence implementation {prefix}")
    return violations


def lifecycle_is_ordered(states: Sequence[str]) -> bool:
    

    order = {name: index for index, name in enumerate(LIFECYCLE_SEQUENCE)}
    highest = -1
    for state in states:
        if state not in order:
            return False
        index = order[state]
                                                                  
        if state in {"pause", "resume"} and highest <= order["resume"]:
            highest = max(highest, index)
            continue
        if index < highest:
            return False
        highest = index
    return True
