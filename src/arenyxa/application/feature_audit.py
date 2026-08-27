from __future__ import annotations

from dataclasses import field
from arenyxa.compat import dataclass
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class FeatureContract:
    







    feature_id: str
    label: str
    root: str
    methods: tuple[str, ...]


@dataclass(slots=True)
class FeatureAuditIssue:
    feature_id: str
    label: str
    missing: list[str] = field(default_factory=list)
    detail: str = ""


@dataclass(slots=True)
class FeatureAuditReport:
    checked: int
    issues: list[FeatureAuditIssue]

    @property
    def healthy(self) -> bool:
        return not self.issues

    @property
    def implemented(self) -> int:
        return self.checked - len(self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "checked": self.checked,
            "implemented": self.implemented,
            "issues": [
                {
                    "feature_id": issue.feature_id,
                    "label": issue.label,
                    "missing": list(issue.missing),
                    "detail": issue.detail,
                }
                for issue in self.issues
            ],
        }


                                                                                              
                                                                                           
                                            
ADVANCED_FEATURE_CONTRACTS: tuple[FeatureContract, ...] = (
    FeatureContract("workflow.engine", "Workflow Engine", "workflows", ("execute",)),
    FeatureContract(
        "workflow.dataset_runtime",
        "Dataset Workflow Runtime",
        "workflow_runtime",
        ("execute_saved_workflow", "execute_revision", "resume_execution"),
    ),
    FeatureContract(
        "data.lineage",
        "Dataset & Data Lineage",
        "lineage",
        ("create_dataset", "materialize_from_runs", "record_derivation", "graph"),
    ),
    FeatureContract("automation.scheduler", "Automation Scheduler", "scheduler", ("add", "set_enabled", "remove")),
    FeatureContract("network.capture", "Network Capture", "capture", ("prepare", "start", "pause", "resume", "stop")),
    FeatureContract("plugins.manager", "Plugin Manager", "plugins", ("discover", "inspect_install")),
    FeatureContract("plugins.sandbox", "Plugin Sandbox", "plugin_sandbox", ("invoke",)),
    FeatureContract("studio.selector", "Selector Studio / Self-Healing", "nextgen.selector", ("analyze", "heal", "heal_with_policy")),
    FeatureContract(
        "studio.recorder",
        "Browser Recorder 2.0",
        "nextgen.recorder",
        ("normalize", "to_workflow", "compile_semantics", "to_semantic_workflow", "execute_playwright", "record_live", "to_playwright"),
    ),
    FeatureContract(
        "studio.http",
        "HTTP Request Workbench",
        "nextgen.request",
        ("send", "send_with_assertions", "apply_variables", "apply_actions"),
    ),
    FeatureContract("studio.protocols", "GraphQL / WebSocket / SSE Inspector", "nextgen.protocols", ("graphql", "websocket", "sse")),
    FeatureContract("studio.sources", "Data Source Discovery", "nextgen.sources", ("discover",)),
    FeatureContract("studio.smartpath", "SmartPath 2.0", "nextgen.smartpath", ("analyze",)),
    FeatureContract("studio.web_intelligence", "Web Intelligence Center", "nextgen.web_intelligence", ("analyze", "replay_candidates", "event_to_workflow")),
    FeatureContract("studio.time_machine", "Web Time Machine Linkage", "nextgen.time_machine", ("record", "history")),
    FeatureContract("studio.quality", "Data Quality Studio", "nextgen.quality", ("analyze", "clean", "compare_schema")),
    FeatureContract("studio.secrets", "Secrets Vault", "nextgen.vault", ("set", "get", "delete", "names")),
    FeatureContract("studio.project_env", "Project Environment", "nextgen.projects", ("ensure", "save_environment", "load_environment")),
    FeatureContract("studio.variables", "Workflow Variables", "nextgen.variables", ("resolve",)),
    FeatureContract("studio.templates", "Workflow Template Library", "nextgen.templates", ("templates",)),
    FeatureContract("studio.activity", "Activity Center", "nextgen.activity", ("publish", "snapshot", "subscribe")),
    FeatureContract(
        "studio.python_env",
        "Project Python Environment",
        "nextgen.python_envs",
        ("status", "create", "run", "install", "freeze"),
    ),
    FeatureContract(
        "studio.workers",
        "Distributed Workers",
        "nextgen.workers",
        ("list", "upsert", "health", "remote_tasks", "remote_runs", "run_task", "partition"),
    ),
    FeatureContract("studio.browser_profiles", "Browser Profiles", "nextgen.browser_profiles", ("save", "load", "export_metadata")),
    FeatureContract("studio.marketplace", "Workflow Marketplace", "nextgen.marketplace", ("load_catalog", "install")),
    FeatureContract("studio.regression", "Regression Lab", "nextgen.regression", ("create_baseline", "compare")),
    FeatureContract("studio.intelligence", "Explainable Web Intelligence", "nextgen.intelligence", ("analyze",)),
    FeatureContract(
        "studio.context_bridge",
        "Context Bridge",
        "nextgen.context_bridge",
        ("event_to_request", "request_to_workflow", "event_bundle"),
    ),
    FeatureContract("studio.portability", "Workflow Portability", "nextgen.portability", ("export", "dumps", "load", "secret_findings")),
    FeatureContract("studio.compatibility", "Compatibility Lab", "nextgen.compatibility", ("run", "default_cases")),
    FeatureContract("studio.reliability", "Reliability Advisor", "nextgen.reliability", ("assess",)),
    FeatureContract(
        "studio.autopilot",
        "Autopilot Learning",
        "nextgen.autopilot",
        ("analyze", "record_strategy_outcome", "rank_selector_candidates", "record_selector_outcome"),
    ),
)


def _resolve(root: object, dotted: str) -> object:
    current = root
    for part in dotted.split("."):
        if not hasattr(current, part):
            raise AttributeError(part)
        current = getattr(current, part)
    return current


def audit_advanced_features(context: object, contracts: Iterable[FeatureContract] = ADVANCED_FEATURE_CONTRACTS) -> FeatureAuditReport:
    





    checked = 0
    issues: list[FeatureAuditIssue] = []
    for contract in tuple(contracts):
        checked += 1
        missing: list[str] = []
        try:
            service = _resolve(context, contract.root)
        except (AttributeError, RuntimeError) as exc:
            issues.append(
                FeatureAuditIssue(
                    contract.feature_id,
                    contract.label,
                    [contract.root],
                    f"Backing service is not wired: {exc}",
                )
            )
            continue
        for method in contract.methods:
            candidate = getattr(service, method, None)
            if not callable(candidate):
                missing.append(method)
        if missing:
            issues.append(
                FeatureAuditIssue(
                    contract.feature_id,
                    contract.label,
                    missing,
                    "Required runtime methods are missing or not callable.",
                )
            )
    return FeatureAuditReport(checked=checked, issues=issues)
