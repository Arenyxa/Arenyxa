from __future__ import annotations

"""Deterministic Phase-3 Workflow Test Lab.

The lab never mutates Dataset/Workflow execution state. It validates a workflow in-memory,
runs bounded fixtures, can replace an ``http`` node handler with explicit local mocks, and
compares outputs against canonical golden data for reproducible regression suites.
"""

import hashlib
import json
from dataclasses import asdict, field
from typing import Any, Callable, Iterable, Mapping, Sequence

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import Workflow
from arenyxa.application.workflows import WorkflowEngine, WorkflowResult


@dataclass(frozen=True, slots=True)
class WorkflowFixture:
    name: str
    inputs: tuple[dict[str, Any], ...]
    scopes: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    mock_http: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    expected_outputs: tuple[dict[str, Any], ...] | None = None
    expected_error_count: int | None = None


@dataclass(frozen=True, slots=True)
class WorkflowDryRunReport:
    valid: bool
    node_count: int
    root_nodes: tuple[str, ...]
    terminal_nodes: tuple[str, ...]
    missing_handlers: tuple[str, ...]
    unresolved_variable_refs: tuple[str, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WorkflowFixtureResult:
    name: str
    passed: bool
    output_hash: str
    output_count: int
    error_count: int
    differences: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WorkflowRegressionReport:
    passed: bool
    cases: tuple[WorkflowFixtureResult, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"passed": self.passed, "cases": [item.to_dict() for item in self.cases]}


class WorkflowTestLab:
    MAX_FIXTURE_INPUTS = 10_000
    MAX_GOLDEN_BYTES = 16 * 1024 * 1024

    def __init__(self, engine: WorkflowEngine) -> None:
        self.engine = engine

    @staticmethod
    def _canonical_outputs(outputs: Sequence[Mapping[str, Any]]) -> bytes:
        raw = json.dumps(list(outputs), ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        if len(raw) > WorkflowTestLab.MAX_GOLDEN_BYTES:
            raise ArenyxaError(
                "WORKFLOW_GOLDEN_TOO_LARGE",
                "工作流 Golden Output 超过 16 MiB 安全上限。",
                domain="WORKFLOW",
            )
        return raw

    @classmethod
    def golden_hash(cls, outputs: Sequence[Mapping[str, Any]]) -> str:
        return hashlib.sha256(cls._canonical_outputs(outputs)).hexdigest()

    def dry_run(
        self,
        workflow: Workflow,
        *,
        scopes: Mapping[str, Mapping[str, Any]] | None = None,
        secret_resolver: Callable[[str], str | None] | None = None,
    ) -> WorkflowDryRunReport:
        if not workflow.nodes:
            return WorkflowDryRunReport(False, 0, (), (), (), (), ("workflow-empty",))
        nodes = {node.id: node for node in workflow.nodes if isinstance(node.id, str) and node.id}
        if len(nodes) != len(workflow.nodes):
            return WorkflowDryRunReport(False, len(workflow.nodes), (), (), (), (), ("duplicate-or-invalid-node-id",))

        incoming: dict[str, int] = {node_id: 0 for node_id in nodes}
        warnings: list[str] = []
        for node in workflow.nodes:
            for child in node.next_ids + node.failure_ids:
                if child not in nodes:
                    warnings.append(f"missing-edge-target:{node.id}->{child}")
                else:
                    incoming[child] += 1
        roots = tuple(node_id for node_id, count in incoming.items() if count == 0)
        terminals = tuple(node.id for node in workflow.nodes if not node.next_ids and not node.failure_ids)
        if not roots:
            warnings.append("no-root-or-cycle")
        if not terminals:
            warnings.append("no-terminal-node")
        missing_handlers = tuple(sorted({node.kind for node in workflow.nodes if node.kind not in self.engine.handlers and node.kind != "http"}))

        unresolved: set[str] = set()
        effective_scopes = scopes or {}

        def scan(value: Any) -> None:
            if isinstance(value, str):
                for match in self.engine._VARIABLE.finditer(value):                                                  
                    scope, key = match.group(1), match.group(2)
                    if scope == "secret":
                        resolved = secret_resolver(key) if secret_resolver is not None else None
                    else:
                        resolved = effective_scopes.get(scope, {}).get(key)
                    if resolved is None:
                        unresolved.add(f"{scope}.{key}")
            elif isinstance(value, Mapping):
                for item in value.values():
                    scan(item)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    scan(item)

        for node in workflow.nodes:
            scan(node.config)
        if unresolved:
            warnings.append("unresolved-variables")
        valid = not missing_handlers and not unresolved and not any(
            item.startswith("missing-edge-target") or item == "no-root-or-cycle" for item in warnings
        )
        return WorkflowDryRunReport(
            valid,
            len(workflow.nodes),
            roots,
            terminals,
            missing_handlers,
            tuple(sorted(unresolved)),
            tuple(warnings),
        )

    @staticmethod
    def _mock_http_handler(mock_http: Mapping[str, Mapping[str, Any]]) -> Callable[[dict[str, Any], dict[str, Any]], Iterable[dict[str, Any]]]:
        safe = {str(key): dict(value) for key, value in mock_http.items()}

        def handler(item: dict[str, Any], config: dict[str, Any]) -> Iterable[dict[str, Any]]:
            key = str(config.get("mock_key") or config.get("url") or "")
            if not key or key not in safe:
                raise ArenyxaError(
                    "WORKFLOW_HTTP_MOCK_MISSING",
                    "Workflow Test Lab 拒绝真实 HTTP：当前 http 节点没有对应 mock。",
                    domain="WORKFLOW",
                    context={"mock_key": key},
                )
            response = dict(safe[key])
            return [{**item, **response}]

        return handler

    def run_fixture(
        self,
        workflow: Workflow,
        fixture: WorkflowFixture,
        *,
        secret_resolver: Callable[[str], str | None] | None = None,
    ) -> WorkflowFixtureResult:
        if len(fixture.inputs) > self.MAX_FIXTURE_INPUTS:
            raise ArenyxaError(
                "WORKFLOW_FIXTURE_TOO_LARGE",
                f"Workflow fixture 输入超过 {self.MAX_FIXTURE_INPUTS} 条安全上限。",
                domain="WORKFLOW",
            )
        dry = self.dry_run(workflow, scopes=fixture.scopes, secret_resolver=secret_resolver)
        if not dry.valid:
            return WorkflowFixtureResult(
                fixture.name,
                False,
                "",
                0,
                0,
                tuple(dry.warnings + dry.missing_handlers + dry.unresolved_variable_refs),
            )

                                                                                                 
        test_engine = WorkflowEngine(buffer_size=self.engine.buffer_size)
        test_engine.handlers = dict(self.engine.handlers)
        if any(node.kind == "http" for node in workflow.nodes):
            test_engine.register("http", self._mock_http_handler(fixture.mock_http))
        result: WorkflowResult = test_engine.execute(
            workflow,
            [dict(item) for item in fixture.inputs],
            scopes=fixture.scopes,
            secret_resolver=secret_resolver,
        )
        differences: list[str] = []
        if fixture.expected_outputs is not None:
            actual = self._canonical_outputs(result.outputs)
            expected = self._canonical_outputs(fixture.expected_outputs)
            if actual != expected:
                differences.append(
                    f"golden-output-mismatch expected={hashlib.sha256(expected).hexdigest()} actual={hashlib.sha256(actual).hexdigest()}"
                )
        expected_error_count = 0 if fixture.expected_error_count is None else fixture.expected_error_count
        if len(result.errors) != expected_error_count:
            differences.append(
                f"error-count expected={expected_error_count} actual={len(result.errors)}"
            )
        return WorkflowFixtureResult(
            fixture.name,
            not differences,
            self.golden_hash(result.outputs),
            len(result.outputs),
            len(result.errors),
            tuple(differences),
        )

    def run_suite(
        self,
        workflow: Workflow,
        fixtures: Sequence[WorkflowFixture],
        *,
        secret_resolver: Callable[[str], str | None] | None = None,
    ) -> WorkflowRegressionReport:
        if len(fixtures) > 1000:
            raise ArenyxaError("WORKFLOW_SUITE_TOO_LARGE", "Workflow regression suite 超过 1000 个 case。", domain="WORKFLOW")
        cases = tuple(self.run_fixture(workflow, fixture, secret_resolver=secret_resolver) for fixture in fixtures)
        return WorkflowRegressionReport(all(case.passed for case in cases), cases)
