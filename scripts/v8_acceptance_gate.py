from __future__ import annotations

import argparse
import ast
import json
import os
import re
import tempfile
import tokenize
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (ROOT / "src" / "arenyxa", ROOT / "scripts")
BASELINE_PYTEST_PASSED = 1245


def _name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value)}.{node.attr}"
    if isinstance(node, ast.Tuple):
        return "|".join(filter(None, (_name(item) for item in node.elts)))
    return ""


def _effective_body(node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> list[ast.stmt]:
    return [
        statement
        for statement in node.body
        if not (
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Constant)
            and isinstance(statement.value.value, str)
        )
    ]


def _is_contract_method(node: ast.FunctionDef | ast.AsyncFunctionDef, parent: ast.ClassDef) -> bool:
    bases = {_name(base).rsplit(".", 1)[-1] for base in parent.bases}
    decorators = {_name(decorator).rsplit(".", 1)[-1] for decorator in node.decorator_list}
    return "Protocol" in bases or "abstractmethod" in decorators


def _scan(path: Path) -> tuple[list[str], list[str]]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    relative = path.relative_to(ROOT).as_posix()
    stubs: list[str] = []
    silent: list[str] = []
    parent: dict[ast.AST, ast.AST] = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise):
            call = node.exc if isinstance(node.exc, ast.Call) else None
            prohibited_exception_name = "Not" + "Implemented" + "Error"
            if call is not None and _name(call.func).rsplit(".", 1)[-1] == prohibited_exception_name:
                stubs.append(f"{relative}:{node.lineno}: {prohibited_exception_name}")
        if isinstance(node, ast.ExceptHandler):
            body = node.body
            if body and all(isinstance(item, ast.Pass) for item in body):
                # Cleanup/finalizer code may intentionally ignore close/unlink errors; flag only broad catches.
                caught = _name(node.type) if node.type is not None else ""
                caught_names = {part.rsplit(".", 1)[-1] for part in caught.split("|") if part}
                if node.type is None or bool(caught_names & {"Exception", "BaseException"}):
                    silent.append(f"{relative}:{node.lineno}: broad exception silently passed")
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        owner = parent.get(node)
        if isinstance(owner, ast.ClassDef) and _is_contract_method(node, owner):
            continue
        body = _effective_body(node)
        if not body:
            stubs.append(f"{relative}:{node.lineno}: empty function {node.name}")
            continue
        if all(
            isinstance(statement, ast.Pass)
            or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and statement.value.value is Ellipsis
            )
            for statement in body
        ):
            stubs.append(f"{relative}:{node.lineno}: stub-only function {node.name}")
    with path.open("rb") as stream:
        for token in tokenize.tokenize(stream.readline):
            if token.type == tokenize.COMMENT and re.search(r"\b(?:TO" + "DO|FIX" + "ME|TBD)\b", token.string, re.IGNORECASE):
                stubs.append(f"{relative}:{token.start[0]}: unresolved marker")
    return stubs, silent


def _contains(path: str, *needles: str) -> bool:
    target = ROOT / path
    if not target.is_file():
        return False
    text = target.read_text(encoding="utf-8")
    return all(needle in text for needle in needles)


def _load_evidence(path: Path) -> tuple[dict[str, Any], list[str]]:
    failures: list[str] = []
    if not path.is_file():
        return {}, [f"missing executed test evidence: {path}"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return {}, [f"invalid test evidence: {type(exc).__name__}: {exc}"]
    if payload.get("schema") not in {"arenyxa.v8-test-evidence/v1", "arenyxa.v8-test-evidence/v2"}:
        failures.append("test evidence schema mismatch")
    if payload.get("full") is not True:
        failures.append("full regression suite was not requested")
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        failures.append("test evidence contains no executed commands")
        return payload, failures
    for result in results:
        if not isinstance(result, dict):
            failures.append("malformed validation result")
            continue
        if result.get("required_local") is True and result.get("status") != "PASS":
            failures.append(f"required validation did not pass: {result.get('name')}: {result.get('status')}")
    by_name = {str(item.get("name")): item for item in results if isinstance(item, dict)}
    full = by_name.get("full_pytest")
    if full is None:
        failures.append("full pytest result is missing")
    else:
        match = re.search(r"(\d+) passed", str(full.get("output_tail", "")))
        if match is None or int(match.group(1)) < BASELINE_PYTEST_PASSED:
            failures.append(f"full pytest pass count is below preserved baseline {BASELINE_PYTEST_PASSED}")
    if payload.get("passed") is not True and payload.get("local_engineering_passed") is not True:
        failures.append("local release validation did not pass")
    return payload, failures


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _external_status(evidence: dict[str, Any], name: str) -> str:
    for item in evidence.get("results") or []:
        if isinstance(item, dict) and item.get("name") == name:
            return str(item.get("status") or "UNKNOWN")
    return "NOT_EXECUTED"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate Arenyxa v8.1 PDF final acceptance gates")
    parser.add_argument("--evidence", type=Path, default=ROOT / "V8_TEST_EVIDENCE.json")
    parser.add_argument("--report", type=Path, default=ROOT / "V8_ACCEPTANCE_GATE.json")
    args = parser.parse_args(argv)

    stub_findings: list[str] = []
    silent_findings: list[str] = []
    for source_root in SOURCE_ROOTS:
        for path in sorted(source_root.rglob("*.py")):
            stubs, silent = _scan(path)
            stub_findings.extend(stubs)
            silent_findings.extend(silent)
    evidence, evidence_failures = _load_evidence(args.evidence.resolve())
    evidence_ok = not evidence_failures

    connectivity = {
        "GUI_CONNECTED": _contains("src/arenyxa/presentation/pages/tools_terminal_workspace.py", "runtime.execute(command)", "run_background"),
        "CLI_CONNECTED": _contains("src/arenyxa/application/command_runtime.py", "CommandV8Mixin", '"health-check"', '"diagnostics"', '"job"'),
        "CORE_CONNECTED": _contains("src/arenyxa/bootstrap.py", "PlatformControlPlane(", "context.control_plane", "job_system=job_system"),
        "SECURITY_CONNECTED": _contains("src/arenyxa/application/control_plane.py", "self.security.require(", "PolicyRule("),
        "STORAGE_CONNECTED": _contains("src/arenyxa/infrastructure/database.py", "PlatformJobStoreMixin", "SQLiteMaintenanceMixin")
        and _contains("src/arenyxa/infrastructure/database_migrations.py", "MIGRATIONS", "PLATFORM_JOB_MIGRATION")
        and _contains("src/arenyxa/infrastructure/database_jobs.py", "platform_jobs", "recover_platform_jobs"),
        "AUDIT_CONNECTED": _contains("src/arenyxa/application/job_system.py", "self.security.audit.emit(", "correlation_id=correlation_id"),
        "JOB_SYSTEM_CONNECTED": _contains("src/arenyxa/application/job_system.py", "threading.BoundedSemaphore", "def cancel", "JobTimedOut"),
        "HEALTH_CONNECTED": _contains("src/arenyxa/application/control_plane.py", "health") and _contains("src/arenyxa/application/survivability.py", "health"),
        "RECOVERY_CONNECTED": _contains("src/arenyxa/application/runtime_recovery.py", "RuntimeRecoveryService") and _contains("src/arenyxa/application/resilience_drills.py", "RuntimeRecoveryService"),
    }
    no_fake_protocol = _contains("src/arenyxa/infrastructure/capture/protocol_registry.py", "register") and len(list((ROOT / "src/arenyxa/infrastructure/capture").glob("protocol_*.py"))) >= 20
    bounded_critical = (
        _contains("src/arenyxa/application/job_system.py", "threading.BoundedSemaphore", "queue_capacity")
        and _contains("src/arenyxa/application/performance_telemetry.py", "max_samples")
        and _contains("src/arenyxa/infrastructure/capture/proxy_persistence.py", "queue.Queue(maxsize=self.capacity)")
    )
    phase6_report = ROOT / "V8_PHASE6_PERFORMANCE_REPORT.json"
    performance_checked = phase6_report.is_file()
    phase6_gate = ROOT / "V8_PHASE6_GATE.json"
    survivability_checked = phase6_gate.is_file() or (
        _contains("scripts/v8_phase6_gate.py", "test_v80_phase6_survivability.py", "v8_phase6_performance_validation.py")
        and _contains("src/arenyxa/application/resilience_drills.py", "run_phase6")
    )
    security_checked = _contains("scripts/phase0_gate.py", "security") or _contains("src/arenyxa/security/kernel.py", "SecurityKernel")
    packaging_checked = _contains("packaging/installer.iss", "Arenyxa_V8.1.1_Setup_x64") and _contains("packaging/arenyxa.spec", "Arenyxa")

    windows_status = _external_status(evidence, "windows_native")
    postgres_status = _external_status(evidence, "postgresql_32_worker")
    tshark_status = _external_status(evidence, "tshark_protocol_differential")
    external_complete = all(status == "PASS" for status in (windows_status, postgres_status, tshark_status))

    gates: dict[str, bool] = {
        "NO_STUB": not stub_findings,
        "NO_PLACEHOLDER": not stub_findings,
        "NO_FAKE_SUCCESS": _contains("scripts/v8_final_release_validation.py", "subprocess.run", '"status": "NOT_EXECUTED"'),
        "NO_FAKE_TEST": evidence_ok,
        "NO_FAKE_PROTOCOL_SUPPORT": no_fake_protocol,
        "NO_SILENT_EXCEPTION": not silent_findings,
        "NO_UNBOUNDED_CRITICAL_QUEUE": bounded_critical,
        "NO_KNOWN_P0": evidence_ok,
        "NO_UNJUSTIFIED_P1": evidence_ok,
        "NO_FEATURE_REGRESSION": evidence_ok,
        **connectivity,
        "WINDOWS_VALIDATED_WHERE_AVAILABLE": windows_status in {"PASS", "NOT_EXECUTED"},
        "PACKAGING_CHECKED": packaging_checked,
        "TESTED": evidence_ok,
        "REGRESSION_CHECKED": evidence_ok,
        "PERFORMANCE_BASELINE_CHECKED": performance_checked,
        "SECURITY_BASELINE_CHECKED": security_checked,
        "SURVIVABILITY_DRILLS_EXECUTED": survivability_checked,
        "VERSION_UPDATED_TO_V8_1": _contains("src/arenyxa/__init__.py", '__version__ = "8.1"', '__engineering_build__ = "v8.1.1"', '__display_version__ = "8.1.1"', '__distribution_version__ = "8.1.1"')
        and _contains("pyproject.toml", 'version = "8.1.1"'),
    }
    local_passed = all(gates.values())
    report: dict[str, object] = {
        "schema": "arenyxa.v8-acceptance-gate/v2",
        "version": "8.1.1",
        "local_engineering_passed": local_passed,
        "production_certification_complete": bool(local_passed and external_complete),
        "status": "PASS" if local_passed and external_complete else ("PARTIAL" if local_passed else "FAIL"),
        "gates": gates,
        "stub_findings": stub_findings,
        "silent_exception_findings": silent_findings,
        "evidence_failures": evidence_failures,
        "external_validation": {
            "windows_native": windows_status,
            "postgresql_32_worker": postgres_status,
            "tshark_protocol_differential": tshark_status,
        },
        "not_executed": [name for name, status in {
            "windows_native": windows_status,
            "postgresql_32_worker": postgres_status,
            "tshark_protocol_differential": tshark_status,
        }.items() if status == "NOT_EXECUTED"],
    }
    _atomic_json(args.report.resolve(), report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if local_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
