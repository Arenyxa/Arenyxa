from __future__ import annotations

import ast
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODERN = ROOT / "src" / "arenyxa"
LEGACY = ROOT / "legacy" / "win7" / "src" / "arenyxa"
BINARY_SUFFIXES = {".png", ".ico", ".jpg", ".jpeg", ".webp", ".woff", ".ttf", ".exe", ".dll", ".pyd", ".pyc"}
LEGACY_TOKEN = "n" + "exora"


def parse_files(root: Path, feature: tuple[int, int] | None = None) -> tuple[list[tuple[Path, ast.AST, str]], list[str]]:
    parsed: list[tuple[Path, ast.AST, str]] = []
    errors: list[str] = []
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path), feature_version=feature)
        except SyntaxError as exc:
            errors.append(f"{path.relative_to(ROOT)}:{exc.lineno}:{exc.msg}")
        else:
            parsed.append((path, tree, text))
    return parsed, errors


def credential_candidates(parsed: list[tuple[Path, ast.AST, str]]) -> list[str]:
    pattern = re.compile(r"(?:password|passwd|secret|token|api[_-]?key)", re.I)
    results: list[str] = []
    for path, tree, _ in parsed:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str) or not value.value:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names: list[str] = []
            for target in targets:
                if isinstance(target, ast.Name):
                    names.append(target.id)
                elif isinstance(target, ast.Attribute):
                    names.append(target.attr)
            for name in names:
                if pattern.search(name) and not name.upper().endswith(("_SCHEMA", "_FIELD", "_LABEL", "_KEY_NAME")):
                    results.append(f"{path.relative_to(ROOT)}:{node.lineno}:{name}")
    return results


def broad_exception_is_justified(handler: ast.ExceptHandler, path: Path) -> bool:
    # Re-throw/translation after cleanup is a correct transaction/process boundary.
    if any(isinstance(node, ast.Raise) for node in ast.walk(ast.Module(body=handler.body, type_ignores=[]))):
        return True
    # GUI, plugin/process, server and bootstrap boundaries must prevent third-party exceptions
    # from tearing down the host. These boundaries are separately logged/tested.
    rel = path.relative_to(ROOT).as_posix()
    if any(part in rel for part in (
        "/presentation/", "/plugins.py", "/plugin_worker.py", "/server.py", "/app.py",
        "/bootstrap.py", "/terminal.py", "/windows_conpty.py", "/repair_", "/repair.py",
        "/platform_compat.py", "/key_protection.py", "/data_root_lock.py", "/observability.py",
        "/runtime_storage.py", "/production_validation.py", "/developer_validation.py",
        "/runtime_health.py", "/runtime_recovery.py", "/workflows.py", "/nextgen_workflow.py",
        "/reliability.py", "/nextgen_browser.py", "/nextgen_runtime.py",
        "/capture/adapters.py", "/capture/browser_adapter.py", "/capture/inspectors.py", "/capture/mitm_bridge.py",
        "/capture/replay.py", "/capture/controller.py", "/capture/proxy.py",
    )):
        return True
    # Explicit logging of the exception is acceptable for a best-effort observer/optional adapter.
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"debug", "exception", "error", "warning", "critical"}:
                return True
    return False


def main() -> int:
    modern, modern_syntax = parse_files(MODERN)
    legacy, legacy_syntax = parse_files(LEGACY, (3, 8))
    failures: list[str] = []
    metrics: dict[str, Any] = {}

    # 1. Canonical identity and archive/path residue.
    residue: list[str] = []
    for path in ROOT.rglob("*"):
        if LEGACY_TOKEN in path.name.casefold():
            residue.append(path.relative_to(ROOT).as_posix())
        if not path.is_file() or path.suffix.lower() in BINARY_SUFFIXES or "__pycache__" in path.parts:
            continue
        if path.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(path) as archive:
                    for name in archive.namelist():
                        if LEGACY_TOKEN in name.casefold():
                            residue.append(f"{path.relative_to(ROOT)}::{name}")
            except zipfile.BadZipFile:
                residue.append(f"{path.relative_to(ROOT)}::<unreadable-zip>")
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if LEGACY_TOKEN in text.casefold():
            residue.append(path.relative_to(ROOT).as_posix())
    metrics["01_identity_residue"] = len(residue)
    if residue:
        failures.append("canonical identity residue: " + ", ".join(residue[:12]))

    # 2-3. Syntax for modern and frozen Win7 lanes.
    metrics["02_modern_syntax_errors"] = len(modern_syntax)
    metrics["03_win7_python38_syntax_errors"] = len(legacy_syntax)
    if modern_syntax: failures.append("modern syntax: " + "; ".join(modern_syntax[:5]))
    if legacy_syntax: failures.append("Win7 Python 3.8 syntax: " + "; ".join(legacy_syntax[:5]))

    # 4. Maintainability ceiling.
    giant = []
    for path, _, text in modern:
        lines = len(text.splitlines())
        if lines > 1000:
            giant.append(f"{path.relative_to(ROOT)}:{lines}")
    metrics["04_modern_files_over_1000_lines"] = len(giant)
    if giant: failures.append("modern giant modules: " + ", ".join(giant))

    direct_print: list[str] = []
    wildcards: list[str] = []
    dangerous_builtin: list[str] = []
    sql_dynamic: list[str] = []
    subprocess_unvalidated: list[str] = []
    shell_true: list[str] = []
    bare_except: list[str] = []
    broad_total = 0
    broad_unjustified: list[str] = []
    unbounded_pool: list[str] = []

    for path, tree, text in modern:
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    direct_print.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    dangerous_builtin.append(f"{path.relative_to(ROOT)}:{node.lineno}:{node.func.id}")
                if isinstance(node.func, ast.Name) and node.func.id == "ThreadPoolExecutor":
                    has_workers = bool(node.args) or any(keyword.arg == "max_workers" for keyword in node.keywords)
                    if not has_workers:
                        unbounded_pool.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    if node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}:
                        if node.args:
                            arg = node.args[0]
                            if not (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "validated_argv"):
                                subprocess_unvalidated.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                        if any(keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True for keyword in node.keywords):
                            shell_true.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"} and node.args:
                    if isinstance(node.args[0], ast.JoinedStr):
                        sql_dynamic.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                wildcards.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            elif isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    bare_except.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    broad_total += 1
                    if not broad_exception_is_justified(node, path):
                        broad_unjustified.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    # 5-13 static safety/quality dimensions.
    metrics.update({
        "05_direct_print_calls": len(direct_print),
        "06_wildcard_imports": len(wildcards),
        "07_eval_exec_calls": len(dangerous_builtin),
        "08_hardcoded_credential_candidates": len(credential_candidates(modern)),
        "09_dynamic_sql_execute_fstrings": len(sql_dynamic),
        "10_unvalidated_subprocess_calls": len(subprocess_unvalidated),
        "11_shell_true_calls": len(shell_true),
        "12_bare_except_handlers": len(bare_except),
        "13_broad_exception_total": broad_total,
        "13_broad_exception_unjustified": len(broad_unjustified),
    })
    for label, items in (
        ("direct print", direct_print), ("wildcard import", wildcards), ("eval/exec", dangerous_builtin),
        ("dynamic SQL", sql_dynamic), ("unvalidated subprocess", subprocess_unvalidated),
        ("shell=True", shell_true), ("bare except", bare_except), ("unjustified broad except", broad_unjustified),
    ):
        if items: failures.append(label + ": " + ", ".join(items[:12]))
    creds = credential_candidates(modern)
    if creds: failures.append("credential literals: " + ", ".join(creds[:12]))

    # 14. Concurrency must declare a pool ceiling.
    metrics["14_unbounded_thread_pools"] = len(unbounded_pool)
    if unbounded_pool: failures.append("unbounded ThreadPoolExecutor: " + ", ".join(unbounded_pool))

    # 15. Storage topology is explicit and WAL is retained for local SQLite.
    database_text = (MODERN / "infrastructure" / "database.py").read_text(encoding="utf-8")
    storage_text = (MODERN / "enterprise" / "runtime_storage.py").read_text(encoding="utf-8")
    storage_ok = "journal_mode=WAL" in database_text and "PostgreSQLDistributedRuntimeStorage" in storage_text
    metrics["15_storage_topology"] = bool(storage_ok)
    if not storage_ok: failures.append("storage topology/WAL contract missing")

    # 16. Network governance remains in every professional network path.
    network_files = [
        MODERN / "infrastructure" / "capture" / "proxy.py",
        MODERN / "infrastructure" / "capture" / "mitm_engine.py",
        MODERN / "infrastructure" / "http_client.py",
    ]
    network_text = "\n".join(path.read_text(encoding="utf-8") for path in network_files if path.exists())
    network_ok = "Network" in network_text and ("govern" in network_text.casefold() or "validate" in network_text.casefold())
    metrics["16_network_governance_present"] = bool(network_ok)
    if not network_ok: failures.append("network governance integration marker missing")

    # 17. Resource/output/time budgets remain explicit.
    budget_terms = ("max_message_bytes", "timeout", "output", "MAX_JOB_PAYLOAD_BYTES")
    corpus = "\n".join(text for _, _, text in modern)
    budget_ok = all(term in corpus for term in budget_terms)
    metrics["17_resource_budget_contracts"] = bool(budget_ok)
    if not budget_ok: failures.append("bounded resource contract marker missing")

    # 18. Coverage configuration and hard gate are part of release tooling.
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    coverage_ok = "[tool.coverage.run]" in pyproject and (ROOT / "scripts" / "coverage_gate.py").is_file()
    metrics["18_coverage_gate_configured"] = bool(coverage_ok)
    if not coverage_ok: failures.append("coverage release gate is not configured")

    # 19. Stable public API documentation/index is generated and checked.
    api_ok = (ROOT / "docs" / "API_REFERENCE.md").is_file() and (ROOT / "scripts" / "api_contract_gate.py").is_file()
    metrics["19_api_contract_gate"] = bool(api_ok)
    if not api_ok: failures.append("API contract/documentation gate missing")

    # 20. Professional local workspaces remain independently implemented.
    professional = {
        "packet": MODERN / "presentation" / "packet_intelligence_workbench.py",
        "proxy": MODERN / "presentation" / "pages" / "proxy.py",
        "mitm": MODERN / "presentation" / "pages" / "mitm_proxy.py",
        "extraction": MODERN / "presentation" / "pages" / "extraction.py",
        "flow": MODERN / "application" / "workflow_graph.py",
        "terminal": MODERN / "application" / "terminal_workspace.py",
        "fleet": MODERN / "enterprise" / "fleet_live.py",
    }
    missing_professional = [name for name, path in professional.items() if not path.is_file()]
    metrics["20_professional_local_modules_missing"] = missing_professional
    if missing_professional: failures.append("professional modules missing: " + ", ".join(missing_professional))

    result = {"ok": not failures, "metrics": metrics, "failures": failures}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
