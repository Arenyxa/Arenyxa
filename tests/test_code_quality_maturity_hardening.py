from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "arenyxa"
TESTS = ROOT / "tests"


def _trees(root: Path):
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _source_metrics() -> dict[str, int]:
    metrics = {
        "functions": 0,
        "partially_typed": 0,
        "documented_functions": 0,
        "documented_classes": 0,
        "broad_exception": 0,
        "bare_except": 0,
        "base_exception": 0,
        "exec": 0,
        "eval": 0,
        "print": 0,
        "over_100_lines": 0,
        "max_function_lines": 0,
    }
    for _path, tree in _trees(SOURCE):
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                metrics["functions"] += 1
                length = int(node.end_lineno or node.lineno) - node.lineno + 1
                metrics["max_function_lines"] = max(metrics["max_function_lines"], length)
                metrics["over_100_lines"] += int(length > 100)
                metrics["documented_functions"] += int(bool(ast.get_docstring(node)))
                args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                if node.args.vararg is not None:
                    args.append(node.args.vararg)
                if node.args.kwarg is not None:
                    args.append(node.args.kwarg)
                missing_parameter = any(
                    argument.arg not in {"self", "cls"} and argument.annotation is None
                    for argument in args
                )
                metrics["partially_typed"] += int(missing_parameter or node.returns is None)
            elif isinstance(node, ast.ClassDef):
                metrics["documented_classes"] += int(bool(ast.get_docstring(node)))
            elif isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    metrics["bare_except"] += 1
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    metrics["broad_exception"] += 1
                elif isinstance(node.type, ast.Name) and node.type.id == "BaseException":
                    metrics["base_exception"] += 1
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in {"exec", "eval", "print"}:
                    metrics[node.func.id] += 1
    return metrics


def _function_length(relative_path: str, function_name: str) -> int:
    path = ROOT / relative_path
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
    ]
    assert len(matches) == 1, f"expected one {relative_path}::{function_name}"
    node = matches[0]
    return int(node.end_lineno or node.lineno) - node.lineno + 1


def test_runtime_quality_ratchets_do_not_regress() -> None:
    metrics = _source_metrics()
    assert metrics["bare_except"] == 0
    assert metrics["exec"] == 0
    assert metrics["eval"] == 0
    assert metrics["print"] == 0
    assert metrics["broad_exception"] <= 306
    assert metrics["base_exception"] <= 5
    # v8.1 modularization baseline; new work must not increase partial typing.
    assert metrics["partially_typed"] <= 104
    assert metrics["documented_functions"] >= 235
    assert metrics["documented_classes"] >= 58
    # v8.1 shipped baseline is 57; keep long-function debt non-increasing from that verified baseline.
    assert metrics["over_100_lines"] <= 57
    assert metrics["max_function_lines"] <= 290


def test_refactored_core_hotspots_stay_bounded() -> None:
    assert _function_length("src/arenyxa/application/command_runtime_terminal.py", "_terminal") <= 30
    assert _function_length("src/arenyxa/application/run_execution.py", "_execute") <= 100
    assert _function_length("src/arenyxa/infrastructure/capture/browser_adapter.py", "_run") <= 50
    assert _function_length("src/arenyxa/bootstrap.py", "bootstrap") <= 180
    assert _function_length("src/arenyxa/app.py", "main") <= 290
    assert _function_length("src/arenyxa/presentation/pages/tools_terminal_workspace.py", "_execute_builtin") <= 20


def test_async_runtime_regressions_remain_real_async_tests() -> None:
    async_tests = 0
    for path, tree in _trees(TESTS):
        if path.name == "test_code_quality_maturity_hardening.py":
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith("test_"):
                async_tests += 1
    assert async_tests >= 4
