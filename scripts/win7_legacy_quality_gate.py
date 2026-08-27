from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEGACY = ROOT / "legacy" / "win7" / "src" / "arenyxa"
MAX_BROAD_EXCEPTION = 337


def main() -> int:
    metrics = {
        "python_files": 0,
        "syntax_errors": 0,
        "direct_print_calls": 0,
        "wildcard_imports": 0,
        "eval_exec_calls": 0,
        "dynamic_sql_execute_fstrings": 0,
        "unvalidated_subprocess_calls": 0,
        "shell_true_calls": 0,
        "bare_except_handlers": 0,
        "broad_exception_handlers": 0,
    }
    failures: list[str] = []
    for path in LEGACY.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        metrics["python_files"] += 1
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path), feature_version=(3, 8))
        except SyntaxError as exc:
            metrics["syntax_errors"] += 1
            failures.append(f"syntax:{path.relative_to(ROOT)}:{exc.lineno}:{exc.msg}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    metrics["direct_print_calls"] += 1
                    failures.append(f"print:{path.relative_to(ROOT)}:{node.lineno}")
                if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                    metrics["eval_exec_calls"] += 1
                    failures.append(f"{node.func.id}:{path.relative_to(ROOT)}:{node.lineno}")
                if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"} and node.args:
                    if isinstance(node.args[0], ast.JoinedStr):
                        metrics["dynamic_sql_execute_fstrings"] += 1
                        failures.append(f"sql:{path.relative_to(ROOT)}:{node.lineno}")
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    if node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}:
                        if node.args:
                            arg = node.args[0]
                            valid = isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name) and arg.func.id == "validated_argv"
                            if not valid:
                                metrics["unvalidated_subprocess_calls"] += 1
                                failures.append(f"subprocess:{path.relative_to(ROOT)}:{node.lineno}")
                        if any(
                            keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True
                            for keyword in node.keywords
                        ):
                            metrics["shell_true_calls"] += 1
                            failures.append(f"shell=True:{path.relative_to(ROOT)}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
                metrics["wildcard_imports"] += 1
                failures.append(f"wildcard:{path.relative_to(ROOT)}:{node.lineno}")
            elif isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    metrics["bare_except_handlers"] += 1
                    failures.append(f"bare-except:{path.relative_to(ROOT)}:{node.lineno}")
                elif isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    metrics["broad_exception_handlers"] += 1
    if metrics["broad_exception_handlers"] > MAX_BROAD_EXCEPTION:
        failures.append(
            f"broad-exception ratchet exceeded: {metrics['broad_exception_handlers']} > {MAX_BROAD_EXCEPTION}"
        )
    payload = {"ok": not failures, "max_broad_exception_handlers": MAX_BROAD_EXCEPTION, "metrics": metrics, "failures": failures[:30]}
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
