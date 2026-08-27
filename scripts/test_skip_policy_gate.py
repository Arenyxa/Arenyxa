from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    current: ast.AST | None = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def main() -> int:
    policy_path = TESTS / "skip_policy.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    if policy.get("schema") != "arenyxa.skip-policy/v2":
        raise SystemExit("skip policy schema must be arenyxa.skip-policy/v2")
    optional = {str(item) for item in policy.get("allowed_optional_dependencies", [])}
    reason_fragments = tuple(str(item).casefold() for item in policy.get("allowed_reason_fragments", []))
    failures: list[str] = []
    observations: list[dict[str, Any]] = []

    for path in sorted(TESTS.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        rel = path.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            if name.endswith("pytest.importorskip") or name == "pytest.importorskip":
                dependency = _literal_string(node.args[0]) if node.args else None
                observations.append({"file": rel, "line": node.lineno, "kind": "importorskip", "value": dependency})
                if dependency not in optional:
                    failures.append(f"{rel}:{node.lineno}: unapproved optional dependency skip {dependency!r}")
                continue
            if name.endswith("pytest.skip") or name == "pytest.skip":
                reason = _literal_string(node.args[0]) if node.args else None
                observations.append({"file": rel, "line": node.lineno, "kind": "runtime-skip", "reason": reason})
                if policy.get("reason_required", True) and not reason:
                    failures.append(f"{rel}:{node.lineno}: pytest.skip requires a literal reason")
                elif reason and reason_fragments and not any(fragment in reason.casefold() for fragment in reason_fragments):
                    failures.append(f"{rel}:{node.lineno}: skip reason is not approved: {reason!r}")

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                name = _call_name(decorator)
                if name.endswith("pytest.mark.skip") or name == "pytest.mark.skip":
                    if policy.get("unconditional_skip_forbidden", True):
                        failures.append(f"{rel}:{decorator.lineno}: unconditional @pytest.mark.skip is forbidden")
                if name.endswith("pytest.mark.skipif") or name == "pytest.mark.skipif":
                    reason = next(
                        (_literal_string(keyword.value) for keyword in decorator.keywords if keyword.arg == "reason"),
                        None,
                    )
                    observations.append({"file": rel, "line": decorator.lineno, "kind": "skipif", "reason": reason})
                    if policy.get("reason_required", True) and not reason:
                        failures.append(f"{rel}:{decorator.lineno}: @pytest.mark.skipif requires a literal reason")
                    elif reason and reason_fragments and not any(fragment in reason.casefold() for fragment in reason_fragments):
                        failures.append(f"{rel}:{decorator.lineno}: skipif reason is not approved: {reason!r}")
                    elif reason and "release/soak gate" in reason.casefold():
                        condition = ast.unparse(decorator.args[0]) if decorator.args else ""
                        if "ARENYXA_24H_LEAK_TEST" not in condition:
                            failures.append(
                                f"{rel}:{decorator.lineno}: release/soak skip must be controlled by ARENYXA_24H_LEAK_TEST"
                            )

    payload = {
        "schema": "arenyxa.skip-policy-audit/v2",
        "passed": not failures,
        "observed_skip_sites": len(observations),
        "failures": failures,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
