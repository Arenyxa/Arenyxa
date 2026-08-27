from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CRITICAL = (
    ROOT / "src" / "arenyxa" / "presentation" / "main_window.py",
    ROOT / "src" / "arenyxa" / "presentation" / "pages" / "network.py",
    ROOT / "src" / "arenyxa" / "presentation" / "pages" / "proxy.py",
    ROOT / "src" / "arenyxa" / "presentation" / "pages" / "mitm_proxy.py",
    ROOT / "src" / "arenyxa" / "presentation" / "pages" / "extraction.py",
    ROOT / "src" / "arenyxa" / "presentation" / "pages" / "data.py",
    ROOT / "src" / "arenyxa" / "presentation" / "pages" / "tasks.py",
    ROOT / "src" / "arenyxa" / "presentation" / "pages" / "server_ops.py",
)


def untyped_functions(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    missing: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs)
        untyped = [item.arg for item in arguments if item.arg not in {"self", "cls"} and item.annotation is None]
        if node.args.vararg is not None and node.args.vararg.annotation is None:
            untyped.append("*" + node.args.vararg.arg)
        if node.args.kwarg is not None and node.args.kwarg.annotation is None:
            untyped.append("**" + node.args.kwarg.arg)
        if untyped or node.returns is None:
            details = ",".join(untyped) if untyped else "return"
            missing.append(f"{path.relative_to(ROOT)}:{node.lineno}:{node.name}:{details}")
    return missing


def main() -> int:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    failures: list[str] = []
    if 'module = ["arenyxa.presentation.*"]' in pyproject:
        failures.append("broad presentation mypy override is forbidden")
    for path in CRITICAL:
        failures.extend(untyped_functions(path))
    if failures:
        print("UI_TYPE_GATE=FAIL")
        for item in failures:
            print(item)
        return 1
    print("UI_TYPE_GATE=PASS")
    print(f"strict_critical_modules={len(CRITICAL)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
