from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STABLE_MODULES = (
    "src/arenyxa/application/command_runtime.py",
    "src/arenyxa/infrastructure/database.py",
    "src/arenyxa/enterprise/distributed.py",
    "src/arenyxa/enterprise/identity.py",
    "src/arenyxa/application/terminal.py",
    "src/arenyxa/security/sql_safety.py",
    "src/arenyxa/application/extraction_recipe.py",
    "src/arenyxa/application/workflow_graph.py",
)


def public_symbols(tree: ast.Module) -> list[ast.AST]:
    return [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_")]


def main() -> int:
    missing: list[str] = []
    index: list[tuple[str, list[str]]] = []
    for relative in STABLE_MODULES:
        path = ROOT / relative
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not ast.get_docstring(tree):
            missing.append(f"{relative}:module")
        names: list[str] = []
        for node in public_symbols(tree):
            names.append(node.name)
            if not ast.get_docstring(node):
                missing.append(f"{relative}:{node.name}")
        index.append((relative, names))
    reference = ROOT / "docs" / "API_REFERENCE.md"
    if not reference.is_file():
        missing.append("docs/API_REFERENCE.md")
    print(json.dumps({"ok": not missing, "stable_modules": len(STABLE_MODULES), "missing_docstrings_or_reference": missing}, indent=2))
    return 0 if not missing else 1


if __name__ == "__main__":
    raise SystemExit(main())
