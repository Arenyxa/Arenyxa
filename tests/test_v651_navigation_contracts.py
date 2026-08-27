from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
MAIN_WINDOW = SRC / "arenyxa" / "presentation" / "main_window.py"
MAIN_WINDOW_REGISTRY = SRC / "arenyxa" / "presentation" / "main_window_registry.py"


def _module_index() -> dict[str, tuple[Path, set[str], ast.Module]]:
    modules: dict[str, tuple[Path, set[str], ast.Module]] = {}
    for path in SRC.rglob("*.py"):
        relative = path.relative_to(SRC).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = ".".join(parts)
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        names: set[str] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
        modules[module] = (path, names, tree)
    return modules


def test_internal_from_imports_reference_exported_names() -> None:
    
    modules = _module_index()
    missing: list[str] = []
    for _module, (path, _names, tree) in modules.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.level or not node.module:
                continue
            if not node.module.startswith("arenyxa") or node.module not in modules:
                continue
            exported = modules[node.module][1]
                                                                                         
                                                                                           
                                                                                     
            if "__dynamic_exports__" in exported:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                if alias.name not in exported and f"{node.module}.{alias.name}" not in modules:
                    missing.append(f"{path.relative_to(ROOT)}:{node.lineno}: {node.module}.{alias.name}")
    assert missing == []


def test_page_navigation_contract_is_unique_and_routes_are_known() -> None:
    tree = ast.parse(MAIN_WINDOW_REGISTRY.read_text(encoding="utf-8-sig"), filename=str(MAIN_WINDOW_REGISTRY))
    page_ids: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "PAGE_DEFINITIONS" for target in node.targets):
            continue
        for element in node.value.elts:                            
            page_ids.append(element.elts[0].value)                            
        break

    assert page_ids
    assert len(page_ids) == len(set(page_ids))

    unknown: list[str] = []
    for path in (SRC / "arenyxa").rglob("*.py"):
        module_tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        for node in ast.walk(module_tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {"navigate", "_navigate"} or not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value not in page_ids:
                unknown.append(f"{path.relative_to(ROOT)}:{node.lineno}:{arg.value}")
    assert unknown == []


def test_navigation_buttons_use_explicit_exclusive_qbutton_group() -> None:
    source = MAIN_WINDOW.read_text(encoding="utf-8-sig") + "\n" + (MAIN_WINDOW.parent / "main_window_navigation.py").read_text(encoding="utf-8")
    assert "self.nav_button_group = QButtonGroup(self)" in source
    assert "self.nav_button_group.setExclusive(True)" in source
    assert "self.nav_button_group.addButton(button)" in source
    assert "def _sync_navigation_selection" in source
