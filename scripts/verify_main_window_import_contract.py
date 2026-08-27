from __future__ import annotations

"""Verify the split MainWindow dependency graph before a GUI build is released."""

import builtins
import importlib
import os
import symtable
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
PRESENTATION = SRC / "arenyxa" / "presentation"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

MIXIN_FILES = (
    "main_window_navigation.py",
    "main_window_operations.py",
    "main_window_lifecycle.py",
)


def _undefined_global_references(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    table = symtable.symtable(source, str(path), "exec")
    defined = {
        symbol.get_name()
        for symbol in table.get_symbols()
        if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace() or symbol.is_parameter()
    }
    referenced: set[str] = set()

    def walk(node: symtable.SymbolTable) -> None:
        for symbol in node.get_symbols():
            if symbol.is_referenced() and symbol.is_global():
                referenced.add(symbol.get_name())
        for child in node.get_children():
            walk(child)

    walk(table)
    return sorted(referenced - defined - set(dir(builtins)))


def verify_static_contract() -> None:
    for name in MIXIN_FILES:
        path = PRESENTATION / name
        missing = _undefined_global_references(path)
        if missing:
            raise RuntimeError(f"{name}: unresolved module globals: {', '.join(missing)}")

    source = (PRESENTATION / "main_window.py").read_text(encoding="utf-8")
    required = (
        "from arenyxa.presentation.main_window_navigation import MainWindowNavigationMixin",
        "from arenyxa.presentation.main_window_operations import MainWindowOperationsMixin",
        "from arenyxa.presentation.main_window_lifecycle import MainWindowLifecycleMixin",
        "class MainWindow(MainWindowNavigationMixin, MainWindowOperationsMixin, MainWindowLifecycleMixin, QMainWindow):",
    )
    for token in required:
        if token not in source:
            raise RuntimeError(f"main_window.py missing split-shell contract token: {token}")

    registry = (PRESENTATION / "main_window_registry.py").read_text(encoding="utf-8")
    for token in ("PAGE_DEFINITIONS", "PAGE_TYPES", "PAGE_GROUP", "NAVIGATION", "DEVELOPER_SHORTCUTS"):
        if token not in registry:
            raise RuntimeError(f"main_window_registry.py missing {token}")

    operations = (PRESENTATION / "main_window_operations.py").read_text(encoding="utf-8")
    if "from arenyxa.presentation.command_palette import CommandPalette" not in operations:
        raise RuntimeError("MainWindowOperationsMixin must import CommandPalette from its split component")


def verify_runtime_import_when_qt_available() -> str:
    from arenyxa.qt_compat import binding_available

    if not binding_available():
        return "SKIP (Qt binding unavailable in validation environment)"
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    module = importlib.import_module("arenyxa.presentation.main_window")
    main_window = getattr(module, "MainWindow", None)
    if main_window is None:
        raise RuntimeError("arenyxa.presentation.main_window.MainWindow is missing")
    expected = {"MainWindowNavigationMixin", "MainWindowOperationsMixin", "MainWindowLifecycleMixin"}
    bases = {base.__name__ for base in main_window.__mro__}
    missing = sorted(expected - bases)
    if missing:
        raise RuntimeError(f"MainWindow MRO is missing mixins: {', '.join(missing)}")
    return "PASS"


def main() -> int:
    verify_static_contract()
    runtime = verify_runtime_import_when_qt_available()
    print("Arenyxa MainWindow import contract: PASS")
    print(f"- static split-shell dependency graph: PASS")
    print(f"- runtime Qt import: {runtime}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
