from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PAGES = ROOT / "src" / "arenyxa" / "presentation" / "pages"


def _method_source(path: Path, method_name: str) -> str:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name:
            lines = source.splitlines()
            end = getattr(node, "end_lineno", node.lineno)
            return "\n".join(lines[node.lineno - 1 : end])
    raise AssertionError(f"missing method {method_name}: {path}")


def test_extraction_uses_qt_header_compat_helper() -> None:
    source = (PAGES / "extraction.py").read_text(encoding="utf-8")
    assert "set_table_header_stretch_last(self.fields, True)" in source
    assert "set_table_header_stretch_last(self.recipe_steps, True)" in source
    assert ".horizontalHeader().setStretchLastSection" not in source


def test_proxy_deep_controls_are_connected_after_creation() -> None:
    path = PAGES / "proxy.py"
    summary = _method_source(path, "_build_session_summary_tab")
    deep = _method_source(path, "_build_deep_analysis_tab")
    assert "deep_inspect_button" not in summary
    for name in ("deep_inspect_button", "deep_compare_button", "deep_timeline_button"):
        assignment = f"self.{name} = QPushButton"
        connection = f"self.{name}.clicked.connect"
        assert assignment in deep
        assert connection in deep
        assert deep.index(assignment) < deep.index(connection)
