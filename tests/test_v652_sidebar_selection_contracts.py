from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
MAIN = SRC / "arenyxa" / "presentation" / "main_window.py"
DATA = SRC / "arenyxa" / "presentation" / "pages" / "data.py"
NETWORK = SRC / "arenyxa" / "presentation" / "pages" / "network.py"
TOOLS = SRC / "arenyxa" / "presentation" / "pages" / "tools.py"
TASKS = SRC / "arenyxa" / "presentation" / "pages" / "tasks.py"
THEMES = SRC / "arenyxa" / "presentation" / "themes.py"


def test_sidebar_uses_pinned_footer_and_compact_dimensions() -> None:
    source = MAIN.read_text(encoding="utf-8-sig") + "\n" + (MAIN.parent / "main_window_navigation.py").read_text(encoding="utf-8")
    assert 'def _shell_metric(self, value: int) -> int:' in source
    assert 'self.nav.setFixedWidth(self._shell_metric(236))' in source
    assert 'self.motion.animate_width(self.nav, self._shell_metric(68)' in source
    assert 'self.nav_footer = QWidget()' in source
    assert 'add_nav_button(page_id, symbol, key, group, footer_layout)' in source
    assert 'self.service_label.setProperty("servicePill", True)' in source
    assert 'button.setFixedHeight(40 if group in {"core", "system"} else 36)' in source


def test_sidebar_visual_contract_has_single_selected_surface() -> None:
    qss = THEMES.read_text(encoding="utf-8-sig")
    assert 'QPushButton[nav="true"]:checked' in qss
    assert 'background-color: {t.accent_soft}' in qss
    assert 'border-left: 3px solid {t.accent}' in qss
    assert 'QPushButton[nav="true"][navCompact="true"]' in qss
                                                                                            
    normal_nav = qss.split('QPushButton[nav="true"] {{', 1)[1].split('}}', 1)[0]
    assert 'color: {t.text}' in normal_nav
    assert 'color: {t.accent}' not in normal_nav


def test_single_object_views_are_explicitly_single_selection() -> None:
    main = MAIN.read_text(encoding="utf-8-sig") + "\n" + (MAIN.parent / "command_palette.py").read_text(encoding="utf-8")
    data = DATA.read_text(encoding="utf-8-sig")
    network = NETWORK.read_text(encoding="utf-8-sig")
    tools = TOOLS.read_text(encoding="utf-8-sig")
    tasks = TASKS.read_text(encoding="utf-8-sig")

    assert 'self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)' in main
    assert data.count('SelectionMode.SingleSelection') >= 2
    assert network.count('SelectionMode.SingleSelection') >= 2
    assert 'self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)' in tools
    assert tasks.count('SelectionMode.SingleSelection') >= 2
    assert 'self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)' in tools


def test_revision_compare_has_hard_two_selection_budget() -> None:
    source = DATA.read_text(encoding="utf-8-sig")
    tree = ast.parse(source, filename=str(DATA))
    methods = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "_limit_revision_selection" in methods
    assert 'self.list.itemSelectionChanged.connect(self._limit_revision_selection)' in source
    assert 'if len(self._revision_selection_order) <= 2:' in source
    assert 'keep = set(self._revision_selection_order[-2:])' in source
