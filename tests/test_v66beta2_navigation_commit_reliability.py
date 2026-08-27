from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def _block(source: str, start: str, end: str) -> str:
    a = source.index(start)
    b = source.index(end, a)
    return source[a:b]


def test_route_is_visually_committed_before_db_refresh_and_i18n_walk() -> None:
    source = (SRC / "presentation" / "main_window_navigation.py").read_text(encoding="utf-8")
    navigate = _block(source, "    def navigate(self, page_id: str)", "    def _nav_group_expanded")
    assert "self._commit_stack_page(page)" in navigate
    assert "page.activated()" not in navigate
    assert "self.language.translate_tree(page)" not in navigate
    assert "QTimer.singleShot(0" in navigate
    assert navigate.index("self._commit_stack_page(page)") < navigate.index("QTimer.singleShot(0")


def test_deferred_page_refresh_is_generation_guarded_and_nonfatal() -> None:
    source = (SRC / "presentation" / "main_window_navigation.py").read_text(encoding="utf-8")
    finish = _block(source, "    def _finish_navigation", "    def navigate(self, page_id: str)")
    assert "generation != self._route_generation" in finish
    assert "page.activated()" in finish
    assert "self.language.translate_tree(page)" in finish
    assert "except Exception as exc" in finish
    assert "页面已打开，但刷新失败" in finish


def test_motion_is_not_part_of_route_correctness_anymore() -> None:
    source = (SRC / "presentation" / "main_window_navigation.py").read_text(encoding="utf-8")
    commit = _block(source, "    def _commit_stack_page", "    def _finish_navigation")
    assert "self.motion.transition_stack" not in commit
    assert "self.stack.setCurrentIndex(index)" in commit
    assert "self.stack.setCurrentWidget(page)" in commit
    assert "QStackedWidget refused to commit" in commit


def test_windows_table_wrappers_are_optional_not_page_fatal() -> None:
    widgets = (SRC / "presentation" / "widgets.py").read_text(encoding="utf-8")
    assert "def set_table_header_resize_mode" in widgets
    assert "def set_table_header_stretch_last" in widgets
    assert "def table_selection_model" in widgets
    assert "def connect_current_row_changed" in widgets
    for name in ("tasks.py", "network.py", "data.py"):
        source = (SRC / "presentation" / "pages" / name).read_text(encoding="utf-8")
        assert ".horizontalHeader().set" not in source
    network = (SRC / "presentation" / "pages" / "network.py").read_text(encoding="utf-8")
    data = (SRC / "presentation" / "pages" / "data.py").read_text(encoding="utf-8")
    assert "connect_current_row_changed(self.table, self.inspect_event)" in network
    assert "connect_current_row_changed(self.table, self.inspect_row)" in data
