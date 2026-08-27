from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def source(relative: str) -> str:
    return (SRC / relative).read_text(encoding="utf-8")


def block(text: str, start: str, end: str) -> str:
    a = text.index(start)
    b = text.index(end, a)
    return text[a:b]


def test_navigation_verification_is_wrapper_identity_independent() -> None:
    main = source("presentation/main_window.py") + "\n" + source("presentation/main_window_navigation.py") + "\n" + source("presentation/main_window_lifecycle.py") + "\n" + source("presentation/main_window_operations.py")
    commit = block(main, "    def _commit_stack_page", "    def _finish_navigation")
    assert "self.stack.currentIndex() != index" in commit
    assert "currentWidget() is not page" not in commit
    navigate = block(main, "    def navigate(self, page_id: str)", "    def _nav_group_expanded")
    assert "previous = self.pages.get(previous_page_id)" in navigate


def test_high_frequency_settings_and_personalization_persistence_is_debounced() -> None:
    settings = source("presentation/pages/settings.py")
    personalization = source("presentation/pages/personalization.py")
    save_concurrency = block(settings, "    def _save_concurrency", "    def _sync_controls_from_settings")
    apply_motion = block(personalization, "    def apply_motion", "    def _ui_scale_changed")
    assert "self._schedule_settings_save()" in apply_motion
    assert "settings.save(" not in apply_motion
    assert "self._schedule_settings_save()" in save_concurrency
    assert "settings.save(" not in save_concurrency
    assert "self._settings_save_timer.setInterval(180)" in settings
    assert "self._settings_save_dirty = True" in settings
    assert "self._settings_save_timer.setInterval(180)" in personalization
    assert "self._settings_save_dirty = True" in personalization


def test_motion_profile_repaint_is_coalesced_and_visible_only() -> None:
    motion = source("presentation/motion.py")
    set_profile = block(motion, "    def set_profile", "    def effective_quality")
    assert "self._schedule_glass_refresh()" in set_profile
    assert "app.allWidgets()" not in set_profile
    refresh = block(motion, "    def _refresh_visible_glass_widgets", "    def _schedule_glass_refresh")
    assert "widget.isVisible()" in refresh


def test_side_effecting_combo_boxes_are_wheel_safe() -> None:
    data = source("presentation/pages/data.py")
    visualization = source("presentation/pages/visualization.py")
    tools = source("presentation/pages/tools.py") + "\n" + source("presentation/pages/tools_console.py")
    assert "self.run_selector = ScrollSafeComboBox()" in data
    assert "self.run = ScrollSafeComboBox()" in visualization
    assert "self.mode = ScrollSafeComboBox()" in tools


def test_status_clear_timer_cannot_clear_a_newer_message() -> None:
    main = source("presentation/main_window.py") + "\n" + source("presentation/main_window_navigation.py") + "\n" + source("presentation/main_window_lifecycle.py") + "\n" + source("presentation/main_window_operations.py")
    status = block(main, "    def show_status", "    def refresh_global_status")
    assert "self._status_generation += 1" in status
    assert "generation == self._status_generation" in status


def test_windows_taskbar_balances_com_initialization() -> None:
    taskbar = source("presentation/taskbar.py")
    assert "self._com_initialized" in taskbar
    assert "CoUninitialize" in taskbar
    assert "self.close()" in taskbar


def test_arabic_technical_line_edit_detection_uses_actual_text() -> None:
    language = source("presentation/language.py")
    direction = block(language, "    def _apply_direction", "    def _translate_text_property")
    assert "widget.text()" in direction
    assert '"://"' in direction
