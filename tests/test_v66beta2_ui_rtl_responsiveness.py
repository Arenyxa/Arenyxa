from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def _source(relative: str) -> str:
    return (SRC / relative).read_text(encoding="utf-8")


def test_arabic_does_not_mirror_the_application_shell() -> None:
    source = _source("presentation/language.py")
    apply_block = source[source.index("    def apply(self, locale: str)"):source.index("    def eventFilter", source.index("    def apply(self, locale: str)"))]
    assert "setLayoutDirection(Qt.LayoutDirection.LeftToRight)" in apply_block
    assert 'setProperty("arenyxa_content_rtl", self.locale.startswith("ar"))' in apply_block
    assert "RightToLeft" not in apply_block
    direction = source[source.index("    def _apply_direction"):source.index("    def _translate_text_property", source.index("    def _apply_direction"))]
    assert "widget.setLayoutDirection(Qt.LayoutDirection.LeftToRight)" in direction
    assert "widget.setLayoutDirection(Qt.LayoutDirection.RightToLeft)" not in direction
    assert "AlignRight" in direction


def test_hot_locale_switch_only_translates_visible_surfaces() -> None:
    source = _source("presentation/main_window.py") + "\n" + _source("presentation/main_window_lifecycle.py") + "\n" + _source("presentation/main_window_navigation.py")
    retranslate = source[source.index("    def retranslate(self)"):source.index("    def open_project", source.index("    def retranslate(self)"))]
    assert "self.language.translate_tree(self)" not in retranslate
    assert "self.nav, self.topbar, self.inspector, self.statusBar()" in retranslate
    assert "self.pages.get(self.current_page_id)" in retranslate

    navigate = source[source.index("    def navigate(self, page_id: str)"):source.index("    def _nav_group_expanded", source.index("    def navigate(self, page_id: str)"))]
    finish = source[source.index("    def _finish_navigation"):source.index("    def navigate(self, page_id: str)", source.index("    def _finish_navigation"))]
    assert navigate.count("self.language.translate_tree(page)") == 0
    assert finish.count("self.language.translate_tree(page)") == 1
    assert "self._finish_navigation(page_id, page, generation)" in navigate


def test_expensive_workspace_compositing_is_adaptive() -> None:
    motion = _source("presentation/motion.py")
    capture = motion[motion.index("    def capture_stack_transition("):motion.index("    def transition_committed_stack", motion.index("    def capture_stack_transition("))]
    transition = motion[motion.index("    def transition_committed_stack("):motion.index("    def transition_stack(", motion.index("    def transition_committed_stack("))]
    assert 'quality != "efficiency"' in capture
    assert 'self._animation_mode() == "always"' in capture
    assert "self._duration(300, minimum=220)" in transition
    assert "self._ios_ease_out()" in transition
    assert "pixel_area * device_ratio * device_ratio > 1_250_000" not in capture
    assert 'property("arenyxa_motion_static")' not in transition

    event_filter = motion[motion.index("    def eventFilter("):motion.index("    def _button_opacity", motion.index("    def eventFilter("))]
    assert 'self.effective_quality() == "high"' in event_filter
    assert "_has_static_motion_ancestor" in event_filter


def test_toolbar_about_and_glass_surfaces_avoid_pointer_repaint_storms() -> None:
    main = _source("presentation/main_window.py")
    settings = _source("presentation/pages/settings.py") + "\n" + _source("presentation/pages/settings_support.py")
    glass = _source("presentation/glass.py")
    assert 'self.topbar.setProperty("arenyxa_motion_static", True)' in main
    about = settings[settings.index("class AboutPage"):]
    assert 'self.setProperty("arenyxa_motion_static", True)' in about
    assert "def _motion_static" in glass
    assert "self._hover_timer.stop()" in glass


def test_windows_taskbar_progress_deduplicates_com_updates() -> None:
    source = _source("presentation/taskbar.py")
    assert "self._last_state" in source
    assert "self._last_progress" in source
    assert "if self._last_progress == progress" in source
    assert "if not self._available or self._last_state == int(state)" in source


def test_frame_profiler_sampling_is_capped_at_60hz() -> None:
    source = _source("presentation/motion_support.py") + "\n" + _source("presentation/motion.py")
    sampler = source[source.index("class FrameSampler"):source.index("class MotionOrchestrator")]
    assert "sample_hz = min(60.0" in sampler
    assert "1000 / sample_hz" in sampler
