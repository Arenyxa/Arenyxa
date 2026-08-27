from __future__ import annotations

from pathlib import Path


def _source(relative: str) -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / relative).read_text(encoding="utf-8")


def test_theme_crossfade_paints_snapshot_before_expensive_style_update() -> None:
    source = _source("src/arenyxa/presentation/motion.py")
    body = source[source.index("    def crossfade_style("):source.index("    def _cancel_page_transition(")]
    overlay_index = body.index("overlay.show()")
    animated_apply_index = body.index("apply_update()", overlay_index)
    assert overlay_index < animated_apply_index
    assert body.index("app.processEvents()", overlay_index) < animated_apply_index
    assert "QEventLoop" not in body


def test_navigation_refresh_uses_cached_context_and_explicit_button_targets() -> None:
    source = _source("src/arenyxa/presentation/main_window_navigation.py")
    body = source[source.index("    def _refresh_nav_visibility("):source.index("    def open_developer_tool(")]
    assert "experience = self._experience_context()" in body
    assert "navigation = experience.navigation" in body
    assert 'button.property("navPageId")' in body
    assert 'button.property("navActionTarget")' in body
    assert "next((key for key, value in self.nav_buttons.items()" not in body


def test_mode_switch_animates_new_navigation_and_uses_safe_landing_page() -> None:
    source = _source("src/arenyxa/presentation/main_window_navigation.py")
    body = source[source.index("    def _complete_welcome_center("):source.index("    def _apply_theme_requested(")]
    assert "navigation_policy_engine.rebuild(event.current)" in body
    assert "if landing_page not in resolved.visible" in body
    assert "self.motion.reveal_staggered(added_buttons, interval_ms=18)" in body
    assert "使用模式不会改变安全权限" in body


def test_root_gate_reprobes_live_registration_and_fails_closed() -> None:
    source = _source("src/arenyxa/app.py")
    body = source[source.index("def _enforce_registered_root_startup("):source.index("def _schedule_startup_health_checks(")]
    assert "manager.root_workstation_registered()" in body
    assert "manager.root_capability_state()" in body
    assert "registered = True" in body
    assert "failing closed into Root authentication" in body


def test_startup_progress_has_granular_real_activity_stages() -> None:
    source = _source("src/arenyxa/bootstrap.py")
    stages = [4, 10, 16, 20, 24, 30, 36, 42, 48, 56, 64, 70, 78, 84, 90, 94, 97, 99]
    positions = [source.index(f"report({stage},") for stage in stages]
    assert positions == sorted(positions)
    shell = _source("src/arenyxa/presentation/shell_window.py")
    assert "_STARTUP_ACTIVITY_HINTS" in shell
    assert "self.activity" in shell
