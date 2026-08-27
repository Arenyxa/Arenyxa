from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MOTION = ROOT / "src" / "arenyxa" / "presentation" / "motion.py"
MOTION_SUPPORT = ROOT / "src" / "arenyxa" / "presentation" / "motion_support.py"
MAIN = ROOT / "src" / "arenyxa" / "presentation" / "main_window.py"
MAIN_NAV = ROOT / "src" / "arenyxa" / "presentation" / "main_window_navigation.py"


def test_layout_width_uses_bounded_spring_with_hard_completion_guard() -> None:
    source = MOTION.read_text(encoding="utf-8")
    block = source[source.index("    def animate_width("):source.index("    def animate_progress(")]
    assert "SpringAnimator(" in block
    assert "damping = max(1.0" in block
    assert "bounded = max(low, min(high" in block
    assert "position_epsilon=0.35" in block
    assert "max_duration=" in block


def test_spring_animator_has_tolerance_and_timeout_fail_safe() -> None:
    source = MOTION_SUPPORT.read_text(encoding="utf-8")
    block = source[source.index("class SpringAnimator"):source.index("class FrameProfiler")]
    assert "position_epsilon" in block
    assert "velocity_epsilon" in block
    assert "expired =" in block
    assert "now - self._started_at >= self.max_duration" in block
    assert "self.velocity = 0.0" in block


def test_route_motion_is_cosmetic_after_atomic_commit() -> None:
    source = MAIN_NAV.read_text(encoding="utf-8")
    navigate = source[source.index("    def navigate("):source.index("    def _nav_group_expanded", source.index("    def navigate("))]
    capture_at = navigate.index("self.motion.capture_stack_transition(self.stack, page)")
    commit_at = navigate.index("self._commit_stack_page(page)")
    transition_at = navigate.index("self.motion.transition_committed_stack(")
    assert capture_at < commit_at < transition_at
    assert "self.motion.transition_stack" not in navigate


def test_non_efficiency_pages_use_ios_nonlinear_reveal() -> None:
    source = MOTION.read_text(encoding="utf-8")
    reveal = source[source.index("    def reveal("):source.index("    def reveal_window", source.index("    def reveal("))]
    assert 'quality != "efficiency"' in reveal
    assert 'self._animation_mode() == "always"' in reveal
    assert 'self._duration(260, minimum=180)' in reveal
    assert 'self._ios_ease_out()' in reveal
    assert 'pixel_area * device_ratio * device_ratio > 520_000' not in reveal

def test_theme_change_snapshot_crossfade_uses_non_efficiency_policy() -> None:
    motion = MOTION.read_text(encoding="utf-8")
    main = MAIN.read_text(encoding="utf-8") + "\n" + MAIN_NAV.read_text(encoding="utf-8")
    theme_transition = (ROOT / "src" / "arenyxa" / "presentation" / "theme_transition.py").read_text(encoding="utf-8")
    policy = motion[motion.index("    def _style_crossfade_allowed("):motion.index("    def crossfade_style(")]
    block = motion[motion.index("    def crossfade_style("):motion.index("    def _cancel_page_transition", motion.index("    def crossfade_style("))]
    assert 'quality != "efficiency"' in policy
    assert 'self._animation_mode() == "always"' in policy
    assert "WA_TransparentForMouseEvents" in block
    assert "apply_update()" in block
    assert "2_200_000" in policy
    assert "ThemeTransitionController" in main
    assert "self.motion.crossfade_style" in theme_transition

def test_button_micro_effect_is_removed_after_full_opacity_restore() -> None:
    source = MOTION.read_text(encoding="utf-8")
    block = source[source.index("    def _button_opacity"):source.index("    def _publish_profile_properties", source.index("    def _button_opacity"))]
    assert "if float(target) >= 0.999" in block
    assert "button.setGraphicsEffect(None)" in block
    assert "self.active.get(key) is not animation" in block


def test_staggered_reveal_has_quality_aware_animation_budget() -> None:
    source = MOTION.read_text(encoding="utf-8")
    block = source[source.index("    def reveal_staggered"):source.index("    def morph_geometry", source.index("    def reveal_staggered"))]
    assert 'animation_cap = 18 if quality == "high" else 8' in block
    assert "items[:animation_cap]" in block
    assert "items[animation_cap:]" in block
