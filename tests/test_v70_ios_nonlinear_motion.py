from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOTION = ROOT / "src" / "arenyxa" / "presentation" / "motion.py"
MAIN = ROOT / "src" / "arenyxa" / "presentation" / "main_window_navigation.py"
WELCOME = ROOT / "src" / "arenyxa" / "presentation" / "pages" / "welcome.py"
QTCORE = ROOT / "src" / "arenyxa" / "qt_compat" / "QtCore.py"


def test_motion_uses_custom_cubic_bezier_curves() -> None:
    source = MOTION.read_text(encoding="utf-8")
    assert "QEasingCurve.Type.BezierSpline" in source
    assert "_bezier_curve(0.22, 1.0, 0.36, 1.0)" in source
    assert "_bezier_curve(0.65, 0.0, 0.35, 1.0)" in source
    assert "_bezier_curve(0.25, 0.82, 0.25, 1.0)" in source


def test_first_run_welcome_has_nonlinear_window_entrance() -> None:
    motion = MOTION.read_text(encoding="utf-8")
    welcome = WELCOME.read_text(encoding="utf-8")
    assert 'def reveal_window(' in motion
    assert 'b"windowOpacity"' in motion
    assert 'b"pos"' in motion
    assert 'self.motion.reveal_window(self, duration_ms=360, offset_px=16)' in welcome


def test_navigation_captures_then_commits_then_animates() -> None:
    source = MAIN.read_text(encoding="utf-8")
    block = source[source.index("    def navigate("):source.index("    def _nav_group_expanded", source.index("    def navigate("))]
    capture = block.index("capture_stack_transition")
    commit = block.index("_commit_stack_page(page)")
    animate = block.index("transition_committed_stack")
    assert capture < commit < animate


def test_page_transition_has_depth_drift_and_asymmetric_opacity() -> None:
    source = MOTION.read_text(encoding="utf-8")
    block = source[source.index("    def transition_committed_stack("):source.index("    def transition_stack(", source.index("    def transition_committed_stack("))]
    assert "target_effect.setOpacity(0.84)" in block
    assert "source_geometry.translated(-drift, 0)" in block
    assert "0.84 + 0.16 * progress" in block
    assert "self._ios_ease_out()" in block


def test_qt_compat_exposes_bezier_spline_for_pyside2_and_pyside6() -> None:
    source = QTCORE.read_text(encoding="utf-8")
    assert '"BezierSpline":"BezierSpline"' in source


def test_first_run_fleet_control_uses_final_product_name_and_route() -> None:
    welcome = WELCOME.read_text(encoding="utf-8")
    main = MAIN.read_text(encoding="utf-8")
    assert 'SectionCard(theme, "Fleet Control")' in welcome
    assert 'QPushButton("打开 Fleet Control")' in welcome
    assert 'fleetRequested = Signal()' in welcome
    assert 'dialog.fleetRequested.connect(open_fleet)' in main
    assert 'self.navigate("server_ops")' in main
