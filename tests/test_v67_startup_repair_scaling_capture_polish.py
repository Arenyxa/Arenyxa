from __future__ import annotations

from pathlib import Path

from arenyxa.presentation.ui_scale_math import effective_ui_scale, scale_stylesheet_metrics

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_startup_handoff_is_armed_before_main_window_is_shown() -> None:
    app = (SRC / "app.py").read_text(encoding="utf-8")
    prepare = app.index("startup_splash.prepare_handoff(window)")
    show = app.index("if launch_geometry.maximized:", prepare)
    finish = app.index("startup_splash.finish(window)", show)
    assert prepare < show < finish

    splash = (SRC / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    assert "def prepare_handoff" in splash
    assert "self._handoff_overlay" in splash


def test_startup_reveal_is_continuous_centered_logo_and_workspace_mask() -> None:
    splash = (SRC / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    motion_math = (SRC / "presentation" / "startup_motion_math.py").read_text(encoding="utf-8")
    assert "handoff_visuals as _handoff_visuals" in splash
    assert "icon_opacity = 1.0 - stage(p, 0.42, 0.74)" in motion_math
    assert "reveal_progress = stage(p, 0.48, 1.0)" in motion_math
    assert "def reveal_radius" in motion_math
    assert "overlay.capture_workspace()" in splash
    assert "QPainterPath" in splash
    assert "painter.setClipPath(aperture)" in splash


def test_repair_relaunch_detaches_from_temporary_console() -> None:
    recovery = (SRC / "repair_recovery.py").read_text(encoding="utf-8")
    assert 'return str(sys.executable)' in recovery
    assert 'command = [source_python_executable(), "-m", "arenyxa", "--post-repair"]' in recovery
    assert 'with_name("pythonw.exe")' not in recovery
    assert 'getattr(subprocess, "CREATE_NO_WINDOW", 0)' in recovery
    assert 'getattr(subprocess, "DETACHED_PROCESS", 0)' in recovery
    assert 'getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)' in recovery
    assert "stdin=subprocess.DEVNULL" in recovery
    assert "stdout=subprocess.DEVNULL" in recovery
    assert "stderr=subprocess.DEVNULL" in recovery


def test_ui_scale_auto_grows_with_large_window_and_manual_is_exact() -> None:
    assert effective_ui_scale("manual", 135, 1200, 760) == 1.35
    compact = effective_ui_scale("auto", 100, 1200, 760)
    desktop = effective_ui_scale("auto", 100, 1920, 1080)
    large = effective_ui_scale("auto", 100, 2560, 1440)
    ultra = effective_ui_scale("auto", 100, 3840, 2160)
    assert 0.95 <= compact <= desktop <= large <= ultra <= 1.30
    assert large >= 1.10


def test_ui_scale_qss_transform_is_not_cumulative_and_preserves_non_px_numbers() -> None:
    source = "QLabel{font-size:13px; border:1px solid rgba(1,2,3,0.5); padding:0 10px;}"
    scaled = scale_stylesheet_metrics(source, 1.25)
    assert "font-size:16.2px" in scaled or "font-size:16.3px" in scaled
    assert "rgba(1,2,3,0.5)" in scaled
    assert "padding:0 12.5px" in scaled


def test_personalization_exposes_auto_and_manual_ui_scaling() -> None:
    personalization = (SRC / "presentation" / "pages" / "personalization.py").read_text(encoding="utf-8")
    config = (SRC / "config.py").read_text(encoding="utf-8")
    main = ((SRC / "presentation" / "main_window.py").read_text(encoding="utf-8") + "\n" + (SRC / "presentation" / "main_window_navigation.py").read_text(encoding="utf-8"))
    assert 'ui_scale_mode: str = "auto"' in config
    assert "ui_scale_percent: int = 100" in config
    assert 'self.ui_scale_mode.addItem("自动（随窗口大小）", "auto")' in personalization
    assert 'self.ui_scale_mode.addItem("手动", "manual")' in personalization
    assert "self.ui_scale_percent.setRange(85, 160)" in personalization
    assert "page.uiScaleRequested.connect(self._apply_ui_scale_requested)" in main
    assert "manager.schedule_recompute()" in main


def test_capture_terminal_transition_clears_indeterminate_top_progress() -> None:
    network = (
        (SRC / "presentation" / "pages" / "network.py").read_text(encoding="utf-8")
        + "\n"
        + (SRC / "presentation" / "pages" / "network_capture_actions.py").read_text(encoding="utf-8")
    )
    assert 'terminal = state in {"completed", "failed", "cancelled", "idle"}' in network
    assert 'self.operationProgress.emit("Capture", 0, 0, "clear")' in network
    assert "if terminal and state != self._last_capture_state:" in network
