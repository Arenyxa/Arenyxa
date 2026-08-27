from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_launch_geometry_is_resolved_once_and_shared_by_splash_and_main_window() -> None:
    app = (SRC / "app.py").read_text(encoding="utf-8")
    main = app[app.index("def main("):]
    splash = app[app.index("def _create_runtime_splash"):app.index("def _show_bootstrap_recovery")]
    resolve = main.index('launch_geometry = resolve_launch_geometry(paths.root / "window.ini")')
    splash_call = main.index("startup_splash = _create_runtime_splash(")
    bootstrap = main.index("context = bootstrap(")
    main_geometry = main.index("launch_geometry=launch_geometry")
    show = main.index("if launch_geometry.maximized:")
    finish = main.index("startup_splash.finish(window)")
    assert "geometry=launch_geometry.rect" in splash
    assert resolve < splash_call < bootstrap < main_geometry < show < finish


def test_splash_no_longer_chooses_primary_screen_on_the_normal_path() -> None:
    splash = (SRC / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    assert "def _place_on_launch_geometry" in splash
    assert "if geometry is not None and geometry.isValid():" in splash
    assert "self.setGeometry(QRect(geometry))" in splash
                                                                                                    
    start = splash.index("def _place_on_launch_geometry")
    fallback = splash.index("app = QApplication.instance()", start)
    normal_path = splash[start:fallback]
    assert "primaryScreen" not in normal_path


def test_main_window_reuses_launch_geometry_and_persists_monitor_identity() -> None:
    main = ((SRC / "presentation" / "main_window.py").read_text(encoding="utf-8") + "\n" + (SRC / "presentation" / "main_window_lifecycle.py").read_text(encoding="utf-8"))
    assert "launch_geometry: LaunchGeometryPlan | None = None" in main
    assert "self.setGeometry(self._launch_geometry.rect)" in main
    assert 'settings.setValue("screen_name"' in main
    assert 'settings.setValue("maximized", bool(self.isMaximized()))' in main
    assert 'screen_at(launch_geometry.rect.center())' in main
    assert 'target_screen.refreshRate()' in main


def test_startup_handoff_becomes_a_child_overlay_inside_main_window() -> None:
    splash = (SRC / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    assert "class _StartupHandoffOverlay(QWidget):" in splash
    assert "super().__init__(parent)" in splash
    assert 'self.setObjectName("ArenyxaStartupHandoffOverlay")' in splash
    assert "self.setGeometry(parent.rect())" in splash
    assert "overlay.present()" in splash
    assert "app.processEvents()" in splash
    assert "self.hide()" in splash
    assert "overlay.start_exit()" in splash
    assert splash.index("overlay.present()") < splash.index("self.hide()", splash.index("overlay.present()"))


def test_handoff_overlay_does_not_intercept_input_or_block_readiness() -> None:
    splash = (SRC / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    assert "WA_TransparentForMouseEvents" in splash
    assert "QTimer.singleShot(0, animation.start)" in splash
    assert "time.sleep" not in splash
    assert ".exec()" not in splash


def test_launch_geometry_clamps_restored_window_to_connected_screens() -> None:
    geometry = (SRC / "presentation" / "launch_geometry.py").read_text(encoding="utf-8")
    assert "def _screen_by_name" in geometry
    assert "def _screen_for_rect" in geometry
    assert "def _screen_under_cursor" in geometry
    assert "def _clamp_rect_to_screen" in geometry
    assert 'settings.value("screen_name", "")' in geometry
    assert 'settings.value("maximized", None)' in geometry
    assert "screen.availableGeometry()" in geometry


def test_recovery_mode_stays_on_the_same_resolved_launch_display() -> None:
    app = (SRC / "app.py").read_text(encoding="utf-8")
    boundary = app.index('recovery_window = QMainWindow()')
    show = app.index('recovery_window.show()', boundary)
    block = app[boundary:show]
    assert 'launch_geometry.rect.width()' in block
    assert 'launch_geometry.rect.height()' in block
    assert 'recovery_window.setGeometry(' in block
