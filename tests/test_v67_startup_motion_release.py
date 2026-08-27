from __future__ import annotations

from pathlib import Path

import arenyxa
ROOT = Path(__file__).resolve().parents[1]


def test_v67_public_and_packaging_identity_are_aligned() -> None:
    assert arenyxa.__version__ == "8.1"
    assert arenyxa.__package_version__ == "8.1.0"
    assert arenyxa.__compat_version__ == "6.8.0"
    assert 'version = "8.1.0"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    version_info = (ROOT / "packaging" / "version_info.txt").read_text(encoding="utf-8")
    assert "filevers=(8,1,0,0)" in version_info
    assert "FileDescription', 'Arenyxa V8.1'" in version_info
    assert "ProductVersion', '8.1'" in version_info

    installer = (ROOT / "packaging" / "installer.iss").read_text(encoding="utf-8")
    legacy = (ROOT / "packaging" / "installer_win7.iss").read_text(encoding="utf-8")
    assert '#define MyAppVersion "8.1"' in installer
    assert "OutputBaseFilename=Arenyxa_V8.1_Setup_x64" in installer
    assert '#define MyAppVersion "8.1"' in legacy
    assert "OutputBaseFilename=Arenyxa_V8.1_Legacy_Win7_x64_Setup" in legacy


def test_v67_splash_never_uses_blocking_cosmetic_waits() -> None:
    source = (ROOT / "src" / "arenyxa" / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    assert "time.sleep" not in source
    assert ".exec()" not in source
    assert ".exec_(" not in source
    assert "class _SmoothFrameDriver(QObject):" in source
    assert "Qt.TimerType.PreciseTimer" in source
    assert "screen.refreshRate()" in source
    assert "time.perf_counter()" in source
    assert "QVariantAnimation" not in source
    assert "QEasingCurve" not in source
    motion_math = (ROOT / "src" / "arenyxa" / "presentation" / "startup_motion_math.py").read_text(encoding="utf-8")
    assert "def smootherstep" in motion_math
    assert "t * t * t * (t * (t * 6.0 - 15.0) + 10.0)" in motion_math
    assert "app.processEvents()" in source


def test_v67_startup_order_keeps_bootstrap_and_recovery_authoritative() -> None:
    source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    main = source[source.index("def main("):]
    splash_helper = source[source.index("def _create_runtime_splash"):source.index("def _show_bootstrap_recovery")]
    recovery_helper = source[source.index("def _show_bootstrap_recovery"):source.index("def _make_runtime_finalizer")]
    splash_call = main.index("startup_splash = _create_runtime_splash(")
    bootstrap = main.index("context = bootstrap(")
    show_main = main.index("window.show()")
    finish = main.index("startup_splash.finish(window)")
    assert "startup_splash.present()" in splash_helper
    assert splash_call < bootstrap < show_main < finish

    abort = recovery_helper.index("startup_splash.abort()")
    recovery_show = recovery_helper.index("recovery_window.show()")
    assert abort < recovery_show


def test_v67_splash_has_accessibility_and_diagnostic_bypasses() -> None:
    source = (ROOT / "src" / "arenyxa" / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    assert "if safe_mode or smoke_test or reduced_visuals:" in source
    assert "animated=not bool(reduce_motion)" in source
    assert 'self._performance_mode != "efficiency"' in source
    motion_math = (ROOT / "src" / "arenyxa" / "presentation" / "startup_motion_math.py").read_text(encoding="utf-8")
    assert 'if mode == "efficiency":' in motion_math
    assert "return 360" in motion_math
    assert "Startup splash creation failed; continuing with ordinary startup" in source


def test_v67_splash_uses_approved_application_icon() -> None:
    source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    assert "preferred_window_icon_path()" in source
    assert "create_startup_splash(" in source
    assert "ArenyxaStartupSplash" in (ROOT / "src" / "arenyxa" / "presentation" / "startup_splash.py").read_text(encoding="utf-8")


def test_v67_splash_is_never_a_hard_startup_dependency() -> None:
    source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    assert 'LOGGER.exception("Startup splash failed; continuing with ordinary startup")' in source
    assert "startup_splash = None" in source


def test_v67_main_window_construction_failure_releases_bootstrapped_resources() -> None:
    source = (ROOT / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    boundary = source.index("window = MainWindow(context")
    cleanup = source.index("context.shutdown()", boundary)
    lease_release = source.index("data_root_lease.release()", cleanup)
    error_surface = source.index("Arenyxa interface initialization failed", lease_release)
    assert boundary < cleanup < lease_release < error_surface


def test_startup_frame_driver_tracks_high_refresh_displays_without_timer_drift() -> None:
    from arenyxa.presentation.startup_motion_math import frame_interval_ms

    assert frame_interval_ms(60.0) == 16
    assert frame_interval_ms(120.0) == 8
    assert frame_interval_ms(144.0) == 6
    assert frame_interval_ms(165.0) == 6
    assert frame_interval_ms(240.0) == 4
    assert frame_interval_ms(float("nan")) == 16

    source = (ROOT / "src" / "arenyxa" / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    driver = source[source.index("class _SmoothFrameDriver"):source.index("class _StartupHandoffOverlay")]
    assert "progress = _clamp01((time.perf_counter() - self._started_at) / self._duration_s)" in driver
    assert "self._timer.timeout.connect(self._tick)" in driver
    assert "self._timer.setTimerType(Qt.TimerType.PreciseTimer)" in driver
