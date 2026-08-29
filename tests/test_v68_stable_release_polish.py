from __future__ import annotations

from concurrent.futures import Future
from pathlib import Path

import arenyxa
from arenyxa.application.runner import RunHandle
from arenyxa.domain.enums import RunStatus
from arenyxa.domain.models import Run
from arenyxa.presentation.startup_motion_math import handoff_visuals, reveal_radius, smootherstep

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_v68_stable_identity_is_consistent_across_runtime_and_packaging() -> None:
    assert arenyxa.__version__ == "8.1"
    assert arenyxa.__package_version__ == "8.1.0"
    assert arenyxa.__compat_version__ == "6.8.0"
    assert 'version = "8.1.1"' in (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    version_info = (ROOT / "packaging" / "version_info.txt").read_text(encoding="utf-8")
    installer = (ROOT / "packaging" / "installer.iss").read_text(encoding="utf-8")
    legacy = (ROOT / "packaging" / "installer_win7.iss").read_text(encoding="utf-8")
    assert "filevers=(8,1,1,0)" in version_info
    assert "Arenyxa V8.1" in version_info
    assert "Beta" not in version_info
    assert '#define MyAppVersion "8.1.1"' in installer
    assert "OutputBaseFilename=Arenyxa_V8.1.1_Setup_x64" in installer
    assert '#define MyAppVersion "8.1"' in legacy
    assert "OutputBaseFilename=Arenyxa_V8.1_Legacy_Win7_x64_Setup" in legacy


def test_startup_smootherstep_is_bounded_monotonic_and_has_soft_endpoints() -> None:
    samples = [smootherstep(index / 200.0) for index in range(201)]
    assert samples[0] == 0.0
    assert samples[-1] == 1.0
    assert all(0.0 <= value <= 1.0 for value in samples)
    assert all(left <= right for left, right in zip(samples, samples[1:]))
                                                                                    
    start_delta = samples[1] - samples[0]
    middle_delta = samples[101] - samples[100]
    end_delta = samples[-1] - samples[-2]
    assert start_delta < middle_delta * 0.02
    assert end_delta < middle_delta * 0.02


def test_startup_handoff_hides_brand_before_workspace_becomes_materially_visible() -> None:
    previous_icon = 1.0
    previous_reveal = 0.0
    for index in range(201):
        scale, icon_opacity, reveal_progress = handoff_visuals(index / 200.0, allow_scale=True)
        assert 1.0 <= scale <= 1.920001
        assert 0.0 <= icon_opacity <= previous_icon + 1e-9
        assert previous_reveal - 1e-9 <= reveal_progress <= 1.0
        previous_icon = icon_opacity
        previous_reveal = reveal_progress
    assert handoff_visuals(0.64, allow_scale=True)[0] > 1.8
    assert handoff_visuals(0.64, allow_scale=False)[0] == 1.0


def test_startup_reveal_radius_covers_wide_tall_and_high_dpi_logical_surfaces() -> None:
    for width, height in ((360, 800), (1920, 1080), (3840, 1080), (1800, 3200)):
        radii = [reveal_radius(width, height, index / 100.0) for index in range(101)]
        assert radii[0] == 0.0
        assert all(left <= right for left, right in zip(radii, radii[1:]))
        assert radii[-1] > ((width * width + height * height) ** 0.5) / 2.0


def test_startup_handoff_uses_single_paint_surface_not_per_frame_pixmap_resampling() -> None:
    source = (SRC / "presentation" / "startup_splash.py").read_text(encoding="utf-8")
    overlay = source[source.index("class _StartupHandoffOverlay"):source.index("class StartupSplash")]
    assert "def paintEvent" in overlay
    assert "SmoothPixmapTransform" in overlay
    assert "QGraphicsOpacityEffect" not in overlay
    assert "self._base_pixmap.scaled" not in overlay
    assert "self._icon_scale" in overlay
    assert "self._reveal_progress" in overlay
    assert "self._workspace_snapshot" in overlay
    assert "parent.grab()" in overlay
    assert "painter.setClipPath(aperture)" in overlay
    assert "painter.drawPixmap(0, 0, self._workspace_snapshot)" in overlay
    assert "class _SmoothFrameDriver" in source
    assert "Qt.TimerType.PreciseTimer" in source


def test_startup_mask_native_qt_render_reveals_center_then_entire_workspace(qapp) -> None:
    from arenyxa.presentation.startup_splash import _StartupHandoffOverlay
    from arenyxa.qt_compat.QtGui import QPixmap
    from arenyxa.qt_compat.QtWidgets import QWidget

    parent = QWidget()
    try:
        parent.resize(640, 400)
        parent.setStyleSheet("background:#c82850")
        parent.show()
        qapp.processEvents()
        icon = QPixmap(str(SRC / "resources" / "icons" / "arenyxa.png"))
        overlay = _StartupHandoffOverlay(
            parent,
            icon,
            icon_size=120,
            animated=False,
            performance_mode="balanced",
        )
        overlay.present()
        qapp.processEvents()
        assert overlay.capture_workspace()

        overlay._icon_opacity = 0.0
        overlay._reveal_progress = 0.35
        middle = QPixmap(parent.size())
        overlay.render(middle)
        middle_image = middle.toImage()
        assert middle_image.pixelColor(320, 200).getRgb()[:3] == (200, 40, 80)
        assert middle_image.pixelColor(5, 5).getRgb()[:3] == (3, 7, 6)

        overlay._reveal_progress = 1.0
        completed = QPixmap(parent.size())
        overlay.render(completed)
        completed_image = completed.toImage()
        assert completed_image.pixelColor(320, 200).getRgb()[:3] == (200, 40, 80)
        assert completed_image.pixelColor(5, 5).getRgb()[:3] == (200, 40, 80)
    finally:
        parent.close()


def test_startup_handoff_preserves_prepare_show_finish_order_and_multimonitor_geometry() -> None:
    app = (SRC / "app.py").read_text(encoding="utf-8")
    prepare = app.index("startup_splash.prepare_handoff(window)")
    show = app.index("if launch_geometry.maximized:", prepare)
    finish = app.index("startup_splash.finish(window)", show)
    assert prepare < show < finish
    assert "resolve_launch_geometry(paths.root / \"window.ini\")" in app
    assert "launch_geometry=launch_geometry" in app


def test_repair_single_console_contract_is_still_present() -> None:
    recovery = (SRC / "repair_recovery.py").read_text(encoding="utf-8")
    assert 'return str(sys.executable)' in recovery
    assert 'command = [source_python_executable(), "-m", "arenyxa", "--post-repair"]' in recovery
    assert 'with_name("pythonw.exe")' not in recovery
    assert 'getattr(subprocess, "CREATE_NO_WINDOW", 0)' in recovery
    assert 'getattr(subprocess, "DETACHED_PROCESS", 0)' in recovery
    assert "stdin=subprocess.DEVNULL" in recovery
    assert "stdout=subprocess.DEVNULL" in recovery
    assert "stderr=subprocess.DEVNULL" in recovery


def test_capture_terminal_state_still_clears_indeterminate_progress() -> None:
    network = (
        (SRC / "presentation" / "pages" / "network.py").read_text(encoding="utf-8")
        + "\n"
        + (SRC / "presentation" / "pages" / "network_capture_actions.py").read_text(encoding="utf-8")
    )
    assert 'terminal = state in {"completed", "failed", "cancelled", "idle"}' in network
    assert 'self.operationProgress.emit("Capture", 0, 0, "clear")' in network


class _FailingToken:
    cancelled = False
    paused = False

    def pause(self) -> None:
        raise RuntimeError("synthetic pause failure")

    def resume(self) -> None:
        raise RuntimeError("synthetic resume failure")

    def cancel(self) -> None:
        self.cancelled = True


def _pending_future() -> Future[Run]:
    return Future()


def test_pause_token_failure_never_changes_visible_or_durable_state() -> None:
    run = Run(task_id="task", task_snapshot={})
    run.status = RunStatus.RUNNING
    persisted: list[RunStatus] = []
    handle = RunHandle(
        run=run,
        token=_FailingToken(),                          
        future=_pending_future(),
        persist_status=lambda _run_id, status: persisted.append(status) is None,
    )
    handle.pause()
    assert run.status == RunStatus.RUNNING
    assert persisted == []


def test_resume_token_failure_never_changes_visible_or_durable_state() -> None:
    run = Run(task_id="task", task_snapshot={})
    run.status = RunStatus.PAUSED
    persisted: list[RunStatus] = []
    token = _FailingToken()
    token.paused = True
    handle = RunHandle(
        run=run,
        token=token,                          
        future=_pending_future(),
        persist_status=lambda _run_id, status: persisted.append(status) is None,
    )
    handle.resume()
    assert run.status == RunStatus.PAUSED
    assert persisted == []


def test_release_critical_static_analysis_is_packaging_blocking() -> None:
    script = (ROOT / "scripts" / "test.ps1").read_text(encoding="utf-8")
    assert "Running release-blocking critical Ruff" in script
    assert "static_quality_gate.py" in script
    assert "Static quality gate failed" in script
    assert "do not block packaging" not in script
