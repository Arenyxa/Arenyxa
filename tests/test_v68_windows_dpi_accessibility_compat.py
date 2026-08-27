from __future__ import annotations

import ast
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arenyxa.bootstrap import bootstrap
from arenyxa.branding import LEGACY_RUNTIME_TIER_ENV, RUNTIME_TIER_ENV
from arenyxa.domain.models import MotionProfile
from arenyxa.platform_compat import (
    LEGACY_RUNTIME,
    MODERN_RUNTIME,
    WindowsVersion,
    select_runtime,
    windows_reduced_motion_requested,
)

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_explicit_legacy_tier_is_available_on_modern_windows_without_changing_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows_11 = WindowsVersion(10, 0, 22631, 0)
    monkeypatch.delenv(RUNTIME_TIER_ENV, raising=False)
    monkeypatch.delenv(LEGACY_RUNTIME_TIER_ENV, raising=False)

    assert select_runtime(platform_name="nt", win_version=windows_11) is MODERN_RUNTIME
    assert (
        select_runtime(
            platform_name="nt",
            win_version=windows_11,
            runtime_tier="legacy-enterprise",
        )
        is LEGACY_RUNTIME
    )

    monkeypatch.setenv(RUNTIME_TIER_ENV, "legacy-enterprise")
    assert select_runtime(platform_name="nt", win_version=windows_11) is LEGACY_RUNTIME


def test_windows_reduced_motion_query_is_success_only_and_failure_safe() -> None:
    def query_with_value(value: int, *, success: int = 1):
        def query(_action, _parameter, pointer, _flags):
            ctypes.cast(pointer, ctypes.POINTER(ctypes.c_int)).contents.value = value
            return success

        return query

    assert windows_reduced_motion_requested(
        platform_name="nt",
        system_parameters_info=query_with_value(0),
    )
    assert not windows_reduced_motion_requested(
        platform_name="nt",
        system_parameters_info=query_with_value(1),
    )
    assert not windows_reduced_motion_requested(
        platform_name="nt",
        system_parameters_info=query_with_value(0, success=0),
    )
    assert not windows_reduced_motion_requested(
        platform_name="posix",
        system_parameters_info=lambda *_args: pytest.fail("native query should not run"),
    )


@pytest.mark.parametrize(("width", "height"), [(960, 540), (800, 600)])
def test_small_logical_desktop_keeps_splash_and_main_window_geometry_continuous(
    qapp,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    width: int,
    height: int,
) -> None:
    from arenyxa.presentation.launch_geometry import LaunchGeometryPlan
    from arenyxa.qt_compat.QtCore import QRect

    monkeypatch.setattr("arenyxa.bootstrap.windows_reduced_motion_requested", lambda: True)
    context = bootstrap(tmp_path / "small-dpi-runtime")
    window = None
    try:
        from arenyxa.presentation.main_window import MainWindow

        plan = LaunchGeometryPlan(QRect(40, 30, width, height), "offscreen", False, False)
        window = MainWindow(context, launch_geometry=plan)
        window.show()
        qapp.processEvents()

        assert (window.minimumWidth(), window.minimumHeight()) == (width, height)
        assert (window.width(), window.height()) == (width, height)
        assert window.motion.profile.reduce_motion is True
        assert context.system_reduce_motion is True
        assert context.settings.reduce_motion is False
        replacement = MotionProfile(reduce_motion=False)
        window.motion.set_profile(replacement)
        assert replacement.reduce_motion is False
        assert window.motion.profile.reduce_motion is True
    finally:
        if window is not None:
            window.close()
            qapp.processEvents()
        else:
            context.shutdown()

    persisted = json.loads((context.paths.root / "settings.json").read_text(encoding="utf-8"))
    assert persisted["reduce_motion"] is False


def test_startup_logo_uses_physical_pixels_for_device_ratio() -> None:
    from arenyxa.qt_compat import binding_available

    if not binding_available():
        pytest.skip("No supported Qt binding is installed")

    script = """
import json
from pathlib import Path
from arenyxa.presentation.startup_splash import StartupSplash
from arenyxa.qt_compat.QtCore import QRect
from arenyxa.qt_compat.QtWidgets import QApplication

application = QApplication([])
splash = StartupSplash(
    Path('src/arenyxa/resources/icons/arenyxa.png'),
    animated=False,
    geometry=QRect(0, 0, 960, 540),
)
pixmap = splash._icon.pixmap()
print(json.dumps({
    'widget_dpr': splash.devicePixelRatioF(),
    'icon_size': splash._icon_size,
    'pixel_width': pixmap.width(),
    'pixmap_dpr': pixmap.devicePixelRatio(),
}))
"""
    environment = dict(os.environ)
    environment["QT_QPA_PLATFORM"] = "offscreen"
    environment["QT_SCALE_FACTOR"] = "2"
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=20,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    assert payload["widget_dpr"] == pytest.approx(2.0)
    assert payload["pixmap_dpr"] == pytest.approx(2.0)
    assert payload["pixel_width"] == payload["icon_size"] * 2


def test_every_nextgen_text_subprocess_has_decode_error_fallback() -> None:
    tree = ast.parse((SRC / "application" / "nextgen_runtime.py").read_text(encoding="utf-8"))
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function = node.func
        if not (
            isinstance(function, ast.Attribute)
            and function.attr == "run"
            and isinstance(function.value, ast.Name)
            and function.value.id == "subprocess"
        ):
            continue
        keywords = {item.arg: item.value for item in node.keywords if item.arg is not None}
        if isinstance(keywords.get("text"), ast.Constant) and keywords["text"].value is True:
            calls.append(keywords)

    assert len(calls) == 4
    assert all(
        isinstance(call.get("errors"), ast.Constant) and call["errors"].value == "replace"
        for call in calls
    )


def test_source_launcher_probes_all_core_runtime_dependencies() -> None:
    launcher = (ROOT / "scripts" / "launch.ps1").read_text(encoding="utf-8")
    assert "$EnvironmentProbe = @'" in launcher
    assert "importlib.import_module(module_name)" in launcher
    for module_name in ("lxml", "cssselect", "dns", "openpyxl", "cryptography", "tzdata"):
        assert f'"{module_name}"' in launcher

    app = (SRC / "app.py").read_text(encoding="utf-8")
    assert "system_reduce_motion = windows_reduced_motion_requested()" in app
    assert "startup_settings.reduce_motion or system_reduce_motion" in app
