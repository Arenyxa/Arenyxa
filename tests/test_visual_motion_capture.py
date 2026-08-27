from __future__ import annotations

import pytest

from arenyxa.qt_compat import binding_available
if not binding_available():
    pytest.skip("No supported Qt binding is installed", allow_module_level=True)

from arenyxa.qt_compat.QtCore import Qt
from arenyxa.qt_compat.QtWidgets import QLineEdit

from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.infrastructure.capture.controller import CaptureController
from arenyxa.presentation.language import LanguageManager
from arenyxa.presentation.motion import FrameProfiler
from arenyxa.presentation.themes import THEMES, ThemeManager


def test_six_theme_presets_preserve_widget_state(qapp) -> None:
    assert set(THEMES) == {
        "clean_light",
        "modern_dark",
        "professional_graphite",
        "terminal_green",
        "blue_productivity",
        "aurora_glass",
    }
    widget = QLineEdit("business-state")
    manager = ThemeManager(qapp, "clean_light")
    for theme_id in THEMES:
        manager.apply(theme_id, widget)
        assert manager.current.id == theme_id
        assert widget.text() == "business-state"
        assert qapp.styleSheet()


def test_locale_direction_and_frame_quality(qapp) -> None:
    languages = LanguageManager(qapp, "zh_CN")
    languages.apply("ar_SA")
                                                                                             
    assert qapp.layoutDirection() == Qt.LayoutDirection.LeftToRight
    languages.apply("zh_CN")
    assert qapp.layoutDirection() == Qt.LayoutDirection.LeftToRight

    profiler = FrameProfiler(120)
    for _ in range(60):
        profiler.record(20.0)
    assert profiler.snapshot()["quality"] == "efficiency"
    assert profiler.snapshot()["dropped_frames"] == 60


def test_capture_backpressure_accounts_for_drops(store) -> None:
    emitted = 10_000

    class BurstAdapter:
        def start(self, session, emit) -> None:
            for index in range(emitted):
                emit(
                    NetworkEvent(
                        session.id,
                        CaptureSource.BROWSER,
                        "https",
                        "bidirectional",
                        index,
                        host="example.com",
                    )
                )

        def stop(self) -> None:
            return

        def pause(self) -> None:
            return

        def resume(self) -> None:
            return

    controller = CaptureController(store, queue_capacity=8, flush_size=100)
    session = CaptureSession("burst", CaptureSource.BROWSER)
    controller.prepare(session, BurstAdapter())
    controller.start()
    completed = controller.stop()
    assert completed.state is CaptureState.COMPLETED
    assert completed.event_count + completed.dropped_events == emitted
    assert completed.dropped_events > 0
