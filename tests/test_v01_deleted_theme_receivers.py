from __future__ import annotations

import sys
import pytest

from arenyxa.qt_compat.QtCore import QCoreApplication, QEvent, QObject, Signal
from arenyxa.presentation.glass import GlassPanel
from arenyxa.presentation.widgets import RingGauge, MiniBars


@pytest.mark.parametrize("widget_type", (GlassPanel, RingGauge, MiniBars))
def test_deleted_glass_panel_disconnects_from_long_lived_theme(qapp, monkeypatch, widget_type):
    class Theme(QObject):
        changed = Signal(str)

    theme = Theme()
    errors = []
    monkeypatch.setattr(sys, "excepthook", lambda *error: errors.append(error))
    panel = widget_type(theme)
    panel.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    theme.changed.emit("modern_dark")
    assert errors == []
