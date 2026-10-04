from __future__ import annotations

from types import SimpleNamespace

import pytest

from arenyxa.domain.enums import CaptureSource
from arenyxa.presentation.pages import network_capture_actions as actions
from arenyxa.qt_compat.QtWidgets import QComboBox, QLineEdit


@pytest.mark.parametrize("source", (CaptureSource.HAR_IMPORT, CaptureSource.PCAP_IMPORT))
def test_qt_string_data_dispatches_to_offline_file_import(qapp, monkeypatch, source):
    combo = QComboBox()
    combo.addItem("Translated label", source)
    observed = []
    monkeypatch.setattr(actions.QFileDialog, "getOpenFileName", lambda *args: (observed.append("file") or "", ""))
    monkeypatch.setattr(actions.QInputDialog, "getText", lambda *args, **kwargs: (observed.append("system") or "", False))
    monkeypatch.setattr(actions.QMessageBox, "critical", lambda *args: observed.append("error"))
    page = SimpleNamespace(source=combo, filter=QLineEdit())
    actions.NetworkCaptureActionsMixin.start_capture(page)
    assert observed == ["file"]
