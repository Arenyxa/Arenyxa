from __future__ import annotations
from arenyxa.presentation.pages.studio_intelligence import StudioIntelligenceMixin
from arenyxa.presentation.pages.studio_operations import StudioOperationsMixin

from arenyxa.application.autopilot_validation import AutopilotProductionValidator

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from arenyxa.qt_compat.QtCore import QTimer
from arenyxa.qt_compat.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arenyxa import __version__
from arenyxa.application.nextgen import (
    BrowserAction, DistributedWorker, RequestAssertion,
    SelectorFingerprint, WorkflowDebugger,
)
from arenyxa.application.runtime_ecosystem import BrowserProfile
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import NetworkEvent, RequestSpec, RetryPolicy, Workflow, WorkflowNode
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader


class IntelligenceStudioPage(StudioIntelligenceMixin, StudioOperationsMixin, WorkspacePage):
    





    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        self._debugger = WorkflowDebugger()
        self._last_selector_fingerprint: dict[str, Any] | None = None
        self._last_response = None
        self._last_smartpath: dict[str, Any] | None = None
        self._last_blueprint: dict[str, Any] | None = None
        self._last_portable_workflow: Workflow | None = None
        self._last_autopilot_response = None
        self._last_autopilot_events: list[NetworkEvent] = []
        self._last_autopilot_plan: dict[str, Any] | None = None
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("Web Intelligence", "Explainable Blueprint · SmartPath 2.0 · Context Bridge · Selector Self-Healing · Compatibility Lab · Portable Workflows · Debugger"), 1)
        self.refresh_live_button = QPushButton("Refresh Live Center")
        header.addWidget(self.refresh_live_button)
        layout.addLayout(header)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self._build_smartpath_tab()
        self._build_blueprint_tab()
        self._build_selector_tab()
        self._build_http_tab()
        self._build_protocol_tab()
        self._build_quality_tab()
        self._build_recorder_tab()
        self._build_debugger_tab()
        self._build_secrets_tab()
        self._build_templates_environment_tab()
        self._build_ecosystem_tab()
        self._build_workers_tab()
        self._build_compatibility_tab()
        self._build_portability_tab()
        self._build_live_tab()
        self._build_autopilot_tab()

        self.refresh_live_button.clicked.connect(self.refresh_live)
        self.live_timer = QTimer(self)
        self.live_timer.timeout.connect(self.refresh_live)
        self.live_timer.setInterval(max(500, int(context.performance.status_refresh_ms)))

                                   
    @staticmethod
    def _editor(readonly: bool = False, text: str = "") -> QPlainTextEdit:
        editor = QPlainTextEdit()
        editor.setReadOnly(readonly)
        if text:
            editor.setPlainText(text)
        return editor

    @staticmethod
    def _json(editor: QPlainTextEdit, fallback: Any) -> Any:
        text = editor.toPlainText().strip()
        if not text:
            return fallback
        return json.loads(text)

    def _capture_events(self, session_id: str | None = None, limit: int = 20_000) -> list[NetworkEvent]:
        if not session_id:
            captures = self.context.store.list_captures(limit=1)
            session_id = captures[0]["id"] if captures else None
        if not session_id:
            return []
        events = []
        for raw in self.context.store.iter_network_events(session_id, limit=limit):
            normalized = dict(raw)
            normalized["source_type"] = CaptureSource(normalized["source_type"])
            normalized["sensitivity_flags"] = normalized.pop("sensitivity", [])
            events.append(NetworkEvent(**{key: value for key, value in normalized.items() if key in NetworkEvent.__dataclass_fields__}))
        return events

    def _async(self, fn, output: QPlainTextEdit, success_message: str = "完成") -> None:
        output.setPlainText("Working…")
        def completed(value: object) -> None:
            if isinstance(value, str):
                output.setPlainText(value)
            else:
                output.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit(success_message)
        def failed(message: str) -> None:
            output.setPlainText(message)
            self.statusMessage.emit("操作失败")
        run_background(fn, completed, failed)

                                               




                                                                  



                                    



                                





                                    


                                   



                                    




                                    






                                   





                                                   







                                                                     






                                               



                                             


                                                     





                                                            







                                       







    def activated(self) -> None:
                                                                             
        captures = self.context.store.list_captures(limit=100)
        for combo in (self.smart_session, self.blueprint_session, self.protocol_session, self.autopilot_session):
            selected = combo.currentData(); combo.clear(); combo.addItem("Latest / Auto", None)
            for capture in captures:
                combo.addItem(f"{capture['created_at'][:19]} · {capture['source_type']} · {capture['event_count']}", capture["id"])
                if capture["id"] == selected: combo.setCurrentIndex(combo.count() - 1)
        self.refresh_live(); self.live_timer.start()

    def deactivated(self) -> None:
        self.live_timer.stop()
