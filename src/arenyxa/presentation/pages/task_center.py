from __future__ import annotations

"""Task-oriented landing page used only by the Personal/Simple experience."""

import json
from typing import Any

from arenyxa.qt_compat.QtCore import Signal
from arenyxa.qt_compat.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QScrollArea, QVBoxLayout, QWidget,
)

from arenyxa.application.general_user import GeneralUserIntentRouter, RuntimeCapabilityService
from arenyxa.presentation.background import run_background
from arenyxa.presentation.i18n_runtime import current_text, source_text
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, SectionCard


class _TaskCard(QFrame):
    requested = Signal(str)

    def __init__(self, workflow: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.workflow = workflow
        self.setProperty("card", True)
        self.setMinimumHeight(145)
        layout = QVBoxLayout(self)
        title_key = f"task_center.workflow.{workflow.id}.title"
        summary_key = f"task_center.workflow.{workflow.id}.summary"
        title = QLabel(source_text(title_key))
        title.setProperty("i18n_key_text", title_key)
        title.setProperty("section", True)
        title.setStyleSheet("font-size: 16px; font-weight: 700;")
        summary = QLabel(source_text(summary_key))
        summary.setProperty("i18n_key_text", summary_key)
        summary.setWordWrap(True)
        summary.setProperty("muted", True)
        button = QPushButton(source_text("task_center.action.start"))
        button.setProperty("i18n_key_text", "task_center.action.start")
        button.clicked.connect(lambda: self.requested.emit(workflow.id))
        layout.addWidget(title)
        layout.addWidget(summary)
        layout.addStretch(1)
        layout.addWidget(button)


class TaskCenterPage(WorkspacePage):
    """Simple-mode task center; hidden from Power/Professional/Developer profiles."""

    workflowRequested = Signal(str)
    assistantRequested = Signal(str)

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self.router = GeneralUserIntentRouter()
        outer = page_layout(self)
        outer.addWidget(PageHeader(
            source_text("task_center.page.title"),
            source_text("task_center.page.subtitle"),
            title_key="task_center.page.title",
            subtitle_key="task_center.page.subtitle",
        ))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        body = QVBoxLayout(container)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(12)
        body.addWidget(self._build_assistant(theme))
        body.addWidget(self._build_tasks(theme))
        body.addWidget(self._build_guide(theme))
        body.addWidget(self._build_capabilities(theme))
        body.addStretch(1)
        scroll.setWidget(container)
        outer.addWidget(scroll, 1)
        self._last_workflow_id: str | None = None
        self.refresh_capabilities()

    def _build_assistant(self, theme: Any) -> QWidget:
        card = SectionCard(theme, source_text("task_center.assistant.title"), title_key="task_center.assistant.title")
        hint = QLabel(source_text("task_center.assistant.hint")); hint.setProperty("i18n_key_text", "task_center.assistant.hint")
        hint.setWordWrap(True)
        hint.setProperty("muted", True)
        card.body.addWidget(hint)
        row = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText(source_text("task_center.assistant.placeholder")); self.query.setProperty("i18n_key_placeholder", "task_center.assistant.placeholder")
        self.go = QPushButton(source_text("task_center.assistant.continue")); self.go.setProperty("i18n_key_text", "task_center.assistant.continue")
        row.addWidget(self.query, 1)
        row.addWidget(self.go)
        card.body.addLayout(row)
        self.query.returnPressed.connect(self._submit)
        self.go.clicked.connect(self._submit)
        return card

    def _build_tasks(self, theme: Any) -> QWidget:
        card = SectionCard(theme, source_text("task_center.tasks.title"), title_key="task_center.tasks.title")
        grid = QGridLayout()
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)
        for index, workflow in enumerate(self.router.workflows()):
            task = _TaskCard(workflow)
            task.requested.connect(self._request_workflow)
            grid.addWidget(task, index // 2, index % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        card.body.addLayout(grid)
        return card

    def _build_guide(self, theme: Any) -> QWidget:
        card = SectionCard(theme, source_text("task_center.guide.title"), title_key="task_center.guide.title")
        self.guide = QPlainTextEdit()
        self.guide.setReadOnly(True)
        self.guide.setMaximumHeight(210)
        self.guide.setPlainText(source_text("task_center.guide.initial"))
        card.body.addWidget(self.guide)
        return card

    def _build_capabilities(self, theme: Any) -> QWidget:
        card = SectionCard(theme, source_text("task_center.capability.title"), title_key="task_center.capability.title")
        self.capability = QLabel()
        self.capability.setWordWrap(True)
        self.capability.setProperty("muted", True)
        card.body.addWidget(self.capability)
        return card

    def activated(self) -> None:
        self.refresh_capabilities()

    def refresh_capabilities(self) -> None:
        self.capability.setText(current_text("task_center.capability.checking"))

        def completed(value: object) -> None:
            caps = value if isinstance(value, dict) else {}
            required = {"packet.native", "packet.deep", "capture.system", "browser.automation", "mitm.external"}
            if not required.issubset(caps):
                self.capability.setText(current_text("task_center.capability.incomplete"))
                return
            self.capability.setText(
                current_text("task_center.capability.summary").format(
                    native=caps["packet.native"].state,
                    deep=caps["packet.deep"].state,
                    capture=caps["capture.system"].state,
                    browser=caps["browser.automation"].state,
                    mitm=caps["mitm.external"].state,
                )
            )

        def failed(message: str) -> None:
            self.capability.setText(current_text("task_center.capability.failed").format(message=message))

        run_background(RuntimeCapabilityService().snapshot, completed, failed)

    def show_result(self, title: str, payload: Any) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        self.guide.setPlainText(f"{title}\n\n{text}")

    def _submit(self) -> None:
        text = self.query.text().strip()
        if not text:
            return
        workflow = self.router.resolve(text)
        if workflow is None:
            self.guide.setPlainText(current_text("task_center.assistant.no_match"))
            self.statusMessage.emit(current_text("task_center.assistant.no_match_status"))
            return
        self._show_workflow(workflow)
        self.assistantRequested.emit(text)
        self.workflowRequested.emit(workflow.id)

    def _request_workflow(self, workflow_id: str) -> None:
        workflow = self.router.get(workflow_id)
        self._show_workflow(workflow)
        self.workflowRequested.emit(workflow.id)

    def _show_workflow(self, workflow: Any) -> None:
        self._last_workflow_id = workflow.id
        title = current_text(f"task_center.workflow.{workflow.id}.title")
        steps = [
            current_text(f"task_center.workflow.{workflow.id}.step.{index}")
            for index, _step in enumerate(workflow.steps)
        ]
        lines = [title, "", *[f"{index}. {step}" for index, step in enumerate(steps, 1)]]
        if workflow.fallback_note:
            fallback = current_text(f"task_center.workflow.{workflow.id}.fallback")
            lines.extend(("", current_text("task_center.workflow.fallback_prefix") + fallback))
        self.guide.setPlainText("\n".join(lines))

    def refresh_localized_previews(self) -> None:
        if self._last_workflow_id:
            self._show_workflow(self.router.get(self._last_workflow_id))
        else:
            self.guide.setPlainText(current_text("task_center.guide.initial"))
        self.refresh_capabilities()


__all__ = ["TaskCenterPage"]
