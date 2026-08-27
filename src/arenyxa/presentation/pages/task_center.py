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
        title = QLabel(workflow.title)
        title.setProperty("section", True)
        title.setStyleSheet("font-size: 16px; font-weight: 700;")
        summary = QLabel(workflow.summary)
        summary.setWordWrap(True)
        summary.setProperty("muted", True)
        button = QPushButton("开始")
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
            "Arenyxa 简单模式",
            "告诉 Arenyxa 你想完成什么。底层专业能力保持不变，但这里不要求理解模块、协议栈或命令树。",
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
        self.refresh_capabilities()

    def _build_assistant(self, theme: Any) -> QWidget:
        card = SectionCard(theme, "快速助手")
        hint = QLabel("例如：分析这个 PCAP、检查 DNS 隧道、看看电脑连接了哪些服务器、调试 API")
        hint.setWordWrap(True)
        hint.setProperty("muted", True)
        card.body.addWidget(hint)
        row = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("直接输入你想做的事…")
        self.go = QPushButton("继续")
        row.addWidget(self.query, 1)
        row.addWidget(self.go)
        card.body.addLayout(row)
        self.query.returnPressed.connect(self._submit)
        self.go.clicked.connect(self._submit)
        return card

    def _build_tasks(self, theme: Any) -> QWidget:
        card = SectionCard(theme, "常用任务")
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
        card = SectionCard(theme, "操作步骤 / 分析结果")
        self.guide = QPlainTextEdit()
        self.guide.setReadOnly(True)
        self.guide.setMaximumHeight(210)
        self.guide.setPlainText("选择上面的任务后，这里会展示简化步骤。高级参数只在需要时出现。")
        card.body.addWidget(self.guide)
        return card

    def _build_capabilities(self, theme: Any) -> QWidget:
        card = SectionCard(theme, "运行能力")
        self.capability = QLabel()
        self.capability.setWordWrap(True)
        self.capability.setProperty("muted", True)
        card.body.addWidget(self.capability)
        return card

    def activated(self) -> None:
        self.refresh_capabilities()

    def refresh_capabilities(self) -> None:
        self.capability.setText("正在检查本机运行能力… 这不会影响原生 PCAP 分析。")

        def completed(value: object) -> None:
            caps = value if isinstance(value, dict) else {}
            required = {"packet.native", "packet.deep", "capture.system", "browser.automation", "mitm.external"}
            if not required.issubset(caps):
                self.capability.setText("能力检查返回不完整；原生 PCAP 分析仍可使用。")
                return
            self.capability.setText(
                f"PCAP 原生分析：{caps['packet.native'].state} · 深度协议：{caps['packet.deep'].state} · "
                f"系统抓包：{caps['capture.system'].state} · 浏览器：{caps['browser.automation'].state} · "
                f"高级 MITM：{caps['mitm.external'].state}\n"
                "缺少或失效的可选组件会自动降级到原生/内置路径，并明确提示影响范围。"
            )

        def failed(message: str) -> None:
            self.capability.setText(f"能力检查暂时不可用：{message}；原生 PCAP 分析仍可使用。")

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
            self.guide.setPlainText("没有找到足够明确的任务。可尝试：分析 PCAP / 抓包 / 安全检查 / 调试 API / 分析网站 / 网络诊断。")
            self.statusMessage.emit("简单模式没有识别该任务；请换一种说法。")
            return
        self._show_workflow(workflow)
        self.assistantRequested.emit(text)
        self.workflowRequested.emit(workflow.id)

    def _request_workflow(self, workflow_id: str) -> None:
        workflow = self.router.get(workflow_id)
        self._show_workflow(workflow)
        self.workflowRequested.emit(workflow.id)

    def _show_workflow(self, workflow: Any) -> None:
        lines = [workflow.title, "", *[f"{index}. {step}" for index, step in enumerate(workflow.steps, 1)]]
        if workflow.fallback_note:
            lines.extend(("", "自动降级：" + workflow.fallback_note))
        self.guide.setPlainText("\n".join(lines))


__all__ = ["TaskCenterPage"]
