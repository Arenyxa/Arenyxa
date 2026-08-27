from __future__ import annotations

from arenyxa.qt_compat.QtCore import Signal, Qt
from arenyxa.qt_compat.QtWidgets import (
    QDialog, QFrame, QGridLayout, QLabel, QPushButton, QScrollArea, QSizePolicy,
    QVBoxLayout, QWidget,
)

from arenyxa.application.experience import EXPERIENCE_PROFILES
from arenyxa.presentation.widgets import PageHeader, SectionCard


class _ExperienceCard(QFrame):
    selected = Signal(str)

    def __init__(self, profile, parent=None) -> None:
        super().__init__(parent)
        self.profile = profile
        self.setProperty("card", True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMinimumHeight(205)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(8)
        title = QLabel(profile.title)
        title.setProperty("section", True)
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        summary = QLabel(profile.summary)
        summary.setWordWrap(True)
        summary.setProperty("muted", True)
        layout.addWidget(title)
        layout.addWidget(summary)
        for item in profile.detail:
            label = QLabel("• " + item)
            label.setWordWrap(True)
            layout.addWidget(label)
        layout.addStretch(1)
        button = QPushButton("使用此模式")
        button.clicked.connect(lambda: self.selected.emit(profile.id))
        layout.addWidget(button)


class WelcomeCenterDialog(QDialog):
    






    profileSelected = Signal(str)
    enterpriseRequested = Signal()

    def __init__(self, context, theme, motion, anchor=None) -> None:
                                                                                               
                                                                                               
        super().__init__(None)
        self._anchor = anchor
        self.context = context
        self.theme = theme
        self.motion = motion
        self.setWindowTitle("欢迎使用 Arenyxa")
        self.setModal(True)
        self.setMinimumSize(760, 600)
        self.resize(980, 760)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)
        layout.addWidget(PageHeader(
            "欢迎使用 Arenyxa",
            "选择最符合你的工作方式。这里只调整工作区呈现与默认导航，不是权限等级；企业身份和开发者身份由独立安全流程建立。",
        ))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        container = QWidget()
        body = QVBoxLayout(container)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(14)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)
        for index, profile in enumerate(EXPERIENCE_PROFILES):
            card = _ExperienceCard(profile)
            card.selected.connect(self.profileSelected.emit)
            grid.addWidget(card, index // 2, index % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        body.addLayout(grid)

        enterprise = SectionCard(theme, "Enterprise & Operations")
        enterprise_text = QLabel(
            "Enterprise 已进入本地身份、Enrollment、Device Trust、Office Coordinator 与 Workspace Governance 阶段。"
            "创建企业和企业治理使用独立的企业管理流程；加入企业需要一次性 Enrollment Credential。"
        )
        enterprise_text.setWordWrap(True)
        enterprise_text.setProperty("muted", True)
        enterprise.body.addWidget(enterprise_text)
        enterprise_button = QPushButton("打开企业管理")
        enterprise_button.clicked.connect(self.enterpriseRequested.emit)
        enterprise.body.addWidget(enterprise_button)
        body.addWidget(enterprise)

        server = SectionCard(theme, "Server / Worker")
        server_text = QLabel(
            "Enterprise Server / Distributed Worker 已进入 Phase 11 开发运行时，并继续复用同一套 Core Runtime。"
            "打开企业管理可查看 Server、Worker、队列与远程运维状态。"
        )
        server_text.setWordWrap(True)
        server_text.setProperty("muted", True)
        server.body.addWidget(server_text)
        server_button = QPushButton("打开 Server / Worker 管理")
        server_button.clicked.connect(self.enterpriseRequested.emit)
        server.body.addWidget(server_button)
        body.addWidget(server)

        note = QLabel(
            "之后可在 设置 → 使用模式 重新打开此独立窗口。主题、字体、缩放与动效继续放在独立“个性化”页面。"
        )
        note.setWordWrap(True)
        note.setProperty("muted", True)
        body.addWidget(note)
        body.addStretch(1)
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        anchor = self._anchor
        if anchor is not None:
            frame = self.frameGeometry()
            frame.moveCenter(anchor.frameGeometry().center())
            self.move(frame.topLeft())
