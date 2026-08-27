from __future__ import annotations

from arenyxa.qt_compat.QtCore import Signal, Qt
from arenyxa.qt_compat.QtWidgets import (
    QComboBox, QDialog, QFrame, QGridLayout, QLabel, QPushButton, QScrollArea, QSizePolicy,
    QVBoxLayout, QWidget,
)

from arenyxa.application.experience import EXPERIENCE_PROFILES
from arenyxa.navigation import NavigationContextFactory, NavigationResolver, RuntimeMode
from arenyxa.navigation.manifest import DEFAULT_PAGE_MANIFESTS
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
    fleetRequested = Signal()

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
        self.setWindowOpacity(0.0)

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

        scenario = SectionCard(theme, "Personal 首页场景")
        scenario_hint = QLabel("选择 Personal Mode 时，Arenyxa 会用该场景配置首次进入的首页；之后仍可访问全部个人功能。")
        scenario_hint.setWordWrap(True)
        scenario_hint.setProperty("muted", True)
        self.personal_scenario = QComboBox()
        self.personal_scenario.addItem("网站分析", "website_analysis")
        self.personal_scenario.addItem("API 调试", "api_debugging")
        self.personal_scenario.addItem("网络诊断", "network_diagnostics")
        self.personal_scenario.addItem("数据采集", "data_collection")
        self.personal_scenario.addItem("网络安全学习", "security_learning")
        scenario.body.addWidget(scenario_hint)
        scenario.body.addWidget(self.personal_scenario)
        body.addWidget(scenario)

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
            "企业工作模式提供本地企业身份、设备加入与信任、局域网协调器以及工作区治理。"
            "创建企业会建立独立的企业身份；加入现有企业需要管理员提供的一次性设备加入凭据。"
        )
        enterprise_text.setWordWrap(True)
        enterprise_text.setProperty("muted", True)
        enterprise.body.addWidget(enterprise_text)
        enterprise_button = QPushButton("进入企业工作模式")
        enterprise_button.clicked.connect(lambda: self.profileSelected.emit("enterprise"))
        enterprise.body.addWidget(enterprise_button)
        body.addWidget(enterprise)

        # Do not advertise an operations surface that the live identity cannot open.
        # This is presentation filtering only; NavigationResolver remains the authority.
        navigation = NavigationContextFactory.from_application(context)
        fleet_target = (
            "server_ops"
            if navigation.runtime_mode in {RuntimeMode.SERVER, RuntimeMode.WORKER}
            else "server"
        )
        fleet_allowed = NavigationResolver(DEFAULT_PAGE_MANIFESTS).allowed(
            fleet_target, navigation
        )
        if fleet_allowed:
            server = SectionCard(theme, "Fleet Control")
            server_text = QLabel(
                "集中查看 Enterprise Server、Distributed Worker、并行 Slots、Jobs、Leases、存储拓扑与健康状态。"
                "Fleet Control 只提供已授权的运行与运维视图，不改变 Enterprise 权限边界。"
            )
            server_text.setWordWrap(True)
            server_text.setProperty("muted", True)
            server.body.addWidget(server_text)
            server_button = QPushButton("打开 Fleet Control")
            server_button.clicked.connect(self.fleetRequested.emit)
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

    def selected_personal_scenario(self) -> str:
        return str(self.personal_scenario.currentData() or "website_analysis")

    def showEvent(self, event) -> None:
        super().showEvent(event)
        anchor = self._anchor
        if anchor is not None:
            frame = self.frameGeometry()
            frame.moveCenter(anchor.frameGeometry().center())
            self.move(frame.topLeft())
        self.motion.reveal_window(self, duration_ms=360, offset_px=16)
