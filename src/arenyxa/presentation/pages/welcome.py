from __future__ import annotations

from arenyxa.qt_compat.QtCore import Signal, Qt
from arenyxa.qt_compat.QtWidgets import (
    QComboBox, QDialog, QFrame, QGridLayout, QLabel, QPushButton, QScrollArea, QSizePolicy,
    QVBoxLayout, QWidget,
)

from arenyxa.application.experience import EXPERIENCE_PROFILES
from arenyxa.navigation import NavigationContextFactory, NavigationResolver, RuntimeMode
from arenyxa.navigation.manifest import DEFAULT_PAGE_MANIFESTS
from arenyxa.presentation.language import source_text
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
        title = QLabel(source_text(f"welcome.profile.{profile.id}.title"))
        title.setProperty("i18n_key_text", f"welcome.profile.{profile.id}.title")
        title.setProperty("section", True)
        title.setStyleSheet("font-size: 18px; font-weight: 700;")
        summary = QLabel(source_text(f"welcome.profile.{profile.id}.summary"))
        summary.setProperty("i18n_key_text", f"welcome.profile.{profile.id}.summary")
        summary.setWordWrap(True)
        summary.setProperty("muted", True)
        layout.addWidget(title)
        layout.addWidget(summary)
        for detail_index, _item in enumerate(profile.detail):
            detail_key = f"welcome.profile.{profile.id}.detail.{detail_index}"
            label = QLabel("• " + source_text(detail_key))
            label.setProperty("i18n_key_text", detail_key)
            label.setWordWrap(True)
            layout.addWidget(label)
        layout.addStretch(1)
        button = QPushButton(source_text("welcome.use_mode"))
        button.setProperty("i18n_key_text", "welcome.use_mode")
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
        self.setWindowTitle(source_text("welcome.title"))
        self.setProperty("i18n_key_window_title", "welcome.title")
        self.setModal(True)
        self.setMinimumSize(760, 600)
        self.resize(980, 760)
        self.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
        self.setWindowOpacity(0.0)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(14)
        layout.addWidget(PageHeader(
            source_text("welcome.title"),
            source_text("welcome.subtitle"),
            title_key="welcome.title",
            subtitle_key="welcome.subtitle",
        ))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        container = QWidget()
        body = QVBoxLayout(container)
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(14)

        scenario = SectionCard(theme, source_text("welcome.scenario.title"), title_key="welcome.scenario.title")
        scenario_hint = QLabel(source_text("welcome.scenario.hint"))
        scenario_hint.setProperty("i18n_key_text", "welcome.scenario.hint")
        scenario_hint.setWordWrap(True)
        scenario_hint.setProperty("muted", True)
        self.personal_scenario = QComboBox()
        self.personal_scenario.addItem(source_text("welcome.scenario.website_analysis"), "website_analysis")
        self.personal_scenario.setProperty("i18n_item_key_0", "welcome.scenario.website_analysis")
        self.personal_scenario.addItem(source_text("welcome.scenario.api_debugging"), "api_debugging")
        self.personal_scenario.setProperty("i18n_item_key_1", "welcome.scenario.api_debugging")
        self.personal_scenario.addItem(source_text("welcome.scenario.network_diagnostics"), "network_diagnostics")
        self.personal_scenario.setProperty("i18n_item_key_2", "welcome.scenario.network_diagnostics")
        self.personal_scenario.addItem(source_text("welcome.scenario.data_collection"), "data_collection")
        self.personal_scenario.setProperty("i18n_item_key_3", "welcome.scenario.data_collection")
        self.personal_scenario.addItem(source_text("welcome.scenario.security_learning"), "security_learning")
        self.personal_scenario.setProperty("i18n_item_key_4", "welcome.scenario.security_learning")
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

        enterprise = SectionCard(theme, source_text("welcome.enterprise.title"), title_key="welcome.enterprise.title")
        enterprise_text = QLabel(source_text("welcome.enterprise.description"))
        enterprise_text.setProperty("i18n_key_text", "welcome.enterprise.description")
        enterprise_text.setWordWrap(True)
        enterprise_text.setProperty("muted", True)
        enterprise.body.addWidget(enterprise_text)
        enterprise_button = QPushButton(source_text("welcome.enterprise.open"))
        enterprise_button.setProperty("i18n_key_text", "welcome.enterprise.open")
        enterprise_button.clicked.connect(lambda: self.profileSelected.emit("enterprise"))
        enterprise.body.addWidget(enterprise_button)
        body.addWidget(enterprise)

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
            server = SectionCard(theme, source_text("welcome.fleet.title"), title_key="welcome.fleet.title")
            server_text = QLabel(source_text("welcome.fleet.description"))
            server_text.setProperty("i18n_key_text", "welcome.fleet.description")
            server_text.setWordWrap(True)
            server_text.setProperty("muted", True)
            server.body.addWidget(server_text)
            server_button = QPushButton(source_text("welcome.fleet.open"))
            server_button.setProperty("i18n_key_text", "welcome.fleet.open")
            server_button.clicked.connect(self.fleetRequested.emit)
            server.body.addWidget(server_button)
            body.addWidget(server)

        note = QLabel(source_text("welcome.note"))
        note.setProperty("i18n_key_text", "welcome.note")
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
