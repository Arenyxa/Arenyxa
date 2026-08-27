from __future__ import annotations

from arenyxa.qt_compat.QtWidgets import QHBoxLayout, QLabel, QTabWidget, QVBoxLayout, QWidget

from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.pages.mitm_proxy import MitmInterceptionPage
from arenyxa.presentation.pages.network import NetworkPage
from arenyxa.presentation.pages.proxy import ProxyPage
from arenyxa.presentation.pages.traffic_forensics import TrafficForensicsPage
from arenyxa.presentation.pages.zero_trust import ZeroTrustPage
from arenyxa.presentation.pages.dlp import DataLossPreventionPage
from arenyxa.presentation.pages.studio import IntelligenceStudioPage
from arenyxa.presentation.pages.tools import AutomationPage, WorkflowPage
from arenyxa.presentation.widgets import PageHeader


class ProfessionalSuitePage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Professional Suite",
                "Packet intelligence, interception proxy, MITM automation, web extraction and workflow orchestration in one workspace",
            ),
            1,
        )
        root.addLayout(header)

        note = QLabel(
            "Shared professional surface: inspect packets, decrypt and edit authorized HTTP(S) traffic, apply rules and replay flows, "
            "discover web data sources, then move results into workflows and scheduled automation without duplicating tool-specific shells."
        )
        note.setWordWrap(True)
        note.setProperty("muted", True)
        root.addWidget(note)

        self.tabs = QTabWidget()
        self.packet_page = NetworkPage(context, theme, motion, self)
        self.proxy_page = ProxyPage(context, theme, motion, self)
        self.mitm_page = MitmInterceptionPage(context, theme, motion, self)
        self.extraction_page = IntelligenceStudioPage(context, theme, motion, self)
        self.forensics_page = TrafficForensicsPage(context, theme, motion, self)
        self.zero_trust_page = ZeroTrustPage(context, theme, motion, self)
        self.dlp_page = DataLossPreventionPage(context, theme, motion, self)
        self.workflow_page = WorkflowPage(context, theme, motion, self)
        self.automation_page = AutomationPage(context, theme, motion, self)

        self.tabs.addTab(self.packet_page, "Packet Intelligence")
        self.tabs.addTab(self.proxy_page, "Intercept & Debug")
        self.tabs.addTab(self.mitm_page, "MITM Proxy")
        self.tabs.addTab(self.extraction_page, "Extraction Lab")
        self.tabs.addTab(self.forensics_page, "Traffic Forensics")
        self.tabs.addTab(self.zero_trust_page, "Zero Trust")
        self.tabs.addTab(self.dlp_page, "DLP")
        self.tabs.addTab(self._build_automation_workspace(), "Flow & Automation")
        self.tabs.currentChanged.connect(self._activate_current)
        root.addWidget(self.tabs, 1)

        for page in (
            self.packet_page,
            self.proxy_page,
            self.mitm_page,
            self.extraction_page,
            self.forensics_page,
            self.zero_trust_page,
            self.dlp_page,
            self.workflow_page,
            self.automation_page,
        ):
            page.statusMessage.connect(self.statusMessage.emit)

    def _build_automation_workspace(self) -> QWidget:
        holder = QWidget(self)
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        tabs = QTabWidget(holder)
        tabs.addTab(self.workflow_page, "Flow Designer")
        tabs.addTab(self.automation_page, "Automation Center")
        layout.addWidget(tabs, 1)
        self.automation_tabs = tabs
        return holder

    def _all_pages(self):
        return (
            self.packet_page,
            self.proxy_page,
            self.mitm_page,
            self.extraction_page,
            self.forensics_page,
            self.zero_trust_page,
            self.dlp_page,
            self.workflow_page,
            self.automation_page,
        )

    def _selected_pages(self):
        index = self.tabs.currentIndex()
        if index == 0:
            return (self.packet_page,)
        if index == 1:
            return (self.proxy_page,)
        if index == 2:
            return (self.mitm_page,)
        if index == 3:
            return (self.extraction_page,)
        if index == 4:
            return (self.forensics_page,)
        if index == 5:
            return (self.zero_trust_page,)
        if index == 6:
            return (self.dlp_page,)
        if index == 7:
            return (self.workflow_page, self.automation_page)
        return ()

    def _activate_current(self, _index: int = -1) -> None:
        selected = set(self._selected_pages())
        for page in self._all_pages():
            if page in selected:
                page.activated()
            else:
                page.deactivated()

    def activated(self) -> None:
        self._activate_current()

    def deactivated(self) -> None:
        for page in self._all_pages():
            page.deactivated()
