from __future__ import annotations

"""Shared page registry for the Arenyxa desktop shell.

This module owns navigation metadata used by the main window and its mixins. Keeping the
registry outside ``main_window.py`` avoids circular imports when the shell is split across
multiple mixin modules.
"""

from arenyxa.presentation.pages.dashboard import DashboardPage
from arenyxa.presentation.pages.task_center import TaskCenterPage
from arenyxa.presentation.pages.data import DataPage, SearchPage, VersionPage
from arenyxa.presentation.pages.enterprise import EnterprisePage
from arenyxa.presentation.pages.extraction import ExtractionStudioPage
from arenyxa.presentation.pages.crawler import CrawlerLabPage
from arenyxa.presentation.pages.mitm_proxy import MitmInterceptionPage
from arenyxa.presentation.pages.network import NetworkPage
from arenyxa.presentation.pages.personalization import PersonalizationPage
from arenyxa.presentation.pages.proxy import ProxyPage
from arenyxa.presentation.pages.professional_platform import AiTrafficIntelligencePage, ApiSecurityLabPage
from arenyxa.presentation.pages.professional_automation import AutomationEnginePage
from arenyxa.presentation.pages.recovery import RecoveryCenterPage
from arenyxa.presentation.pages.server_ops import ServerOperationsPage
from arenyxa.presentation.pages.settings import AboutPage, SettingsPage
from arenyxa.presentation.pages.studio import IntelligenceStudioPage
from arenyxa.presentation.pages.tasks import TasksPage
from arenyxa.presentation.pages.tools import (
    AdvancedPlatformPage,
    ConsolePage,
    LogsPage,
    PluginsPage,
    WorkflowPage,
)
from arenyxa.presentation.pages.visualization import VisualizationPage
from arenyxa.presentation.pages.traffic_forensics import TrafficForensicsPage
from arenyxa.presentation.pages.platform_workbenches import (
    AuditWorkbenchPage,
    DeveloperWorkbenchPage,
    DiagnosticsWorkbenchPage,
    PerformanceWorkbenchPage,
    PlatformJobsWorkbenchPage,
    ProtocolWorkbenchPage,
    SecurityWorkbenchPage,
    ServerWorkbenchPage,
    StorageWorkbenchPage,
    WorkersWorkbenchPage,
)

PAGE_DEFINITIONS = [
    ("task_center", "★", "nav.task_center", TaskCenterPage, "core"),
    ("dashboard", "⌂", "nav.dashboard", DashboardPage, "core"),
    ("search", "⌕", "nav.search", SearchPage, "core"),
    ("tasks", "◎", "nav.capture", TasksPage, "core"),
    ("network", "◫", "nav.network", NetworkPage, "core"),
    ("protocol", "≋", "nav.protocol", ProtocolWorkbenchPage, "core"),
    ("security_center", "◆", "nav.security_center", SecurityWorkbenchPage, "core"),
    ("proxy", "⇄", "nav.proxy", ProxyPage, "core"),
    ("api_security", "{}", "nav.api_security", ApiSecurityLabPage, "core"),
    ("forensics", "⌖", "nav.forensics", TrafficForensicsPage, "core"),
    ("traffic_ai", "◉", "nav.traffic_ai", AiTrafficIntelligencePage, "core"),
    ("mitm", "⇌", "nav.mitm_proxy", MitmInterceptionPage, "core"),
    ("studio", "⌬", "nav.studio", IntelligenceStudioPage, "core"),
    ("extraction", "⌗", "nav.extraction", ExtractionStudioPage, "core"),
    ("crawler", "⌁", "nav.crawler", CrawlerLabPage, "core"),
    ("workflow", "◇", "nav.workflow", WorkflowPage, "core"),
    ("automation", "◷", "nav.automation", AutomationEnginePage, "core"),
    ("data", "▤", "nav.data", DataPage, "core"),
    ("visualization", "▥", "nav.visualization", VisualizationPage, "core"),
    ("recovery", "↻", "nav.recovery", RecoveryCenterPage, "advanced"),
    ("advanced", "✦", "nav.advanced", AdvancedPlatformPage, "advanced"),
    ("version", "⑂", "nav.version", VersionPage, "advanced"),
    ("plugins", "⬡", "nav.plugins", PluginsPage, "advanced"),
    ("console", ">_", "nav.console", ConsolePage, "developer"),
    ("logs", "≣", "nav.logs", LogsPage, "developer"),
    ("developer_center", "◇", "nav.developer_center", DeveloperWorkbenchPage, "developer"),
    ("server_ops", "▦", "nav.server_ops", ServerOperationsPage, "system"),
    ("server", "▧", "nav.server", ServerWorkbenchPage, "system"),
    ("workers", "◈", "nav.workers", WorkersWorkbenchPage, "system"),
    ("platform_jobs", "◉", "nav.platform_jobs", PlatformJobsWorkbenchPage, "system"),
    ("storage", "▤", "nav.storage", StorageWorkbenchPage, "system"),
    ("audit", "◌", "nav.audit", AuditWorkbenchPage, "system"),
    ("diagnostics", "⊙", "nav.diagnostics", DiagnosticsWorkbenchPage, "system"),
    ("performance", "⌁", "nav.performance", PerformanceWorkbenchPage, "system"),
    ("enterprise", "▣", "nav.enterprise", EnterprisePage, "system"),
    ("personalization", "✧", "nav.personalization", PersonalizationPage, "system"),
    ("settings", "⚙", "nav.settings", SettingsPage, "system"),
    ("about", "ⓘ", "nav.about", AboutPage, "system"),
]

NAVIGATION = [
    (page_id, symbol, key, page_type)
    for page_id, symbol, key, page_type, _group in PAGE_DEFINITIONS
]
PAGE_GROUP = {
    page_id: group
    for page_id, _symbol, _key, _page_type, group in PAGE_DEFINITIONS
}
DEVELOPER_PAGE_IDS = {
    page_id for page_id, group in PAGE_GROUP.items() if group == "developer"
}
PAGE_TYPES = {
    page_id: page_type
    for page_id, _symbol, _key, page_type, _group in PAGE_DEFINITIONS
}
DEVELOPER_SHORTCUTS = [
    ("dev_api", "{}", "nav.dev.api"),
    ("dev_sandbox", "⬢", "nav.dev.sandbox"),
    ("dev_performance", "⌁", "nav.dev.performance"),
]
DEVELOPER_SHORTCUT_TARGETS = {
    "dev_api": "advanced",
    "dev_sandbox": "plugins",
    "dev_performance": "advanced",
}

__all__ = [
    "DEVELOPER_PAGE_IDS",
    "DEVELOPER_SHORTCUTS",
    "DEVELOPER_SHORTCUT_TARGETS",
    "NAVIGATION",
    "PAGE_DEFINITIONS",
    "PAGE_GROUP",
    "PAGE_TYPES",
]
