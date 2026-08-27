"""Built-in page manifests for the Arenyxa navigation capability architecture."""

from __future__ import annotations

from arenyxa.navigation.models import (
    AccountRole,
    DEVELOPER_SURFACE_CAPABILITY,
    ExperienceMode,
    PageManifest,
    RuntimeMode,
)

ALL_EXPERIENCES = frozenset(ExperienceMode)
PROFESSIONAL_EXPERIENCES = frozenset({ExperienceMode.PROFESSIONAL, ExperienceMode.DEVELOPER, ExperienceMode.ROOT_DEVELOPER})
ENTERPRISE_OPERATIONS_EXPERIENCES = frozenset({
    ExperienceMode.PROFESSIONAL,
    ExperienceMode.DEVELOPER,
    ExperienceMode.ENTERPRISE,
    ExperienceMode.ROOT_DEVELOPER,
})
DEVELOPER_EXPERIENCE = frozenset({ExperienceMode.DEVELOPER})
ENTERPRISE_EXPERIENCE = frozenset({ExperienceMode.ENTERPRISE, ExperienceMode.ROOT_DEVELOPER})
ALL_RUNTIMES = frozenset(RuntimeMode)
DESKTOP_RUNTIME = frozenset({RuntimeMode.DESKTOP})
SERVER_RUNTIMES = frozenset({RuntimeMode.SERVER, RuntimeMode.WORKER})
ENTERPRISE_ADMIN_ROLES = frozenset(
    {AccountRole.ENTERPRISE_ADMIN, AccountRole.LOCAL_SUPER_ADMIN}
)


def _page(
    page_id: str,
    import_path: str,
    *,
    group: str = "core",
    experiences: frozenset[ExperienceMode] = ALL_EXPERIENCES,
    runtimes: frozenset[RuntimeMode] = DESKTOP_RUNTIME,
    roles: frozenset[AccountRole] = frozenset(),
    capabilities: frozenset[str] = frozenset(),
    developer: bool = False,
    root_only: bool = False,
) -> PageManifest:
    return PageManifest(
        id=page_id,
        group=group,
        experience_modes=experiences,
        runtime_modes=runtimes,
        required_roles=roles,
        required_capabilities=capabilities,
        requires_developer_authority=developer,
        root_only=root_only,
        import_path=import_path,
    )


DEFAULT_PAGE_MANIFESTS: tuple[PageManifest, ...] = (
    _page("task_center", "arenyxa.presentation.pages.task_center:TaskCenterPage", experiences=frozenset({ExperienceMode.GUIDED})),
    _page("dashboard", "arenyxa.presentation.pages.dashboard:DashboardPage"),
    _page("search", "arenyxa.presentation.pages.data:SearchPage"),
    _page("tasks", "arenyxa.presentation.pages.tasks:TasksPage"),
    _page("network", "arenyxa.presentation.pages.network:NetworkPage"),
    _page("protocol", "arenyxa.presentation.pages.platform_workbenches:ProtocolWorkbenchPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("security_center", "arenyxa.presentation.pages.platform_workbenches:SecurityWorkbenchPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("proxy", "arenyxa.presentation.pages.proxy:ProxyPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("api_security", "arenyxa.presentation.pages.professional_platform:ApiSecurityLabPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("forensics", "arenyxa.presentation.pages.traffic_forensics:TrafficForensicsPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("traffic_ai", "arenyxa.presentation.pages.professional_platform:AiTrafficIntelligencePage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("mitm", "arenyxa.presentation.pages.mitm_proxy:MitmInterceptionPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("studio", "arenyxa.presentation.pages.studio:IntelligenceStudioPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("extraction", "arenyxa.presentation.pages.extraction:ExtractionStudioPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("crawler", "arenyxa.presentation.pages.crawler:CrawlerLabPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("workflow", "arenyxa.presentation.pages.tools:WorkflowPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("automation", "arenyxa.presentation.pages.professional_automation:AutomationEnginePage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("data", "arenyxa.presentation.pages.data:DataPage"),
    _page("visualization", "arenyxa.presentation.pages.visualization:VisualizationPage", experiences=PROFESSIONAL_EXPERIENCES),
    _page("recovery", "arenyxa.presentation.pages.recovery:RecoveryCenterPage", group="advanced"),
    _page("advanced", "arenyxa.presentation.pages.tools:AdvancedPlatformPage", group="advanced", experiences=PROFESSIONAL_EXPERIENCES),
    _page("version", "arenyxa.presentation.pages.data:VersionPage", group="advanced", experiences=PROFESSIONAL_EXPERIENCES),
    _page("plugins", "arenyxa.presentation.pages.tools:PluginsPage", group="advanced", experiences=PROFESSIONAL_EXPERIENCES),
    _page(
        "console",
        "arenyxa.presentation.pages.tools:ConsolePage",
        group="developer",
        experiences=DEVELOPER_EXPERIENCE,
        capabilities=frozenset({DEVELOPER_SURFACE_CAPABILITY}),
    ),
    _page(
        "logs",
        "arenyxa.presentation.pages.tools:LogsPage",
        group="developer",
        experiences=DEVELOPER_EXPERIENCE,
        capabilities=frozenset({DEVELOPER_SURFACE_CAPABILITY}),
    ),
    _page("developer_center", "arenyxa.presentation.pages.platform_workbenches:DeveloperWorkbenchPage", group="developer", experiences=frozenset({ExperienceMode.DEVELOPER, ExperienceMode.ROOT_DEVELOPER})),
    _page("server_ops", "arenyxa.presentation.pages.server_ops:ServerOperationsPage", group="system", experiences=ENTERPRISE_OPERATIONS_EXPERIENCES, runtimes=SERVER_RUNTIMES, roles=ENTERPRISE_ADMIN_ROLES),
    _page("server", "arenyxa.presentation.pages.platform_workbenches:ServerWorkbenchPage", group="system", experiences=ENTERPRISE_OPERATIONS_EXPERIENCES, runtimes=ALL_RUNTIMES, roles=ENTERPRISE_ADMIN_ROLES),
    _page("workers", "arenyxa.presentation.pages.platform_workbenches:WorkersWorkbenchPage", group="system", experiences=ENTERPRISE_OPERATIONS_EXPERIENCES, runtimes=ALL_RUNTIMES, roles=ENTERPRISE_ADMIN_ROLES),
    _page("platform_jobs", "arenyxa.presentation.pages.platform_workbenches:PlatformJobsWorkbenchPage", group="system", experiences=ENTERPRISE_OPERATIONS_EXPERIENCES),
    _page("storage", "arenyxa.presentation.pages.platform_workbenches:StorageWorkbenchPage", group="system", experiences=PROFESSIONAL_EXPERIENCES),
    _page("audit", "arenyxa.presentation.pages.platform_workbenches:AuditWorkbenchPage", group="system", experiences=ENTERPRISE_OPERATIONS_EXPERIENCES),
    _page("diagnostics", "arenyxa.presentation.pages.platform_workbenches:DiagnosticsWorkbenchPage", group="system", experiences=PROFESSIONAL_EXPERIENCES),
    _page("performance", "arenyxa.presentation.pages.platform_workbenches:PerformanceWorkbenchPage", group="system", experiences=PROFESSIONAL_EXPERIENCES),
    _page("enterprise", "arenyxa.presentation.pages.enterprise:EnterprisePage", group="system", experiences=ENTERPRISE_EXPERIENCE, runtimes=ALL_RUNTIMES),
    _page("personalization", "arenyxa.presentation.pages.personalization:PersonalizationPage", group="system"),
    _page("settings", "arenyxa.presentation.pages.settings:SettingsPage", group="system"),
    _page("about", "arenyxa.presentation.pages.settings:AboutPage", group="system"),
)


def manifest_by_id() -> dict[str, PageManifest]:
    return {manifest.id: manifest for manifest in DEFAULT_PAGE_MANIFESTS}
