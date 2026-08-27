"""Identity-driven primary navigation policy.

The resolver controls page access. This engine controls which workspace destinations are
presented as first-level navigation. Keeping those decisions separate prevents an
Experience Mode choice from being mistaken for an authority grant.
"""

from __future__ import annotations

from typing import Any

from arenyxa.compat import dataclass
from arenyxa.navigation.models import ExperienceContext, ExperienceMode


@dataclass(frozen=True, slots=True)
class WorkspaceDestination:
    page_id: str
    label_key: str


@dataclass(frozen=True, slots=True)
class WorkspaceNavigation:
    mode: ExperienceMode
    workspace: str
    start_page: str
    destinations: tuple[WorkspaceDestination, ...]

    def __post_init__(self) -> None:
        if len(self.destinations) > 8:
            raise ValueError("a workspace may expose at most eight first-level destinations")
        ids = tuple(item.page_id for item in self.destinations)
        if len(ids) != len(set(ids)):
            raise ValueError("workspace destination IDs must be unique")


class NavigationPolicyEngine:
    """Build the compact sidebar for an ExperienceContext."""

    def __init__(self, navigation_resolver: Any | None = None) -> None:
        # Preserve the construction contract used by MainWindow and compatibility
        # callers. Access control remains the responsibility of NavigationResolver.
        self.navigation_resolver = navigation_resolver

    _POLICIES: dict[ExperienceMode, WorkspaceNavigation] = {
        ExperienceMode.PERSONAL: WorkspaceNavigation(
            ExperienceMode.PERSONAL,
            "personal",
            "task_center",
            (
                WorkspaceDestination("task_center", "workspace.personal.home"),
                WorkspaceDestination("dashboard", "workspace.personal.analysis"),
                WorkspaceDestination("network", "workspace.personal.network"),
                WorkspaceDestination("data", "workspace.personal.projects"),
                WorkspaceDestination("tasks", "workspace.personal.automation"),
                WorkspaceDestination("settings", "workspace.settings"),
            ),
        ),
        ExperienceMode.PROFESSIONAL: WorkspaceNavigation(
            ExperienceMode.PROFESSIONAL,
            "professional",
            "dashboard",
            (
                WorkspaceDestination("dashboard", "workspace.professional.home"),
                WorkspaceDestination("protocol", "workspace.professional.analysis"),
                WorkspaceDestination("network", "workspace.professional.traffic"),
                WorkspaceDestination("workflow", "workspace.professional.workspace"),
                WorkspaceDestination("automation", "workspace.automation"),
                WorkspaceDestination("data", "workspace.projects"),
                WorkspaceDestination("settings", "workspace.settings"),
            ),
        ),
        ExperienceMode.DEVELOPER: WorkspaceNavigation(
            ExperienceMode.DEVELOPER,
            "developer",
            "developer_center",
            (
                WorkspaceDestination("developer_center", "workspace.developer.center"),
                WorkspaceDestination("forensics", "workspace.developer.traffic_lab"),
                WorkspaceDestination("automation", "workspace.automation"),
                WorkspaceDestination("data", "workspace.workspace"),
                WorkspaceDestination("settings", "workspace.settings"),
            ),
        ),
        ExperienceMode.ENTERPRISE: WorkspaceNavigation(
            ExperienceMode.ENTERPRISE,
            "enterprise",
            "enterprise",
            (
                WorkspaceDestination("enterprise", "workspace.enterprise.console"),
                WorkspaceDestination("data", "workspace.workspace"),
                WorkspaceDestination("automation", "workspace.automation"),
                WorkspaceDestination("audit", "workspace.audit"),
                WorkspaceDestination("settings", "workspace.settings"),
            ),
        ),
        ExperienceMode.ROOT_DEVELOPER: WorkspaceNavigation(
            ExperienceMode.ROOT_DEVELOPER,
            "root_developer",
            "root_authority",
            (
                WorkspaceDestination("root_authority", "workspace.root.authority"),
                WorkspaceDestination("audit", "workspace.root.security_audit"),
                WorkspaceDestination("release", "workspace.root.release"),
                WorkspaceDestination("policy", "workspace.root.policy"),
            ),
        ),
    }

    def rebuild(self, context: ExperienceContext) -> WorkspaceNavigation:
        policy = self._POLICIES[context.mode]
        workspace_id = str(getattr(context.workspace, "id", context.workspace))
        if policy.workspace != workspace_id:
            return WorkspaceNavigation(
                mode=policy.mode,
                workspace=workspace_id,
                start_page=policy.start_page,
                destinations=policy.destinations,
            )
        return policy

    def start_page(self, context: ExperienceContext) -> str:
        return self.rebuild(context).start_page
