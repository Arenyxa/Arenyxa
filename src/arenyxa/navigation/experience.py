"""Unified Experience Context, mode events, and workspace navigation policy."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from arenyxa.application.experience import apply_experience_profile
from arenyxa.navigation.factory import NavigationContextFactory
from arenyxa.navigation.models import (
    ExperienceContext,
    ExperienceIdentity,
    ExperienceMode,
    ModeChangedEvent,
    NavigationDiff,
    ResolvedNavigation,
    WorkspacePolicy,
)
from arenyxa.navigation.resolver import NavigationResolver


LOGGER = logging.getLogger(__name__)


_SECONDARY_PAGES = (
    "task_center", "dashboard", "search", "tasks", "network", "protocol",
    "security_center", "proxy", "api_security", "forensics", "traffic_ai",
    "mitm", "studio", "extraction", "crawler", "workflow", "automation",
    "data", "visualization", "recovery", "advanced", "version", "plugins",
    "console", "logs", "developer_center", "server_ops", "server", "workers",
    "platform_jobs", "storage", "audit", "diagnostics", "performance",
    "enterprise", "personalization", "settings", "about",
)


WORKSPACE_POLICIES: dict[ExperienceMode, WorkspacePolicy] = {
    ExperienceMode.PERSONAL: WorkspacePolicy(
        "personal", "task_center",
        ("dashboard", "search", "network", "tasks", "data", "settings"),
        _SECONDARY_PAGES,
    ),
    ExperienceMode.PROFESSIONAL: WorkspacePolicy(
        "professional", "dashboard",
        ("dashboard", "network", "studio", "workflow", "automation", "data", "settings"),
        _SECONDARY_PAGES,
    ),
    ExperienceMode.DEVELOPER: WorkspacePolicy(
        "developer", "developer_center",
        ("developer_center", "protocol", "automation", "workflow", "settings"),
        _SECONDARY_PAGES,
    ),
    ExperienceMode.ENTERPRISE: WorkspacePolicy(
        "enterprise", "enterprise",
        ("enterprise", "server", "workers", "platform_jobs", "audit", "settings"),
        _SECONDARY_PAGES,
    ),
    ExperienceMode.ROOT_DEVELOPER: WorkspacePolicy(
        "root_developer", "developer_center",
        ("developer_center", "security_center", "audit", "diagnostics", "version", "settings"),
        _SECONDARY_PAGES,
    ),
}


class ExperienceContextFactory:
    """Project live identity, permissions, capability, and workspace state once."""

    @classmethod
    def from_application(cls, application: Any) -> ExperienceContext:
        navigation = NavigationContextFactory.from_application(application)
        mode = navigation.experience_mode
        if navigation.root_session.active:
            mode = ExperienceMode.ROOT_DEVELOPER

        enterprise_configured = False
        enterprise_authenticated = False
        enterprise_id = ""
        principal_id = navigation.developer_authority.principal_id
        permissions: set[str] = set()
        service = getattr(application, "enterprise_identity", None)
        if service is not None:
            try:
                status = service.status()
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                status = None
            if status is not None:
                enterprise_configured = bool(getattr(status, "configured", False))
                enterprise_authenticated = bool(getattr(status, "authenticated", False))
                enterprise_id = str(getattr(status, "enterprise_id", ""))
                permissions.update(str(item) for item in getattr(status, "permissions", ()))
                if not principal_id and enterprise_authenticated:
                    principal_id = str(getattr(status, "account_id", ""))

        identity = ExperienceIdentity(
            account_role=navigation.account_role,
            enterprise_configured=enterprise_configured,
            enterprise_authenticated=enterprise_authenticated,
            enterprise_id=enterprise_id,
            principal_id=principal_id,
            developer_authenticated=navigation.developer_authority.active,
            root_authenticated=navigation.root_session.active,
        )
        workspace = WORKSPACE_POLICIES[mode]
        if mode is ExperienceMode.PERSONAL:
            scenario = str(getattr(getattr(application, "settings", None), "personal_scenario", ""))
            landing = {
                "website_analysis": "dashboard",
                "api_debugging": "task_center",
                "network_diagnostics": "network",
                "data_collection": "tasks",
                "security_learning": "task_center",
            }.get(scenario, workspace.landing_page)
            workspace = replace(workspace, landing_page=landing)
        return ExperienceContext(
            mode=mode,
            identity=identity,
            permissions=frozenset(permissions),
            capabilities=navigation.effective_capabilities,
            workspace=workspace,
            navigation=navigation,
        )


class NavigationPolicyEngine:
    """Rebuild visible navigation for an Experience Context without minting permission."""

    def __init__(self, resolver: NavigationResolver) -> None:
        self.resolver = resolver

    def rebuild(self, context: ExperienceContext) -> ResolvedNavigation:
        resolved = self.resolver.resolve(context.navigation)
        workspace_order = context.workspace.page_ids
        visible = resolved.visible
        ordered = tuple(page_id for page_id in workspace_order if page_id in visible)
        remaining = tuple(page_id for page_id in resolved.page_ids if page_id not in set(ordered))
        return ResolvedNavigation((*ordered, *remaining), resolved.decisions)

    def diff(self, previous: ExperienceContext, current: ExperienceContext) -> NavigationDiff:
        before = self.rebuild(previous).page_ids
        after = self.rebuild(current).page_ids
        updated = tuple(page_id for page_id in after if page_id in set(before))
        return NavigationDiff.between(before, after, updated=updated)

    def primary_pages(self, context: ExperienceContext) -> tuple[str, ...]:
        visible = self.rebuild(context).visible
        return tuple(page_id for page_id in context.workspace.primary_pages if page_id in visible)


class ExperienceContextController:
    """Persist mode, refresh unified context, then publish a ModeChangedEvent."""

    def __init__(self, application: Any) -> None:
        self.application = application
        self._lock = threading.RLock()
        self._listeners: list[Callable[[ModeChangedEvent], None]] = []
        self._restore_persisted_developer_mode()
        self._current = ExperienceContextFactory.from_application(application)

    def _restore_persisted_developer_mode(self) -> None:
        """Reconcile the durable Developer Mode toggle before navigation is projected.

        Developer Mode is persisted independently from the experience profile. Older or
        interrupted sessions can therefore contain ``developer_mode=true`` while the
        saved experience is Personal/Professional (or blank). Enterprise is preserved
        because it is an explicit workspace choice that must remain independent from the
        public Developer Mode preference. During the
        previous startup path the Settings checkbox restored correctly, but the
        navigation resolver still projected the stale experience and filtered every
        Developer child page until the user toggled Developer Mode off and on again.

        Replaying the same profile transition used by an explicit enable operation fixes
        that split-brain state before the sidebar is constructed. This is presentation
        recovery only: it does not create an Official Developer credential, a Root
        session, or any privileged capability. A valid Root session can still promote
        the live ExperienceContext to Root Developer later in the factory.
        """
        settings = getattr(self.application, "settings", None)
        if settings is None or bool(getattr(self.application, "safe_mode", False)):
            return
        if not bool(getattr(settings, "developer_mode", False)):
            return

        profile_id = str(getattr(settings, "experience_profile", "") or "").casefold()

        # Enterprise is an explicit workspace choice and can coexist with the public
        # Developer Mode preference.  Do not replace it merely to expose Developer
        # tools; the navigation manifest/capability layer decides which tools appear.
        # If the saved profile is already Developer/Root/Enterprise, preserve the
        # user's explicit group-collapse preference.  The restart bug was the stale
        # profile itself, not a legitimate manual collapse.
        if profile_id in {"developer", "root_developer", "enterprise"}:
            return

        apply_experience_profile(settings, "developer")
        settings.developer_nav_expanded = True
        try:
            settings.save(self.application.paths.root / "settings.json")
        except (OSError, TypeError, ValueError):
            # Keep the current process coherent even when durable persistence is
            # temporarily unavailable; no authority is granted by this recovery.
            LOGGER.exception("Failed to persist restored Developer Mode experience")

    @property
    def current(self) -> ExperienceContext:
        with self._lock:
            return self._current

    def subscribe(self, listener: Callable[[ModeChangedEvent], None]) -> Callable[[], None]:
        with self._lock:
            self._listeners.append(listener)

        def unsubscribe() -> None:
            with self._lock:
                if listener in self._listeners:
                    self._listeners.remove(listener)

        return unsubscribe

    def refresh(self) -> ExperienceContext:
        with self._lock:
            self._current = ExperienceContextFactory.from_application(self.application)
            return self._current

    def switch(self, profile_id: str) -> tuple[Any, ModeChangedEvent]:
        with self._lock:
            previous = self._current
            profile = apply_experience_profile(self.application.settings, profile_id)
            self.application.settings.save(self.application.paths.root / "settings.json")
            current = ExperienceContextFactory.from_application(self.application)
            self._current = current
            event = ModeChangedEvent(previous, current, datetime.now(UTC).isoformat())
            listeners = tuple(self._listeners)
        for listener in listeners:
            listener(event)
        return profile, event


__all__ = [
    "ExperienceContextController",
    "ExperienceContextFactory",
    "NavigationPolicyEngine",
    "WORKSPACE_POLICIES",
]
