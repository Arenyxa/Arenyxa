"""Runtime context projection and guarded lazy page construction."""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from typing import Any, TypeVar

from arenyxa.navigation.guards import require_page
from arenyxa.navigation.models import (
    AccountRole,
    ActiveRootSession,
    DEVELOPER_SURFACE_CAPABILITY,
    DeveloperAuthority,
    ExperienceMode,
    NavigationContext,
    RuntimeMode,
)
from arenyxa.navigation.resolver import NavigationResolver

PageT = TypeVar("PageT")


class NavigationContextFactory:
    """Project live application state into the five independent navigation dimensions."""

    _PROFILE_MAP = {
        "": ExperienceMode.PROFESSIONAL,
        "personal": ExperienceMode.PERSONAL,
        "power": ExperienceMode.PROFESSIONAL,
        "professional": ExperienceMode.PROFESSIONAL,
        "developer": ExperienceMode.DEVELOPER,
        "enterprise": ExperienceMode.ENTERPRISE,
        "root_developer": ExperienceMode.ROOT_DEVELOPER,
    }

    @classmethod
    def from_application(cls, application: Any) -> NavigationContext:
        settings = getattr(application, "settings", None)
        profile = str(getattr(settings, "experience_profile", "") or "").casefold()
        experience = cls._PROFILE_MAP.get(profile, ExperienceMode.PROFESSIONAL)

        raw_runtime = str(
            getattr(application, "runtime_mode", "")
            or os.getenv("ARENYXA_RUNTIME_MODE", RuntimeMode.DESKTOP.value)
        ).casefold()
        try:
            runtime = RuntimeMode(raw_runtime)
        except ValueError:
            runtime = RuntimeMode.DESKTOP

        account_role = AccountRole.PERSONAL
        enterprise_capabilities: set[str] = set()
        identity = getattr(application, "enterprise_identity", None)
        if identity is not None:
            try:
                enterprise = identity.status()
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                enterprise = None
            if enterprise is not None and bool(getattr(enterprise, "authenticated", False)):
                roles = {str(item).casefold() for item in getattr(enterprise, "roles", ())}
                enterprise_capabilities.update(
                    str(item) for item in getattr(enterprise, "permissions", ())
                )
                if "super_admin" in roles:
                    account_role = AccountRole.LOCAL_SUPER_ADMIN
                elif "administrator" in roles:
                    account_role = AccountRole.ENTERPRISE_ADMIN
                else:
                    account_role = AccountRole.ENTERPRISE_MEMBER

        developer = DeveloperAuthority()
        root = ActiveRootSession()
        manager = getattr(application, "developer_access", None)
        if manager is not None:
            try:
                status = manager.status()
            except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
                status = None
            if status is not None and bool(getattr(status, "authenticated", False)):
                capabilities = frozenset(str(item) for item in getattr(status, "capabilities", ()))
                kind = str(getattr(status, "kind", ""))
                expiry = str(getattr(status, "session_expires_at", ""))
                developer = DeveloperAuthority(
                    authenticated=True,
                    credential_valid=True,
                    revoked=False,
                    expires_at=expiry,
                    capabilities=capabilities,
                    principal_id=str(getattr(status, "developer_id", "")),
                )
                if (
                    kind == "root_owner"
                    and "platform.root" in capabilities
                    and bool(getattr(application, "root_developer_workstation", False))
                ):
                    root = ActiveRootSession(
                        authenticated=True,
                        revoked=False,
                        expires_at=expiry,
                        capabilities=capabilities,
                    )

        # A persisted preference can request Developer UX, never a Root session.
        if experience is ExperienceMode.ROOT_DEVELOPER and not root.active:
            experience = ExperienceMode.DEVELOPER

        extra = getattr(application, "navigation_capabilities", ())
        projected_capabilities = enterprise_capabilities | {str(item) for item in extra}
        if bool(getattr(settings, "developer_mode", False)):
            projected_capabilities.add(DEVELOPER_SURFACE_CAPABILITY)
        capabilities = frozenset(projected_capabilities)
        return NavigationContext(
            experience_mode=experience,
            runtime_mode=runtime,
            account_role=account_role,
            developer_authority=developer,
            root_session=root,
            capabilities=capabilities,
        )


class PageFactory:
    """Create a page only after permission resolution and retain it in a stable cache."""

    def __init__(self, resolver: NavigationResolver) -> None:
        self.resolver = resolver
        self._cache: dict[str, Any] = {}
        self._lock = threading.RLock()

    @property
    def cache(self) -> dict[str, Any]:
        return self._cache

    def get(self, page_id: str) -> Any | None:
        with self._lock:
            return self._cache.get(str(page_id))

    def get_or_create(
        self,
        page_id: str,
        context: NavigationContext,
        creator: Callable[[], PageT],
    ) -> tuple[PageT, bool]:
        require_page(self.resolver, page_id, context)
        with self._lock:
            existing = self._cache.get(str(page_id))
            if existing is not None:
                return existing, False
            page = creator()
            self._cache[str(page_id)] = page
            return page, True

    def clear(self) -> None:
        """Clear references during final shutdown; preset switches must not call this method."""
        with self._lock:
            self._cache.clear()
