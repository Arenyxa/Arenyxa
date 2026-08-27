from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from arenyxa.navigation import (
    AccountRole,
    ActiveRootSession,
    DEFAULT_PAGE_MANIFESTS,
    DeveloperAuthority,
    ExperienceMode,
    NavigationContext,
    NavigationResolver,
    PageFactory,
    RuntimeMode,
)
from arenyxa.navigation.guards import NavigationAccessError


def _context(
    experience: ExperienceMode = ExperienceMode.ADVANCED,
    runtime: RuntimeMode = RuntimeMode.DESKTOP,
    role: AccountRole = AccountRole.PERSONAL,
    *,
    developer: DeveloperAuthority = DeveloperAuthority(),
    root: ActiveRootSession = ActiveRootSession(),
) -> NavigationContext:
    return NavigationContext(experience, runtime, role, developer, root)


def _future() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat()


def test_personal_advanced_cannot_see_enterprise_administration() -> None:
    resolved = NavigationResolver(DEFAULT_PAGE_MANIFESTS).resolve(_context())
    assert "proxy" in resolved.visible
    assert "enterprise" not in resolved.visible


def test_desktop_runtime_cannot_see_server_administration() -> None:
    context = _context(ExperienceMode.ENTERPRISE, role=AccountRole.ENTERPRISE_ADMIN)
    resolved = NavigationResolver(DEFAULT_PAGE_MANIFESTS).resolve(context)
    assert "enterprise" in resolved.visible
    assert "server_ops" not in resolved.visible


def test_developer_experience_never_grants_developer_authority() -> None:
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    context = _context(ExperienceMode.DEVELOPER)
    assert context.developer_authority.active is False
    assert resolver.decision("console", context).reason == "CAPABILITY_REQUIRED"
    assert "console" not in resolver.resolve(context).visible


def test_valid_developer_credential_enables_developer_tools_only() -> None:
    authority = DeveloperAuthority(
        authenticated=True,
        credential_valid=True,
        expires_at=_future(),
        capabilities=frozenset({"developer.tools"}),
    )
    resolved = NavigationResolver(DEFAULT_PAGE_MANIFESTS).resolve(
        _context(ExperienceMode.DEVELOPER, developer=authority)
    )
    assert {"console", "logs"}.issubset(resolved.visible)
    assert "enterprise" not in resolved.visible
    assert "server_ops" not in resolved.visible


def test_active_root_session_is_the_only_show_all_override() -> None:
    root = ActiveRootSession(
        authenticated=True,
        expires_at=_future(),
        capabilities=frozenset({"platform.root"}),
    )
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    resolved = resolver.resolve(_context(ExperienceMode.GUIDED, root=root))
    assert resolved.visible == frozenset(manifest.id for manifest in DEFAULT_PAGE_MANIFESTS)

    revoked = ActiveRootSession(
        authenticated=True,
        revoked=True,
        expires_at=_future(),
        capabilities=frozenset({"platform.root"}),
    )
    assert "enterprise" not in resolver.resolve(_context(ExperienceMode.GUIDED, root=revoked)).visible


def test_page_factory_checks_permission_before_construction_and_retains_cache() -> None:
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    factory = PageFactory(resolver)
    calls: list[str] = []

    with pytest.raises(NavigationAccessError):
        factory.get_or_create("enterprise", _context(), lambda: calls.append("denied"))
    assert calls == []

    admin = _context(ExperienceMode.ENTERPRISE, role=AccountRole.ENTERPRISE_ADMIN)
    page, created = factory.get_or_create("enterprise", admin, lambda: object())
    assert created is True
    cached, created_again = factory.get_or_create("enterprise", admin, lambda: object())
    assert cached is page
    assert created_again is False
