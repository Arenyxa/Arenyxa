from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from arenyxa.config import AppSettings
from arenyxa.navigation import (
    DEFAULT_PAGE_MANIFESTS,
    AccountRole,
    ExperienceMode,
    NavigationContext,
    NavigationResolver,
    RuntimeMode,
    WORKSPACE_POLICIES,
)
from arenyxa.navigation.experience import ExperienceContextController, NavigationPolicyEngine


class _EnterpriseIdentity:
    def __init__(
        self,
        *,
        configured: bool = False,
        authenticated: bool = False,
        roles: tuple[str, ...] = (),
        permissions: tuple[str, ...] = (),
    ) -> None:
        self.configured = configured
        self.authenticated = authenticated
        self.roles = roles
        self.permissions = permissions

    def status(self) -> SimpleNamespace:
        return SimpleNamespace(
            configured=self.configured,
            unlocked=self.authenticated,
            authenticated=self.authenticated,
            enterprise_id="enterprise-phase14" if self.configured else "",
            account_id="account-phase14" if self.authenticated else "",
            roles=self.roles,
            permissions=self.permissions,
        )


def _application(
    tmp_path: Path,
    settings: AppSettings,
    *,
    identity: _EnterpriseIdentity | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        settings=settings,
        paths=SimpleNamespace(root=tmp_path),
        safe_mode=False,
        runtime_mode="desktop",
        enterprise_identity=identity or _EnterpriseIdentity(),
        developer_access=None,
        navigation_capabilities=(),
        root_developer_workstation=False,
    )


def test_phase1_enterprise_workspace_contract_has_no_experience_or_runtime_self_denial() -> None:
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    context = NavigationContext(
        experience_mode=ExperienceMode.ENTERPRISE,
        runtime_mode=RuntimeMode.DESKTOP,
        account_role=AccountRole.PERSONAL,
    )

    expected = {
        "enterprise": "ALLOWED",
        "server": "ACCOUNT_ROLE_REQUIRED",
        "workers": "ACCOUNT_ROLE_REQUIRED",
        "platform_jobs": "ALLOWED",
        "audit": "ALLOWED",
        "settings": "ALLOWED",
        "server_ops": "RUNTIME_MODE_MISMATCH",
    }
    for page_id, reason in expected.items():
        decision = resolver.decision(page_id, context)
        assert decision.reason == reason, (page_id, decision)
        if page_id != "server_ops":
            assert decision.reason not in {"EXPERIENCE_MODE_MISMATCH", "RUNTIME_MODE_MISMATCH"}

    assert set(WORKSPACE_POLICIES[ExperienceMode.ENTERPRISE].primary_pages).issubset(
        {item.page_id for item in resolver.resolve(context).decisions}
    )


def test_phase2_enterprise_mode_is_experience_not_authority(tmp_path: Path) -> None:
    settings = AppSettings(
        experience_profile="professional",
        experience_setup_completed=True,
        developer_mode=False,
    )
    controller = ExperienceContextController(_application(tmp_path, settings))
    _profile, event = controller.switch("enterprise")
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)

    assert event.current.mode is ExperienceMode.ENTERPRISE
    assert event.current.identity.enterprise_authenticated is False
    assert event.current.navigation.account_role is AccountRole.PERSONAL
    assert not event.current.permissions
    assert resolver.allowed("enterprise", event.current.navigation)
    assert resolver.decision("server", event.current.navigation).reason == "ACCOUNT_ROLE_REQUIRED"
    assert resolver.decision("workers", event.current.navigation).reason == "ACCOUNT_ROLE_REQUIRED"
    assert resolver.decision("server_ops", event.current.navigation).reason == "RUNTIME_MODE_MISMATCH"


def test_phase2_authenticated_enterprise_admin_reaches_desktop_operations_without_root_or_developer() -> None:
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    context = NavigationContext(
        experience_mode=ExperienceMode.ENTERPRISE,
        runtime_mode=RuntimeMode.DESKTOP,
        account_role=AccountRole.ENTERPRISE_ADMIN,
    )

    for page_id in ("enterprise", "server", "workers", "platform_jobs", "audit"):
        assert resolver.allowed(page_id, context), (page_id, resolver.decision(page_id, context))
    assert resolver.decision("server_ops", context).reason == "RUNTIME_MODE_MISMATCH"
    server_runtime = NavigationContext(
        experience_mode=ExperienceMode.ENTERPRISE,
        runtime_mode=RuntimeMode.SERVER,
        account_role=AccountRole.ENTERPRISE_ADMIN,
    )
    assert resolver.allowed("server_ops", server_runtime)
    assert context.developer_authority.active is False
    assert context.root_session.active is False
    assert "platform.root" not in context.effective_capabilities


def test_phase3_explicit_enterprise_choice_survives_restart_with_developer_preference_on(tmp_path: Path) -> None:
    settings = AppSettings(
        experience_profile="developer",
        experience_setup_completed=True,
        developer_mode=True,
        developer_nav_expanded=True,
    )
    app = _application(tmp_path, settings)
    controller = ExperienceContextController(app)
    _profile, event = controller.switch("enterprise")

    assert event.current.mode is ExperienceMode.ENTERPRISE
    assert settings.developer_mode is True
    assert settings.experience_profile == "enterprise"

    restored = AppSettings.load(tmp_path / "settings.json")
    restarted = ExperienceContextController(_application(tmp_path, restored))
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    policy = NavigationPolicyEngine(resolver)

    assert restored.developer_mode is True
    assert restored.experience_profile == "enterprise"
    assert restarted.current.mode is ExperienceMode.ENTERPRISE
    assert resolver.allowed("enterprise", restarted.current.navigation)
    assert "enterprise" in policy.rebuild(restarted.current).visible


def test_phase3_developer_recovery_still_repairs_stale_professional_profile(tmp_path: Path) -> None:
    settings = AppSettings(
        experience_profile="professional",
        experience_setup_completed=True,
        developer_mode=True,
        developer_nav_expanded=True,
    )
    controller = ExperienceContextController(_application(tmp_path, settings))

    assert settings.experience_profile == "developer"
    assert controller.current.mode is ExperienceMode.DEVELOPER


def test_phase4_real_enterprise_identity_projects_role_and_permissions_only_after_authentication(tmp_path: Path) -> None:
    permissions = ("enterprise.audit.read", "enterprise.remote_ops")
    identity = _EnterpriseIdentity(
        configured=True,
        authenticated=True,
        roles=("administrator",),
        permissions=permissions,
    )
    settings = AppSettings(experience_profile="enterprise", experience_setup_completed=True)
    controller = ExperienceContextController(_application(tmp_path, settings, identity=identity))

    assert controller.current.mode is ExperienceMode.ENTERPRISE
    assert controller.current.identity.enterprise_authenticated is True
    assert controller.current.navigation.account_role is AccountRole.ENTERPRISE_ADMIN
    assert controller.current.permissions == frozenset(permissions)
    assert frozenset(permissions).issubset(controller.current.navigation.effective_capabilities)
    assert "platform.root" not in controller.current.navigation.effective_capabilities


def test_phase4_enterprise_console_declared_buttons_have_direct_connections() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "arenyxa"
        / "presentation"
        / "pages"
        / "enterprise.py"
    ).read_text(encoding="utf-8")

    for button in (
        "console_identity_button",
        "console_fleet_button",
        "console_server_button",
        "console_worker_button",
        "console_jobs_button",
        "console_audit_button",
        "console_policy_button",
    ):
        assert f"self.{button}.clicked.connect(" in source
    assert 'destination = "server_ops" if runtime in {"server", "worker"} else "server"' in source
