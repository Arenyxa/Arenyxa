from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from arenyxa.config import AppSettings
from arenyxa.navigation import (
    DEFAULT_PAGE_MANIFESTS,
    DEVELOPER_SURFACE_CAPABILITY,
    AccountRole,
    ActiveRootSession,
    DeveloperAuthority,
    ExperienceMode,
    NavigationContext,
    NavigationResolver,
    RuntimeMode,
)
from arenyxa.navigation.experience import ExperienceContextController, NavigationPolicyEngine


def _application(tmp_path: Path, settings: AppSettings, **overrides: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "settings": settings,
        "paths": SimpleNamespace(root=tmp_path),
        "safe_mode": False,
        "runtime_mode": "desktop",
        "enterprise_identity": None,
        "developer_access": None,
        "navigation_capabilities": (),
        "root_developer_workstation": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _future() -> str:
    return (datetime.now(UTC) + timedelta(hours=1)).isoformat()


def test_phase3_restart_reconciles_persisted_developer_toggle_before_navigation_build(tmp_path: Path) -> None:
    settings = AppSettings(
        experience_profile="professional",
        experience_setup_completed=True,
        developer_mode=True,
        developer_nav_expanded=True,
    )
    controller = ExperienceContextController(_application(tmp_path, settings))
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    policy = NavigationPolicyEngine(resolver)

    assert settings.experience_profile == "developer"
    assert settings.experience_setup_completed is True
    assert settings.developer_mode is True
    assert settings.developer_nav_expanded is True
    assert controller.current.mode is ExperienceMode.DEVELOPER
    assert resolver.allowed("developer_center", controller.current.navigation)
    assert resolver.allowed("console", controller.current.navigation)
    assert resolver.allowed("logs", controller.current.navigation)
    assert {"developer_center", "console", "logs"}.issubset(policy.rebuild(controller.current).visible)

    restored = AppSettings.load(tmp_path / "settings.json")
    assert restored.experience_profile == "developer"
    assert restored.developer_mode is True
    assert restored.developer_nav_expanded is True


def test_phase3_restart_repairs_legacy_blank_profile_without_manual_toggle(tmp_path: Path) -> None:
    settings = AppSettings(
        experience_profile="",
        developer_mode=True,
        developer_nav_expanded=False,
    )
    controller = ExperienceContextController(_application(tmp_path, settings))

    assert settings.experience_profile == "developer"
    assert settings.developer_nav_expanded is True
    assert controller.current.mode is ExperienceMode.DEVELOPER
    assert DEVELOPER_SURFACE_CAPABILITY in controller.current.capabilities


def test_phase3_consistent_developer_profile_preserves_manual_group_collapse(tmp_path: Path) -> None:
    settings = AppSettings(
        experience_profile="developer",
        experience_setup_completed=True,
        developer_mode=True,
        developer_nav_expanded=False,
    )
    controller = ExperienceContextController(_application(tmp_path, settings))

    assert controller.current.mode is ExperienceMode.DEVELOPER
    assert settings.developer_nav_expanded is False
    assert not (tmp_path / "settings.json").exists()


def test_phase3_safe_mode_never_replays_persisted_developer_preference(tmp_path: Path) -> None:
    settings = AppSettings(
        experience_profile="professional",
        developer_mode=True,
        developer_nav_expanded=True,
    )
    controller = ExperienceContextController(_application(tmp_path, settings, safe_mode=True))

    assert settings.experience_profile == "professional"
    assert controller.current.mode is ExperienceMode.PROFESSIONAL
    assert not (tmp_path / "settings.json").exists()


def test_phase3_main_window_constructs_restored_experience_before_sidebar_build() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "arenyxa"
        / "presentation"
        / "main_window.py"
    ).read_text(encoding="utf-8")
    controller_index = source.index("self.experience_controller = ExperienceContextController(context)")
    build_index = source.index("self._build_ui(icon_path)")
    refresh_index = source.index("self._refresh_nav_visibility()", source.index("def _build_ui"))

    assert controller_index < build_index < refresh_index


def test_phase4_public_developer_mode_is_navigation_only_not_official_authority(tmp_path: Path) -> None:
    settings = AppSettings(experience_profile="developer", developer_mode=True)
    controller = ExperienceContextController(_application(tmp_path, settings))
    navigation = controller.current.navigation

    assert navigation.developer_authority.active is False
    assert navigation.root_session.active is False
    assert DEVELOPER_SURFACE_CAPABILITY in navigation.effective_capabilities
    for privileged in ("runtime.debug", "stress_test", "fault_injection", "platform.root"):
        assert privileged not in navigation.effective_capabilities


def test_phase4_developer_profile_without_toggle_does_not_gain_terminal_capability(tmp_path: Path) -> None:
    settings = AppSettings(experience_profile="developer", developer_mode=False)
    controller = ExperienceContextController(_application(tmp_path, settings))
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)

    assert controller.current.mode is ExperienceMode.DEVELOPER
    assert resolver.allowed("developer_center", controller.current.navigation)
    assert not resolver.allowed("console", controller.current.navigation)
    assert not resolver.allowed("logs", controller.current.navigation)
    assert DEVELOPER_SURFACE_CAPABILITY not in controller.current.navigation.effective_capabilities


def test_phase4_official_developer_does_not_gain_root_or_enterprise_authority() -> None:
    authority = DeveloperAuthority(
        authenticated=True,
        credential_valid=True,
        revoked=False,
        expires_at=_future(),
        capabilities=frozenset({"runtime.debug"}),
        principal_id="phase34-official-dev",
    )
    context = NavigationContext(
        experience_mode=ExperienceMode.DEVELOPER,
        runtime_mode=RuntimeMode.DESKTOP,
        account_role=AccountRole.PERSONAL,
        developer_authority=authority,
    )
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)

    assert resolver.allowed("console", context)
    assert resolver.allowed("logs", context)
    assert "platform.root" not in context.effective_capabilities
    assert not resolver.allowed("enterprise", context)
    assert not resolver.allowed("server_ops", context)


def test_phase4_root_session_retains_root_override_without_persisting_root_to_settings(tmp_path: Path) -> None:
    class _RootManager:
        def status(self) -> SimpleNamespace:
            return SimpleNamespace(
                authenticated=True,
                capabilities=("platform.root", "runtime.debug"),
                kind="root_owner",
                session_expires_at=_future(),
                developer_id="root-owner",
            )

    settings = AppSettings(
        experience_profile="developer",
        developer_mode=True,
        developer_nav_expanded=True,
    )
    app = _application(
        tmp_path,
        settings,
        developer_access=_RootManager(),
        root_developer_workstation=True,
    )
    controller = ExperienceContextController(app)

    assert controller.current.mode is ExperienceMode.ROOT_DEVELOPER
    assert controller.current.navigation.root_session.active is True
    assert "platform.root" in controller.current.navigation.effective_capabilities
    # Root authentication remains ephemeral and is never serialized by the Developer-mode recovery.
    if (tmp_path / "settings.json").exists():
        persisted = (tmp_path / "settings.json").read_text(encoding="utf-8")
        assert "platform.root" not in persisted
        assert "root_session" not in persisted


def test_phase4_revoked_root_session_cannot_promote_experience() -> None:
    root = ActiveRootSession(
        authenticated=True,
        revoked=True,
        expires_at=_future(),
        capabilities=frozenset({"platform.root"}),
    )
    context = NavigationContext(
        experience_mode=ExperienceMode.DEVELOPER,
        runtime_mode=RuntimeMode.DESKTOP,
        account_role=AccountRole.PERSONAL,
        root_session=root,
        capabilities=frozenset({DEVELOPER_SURFACE_CAPABILITY}),
    )

    assert root.active is False
    assert "platform.root" not in context.effective_capabilities
    # Revoked Root authority contributes no effective capability at all. Root Phase 2
    # additionally requires the process integrity marker before a live Root session exists.
    assert context.root_session.active is False


def test_phase4_expired_official_developer_capabilities_are_not_effective() -> None:
    expired = DeveloperAuthority(
        authenticated=True,
        credential_valid=True,
        revoked=False,
        expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
        capabilities=frozenset({"runtime.debug", "stress_test"}),
        principal_id="expired-phase34",
    )
    context = NavigationContext(
        experience_mode=ExperienceMode.DEVELOPER,
        runtime_mode=RuntimeMode.DESKTOP,
        account_role=AccountRole.PERSONAL,
        developer_authority=expired,
    )

    assert expired.active is False
    assert "runtime.debug" not in context.effective_capabilities
    assert "stress_test" not in context.effective_capabilities
    assert DEVELOPER_SURFACE_CAPABILITY not in context.effective_capabilities
