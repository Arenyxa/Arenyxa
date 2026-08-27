from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from arenyxa.config import AppSettings
from arenyxa.navigation import (
    DEVELOPER_SURFACE_CAPABILITY,
    DEFAULT_PAGE_MANIFESTS,
    AccountRole,
    DeveloperAuthority,
    ExperienceMode,
    NavigationContext,
    RuntimeMode,
    NavigationContextFactory,
    NavigationResolver,
)


def _application(settings: AppSettings) -> SimpleNamespace:
    return SimpleNamespace(
        settings=settings,
        runtime_mode="desktop",
        enterprise_identity=None,
        developer_access=None,
        navigation_capabilities=(),
        root_developer_workstation=False,
    )


def test_developer_profile_alone_does_not_unlock_terminal_or_logs() -> None:
    settings = AppSettings(experience_profile="developer", developer_mode=False)
    context = NavigationContextFactory.from_application(_application(settings))
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)

    assert context.experience_mode is ExperienceMode.DEVELOPER
    assert DEVELOPER_SURFACE_CAPABILITY not in context.effective_capabilities
    assert resolver.allowed("developer_center", context)
    assert not resolver.allowed("console", context)
    assert not resolver.allowed("logs", context)


def test_explicit_developer_mode_unlocks_public_developer_pages_without_official_credential() -> None:
    settings = AppSettings(experience_profile="developer", developer_mode=True)
    context = NavigationContextFactory.from_application(_application(settings))
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)

    assert DEVELOPER_SURFACE_CAPABILITY in context.effective_capabilities
    assert context.developer_authority.active is False
    assert resolver.allowed("developer_center", context)
    assert resolver.allowed("console", context)
    assert resolver.allowed("logs", context)



def test_official_developer_authority_keeps_existing_developer_page_access() -> None:
    authority = DeveloperAuthority(
        authenticated=True,
        credential_valid=True,
        expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        capabilities=frozenset({"runtime.debug"}),
        principal_id="phase12-test",
    )
    context = NavigationContext(
        ExperienceMode.DEVELOPER,
        RuntimeMode.DESKTOP,
        account_role=AccountRole.PERSONAL,
        developer_authority=authority,
    )
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)

    assert DEVELOPER_SURFACE_CAPABILITY in context.effective_capabilities
    assert resolver.allowed("console", context)
    assert resolver.allowed("logs", context)

def test_terminal_and_logs_are_developer_mode_capability_pages_not_root_pages() -> None:
    manifests = {item.id: item for item in DEFAULT_PAGE_MANIFESTS}
    for page_id in ("console", "logs"):
        manifest = manifests[page_id]
        assert manifest.group == "developer"
        assert manifest.root_only is False
        assert manifest.requires_developer_authority is False
        assert manifest.required_capabilities == frozenset({DEVELOPER_SURFACE_CAPABILITY})




def test_main_window_developer_mode_switch_forces_child_group_open() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "arenyxa"
        / "presentation"
        / "main_window_navigation.py"
    ).read_text(encoding="utf-8")
    method = source.split("    def set_developer_mode(self, enabled: bool) -> None:", 1)[1].split(
        "    def _apply_nav_collapsed_visual", 1
    )[0]
    assert "if enabled:" in method
    assert "self.context.settings.developer_nav_expanded = True" in method
    assert 'self.experience_controller.switch("developer")' in method
    assert "self._refresh_nav_visibility()" in method
    assert 'self.navigate("developer_center")' in method


def test_developer_shortcuts_are_gated_by_explicit_tool_state() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "arenyxa"
        / "presentation"
        / "main_window_navigation.py"
    ).read_text(encoding="utf-8")
    refresh = source.split("    def _refresh_nav_visibility(self) -> None:", 1)[1].split(
        "    def open_developer_tool", 1
    )[0]
    assert "developer_tools_enabled = self._developer_tools_enabled(navigation)" in refresh
    assert 'button.property("navAction")' in refresh
    assert "developer_visible" in refresh
    assert "developer_tools_enabled" in refresh
    assert "(not target or target in allowed)" in refresh


def test_developer_surface_honors_explicit_mode_before_profile_refresh() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "arenyxa"
        / "presentation"
        / "main_window_navigation.py"
    ).read_text(encoding="utf-8")
    surface = source.split("    def _developer_surface_enabled(self, context: NavigationContext | None = None) -> bool:", 1)[1].split(
        "    def _developer_tools_enabled", 1
    )[0]
    assert "self.context.settings.developer_mode" in surface

def test_plugin_sandbox_shortcut_remains_registered_and_routes_to_existing_plugins_page() -> None:
    registry = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "arenyxa"
        / "presentation"
        / "main_window_registry.py"
    ).read_text(encoding="utf-8")
    navigation = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "arenyxa"
        / "presentation"
        / "main_window_navigation.py"
    ).read_text(encoding="utf-8")
    assert '("dev_sandbox", "⬢", "nav.dev.sandbox")' in registry
    method = navigation.split("    def open_developer_tool(self, action_id: str) -> None:", 1)[1].split(
        "    def set_developer_mode", 1
    )[0]
    assert 'elif action_id == "dev_sandbox":' in method
    assert 'self.navigate("plugins")' in method

