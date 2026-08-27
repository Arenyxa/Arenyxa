from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from arenyxa.application.command_runtime import ArenyxaCommandRuntime
from arenyxa.config import AppSettings


ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_permission_status_is_read_only_and_available_without_developer_authority() -> None:
    context = SimpleNamespace(
        settings=AppSettings(experience_profile="personal", developer_mode=False),
        runtime_mode="desktop",
        enterprise_identity=None,
        developer_access=None,
        navigation_capabilities=(),
        root_developer_workstation=False,
    )
    runtime = ArenyxaCommandRuntime(context)

    permissions = runtime.execute("permissions")["data"]
    whoami = runtime.execute("whoami")["data"]

    assert permissions == whoami
    assert permissions["experience_mode"] == "personal"
    assert permissions["runtime_mode"] == "desktop"
    assert permissions["account_role"] == "personal"
    assert permissions["root"]["active"] is False
    assert permissions["developer"]["authenticated"] is False
    assert runtime.help("permissions")["developer_mode_required"] is False
    assert "permissions" in runtime.COMMAND_TREE["terminal"]
    assert "whoami" in runtime.COMMAND_TREE["terminal"]


def test_enterprise_workspace_label_is_presentational_only() -> None:
    experience = _source("src/arenyxa/application/experience.py")
    settings = _source("src/arenyxa/presentation/pages/settings.py")
    welcome = _source("src/arenyxa/presentation/pages/welcome.py")

    assert '"enterprise", "企业工作模式"' in experience
    assert '"enterprise": "企业工作模式"' in settings
    assert 'QPushButton("进入企业工作模式")' in welcome
    assert 'self.profileSelected.emit("enterprise")' in welcome


def test_footer_system_routes_are_filtered_after_they_are_created() -> None:
    source = _source("src/arenyxa/presentation/main_window.py")
    build = source[source.index("    def _build_ui("):]
    system_loop = build.index('if group == "system":')
    add_system = build.index("add_nav_button(page_id, symbol, key, group, footer_layout)", system_loop)
    refresh_after = build.index("self._refresh_nav_visibility()", add_system)
    service_label = build.index('self.service_label = QLabel("●  本地服务', refresh_after)
    assert add_system < refresh_after < service_label


def test_welcome_hides_fleet_surface_when_live_navigation_denies_it() -> None:
    source = _source("src/arenyxa/presentation/pages/welcome.py")
    assert "NavigationContextFactory.from_application(context)" in source
    assert "NavigationResolver(DEFAULT_PAGE_MANIFESTS).allowed" in source
    assert "if fleet_allowed:" in source


def test_startup_progress_appearance_is_frozen_before_global_theme_application() -> None:
    source = _source("src/arenyxa/presentation/shell_window.py")
    assert 'self.progress.setObjectName("ArenyxaStartupProgress")' in source
    assert "QPalette.ColorRole.Highlight" in source
    assert "self.progress.setFixedHeight(startup_height)" in source
    assert "QProgressBar#ArenyxaStartupProgress::chunk" in source
