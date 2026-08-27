from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from arenyxa.config import AppSettings
from arenyxa.navigation import (
    DEFAULT_PAGE_MANIFESTS,
    ExperienceContextController,
    ExperienceContextFactory,
    ExperienceMode,
    NavigationPolicyEngine,
    NavigationResolver,
)


def _application(tmp_path: Path, profile: str, *, developer_mode: bool = False) -> SimpleNamespace:
    settings = AppSettings(
        experience_profile=profile,
        experience_setup_completed=True,
        developer_mode=developer_mode,
        developer_nav_expanded=False,
    )
    return SimpleNamespace(
        settings=settings,
        runtime_mode="desktop",
        enterprise_identity=None,
        developer_access=None,
        navigation_capabilities=(),
        root_developer_workstation=False,
        paths=SimpleNamespace(root=tmp_path),
        safe_mode=False,
    )


def test_enterprise_workspace_selection_is_not_an_enterprise_authority_gate(tmp_path: Path) -> None:
    application = _application(tmp_path, "professional")
    controller = ExperienceContextController(application)
    _profile, event = controller.switch("enterprise")
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    policy = NavigationPolicyEngine(resolver)

    assert event.current.mode is ExperienceMode.ENTERPRISE
    assert event.current.workspace.landing_page == "enterprise"
    assert resolver.allowed("enterprise", event.current.navigation)
    # Privileged fleet/server surfaces remain independently protected.
    assert not resolver.allowed("server", event.current.navigation)
    assert policy.rebuild(event.current).page_ids[0] == "enterprise"


def test_persisted_developer_mode_restores_complete_expanded_navigation(tmp_path: Path) -> None:
    application = _application(tmp_path, "professional", developer_mode=True)
    controller = ExperienceContextController(application)
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    navigation = controller.current.navigation

    assert controller.current.mode is ExperienceMode.DEVELOPER
    assert application.settings.developer_nav_expanded is True
    assert resolver.allowed("developer_center", navigation)
    assert resolver.allowed("console", navigation)
    assert resolver.allowed("logs", navigation)
    assert resolver.allowed("plugins", navigation)

    persisted = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert persisted["developer_mode"] is True
    assert persisted["developer_nav_expanded"] is True
    assert persisted["experience_profile"] == "developer"


def test_developer_shortcuts_have_real_resolver_targets() -> None:
    root = Path(__file__).resolve().parents[1]
    registry = (
        root / "src" / "arenyxa" / "presentation" / "main_window_registry.py"
    ).read_text(encoding="utf-8")
    expected = {
        "dev_api": "advanced",
        "dev_sandbox": "plugins",
        "dev_performance": "advanced",
    }
    for action_id, page_id in expected.items():
        assert f'"{action_id}": "{page_id}"' in registry
    manifest_ids = {item.id for item in DEFAULT_PAGE_MANIFESTS}
    assert set(expected.values()).issubset(manifest_ids)


def test_root_session_projects_root_workspace_only_after_fresh_authority(tmp_path: Path) -> None:
    application = _application(tmp_path, "developer")
    ordinary = ExperienceContextFactory.from_application(application)
    assert ordinary.mode is ExperienceMode.DEVELOPER

    expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    application.root_developer_workstation = True
    application.developer_access = SimpleNamespace(
        status=lambda: SimpleNamespace(
            authenticated=True,
            capabilities=("platform.root",),
            kind="root_owner",
            session_expires_at=expiry,
            developer_id="owner-1",
        )
    )
    context = ExperienceContextFactory.from_application(application)
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)

    assert context.mode is ExperienceMode.ROOT_DEVELOPER
    assert context.navigation.root_session.active
    # An authenticated Root session is the top technical authority in navigation.
    assert all(resolver.allowed(item.id, context.navigation) for item in DEFAULT_PAGE_MANIFESTS)


def test_root_startup_gate_reprobes_live_device_and_has_no_normal_session_bypass() -> None:
    root = Path(__file__).resolve().parents[1]
    app = (root / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    gate = (root / "src" / "arenyxa" / "presentation" / "root_owner_gate.py").read_text(encoding="utf-8")
    shell = (root / "src" / "arenyxa" / "presentation" / "shell_window.py").read_text(encoding="utf-8")

    function = app[app.index("def _enforce_registered_root_startup("):app.index("def _schedule_startup_health_checks(")]
    assert "manager.root_workstation_registered()" in function
    assert "manager.root_capability_state()" in function
    assert "failing closed into Root authentication" in function
    assert 'result = {"mode": "denied"}' in gate
    assert 'return result["mode"] == "root"' in gate
    assert "ROOT_STARTUP_CONTINUE_NORMAL" not in gate
    assert 'self.continue_button.setVisible(False)' in shell
