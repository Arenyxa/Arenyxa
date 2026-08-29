from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

from arenyxa.config import AppSettings
from arenyxa import __display_version__, __distribution_version__, __engineering_build__
from arenyxa.navigation import (
    AccountRole,
    ExperienceContextController,
    ExperienceContextFactory,
    ExperienceMode,
    NavigationContext,
    NavigationPolicyEngine,
    NavigationResolver,
    RuntimeMode,
    WORKSPACE_POLICIES,
)
from arenyxa.navigation.manifest import DEFAULT_PAGE_MANIFESTS


class _EnterpriseIdentity:
    def __init__(self, *, configured: bool = False, authenticated: bool = False) -> None:
        self._configured = configured
        self._authenticated = authenticated

    def status(self):
        return SimpleNamespace(
            configured=self._configured,
            authenticated=self._authenticated,
            enterprise_id="enterprise-test" if self._configured else "",
            account_id="account-test" if self._authenticated else "",
            roles=("administrator",) if self._authenticated else (),
            permissions=("enterprise.audit.read",) if self._authenticated else (),
        )


def _application(root: Path, settings: AppSettings | None = None):
    return SimpleNamespace(
        settings=settings or AppSettings(),
        paths=SimpleNamespace(root=root),
        runtime_mode="desktop",
        enterprise_identity=_EnterpriseIdentity(),
        developer_access=None,
        navigation_capabilities=(),
        root_developer_workstation=False,
    )


class V80ExperienceTests(unittest.TestCase):
    def test_engineering_build_identity(self) -> None:
        self.assertEqual(__engineering_build__, "v8.1.1")
        self.assertEqual(__display_version__, "8.1.1")
        self.assertEqual(__distribution_version__, "8.1.1")

    def test_five_modes_and_primary_navigation_limit(self) -> None:
        self.assertEqual(
            set(ExperienceMode),
            {
                ExperienceMode.PERSONAL,
                ExperienceMode.PROFESSIONAL,
                ExperienceMode.DEVELOPER,
                ExperienceMode.ENTERPRISE,
                ExperienceMode.ROOT_DEVELOPER,
            },
        )
        self.assertTrue(all(len(policy.primary_pages) <= 8 for policy in WORKSPACE_POLICIES.values()))
        self.assertIs(ExperienceMode.GUIDED, ExperienceMode.PERSONAL)
        self.assertIs(ExperienceMode.ADVANCED, ExperienceMode.PROFESSIONAL)

    def test_enterprise_mode_enters_console_without_enterprise_identity(self) -> None:
        context = NavigationContext(
            ExperienceMode.ENTERPRISE,
            RuntimeMode.DESKTOP,
            AccountRole.PERSONAL,
        )
        resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
        self.assertTrue(resolver.allowed("enterprise", context))

    def test_developer_workspace_is_visible_without_minting_tool_authority(self) -> None:
        context = NavigationContext(
            ExperienceMode.DEVELOPER,
            RuntimeMode.DESKTOP,
            AccountRole.PERSONAL,
        )
        resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
        self.assertTrue(resolver.allowed("developer_center", context))
        self.assertFalse(resolver.allowed("console", context))

    def test_switch_persists_context_publishes_event_and_rebuilds_navigation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = _application(root)
            controller = ExperienceContextController(application)
            events = []
            controller.subscribe(events.append)
            profile, event = controller.switch("enterprise")

            self.assertEqual(profile.id, "enterprise")
            self.assertEqual(event.current.mode, ExperienceMode.ENTERPRISE)
            self.assertEqual(event.current.workspace.landing_page, "enterprise")
            self.assertEqual(events, [event])
            persisted = json.loads((root / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["experience_profile"], "enterprise")

            policy = NavigationPolicyEngine(NavigationResolver(DEFAULT_PAGE_MANIFESTS))
            self.assertIn("enterprise", policy.rebuild(event.current).visible)

    def test_personal_scenario_and_restart_restore_landing_page(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = AppSettings(personal_scenario="network_diagnostics")
            controller = ExperienceContextController(_application(root, settings))
            _profile, event = controller.switch("personal")
            self.assertEqual(event.current.workspace.landing_page, "network")

            restored = AppSettings.load(root / "settings.json")
            restored_context = ExperienceContextFactory.from_application(_application(root, restored))
            self.assertEqual(restored_context.mode, ExperienceMode.PERSONAL)
            self.assertEqual(restored_context.workspace.landing_page, "network")

    def test_root_mode_requires_active_root_challenge_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            application = _application(root, AppSettings(experience_profile="root_developer"))
            ordinary = ExperienceContextFactory.from_application(application)
            self.assertEqual(ordinary.mode, ExperienceMode.DEVELOPER)

            expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
            application.root_developer_workstation = True
            application.developer_access = SimpleNamespace(
                status=lambda: SimpleNamespace(
                    authenticated=True,
                    capabilities=("platform.root",),
                    kind="root_owner",
                    session_expires_at=expires,
                    developer_id="root-owner",
                )
            )
            root_context = ExperienceContextFactory.from_application(application)
            self.assertEqual(root_context.mode, ExperienceMode.ROOT_DEVELOPER)
            self.assertTrue(root_context.identity.root_authenticated)


if __name__ == "__main__":
    unittest.main()
