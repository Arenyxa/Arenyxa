from __future__ import annotations

import importlib.util

import pytest

if importlib.util.find_spec("PySide6") is None and importlib.util.find_spec("PySide2") is None:
    pytest.skip("No supported Qt binding is installed", allow_module_level=True)

from datetime import UTC, datetime, timedelta

from arenyxa.navigation import (
    AccountRole,
    ActiveRootSession,
    DEFAULT_PAGE_MANIFESTS,
    DeveloperAuthority,
    ExperienceMode,
    NavigationContext,
    NavigationResolver,
    RuntimeMode,
)
from arenyxa.presentation.virtual_table import VirtualCaptureTableModel


def _context(
    experience: ExperienceMode,
    *,
    developer: bool = False,
    root: bool = False,
) -> NavigationContext:
    expiry = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    authority = DeveloperAuthority(
        authenticated=developer,
        credential_valid=developer,
        expires_at=expiry if developer else "",
    )
    root_session = ActiveRootSession(
        authenticated=root,
        expires_at=expiry if root else "",
        capabilities=frozenset({"platform.root"}) if root else frozenset(),
    )
    return NavigationContext(
        experience,
        RuntimeMode.DESKTOP,
        AccountRole.PERSONAL,
        authority,
        root_session,
    )


def test_navigation_diff_meets_preset_and_root_latency_budgets() -> None:
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    guided = _context(ExperienceMode.GUIDED)
    advanced = _context(ExperienceMode.ADVANCED)
    developer = _context(ExperienceMode.DEVELOPER, developer=True)
    root = _context(ExperienceMode.DEVELOPER, developer=True, root=True)

    advanced_diff, guided_to_advanced_ms = resolver.timed_diff(guided, advanced)
    developer_diff, advanced_to_developer_ms = resolver.timed_diff(advanced, developer)
    root_diff, root_unlock_ms = resolver.timed_diff(developer, root)
    logout_diff, root_logout_ms = resolver.timed_diff(root, advanced)

    assert advanced_diff.changed and guided_to_advanced_ms < 300
    assert developer_diff.changed and advanced_to_developer_ms < 500
    assert root_diff.changed and root_unlock_ms < 800
    assert logout_diff.changed and root_logout_ms < 500


def test_virtual_capture_model_exposes_million_rows_without_allocating_them(qapp) -> None:
    calls: list[tuple[int, int]] = []

    def loader(offset: int, limit: int):
        calls.append((offset, limit))
        return []

    model = VirtualCaptureTableModel(loader, total=1_000_000)
    assert model.rowCount() == 1_000_000
    assert model.loaded_row_count == 0
    assert calls == []
    assert model.max_cached_pages == 24
    assert model.page_size == 1024

