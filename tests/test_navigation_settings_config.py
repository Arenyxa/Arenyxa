from __future__ import annotations

import json

from arenyxa.config import AppSettings


def test_navigation_group_settings_round_trip(tmp_path) -> None:
    path = tmp_path / "settings.json"
    settings = AppSettings(
        left_sidebar_collapsed=True,
        advanced_nav_expanded=True,
        developer_nav_expanded=True,
        developer_mode=True,
    )
    settings.save(path)
    loaded = AppSettings.load(path)
    assert loaded.left_sidebar_collapsed is True
    assert loaded.advanced_nav_expanded is True
    assert loaded.developer_nav_expanded is True
    assert loaded.developer_mode is True


def test_navigation_group_settings_reject_non_boolean_values(tmp_path) -> None:
    path = tmp_path / "settings.json"
    payload = {
        "advanced_nav_expanded": "yes",
        "developer_nav_expanded": 1,
        "developer_mode": "true",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = AppSettings.load(path)
    assert loaded.advanced_nav_expanded is False
    assert loaded.developer_nav_expanded is False
    assert loaded.developer_mode is False


def test_developer_navigation_is_forced_closed_when_developer_mode_is_off(tmp_path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps({"developer_mode": False, "developer_nav_expanded": True}),
        encoding="utf-8",
    )
    loaded = AppSettings.load(path)
    assert loaded.developer_mode is False
    assert loaded.developer_nav_expanded is False
