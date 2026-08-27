from __future__ import annotations

import json
from pathlib import Path

import pytest

from arenyxa.application.runtime_ecosystem import (
    BrowserProfile,
    BrowserProfileService,
    WorkflowMarketplaceService,
)
from arenyxa.domain.errors import ArenyxaError


def test_browser_profile_rejects_path_traversal(tmp_path: Path) -> None:
    service = BrowserProfileService(tmp_path / "profiles")
    with pytest.raises(ArenyxaError) as exc:
        service.save(BrowserProfile("../../escape", "Bad"))
    assert exc.value.code == "BROWSER_PROFILE_ID_INVALID"


def test_browser_profile_round_trip_uses_safe_atomic_path(tmp_path: Path) -> None:
    service = BrowserProfileService(tmp_path / "profiles")
    path = service.save(BrowserProfile("safe-id", "Safe"))
    assert path.is_file()
    assert service.load("safe-id").name == "Safe"
    assert not path.with_suffix(".tmp").exists()


def test_browser_profile_rejects_mismatched_stored_id(tmp_path: Path) -> None:
    root = tmp_path / "profiles"
    path = root / "safe" / "profile.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"id": "other", "name": "Mismatch"}), encoding="utf-8")
    with pytest.raises(ArenyxaError) as exc:
        BrowserProfileService(root).load("safe")
    assert exc.value.code == "BROWSER_PROFILE_INVALID"


def test_marketplace_remote_catalog_requires_https() -> None:
    with pytest.raises(ArenyxaError) as exc:
        WorkflowMarketplaceService().load_catalog("http://example.invalid/catalog.json")
    assert exc.value.code == "MARKETPLACE_INSECURE_URL"


def test_marketplace_local_catalog_validates_hash_format(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    catalog.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "id": "demo",
                        "name": "Demo",
                        "version": "1.0.0",
                        "description": "",
                        "package_url": "https://example.invalid/demo.arenyxa",
                        "sha256": "not-a-hash",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ArenyxaError) as exc:
        WorkflowMarketplaceService().load_catalog(catalog)
    assert exc.value.code == "MARKETPLACE_CATALOG_INVALID"
