from __future__ import annotations

import importlib
from pathlib import Path


def test_legacy_package_is_self_contained() -> None:
    package = importlib.import_module("arenyxa")
    assert getattr(package, "__version__", "") == "7.3"


def test_legacy_core_modules_import_without_modern_arenyxa_dependency() -> None:
    modules = (
        "arenyxa.compat",
        "arenyxa.domain.models",
        "arenyxa.application.runner",
        "arenyxa.infrastructure.database",
    )
    for name in modules:
        module = importlib.import_module(name)
        assert module is not None


def test_legacy_manifest_declares_feature_freeze() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "LEGACY_RUNTIME.json").read_text(encoding="utf-8")
    assert '"status": "feature-frozen"' in text
    assert '"python": "3.8"' in text
