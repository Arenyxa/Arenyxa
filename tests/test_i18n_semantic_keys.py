from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from arenyxa.qt_compat import binding_available

if not binding_available():
    pytest.skip("No supported Qt binding is installed", allow_module_level=True)

from arenyxa.qt_compat.QtWidgets import QComboBox, QLabel

from arenyxa.application.experience import EXPERIENCE_PROFILES
from arenyxa.presentation.language import LanguageManager


ROOT = Path(__file__).resolve().parents[1]
MIGRATED_UI_FILES = (
    ROOT / "src/arenyxa/presentation/pages/welcome.py",
    ROOT / "src/arenyxa/presentation/pages/personalization.py",
)
SEMANTIC_KEY_FILES = (
    *MIGRATED_UI_FILES,
    ROOT / "src/arenyxa/presentation/pages/settings.py",
    ROOT / "src/arenyxa/presentation/pages/settings_support.py",
    ROOT / "src/arenyxa/presentation/main_window.py",
    ROOT / "src/arenyxa/presentation/main_window_navigation.py",
)
CATALOG_LOCALES = ("en_US", "zh_CN", "fr_FR", "de_DE", "ja_JP")
CJK = re.compile(r"[\u3400-\u9fff]")
KEY = re.compile(r'(?:"|\')((?:welcome|personalization)\.[A-Za-z0-9_.]+)(?:"|\')')


def _referenced_keys() -> set[str]:
    keys: set[str] = set()
    for path in SEMANTIC_KEY_FILES:
        text = path.read_text(encoding="utf-8")
        keys.update(KEY.findall(text))
    for profile in EXPERIENCE_PROFILES:
        keys.add(f"welcome.profile.{profile.id}.title")
        keys.add(f"welcome.profile.{profile.id}.summary")
        for index, _detail in enumerate(profile.detail):
            keys.add(f"welcome.profile.{profile.id}.detail.{index}")
    return keys


def test_migrated_pages_do_not_embed_cjk_ui_copy() -> None:
    for path in MIGRATED_UI_FILES:
        text = path.read_text(encoding="utf-8")
        assert not CJK.search(text), f"hard-coded CJK UI copy remains in {path}"


def test_migrated_page_keys_exist_in_packaged_catalogs() -> None:
    required = _referenced_keys()
    assert required
    for locale in CATALOG_LOCALES:
        payload = json.loads((ROOT / f"src/arenyxa/locale/{locale}.json").read_text(encoding="utf-8"))
        missing = sorted(required - payload.keys())
        assert not missing, f"{locale} missing i18n keys: {missing}"


def test_semantic_widget_keys_retranslate_on_locale_change(qapp) -> None:
    manager = LanguageManager(qapp, "en_US")

    label = QLabel("placeholder")
    label.setProperty("i18n_key_text", "personalization.title")

    combo = QComboBox()
    combo.addItem("placeholder", "auto")
    combo.setProperty("i18n_item_key_0", "personalization.animation.auto")

    tooltip = QLabel("placeholder")
    tooltip.setToolTip("placeholder")
    tooltip.setProperty("i18n_key_tooltip", "shell.collapse_sidebar")

    manager.apply("en_US")
    manager.translate_tree(label)
    manager.translate_tree(combo)
    manager.translate_tree(tooltip)
    assert label.text() == "Personalization"
    assert combo.itemText(0) == "Automatic (adapt to performance)"
    assert tooltip.toolTip() == "Collapse sidebar"

    manager.apply("zh_CN")
    manager.translate_tree(label)
    manager.translate_tree(combo)
    manager.translate_tree(tooltip)
    assert label.text() == "个性化"
    assert combo.itemText(0) == "自动（根据性能动态调整）"
    assert tooltip.toolTip() == "折叠侧边栏"
