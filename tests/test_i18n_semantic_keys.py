from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from arenyxa.qt_compat import binding_available

if not binding_available():
    pytest.skip("No supported Qt binding is installed", allow_module_level=True)

from arenyxa.qt_compat.QtWidgets import QComboBox, QLabel, QTabWidget, QWidget

from arenyxa.application.experience import EXPERIENCE_PROFILES
from arenyxa.application.general_user import GeneralUserIntentRouter
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.presentation.i18n_runtime import current_text, source_text
from arenyxa.presentation.language import LanguageManager


ROOT = Path(__file__).resolve().parents[1]
MIGRATED_UI_FILES = (
    ROOT / "src/arenyxa/presentation/pages/welcome.py",
    ROOT / "src/arenyxa/presentation/pages/personalization.py",
    ROOT / "src/arenyxa/presentation/pages/settings.py",
    ROOT / "src/arenyxa/presentation/pages/settings_support.py",
    ROOT / "src/arenyxa/presentation/pages/network.py",
    ROOT / "src/arenyxa/presentation/pages/network_capture_actions.py",
    ROOT / "src/arenyxa/presentation/pages/network_analysis_actions.py",
    ROOT / "src/arenyxa/presentation/pages/studio_operations.py",
    ROOT / "src/arenyxa/presentation/pages/dashboard.py",
    ROOT / "src/arenyxa/presentation/pages/dashboard_widgets.py",
    ROOT / "src/arenyxa/presentation/pages/task_center.py",
    ROOT / "src/arenyxa/presentation/pages/tasks.py",
    ROOT / "src/arenyxa/presentation/pages/data.py",
    ROOT / "src/arenyxa/presentation/pages/studio.py",
    ROOT / "src/arenyxa/presentation/pages/studio_intelligence.py",
    ROOT / "src/arenyxa/presentation/pages/visualization.py",
)
CATALOG_LOCALES = ("en_US", "zh_CN", "fr_FR", "de_DE", "ja_JP")
CJK = re.compile(r"[\u3400-\u9fff]")
KEY = re.compile(
    r'(?:"|\')((?:welcome|personalization|settings|about|developer\.terms|theme|network|studio|studio_intelligence|dashboard|task_center|tasks|data|search|version|visualization)\.[A-Za-z0-9_.]+)(?:"|\')'
)


def _referenced_keys() -> set[str]:
    keys: set[str] = set()
    for path in MIGRATED_UI_FILES:
        text = path.read_text(encoding="utf-8")
        keys.update(KEY.findall(text))
    keys.discard("settings.json")
    keys.discard("visualization.png")
    for profile in EXPERIENCE_PROFILES:
        keys.add(f"welcome.profile.{profile.id}.title")
        keys.add(f"welcome.profile.{profile.id}.summary")
        for index, _detail in enumerate(profile.detail):
            keys.add(f"welcome.profile.{profile.id}.detail.{index}")
    for workflow in GeneralUserIntentRouter().workflows():
        prefix = f"task_center.workflow.{workflow.id}"
        keys.add(f"{prefix}.title")
        keys.add(f"{prefix}.summary")
        for index, _step in enumerate(workflow.steps):
            keys.add(f"{prefix}.step.{index}")
        if workflow.fallback_note:
            keys.add(f"{prefix}.fallback")
    for status in TaskStatus:
        keys.add(f"tasks.status.{status.value}")
    for status in RunStatus:
        keys.add(f"tasks.run_status.{status.value}")
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


def test_semantic_tab_keys_retranslate_on_locale_change(qapp) -> None:
    manager = LanguageManager(qapp, "en_US")
    tabs = QTabWidget()
    tabs.addTab(QWidget(), "placeholder")
    tabs.setProperty("i18n_tab_key_0", "network.tab.overview")

    manager.apply("en_US")
    manager.translate_tree(tabs)
    assert tabs.tabText(0) == "Overview"

    manager.apply("zh_CN")
    manager.translate_tree(tabs)
    assert tabs.tabText(0) == "概览"


def test_studio_semantic_tabs_are_bound() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/studio_operations.py").read_text(
        encoding="utf-8"
    )
    for key in (
        "studio.tab.templates_environment",
        "studio.tab.profiles_marketplace",
        "studio.tab.compatibility",
        "studio.tab.portability",
        "studio.tab.autopilot",
    ):
        assert f'_add_i18n_tab(tab, "{key}")' in source


def test_studio_intelligence_semantic_tabs_are_bound() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/studio_intelligence.py").read_text(
        encoding="utf-8"
    )
    for key in (
        "studio_intelligence.tab.smartpath",
        "studio_intelligence.tab.blueprint",
        "studio_intelligence.tab.selector",
        "studio_intelligence.tab.http",
        "studio_intelligence.tab.protocol",
        "studio_intelligence.tab.quality",
        "studio_intelligence.tab.recorder",
        "studio_intelligence.tab.debugger",
    ):
        assert f'_add_i18n_tab(tab, "{key}")' in source


def test_visualization_chart_display_keys_preserve_machine_values() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/visualization.py").read_text(
        encoding="utf-8"
    )
    for key, value in (
        ("visualization.chart.line", "Line"),
        ("visualization.chart.bar", "Bar"),
        ("visualization.chart.pie", "Pie"),
        ("visualization.chart.heatmap", "Heatmap"),
        ("visualization.chart.timeline", "Timeline"),
        ("visualization.chart.map", "Map"),
    ):
        assert f'("{key}", "{value}")' in source


def test_task_center_workflow_catalogs_cover_router_workflows() -> None:
    required = _referenced_keys()
    for workflow in GeneralUserIntentRouter().workflows():
        prefix = f"task_center.workflow.{workflow.id}"
        assert f"{prefix}.title" in required
        assert f"{prefix}.summary" in required
        for index, _step in enumerate(workflow.steps):
            assert f"{prefix}.step.{index}" in required


def test_task_and_run_status_display_keys_cover_enum_values() -> None:
    required = _referenced_keys()
    assert {f"tasks.status.{status.value}" for status in TaskStatus} <= required
    assert {f"tasks.run_status.{status.value}" for status in RunStatus} <= required


def test_semantic_catalog_helpers_follow_active_locale(qapp) -> None:
    manager = LanguageManager(qapp, "en_US")
    manager.apply("en_US")
    assert source_text("settings.page.title") == "Settings"
    assert current_text("settings.page.title") == "Settings"

    manager.apply("zh_CN")
    assert current_text("settings.page.title") == "设置"


def test_semantic_widget_keys_retranslate_on_locale_change(qapp) -> None:
    manager = LanguageManager(qapp, "en_US")

    label = QLabel("placeholder")
    label.setProperty("i18n_key_text", "personalization.title")

    combo = QComboBox()
    combo.addItem("placeholder", "auto")
    combo.setProperty("i18n_item_key_0", "personalization.animation.auto")

    manager.apply("en_US")
    manager.translate_tree(label)
    manager.translate_tree(combo)
    assert label.text() == "Personalization"
    assert combo.itemText(0) == "Automatic (adapt to performance)"
    assert combo.itemData(0) == "auto"

    manager.apply("zh_CN")
    manager.translate_tree(label)
    manager.translate_tree(combo)
    assert label.text() == "个性化"
    assert combo.itemText(0) == "自动（根据性能动态调整）"
    assert combo.itemData(0) == "auto"
