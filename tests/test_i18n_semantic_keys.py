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
from arenyxa.presentation.shell_window import _STARTUP_ACTIVITY_KEYS


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
    ROOT / "src/arenyxa/presentation/pages/tools_console.py",
    ROOT / "src/arenyxa/presentation/pages/tools_platform.py",
    ROOT / "src/arenyxa/presentation/pages/tools_automation.py",
    ROOT / "src/arenyxa/presentation/pages/enterprise.py",
    ROOT / "src/arenyxa/presentation/pages/enterprise_identity_actions.py",
    ROOT / "src/arenyxa/presentation/pages/enterprise_distributed_actions.py",
    ROOT / "src/arenyxa/presentation/pages/tools_terminal_execution.py",
    ROOT / "src/arenyxa/presentation/pages/tools_terminal_workspace.py",
    ROOT / "src/arenyxa/presentation/command_palette.py",
    ROOT / "src/arenyxa/presentation/main_window.py",
    ROOT / "src/arenyxa/presentation/main_window_lifecycle.py",
    ROOT / "src/arenyxa/presentation/main_window_navigation.py",
    ROOT / "src/arenyxa/presentation/main_window_operations.py",
    ROOT / "src/arenyxa/presentation/shell_window.py",
    ROOT / "src/arenyxa/presentation/root_developer_gate.py",
    ROOT / "src/arenyxa/presentation/root_owner_gate.py",
)
CATALOG_LOCALES = ("en_US", "zh_CN", "fr_FR", "de_DE", "ja_JP")
CJK = re.compile(r"[\u3400-\u9fff]")
PRESENTATION_ROOT = ROOT / "src/arenyxa/presentation"
PRESENTATION_PAGE_FILES = tuple(sorted((PRESENTATION_ROOT / "pages").glob("*.py")))
PRESENTATION_CJK_RESOURCE_FILES = {
    PRESENTATION_ROOT / "language.py",
    PRESENTATION_ROOT / "language_enterprise.py",
    PRESENTATION_ROOT / "i18n_catalog.py",
    PRESENTATION_ROOT / "repair_dialog.py",
    PRESENTATION_ROOT / "product_copy.py",
    PRESENTATION_ROOT / "themes.py",
}
PRESENTATION_RUNTIME_FILES = tuple(
    path
    for path in sorted(PRESENTATION_ROOT.glob("*.py"))
    if path not in PRESENTATION_CJK_RESOURCE_FILES
)
ENTERPRISE_MACHINE_IDENTIFIERS = {
    "enterprise.account.manage",
    "enterprise.audit.read",
    "enterprise.coordinator.manage",
    "enterprise.device.manage",
    "enterprise.enrollment.manage",
    "enterprise.remote_ops",
    "enterprise.vault.manage",
    "enterprise.workspace.manage",
}
SHELL_MACHINE_IDENTIFIERS = {
    "studio.autopilot",
    "studio.blueprint",
    "studio.compatibility",
    "studio.debugger",
    "studio.http",
    "studio.live",
    "studio.portability",
    "studio.profiles",
    "studio.recorder",
    "studio.secrets",
    "studio.selector",
    "studio.smartpath",
    "studio.workers",
}
KEY = re.compile(
    r'(?:"|\')((?:welcome|personalization|settings|about|developer\.terms|theme|network|studio|studio_intelligence|dashboard|task_center|tasks|data|search|version|visualization|tools_console|tools_logs|tools_platform|tools_plugins|tools_automation|tools_workflow|enterprise|tools_terminal|shell|root_gate)\.[A-Za-z0-9_.]+)(?:"|\')'
)


def _referenced_keys() -> set[str]:
    keys: set[str] = set()
    for path in MIGRATED_UI_FILES:
        text = path.read_text(encoding="utf-8")
        keys.update(KEY.findall(text))
    keys.discard("settings.json")
    keys.discard("visualization.png")
    keys.difference_update(ENTERPRISE_MACHINE_IDENTIFIERS)
    keys.difference_update(SHELL_MACHINE_IDENTIFIERS)
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
    for startup_key in set(_STARTUP_ACTIVITY_KEYS.values()):
        keys.add(f"shell.startup.state.{startup_key}")
        keys.add(f"shell.startup.hint.{startup_key}")
    return keys


def test_all_presentation_pages_do_not_embed_cjk_ui_copy() -> None:
    assert PRESENTATION_PAGE_FILES, "presentation/pages discovery unexpectedly returned no Python files"
    for path in PRESENTATION_PAGE_FILES:
        text = path.read_text(encoding="utf-8")
        assert not CJK.search(text), f"hard-coded CJK UI copy remains in presentation page {path}"


def test_presentation_runtime_modules_do_not_embed_cjk_ui_copy() -> None:
    for path in PRESENTATION_RUNTIME_FILES:
        text = path.read_text(encoding="utf-8")
        assert not CJK.search(text), f"hard-coded CJK UI copy remains in presentation runtime {path}"


def test_presentation_cjk_resource_allowlist_is_explicit_and_existing() -> None:
    for path in PRESENTATION_CJK_RESOURCE_FILES:
        assert path.is_file(), f"stale presentation CJK resource allowlist entry: {path}"


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


def test_console_mode_display_keys_preserve_machine_values() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/tools_console.py").read_text(
        encoding="utf-8"
    )
    for key, value in (
        ("tools_console.mode.arenyxa", "arenyxa"),
        ("tools_console.mode.direct", "TerminalMode.DIRECT.value"),
        ("tools_console.mode.powershell", "TerminalMode.POWERSHELL.value"),
        ("tools_console.mode.powershell_session", "TerminalMode.POWERSHELL_SESSION.value"),
        ("tools_console.mode.cmd", "TerminalMode.CMD.value"),
        ("tools_console.mode.cmd_session", "TerminalMode.CMD_SESSION.value"),
        ("tools_console.mode.python", "TerminalMode.PYTHON.value"),
        ("tools_console.mode.python_repl", "TerminalMode.PYTHON_SESSION.value"),
    ):
        assert key in source
        assert value in source


def test_workflow_edge_display_keys_preserve_machine_values() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/tools_automation.py").read_text(
        encoding="utf-8"
    )
    assert '("tools_workflow.edge.normal", "normal")' in source
    assert '("tools_workflow.edge.failure", "failure")' in source


def test_enterprise_resource_kind_display_does_not_replace_machine_value() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/enterprise_distributed_actions.py").read_text(
        encoding="utf-8"
    )
    for key, value in (
        ("enterprise.resource_kind.workflow", "workflow"),
        ("enterprise.resource_kind.dataset", "dataset"),
        ("enterprise.resource_kind.capture", "capture"),
        ("enterprise.resource_kind.schedule", "schedule"),
        ("enterprise.resource_kind.worker", "worker"),
        ("enterprise.resource_kind.project", "project"),
    ):
        assert f'("{key}", "{value}")' in source


def test_terminal_workspace_display_keys_preserve_machine_values() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/tools_terminal_workspace.py").read_text(
        encoding="utf-8"
    )
    for key, value in (
        ("tools_terminal.workspace.mode.powershell", "TerminalMode.POWERSHELL_SESSION.value"),
        ("tools_terminal.workspace.mode.cmd", "TerminalMode.CMD_SESSION.value"),
        ("tools_terminal.workspace.mode.python", "TerminalMode.PYTHON_SESSION.value"),
        ("tools_terminal.workspace.pane.primary", '"primary"'),
        ("tools_terminal.workspace.pane.secondary", '"secondary"'),
        ("tools_terminal.workspace.pane.bottom", '"bottom"'),
    ):
        assert key in source
        assert value in source


def test_terminal_help_is_catalog_backed() -> None:
    source = (ROOT / "src/arenyxa/presentation/pages/tools_terminal_workspace.py").read_text(
        encoding="utf-8"
    )
    assert 'return current_text("tools_terminal.help.text")' in source


def test_shell_navigation_machine_ids_remain_untranslated() -> None:
    referenced = _referenced_keys()
    for identifier in SHELL_MACHINE_IDENTIFIERS:
        assert identifier not in referenced


def test_shell_inspector_localization_does_not_overwrite_dynamic_context() -> None:
    main_source = (ROOT / "src/arenyxa/presentation/main_window.py").read_text(encoding="utf-8")
    nav_source = (ROOT / "src/arenyxa/presentation/main_window_navigation.py").read_text(
        encoding="utf-8"
    )
    lifecycle_source = (ROOT / "src/arenyxa/presentation/main_window_lifecycle.py").read_text(
        encoding="utf-8"
    )
    assert 'setProperty("shellInspectorEmpty", True)' in main_source
    assert 'setProperty("i18n_key_text", None)' in nav_source
    assert 'setProperty("shellInspectorEmpty", False)' in nav_source
    assert 'property("shellInspectorEmpty")' in lifecycle_source
    assert 'current_text("shell.inspector.empty")' in lifecycle_source


def test_shell_startup_dynamic_keys_are_catalog_backed() -> None:
    required = _referenced_keys()
    for startup_key in set(_STARTUP_ACTIVITY_KEYS.values()):
        assert f"shell.startup.state.{startup_key}" in required
        assert f"shell.startup.hint.{startup_key}" in required


def test_root_gate_security_machine_values_remain_unlocalized() -> None:
    developer_source = (ROOT / "src/arenyxa/presentation/root_developer_gate.py").read_text(
        encoding="utf-8"
    )
    owner_source = (ROOT / "src/arenyxa/presentation/root_owner_gate.py").read_text(
        encoding="utf-8"
    )
    assert 'ROOT_CONFIRMATION_TEXT = "ROOT"' in developer_source
    assert 'self.confirmation.text() == ROOT_CONFIRMATION_TEXT' in developer_source
    assert '"platform.root"' in owner_source
    assert '"ROOT_OWNER_AUTH_REQUIRED"' in owner_source
    assert '"ROOT_OWNER_AUTH_ATTEMPTS_EXHAUSTED"' in owner_source


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
