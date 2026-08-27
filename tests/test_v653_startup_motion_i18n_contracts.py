from __future__ import annotations

import ast
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def test_normal_health_check_is_deferred_until_after_main_window_show() -> None:
    source = (SRC / "app.py").read_text(encoding="utf-8")
    main = source[source.index("def main("):]
    health = source[source.index("def _schedule_startup_health_checks"):source.index("def main(")]
    show = main.index("window.show()")
    schedule_call = main.index("_schedule_startup_health_checks(")
    assert show < schedule_call
    assert "def deferred_startup_health_check" in health
    assert "StartupHealthScanner(" in health
    assert "qtimer.singleShot(700, deferred_startup_health_check)" in health
    assert "ask_startup_repair(report, window.language.locale, window)" in health
    assert "Recovery Mode" in source
    assert "ask_startup_repair(failure_report, locale, recovery_window)" in source


def test_page_navigation_commits_atomically_without_layout_geometry_motion() -> None:
    main_window = ((SRC / "presentation" / "main_window.py").read_text(encoding="utf-8") + "\n" + (SRC / "presentation" / "main_window_navigation.py").read_text(encoding="utf-8"))
    navigate = main_window[main_window.index("def navigate("):main_window.index("def _nav_group_expanded", main_window.index("def navigate("))]
    commit = main_window[main_window.index("def _commit_stack_page"):main_window.index("def _finish_navigation", main_window.index("def _commit_stack_page"))]
    assert "self._commit_stack_page(page)" in navigate
    assert "self.stack.setCurrentIndex(index)" in commit
    assert "self.motion.transition_stack" not in commit
    assert ".move(" not in commit

def test_advanced_english_catalog_has_native_targets_for_every_supported_non_english_locale() -> None:
    catalog_path = SRC / "presentation" / "i18n_catalog.py"
    spec = importlib.util.spec_from_file_location("arenyxa_i18n_catalog_test", catalog_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    expected = {
        "Active request budget",
        "Analyze Quality & Schema",
        "Browser Profile Manager",
        "Clean / Deduplicate",
        "Workflow Debugger",
        "Browser Recorder",
        "Data Quality Studio",
        "HTTP Request Builder",
        "Protocol Inspector",
        "Selector Studio",
        "Secrets Vault",
        "Distributed Workers",
        "Project Environment",
        "Workflow Marketplace",
        "Workflow Portability",
        "Compatibility Lab",
        "Autopilot Learning",
        "Request Replay",
        "TLS Inspector",
        "DNS Analyzer",
        "Process Monitor",
        "Database Adapter",
    }
    for locale in ("fr_FR", "ru_RU", "de_DE", "ja_JP", "ko_KR", "ar_SA", "la_VA"):
        table = module.NATIVE_PHRASES[locale]
        missing = sorted(item for item in expected if not table.get(item) or table[item] == item)
        assert missing == [], (locale, missing)


def test_language_walker_tracks_catalogued_english_sources_without_translating_user_fields() -> None:
    source = (SRC / "presentation" / "language.py").read_text(encoding="utf-8")
    assert "def _is_translatable_ui_literal" in source
    assert "candidate in _TRANSLATABLE_ENGLISH" in source
    assert "_ENGLISH_TO_ZH" in source
    assert "QLineEdit" in source and "placeholder" in source
                                                                               
    assert "isinstance(widget, QPlainTextEdit) and widget.isReadOnly()" in source


def test_repair_center_exposes_feature_wiring_category_and_detailed_evidence() -> None:
    repair = ((SRC / "repair.py").read_text(encoding="utf-8") + "\n" + (SRC / "repair_common.py").read_text(encoding="utf-8") + "\n" + (SRC / "repair_engine.py").read_text(encoding="utf-8"))
    dialog = (SRC / "presentation" / "repair_dialog.py").read_text(encoding="utf-8")
    assert 'FEATURE_INTEGRATION = "feature_integration"' in repair
    assert "_verify_feature_integration_files" in repair
    assert "_finding_text" in dialog
    assert "finding.evidence" in dialog
    assert "issues_summary" in dialog


def test_runtime_language_hot_switch_translates_english_first_controls_and_preserves_user_data(qapp) -> None:
    from arenyxa.qt_compat.QtWidgets import QComboBox, QLabel, QLineEdit, QPlainTextEdit, QTabWidget, QVBoxLayout, QWidget
    from arenyxa.presentation.language import LanguageManager

    root = QWidget()
    layout = QVBoxLayout(root)
    action = QLabel("Request Replay")
    layout.addWidget(action)
    count_label = QLabel("0 records")
    layout.addWidget(count_label)
    tabs = QTabWidget()
    tabs.addTab(QWidget(), "Workflow Debugger")
    layout.addWidget(tabs)
    combo = QComboBox()
    combo.addItem("Browser Profile Manager")
    layout.addWidget(combo)
    user_text = QLineEdit("https://example.com/?q=用户输入")
    user_text.setPlaceholderText("URL")
    layout.addWidget(user_text)
    editor = QPlainTextEdit('{"user":"literal"}')
    editor.setReadOnly(False)
    layout.addWidget(editor)

    manager = LanguageManager(qapp, "en_US")
    manager.translate_tree(root)

    manager.apply("fr_FR")
    manager.translate_tree(root)
                                                                                     
                                                                                          
    assert action.text() == "Relecture de requête"
    assert count_label.text() == "0 enregistrements"
    assert tabs.tabText(0) == "Débogueur de Workflow"
    assert combo.itemText(0) == "Gestionnaire de profils navigateur"

    manager.apply("ja_JP")
    manager.translate_tree(root)
    assert action.text() == "リクエスト再生"
    assert tabs.tabText(0) == "Workflow デバッガー"

    manager.apply("zh_CN")
    manager.translate_tree(root)
    assert action.text() == "请求重放"
    count_label.setText("5 records")
    manager.translate_tree(root)
    assert count_label.text() == "5 条记录"
    assert tabs.tabText(0) == "工作流调试器"
    assert combo.itemText(0) == "浏览器配置管理"
    assert user_text.text() == "https://example.com/?q=用户输入"
    assert editor.toPlainText() == '{"user":"literal"}'


def test_direct_static_chinese_controls_are_registered_in_phrase_catalog() -> None:
    phrase_keys: set[str] = set()
    catalog_paths = [
        SRC / "presentation" / "language.py",
        SRC / "presentation" / "language_enterprise.py",
    ]
    for catalog_path in catalog_paths:
        language_tree = ast.parse(catalog_path.read_text(encoding="utf-8"))
        for node in ast.walk(language_tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
                if any(name == "PHRASES" or name.endswith("_PHRASES") for name in targets):
                    phrase_keys.update(
                        key.value for key in node.value.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)
                    )
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and (node.target.id == "PHRASES" or node.target.id.endswith("_PHRASES"))
                and isinstance(node.value, ast.Dict)
            ):
                phrase_keys.update(
                    key.value for key in node.value.keys if isinstance(key, ast.Constant) and isinstance(key.value, str)
                )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and (node.func.value.id == "PHRASES" or node.func.value.id.endswith("_PHRASES"))
                and node.func.attr == "update"
                and node.args
                and isinstance(node.args[0], ast.Dict)
            ):
                phrase_keys.update(
                    key.value for key in node.args[0].keys if isinstance(key, ast.Constant) and isinstance(key.value, str)
                )

    violations: list[str] = []
    widget_constructors = {"QLabel", "QPushButton", "QCheckBox", "QGroupBox", "QRadioButton"}
    for path in (SRC / "presentation" / "pages").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id not in widget_constructors:
                continue
            if not node.args or not isinstance(node.args[0], ast.Constant) or not isinstance(node.args[0].value, str):
                continue
            literal = node.args[0].value.strip()
            if any("\u3400" <= ch <= "\u9fff" for ch in literal) and literal not in phrase_keys:
                violations.append(f"{path.name}:{node.lineno}:{literal[:80]}")
    assert violations == []
