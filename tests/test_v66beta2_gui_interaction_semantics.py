from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "arenyxa"


def _source(relative: str) -> str:
    return (SRC / relative).read_text(encoding="utf-8")


def _block(source: str, start: str, end: str) -> str:
    a = source.index(start)
    b = source.index(end, a)
    return source[a:b]


def test_every_sidebar_destination_uses_the_single_navigate_commit_path() -> None:
    main = _source("presentation/main_window.py") + "\n" + _source("presentation/main_window_registry.py") + "\n" + _source("presentation/main_window_navigation.py")
    assert '("automation", "◷", "nav.automation", AutomationEnginePage, "core")' in main
    assert '("recovery", "↻", "nav.recovery", RecoveryCenterPage, "advanced")' in main
    add_button = _block(main, "        def add_nav_button(", "        def add_developer_shortcut")
    assert "button.clicked.connect(lambda _checked=False, page_id=page_id: self.navigate(page_id))" in add_button
    navigate = _block(main, "    def navigate(self, page_id: str)", "    def _nav_group_expanded")
    assert "self._commit_stack_page(page)" in navigate
    assert "page route commit failed" in navigate


def test_route_commit_is_atomic_and_independent_from_motion() -> None:
    main = _source("presentation/main_window.py") + "\n" + _source("presentation/main_window_registry.py") + "\n" + _source("presentation/main_window_navigation.py")
    commit = _block(main, "    def _commit_stack_page", "    def _finish_navigation")
    assert "self.stack.indexOf(page)" in commit
    assert "self.stack.setCurrentIndex(index)" in commit
    assert "self.motion.transition_stack" not in commit
    assert "self.stack.currentIndex() != index" in commit
    assert "currentWidget() is not page" not in commit


def test_arabic_shell_is_physically_ltr_even_for_late_created_pages() -> None:
    main = _source("presentation/main_window.py") + "\n" + _source("presentation/main_window_registry.py") + "\n" + _source("presentation/main_window_navigation.py")
    base = _source("presentation/pages/base.py")
    qtwidgets = _source("qt_compat/QtWidgets.py")
    assert "def _enforce_shell_ltr" in main
    for name in ("backdrop", "nav", "center_workspace", "topbar", "stack", "inspector"):
        assert f'"{name}"' in main
    assert "root.setDirection(QBoxLayout.Direction.LeftToRight)" in main
    assert "top.setDirection(QBoxLayout.Direction.LeftToRight)" in main
    assert 'self.setProperty("arenyxa_shell_ltr", True)' in base
    assert "QBoxLayout = class_with_scopes" in qtwidgets


def test_settings_and_personalization_wheel_cannot_mutate_closed_controls() -> None:
    widgets = _source("presentation/widgets.py")
    settings = _source("presentation/pages/settings.py")
    personalization = _source("presentation/pages/personalization.py")
    for cls in ("ScrollSafeComboBox", "ScrollSafeSpinBox", "ScrollSafeSlider"):
        assert f"class {cls}" in widgets
    assert "event.ignore()" in widgets
    assert "self.locale_box = ScrollSafeComboBox()" in settings
    assert "self.performance = ScrollSafeComboBox()" in settings
    assert "self.request_concurrency = ScrollSafeSpinBox()" in settings
    assert "self.glass = ScrollSafeSlider" in personalization


def test_language_and_performance_commit_on_explicit_combo_activation_only() -> None:
    settings = _source("presentation/pages/settings.py")
    assert "self.locale_box.activated.connect(self._locale_activated)" in settings
    assert "self.performance.activated.connect(self._performance_activated)" in settings
    assert "self.locale_box.currentIndexChanged.connect" not in settings
    assert "self.performance.currentTextChanged.connect" not in settings


def test_arabic_settings_do_not_fall_back_to_known_english_diagnostics() -> None:
    catalog = _source("presentation/i18n_catalog.py")
    required = (
        "Liquid Glass & Motion",
        "Advanced Settings",
        "Run Diagnostics",
        "Open Repair Center",
        "Export Diagnostic Package",
        "Untranslated diagnostic",
    )
    arabic_tail = catalog[catalog.rindex('NATIVE_PHRASES.setdefault("ar_SA", {})') :]
    for phrase in required:
        assert f'"{phrase}"' in arabic_tail
