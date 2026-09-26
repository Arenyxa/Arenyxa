from __future__ import annotations

from arenyxa.qt_compat.QtWidgets import QApplication
from arenyxa.presentation.language import EN, TRANSLATIONS


def source_text(key: str) -> str:
    """Return the canonical English source text for an i18n key."""
    return EN.get(key, key)


def current_text(key: str) -> str:
    """Return an i18n value for the locale currently applied to QApplication."""
    app = QApplication.instance()
    locale = str(app.property("arenyxa_locale") or "en_US") if app is not None else "en_US"
    table = TRANSLATIONS.get(locale, EN)
    return table.get(key, EN.get(key, key))
