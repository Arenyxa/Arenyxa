"""Coalesced, non-blocking theme transitions for the live desktop shell."""

from __future__ import annotations

from typing import Any

from arenyxa.qt_compat.QtCore import QObject, QTimer


class ThemeTransitionController(QObject):
    def __init__(self, widget: Any, theme: Any, motion: Any, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.widget = widget
        self.theme = theme
        self.motion = motion
        self._pending = ""
        self._scheduled = False

    def request(self, theme_id: str) -> None:
        self._pending = str(theme_id)
        if self._scheduled:
            return
        self._scheduled = True
        QTimer.singleShot(0, self._commit)

    def _commit(self) -> None:
        self._scheduled = False
        theme_id = self._pending
        self._pending = ""
        if theme_id:
            self.motion.crossfade_style(
                self.widget,
                lambda: self.theme.apply(theme_id, self.widget),
            )


__all__ = ["ThemeTransitionController"]
