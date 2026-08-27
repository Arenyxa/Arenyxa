from __future__ import annotations

from typing import Any

from arenyxa.qt_compat.QtCore import QObject, QTimer, Signal
from arenyxa.qt_compat.QtGui import QFont
from arenyxa.qt_compat.QtWidgets import QApplication, QWidget
from arenyxa.presentation.ui_scale_math import (
    clamp_ui_scale,
    effective_ui_scale,
    scale_stylesheet_metrics,
)


class InterfaceScaleManager(QObject):
    







    changed = Signal(float)

    def __init__(
        self,
        application: QApplication,
        window: QWidget,
        settings: Any,
        theme_manager: Any,
    ) -> None:
        super().__init__(window)
        self.application = application
        self.window = window
        self.settings = settings
        self.theme_manager = theme_manager
        self.current_scale = 1.0
        self._base_font = QFont(application.font())
        point_size = float(self._base_font.pointSizeF())
        self._base_point_size = point_size if point_size > 0 else 9.0
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(180)
        self._timer.timeout.connect(self.apply)

    def schedule_recompute(self) -> None:
        if str(getattr(self.settings, "ui_scale_mode", "auto")).casefold() == "auto":
            self._timer.start()

    def set_preferences(self, mode: str, percent: int) -> float:
        normalized = "manual" if str(mode).casefold() == "manual" else "auto"
        self.settings.ui_scale_mode = normalized
        self.settings.ui_scale_percent = max(85, min(160, int(percent)))
        return self.apply(force=True)

    def desired_scale(self) -> float:
        size = self.window.size()
        return effective_ui_scale(
            str(getattr(self.settings, "ui_scale_mode", "auto")),
            int(getattr(self.settings, "ui_scale_percent", 100)),
            int(size.width()),
            int(size.height()),
        )

    def apply(self, force: bool = False) -> float:
        scale = self.desired_scale()
        if not force and abs(scale - self.current_scale) < 0.001:
            return self.current_scale
        self.current_scale = scale
        self.application.setProperty("arenyxa_ui_scale", float(scale))

        font = QFont(self._base_font)
        font.setPointSizeF(max(6.0, self._base_point_size * scale))
        self.application.setFont(font)

        set_theme_scale = getattr(self.theme_manager, "set_ui_scale", None)
        if callable(set_theme_scale):
            set_theme_scale(scale, self.window)
        self.scale_tree(self.window, scale)
        self.changed.emit(float(scale))
        return scale

    def scale_tree(self, root: QWidget, scale: float | None = None) -> None:
        factor = self.current_scale if scale is None else clamp_ui_scale(scale)
        widgets = [root]
        try:
            widgets.extend(root.findChildren(QWidget))
        except (AttributeError, RuntimeError, TypeError):
            pass
        for widget in widgets:
            try:
                current = str(widget.styleSheet() or "")
            except RuntimeError:
                continue
            base = widget.property("arenyxa_unscaled_qss")
            previous_scaled = widget.property("arenyxa_scaled_qss")
                                                                                           
                                                                                            
            if base is None or (previous_scaled is not None and current != str(previous_scaled)):
                base = current
                widget.setProperty("arenyxa_unscaled_qss", base)
            if not base:
                widget.setProperty("arenyxa_scaled_qss", "")
                continue
            scaled = scale_stylesheet_metrics(str(base), factor)
            if current != scaled:
                widget.setStyleSheet(scaled)
            widget.setProperty("arenyxa_scaled_qss", scaled)
