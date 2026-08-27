from __future__ import annotations

import re
from arenyxa.qt_compat.QtCore import QPointF, QRectF, Qt, QTimer
from arenyxa.qt_compat.QtGui import QColor, QLinearGradient, QMouseEvent, QPainter, QPainterPath, QPen
from arenyxa.qt_compat.QtWidgets import QApplication, QFrame, QWidget

from arenyxa.presentation.themes import ThemeManager


_RGBA = re.compile(r"rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*([0-9.]+)\s*\)", re.I)

def _css_color(value: str) -> QColor:
    match = _RGBA.fullmatch(value.strip())
    if match:
        red, green, blue = (int(match.group(i)) for i in range(1, 4))
        alpha_raw = float(match.group(4))
        alpha = round(alpha_raw * 255) if alpha_raw <= 1.0 else round(alpha_raw)
        return QColor(red, green, blue, max(0, min(255, alpha)))
    color = QColor(value)
    return color if color.isValid() else QColor(30, 40, 48, 220)


class GlassPanel(QFrame):
    

    def __init__(
        self, theme_manager: ThemeManager, elevated: bool = False, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.theme_manager = theme_manager
        self.elevated = elevated
        self.setProperty("glass", True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setMouseTracking(True)
        self._pointer = QPointF(-1000, -1000)
        self._specular = 0.0
        self._specular_target = 0.0
        self._hover_timer = QTimer(self)
        self._hover_timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._hover_timer.setInterval(16)
        self._hover_timer.timeout.connect(self._animate_specular)
        self.theme_manager.changed.connect(lambda _theme: self.update())

    def _motion_static(self) -> bool:
        current: QWidget | None = self
        while current is not None:
            try:
                if bool(current.property("arenyxa_motion_static")):
                    return True
                current = current.parentWidget()
            except RuntimeError:
                return True
        return False

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._motion_static():
            if self._hover_timer.isActive():
                self._hover_timer.stop()
            if self._specular != 0.0 or self._specular_target != 0.0:
                self._specular = 0.0
                self._specular_target = 0.0
                self.update()
            super().mouseMoveEvent(event)
            return
        app = QApplication.instance()
        quality = str(app.property("arenyxa_motion_quality") or "balanced") if app is not None else "balanced"
        specular_allowed = bool(app.property("arenyxa_glass_specular")) if app is not None else True
        if quality == "efficiency" or not specular_allowed:
            if self._specular != 0.0:
                self._specular = 0.0
                self._specular_target = 0.0
                self.update()
            super().mouseMoveEvent(event)
            return
                                                                   
        self._pointer = event.position() if hasattr(event, "position") else event.localPos()
        self._specular_target = 1.0
        self._ensure_hover_animation()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:
        if self._motion_static():
            self._hover_timer.stop()
            self._specular = 0.0
            self._specular_target = 0.0
            super().leaveEvent(event)
            return
        self._specular_target = 0.0
        self._ensure_hover_animation()
        super().leaveEvent(event)


    def _ensure_hover_animation(self) -> None:
        app = QApplication.instance()
        reduce_motion = bool(app.property("arenyxa_reduce_motion")) if app is not None else False
        quality = str(app.property("arenyxa_motion_quality") or "balanced") if app is not None else "balanced"
        specular_allowed = bool(app.property("arenyxa_glass_specular")) if app is not None else True
        if quality == "efficiency" or not specular_allowed:
            self._specular = 0.0
            self._specular_target = 0.0
            self._hover_timer.stop()
            return
        if reduce_motion:
            self._specular = self._specular_target
            self.update()
            return
        if not self._hover_timer.isActive():
            self._hover_timer.start()

    def _animate_specular(self) -> None:
        app = QApplication.instance()
        strength = float(app.property("arenyxa_motion_strength") or 0.88) if app is not None else 0.88
        quality = str(app.property("arenyxa_motion_quality") or "balanced") if app is not None else "balanced"
        if quality == "efficiency":
            self._specular = self._specular_target
            self._hover_timer.stop()
            self.update()
            return
                                                                                           
                                                                   
        alpha = 0.22 + 0.16 * max(0.0, min(1.0, strength))
        if quality == "balanced":
            alpha *= 0.84
        self._specular += (self._specular_target - self._specular) * alpha
        if abs(self._specular_target - self._specular) < 0.012:
            self._specular = self._specular_target
            self._hover_timer.stop()
        self.update()

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        tokens = self.theme_manager.current
        app = QApplication.instance()
        glass_strength = float(app.property("arenyxa_glass_strength") or 0.82) if app is not None else 0.82
        blur_strength = float(app.property("arenyxa_blur_strength") or tokens.blur) if app is not None else float(tokens.blur)
        high_contrast = bool(app.property("arenyxa_high_contrast")) if app is not None else False
        quality = str(app.property("arenyxa_motion_quality") or "balanced") if app is not None else "balanced"
        glass_strength = max(0.0, min(1.0, glass_strength))
        blur_norm = max(0.0, min(1.0, (blur_strength - 12.0) / 24.0))

        painter = QPainter(self)
        if quality != "efficiency":
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        bounds = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        path = QPainterPath()
        path.addRoundedRect(bounds, tokens.radius, tokens.radius)

        base = _css_color(tokens.glass_elevated if self.elevated else tokens.glass)
        base_alpha = base.alpha()
                                                                                            
        alpha_scale = 0.72 + 0.34 * glass_strength
        if high_contrast:
            base_alpha = max(base_alpha, 226 if tokens.dark else 238)
        else:
            base_alpha = round(base_alpha * alpha_scale)
        base.setAlpha(max(28, min(248, base_alpha)))
        painter.fillPath(path, base)

                                                                                              
                                                                                           
        if quality == "efficiency":
            accent = _css_color(tokens.accent)
            accent.setAlpha(36 if tokens.dark else 52)
            painter.setPen(QPen(accent, 1.0))
            painter.drawPath(path)
            painter.end()
            return

                                                                                          
                                                                                                            
        rim = QLinearGradient(bounds.topLeft(), bounds.bottomRight())
        accent = _css_color(tokens.accent)
        rim_alpha = 38 + round(42 * glass_strength)
        if high_contrast:
            rim_alpha = min(rim_alpha, 44)
        rim.setColorAt(0.0, QColor(accent.red(), accent.green(), accent.blue(), rim_alpha))
        rim.setColorAt(0.42, QColor(255, 255, 255, 28 if tokens.dark else 62))
        rim.setColorAt(1.0, QColor(accent.red(), accent.green(), accent.blue(), 16))
        painter.setPen(QPen(rim, 1.0 + 0.22 * glass_strength))
        painter.drawPath(path)

        allow_specular = quality != "efficiency" and not high_contrast
        if allow_specular and self._specular > 0.01 and self._pointer.x() >= 0:
            radius = max(90.0, min(self.width(), self.height()) * (0.62 + 0.34 * blur_norm))
            highlight = QLinearGradient(
                self._pointer - QPointF(radius, radius), self._pointer + QPointF(radius, radius)
            )
            highlight.setColorAt(0.0, QColor(255, 255, 255, 0))
            highlight.setColorAt(0.48, QColor(255, 255, 255, round((18 + 16 * glass_strength) * self._specular)))
            highlight.setColorAt(1.0, QColor(255, 255, 255, 0))
            painter.save()
            painter.setClipPath(path)
            painter.fillRect(bounds, highlight)
            painter.restore()
        painter.end()
