from __future__ import annotations

import json
import logging
import math
import sqlite3
from collections import Counter
from datetime import datetime
from urllib.parse import urlparse

from arenyxa.qt_compat.QtCore import QPointF, QRectF, Qt
from arenyxa.qt_compat.QtGui import QColor, QPainter, QPainterPath, QPen
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from arenyxa.compat import strict_zip
from arenyxa.presentation.glass import GlassPanel
from arenyxa.presentation.language import literal_for_locale
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import RingGauge, SectionCard, format_bytes


LOGGER = logging.getLogger(__name__)


def _resample_series(values: list[float], count: int) -> list[float]:
    if count <= 0:
        return []
    if not values:
        return [0.0] * count
    if len(values) == count:
        return [float(value) for value in values]
    if len(values) == 1:
        return [float(values[0])] * count
    result: list[float] = []
    for index in range(count):
        position = index * (len(values) - 1) / max(1, count - 1)
        left = int(math.floor(position))
        right = min(len(values) - 1, left + 1)
        fraction = position - left
        result.append(float(values[left]) * (1.0 - fraction) + float(values[right]) * fraction)
    return result


class Sparkline(QWidget):


    def __init__(self, theme, motion=None, color_role: str = "accent", parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.motion = motion
        self.color_role = color_role
        self.values = [0.34, 0.42, 0.37, 0.55, 0.46, 0.61, 0.52, 0.68, 0.58, 0.72]
        self.setFixedHeight(20)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.theme.changed.connect(lambda _theme: self.update())

    def set_values(self, values: list[float]) -> None:
        if not values:
            return
        target = [float(value) for value in values[-14:]]
        if self.motion is None or not self.motion._enabled(live=True):
            self.values = target
            self.update()
            return
        count = max(len(self.values), len(target), 2)
        start_values = _resample_series(self.values, count)
        target_values = _resample_series(target, count)

        def update(progress: float) -> None:
            progress = max(0.0, min(1.0, progress))
            self.values = [a + (b - a) * progress for a, b in strict_zip(start_values, target_values, strict=True)]
            self.update()

        self.motion.animate_scalar(self, "sparkline_series", 0.0, 1.0, update, 360, live=True)

    def paintEvent(self, event) -> None:
        del event
        if len(self.values) < 2:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = self.theme.current
        color = QColor(getattr(tokens, self.color_role, tokens.accent))
        rect = QRectF(self.rect()).adjusted(1, 2, -1, -2)
        low, high = min(self.values), max(self.values)
        span = max(1e-6, high - low)
        path = QPainterPath()
        for index, value in enumerate(self.values):
            x = rect.left() + rect.width() * index / max(1, len(self.values) - 1)
            y = rect.bottom() - rect.height() * (value - low) / span
            if index == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        painter.setPen(QPen(color, 1.65, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        painter.drawPath(path)
        painter.end()


class DashboardMetricCard(GlassPanel):


    def __init__(
        self,
        theme,
        motion,
        title: str,
        symbol: str,
        value: str,
        detail: str,
        color_role: str = "accent",
        show_sparkline: bool = True,
        parent=None,
    ) -> None:
        super().__init__(theme, parent=parent)
        self.color_role = color_role
        self.setMinimumWidth(145)
        self.setFixedHeight(136)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 10)
        layout.setSpacing(4)
        head = QHBoxLayout()
        head.setSpacing(8)
        self.icon = QLabel(symbol)
        self.icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon.setFixedSize(32, 32)
        self.title = QLabel(title)
        self.title.setProperty("muted", True)
        self.title.setWordWrap(True)
        head.addWidget(self.icon)
        head.addWidget(self.title, 1)
        layout.addLayout(head)

        self.value = QLabel(value)
        self.value.setStyleSheet("font-size: 20px; font-weight: 720;")
        self.value.setMinimumHeight(27)
        self.detail = QLabel(detail)
        self.detail.setProperty("muted", True)
        self.detail.setStyleSheet("font-size: 11px;")
        self.detail.setWordWrap(True)
        layout.addWidget(self.value)
        layout.addWidget(self.detail)

        self.sparkline = Sparkline(theme, motion, color_role, self)
        self.sparkline.setVisible(show_sparkline)
        layout.addWidget(self.sparkline)
        self.theme_manager.changed.connect(lambda _theme: self._sync_style())
        self._sync_style()

    def _sync_style(self) -> None:
        tokens = self.theme_manager.current
        color = getattr(tokens, self.color_role, tokens.accent)
        self.icon.setStyleSheet(
            f"font-size: 17px; font-weight: 750; color: {color}; "
            f"background: {tokens.accent_soft}; border: 1px solid {tokens.border}; border-radius: 8px;"
        )

    def set_metric(self, value: str, detail: str | None = None, values: list[float] | None = None) -> None:
        self.value.setText(value)
        if detail is not None:
            self.detail.setText(detail)
        if values is not None:
            self.sparkline.set_values(values)


class ProgressTrend(QWidget):


    def __init__(self, theme, motion, parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.motion = motion
        self.values = [22, 32, 28, 36, 31, 43, 39, 47, 41, 50, 46, 54]
        self.draw_progress = 1.0
        self.setMinimumHeight(118)
        self.theme.changed.connect(lambda _theme: self.update())

    def set_values(self, values: list[float]) -> None:
        if not values:
            return
        target = [float(value) for value in values[-18:]]
        if not self.motion._enabled(live=True):
            self.values = target
            self.draw_progress = 1.0
            self.update()
            return
        count = max(len(self.values), len(target), 2)
        start_values = _resample_series(self.values, count)
        target_values = _resample_series(target, count)

        def update(progress: float) -> None:
            progress = max(0.0, min(1.0, progress))


            eased = progress * progress * (3.0 - 2.0 * progress)
            self.values = [a + (b - a) * eased for a, b in strict_zip(start_values, target_values, strict=True)]
            self.draw_progress = 1.0
            self.update()

        self.motion.animate_scalar(self, "trend_series", 0.0, 1.0, update, 430, live=True)

    def paintEvent(self, event) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = self.theme.current
        plot = QRectF(self.rect()).adjusted(34, 8, -8, -24)
        painter.setPen(QPen(QColor(tokens.border), 1))
        for index in range(4):
            y = plot.top() + plot.height() * index / 3
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))

        if len(self.values) >= 2:
            low = min(self.values)
            high = max(self.values)
            span = max(1.0, high - low)
            path = QPainterPath()
            for index, value in enumerate(self.values):
                x = plot.left() + plot.width() * index / max(1, len(self.values) - 1)
                y = plot.bottom() - plot.height() * (value - low) / span
                if index == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
            painter.setPen(QPen(QColor(tokens.accent), 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            if self.draw_progress >= 0.999:
                painter.drawPath(path)
            else:
                partial = QPainterPath()
                samples = max(2, round(60 * self.draw_progress))
                for sample in range(samples + 1):
                    pct = self.draw_progress * sample / samples
                    point = path.pointAtPercent(pct)
                    if sample == 0:
                        partial.moveTo(point)
                    else:
                        partial.lineTo(point)
                painter.drawPath(partial)

        painter.setPen(QColor(tokens.text_muted))
        font = painter.font()
        font.setPointSize(8)
        painter.setFont(font)
        labels = ("10:00", "10:15", "10:30", "10:45", "11:00")
        for index, label in enumerate(labels):
            x = plot.left() + plot.width() * index / max(1, len(labels) - 1)
            painter.drawText(QRectF(x - 24, plot.bottom() + 5, 48, 16), Qt.AlignmentFlag.AlignHCenter, label)
        painter.end()


class DonutChart(QWidget):
    def __init__(self, theme, motion=None, parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.motion = motion
        self.items: list[tuple[str, float, str]] = []
        self.center_top = "文件类型"
        self.center_bottom = "0"
        self.setMinimumSize(150, 150)
        self.setMaximumWidth(175)
        self.theme.changed.connect(lambda _theme: self.update())

    def set_items(self, items: list[tuple[str, float, str]], center_bottom: str) -> None:
        target = [(label, float(value), role) for label, value, role in items]
        self.center_bottom = center_bottom
        if self.motion is None or not self.motion._enabled(live=True) or not self.items:
            self.items = target
            self.update()
            return
        old_by_label = {label: (float(value), role) for label, value, role in self.items}
        labels = [label for label, _value, _role in target]
        start_values = [old_by_label.get(label, (0.0, role))[0] for label, _value, role in target]
        target_values = [value for _label, value, _role in target]
        roles = [role for _label, _value, role in target]

        def update(progress: float) -> None:
            progress = max(0.0, min(1.0, progress))
            eased = progress * progress * (3.0 - 2.0 * progress)
            self.items = [
                (label, start + (end - start) * eased, role)
                for label, start, end, role in strict_zip(labels, start_values, target_values, roles, strict=True)
            ]
            self.update()

        self.motion.animate_scalar(self, "donut_distribution", 0.0, 1.0, update, 460, live=True)

    def paintEvent(self, event) -> None:
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = self.theme.current
        side = min(self.width(), self.height()) - 34
        rect = QRectF((self.width() - side) / 2, 8, side, side)
        total = sum(max(0.0, value) for _, value, _ in self.items)
        if total <= 0:
            painter.setPen(QPen(QColor(tokens.border), 14))
            painter.drawEllipse(rect)
        else:
            start = 90 * 16
            for _label, value, role in self.items:
                span = -round(360 * 16 * max(0.0, value) / total)
                painter.setPen(QPen(QColor(getattr(tokens, role, tokens.accent)), 14, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap))
                painter.drawArc(rect, start, span)
                start += span
        painter.setPen(QColor(tokens.text))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(10)
        painter.setFont(font)
        app = QApplication.instance()
        locale = str(app.property("arenyxa_locale") or "zh_CN") if app is not None else "zh_CN"
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, literal_for_locale(self.center_top, locale))
        font.setBold(False)
        font.setPointSize(8)
        painter.setFont(font)
        painter.setPen(QColor(tokens.text_muted))
        painter.drawText(QRectF(rect.left(), rect.center().y() + 14, rect.width(), 18), Qt.AlignmentFlag.AlignHCenter, self.center_bottom)
        painter.end()
