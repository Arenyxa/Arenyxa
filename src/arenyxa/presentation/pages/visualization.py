from __future__ import annotations

import collections
from itertools import islice
from typing import Any

from arenyxa.qt_compat.QtCore import QLineF, QPointF, QRectF, Qt
from arenyxa.qt_compat.QtGui import QColor, QPainter, QPainterPath, QPen
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QWidget,
)

from arenyxa.domain.models import new_id, utc_now
from arenyxa.presentation.background import run_background
from arenyxa.presentation.language import literal_for_locale
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, ScrollSafeComboBox


class ChartCanvas(QWidget):
    def __init__(self, theme, parent=None) -> None:
        super().__init__(parent)
        self.theme = theme
        self.chart_type = "Bar"
        self.records: list[dict[str, Any]] = []
        self.x_field = ""
        self.y_field = ""
        self.setMinimumSize(520, 360)
        self.theme.changed.connect(lambda _theme: self.update())

    def configure(self, chart_type: str, records: list[dict[str, Any]], x_field: str, y_field: str) -> None:
        self.chart_type = chart_type
        self.records = records
        self.x_field = x_field
        self.y_field = y_field
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = self.theme.current
        painter.fillRect(self.rect(), QColor(tokens.surface))
        painter.setPen(QColor(tokens.text))
        if not self.records or not self.x_field:
            app = QApplication.instance()
            locale = str(app.property("arenyxa_locale") or "zh_CN") if app is not None else "zh_CN"
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, literal_for_locale("选择 Run 与字段生成可视化", locale))
            return
        bounds = QRectF(self.rect()).adjusted(64, 38, -34, -56)
        if self.chart_type == "Pie":
            self._pie(painter, bounds, tokens)
        elif self.chart_type == "Heatmap":
            self._heatmap(painter, bounds, tokens)
        elif self.chart_type == "Map":
            self._map(painter, bounds, tokens)
        else:
            self._cartesian(painter, bounds, tokens, line=self.chart_type in {"Line", "Timeline"})

    def _grouped(self) -> list[tuple[str, float]]:
        grouped: dict[str, float] = collections.defaultdict(float)
        for record in self.records:
            key = str(record.get(self.x_field, "(empty)"))
            raw = record.get(self.y_field, 1) if self.y_field else 1
            try:
                grouped[key] += float(raw)
            except (TypeError, ValueError):
                grouped[key] += 1
        return sorted(grouped.items(), key=lambda item: item[1], reverse=True)[:40]

    def _cartesian(self, painter: QPainter, bounds: QRectF, tokens, line: bool) -> None:
        values = self._grouped()
        maximum = max((value for _, value in values), default=1) or 1
        painter.setPen(QPen(QColor(tokens.border), 1))
        painter.drawLine(bounds.bottomLeft(), bounds.bottomRight())
        painter.drawLine(bounds.bottomLeft(), bounds.topLeft())
        accent = QColor(tokens.accent)
        if line:
            path = QPainterPath()
            for index, (label, value) in enumerate(values):
                x = bounds.left() + bounds.width() * index / max(1, len(values) - 1)
                y = bounds.bottom() - bounds.height() * value / maximum
                if index == 0:
                    path.moveTo(x, y)
                else:
                    path.lineTo(x, y)
                painter.setBrush(accent)
                painter.drawEllipse(QPointF(x, y), 3.5, 3.5)
            painter.setPen(QPen(accent, 2.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(path)
        else:
            width = bounds.width() / max(1, len(values))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(accent)
            for index, (_label, value) in enumerate(values):
                height = bounds.height() * value / maximum
                painter.drawRoundedRect(
                    QRectF(
                        bounds.left() + index * width + 3, bounds.bottom() - height, max(2, width - 6), height
                    ),
                    4,
                    4,
                )
        painter.setPen(QColor(tokens.text_muted))
        for index, (label, _value) in enumerate(values[:12]):
            x = bounds.left() + bounds.width() * index / max(1, min(12, len(values)) - 1)
            painter.drawText(
                QRectF(x - 34, bounds.bottom() + 7, 68, 36),
                Qt.AlignmentFlag.AlignHCenter | Qt.TextFlag.TextWordWrap,
                label[:14],
            )

    def _pie(self, painter: QPainter, bounds: QRectF, tokens) -> None:
        values = self._grouped()[:12]
        total = sum(value for _, value in values) or 1
        side = min(bounds.width(), bounds.height())
        pie = QRectF(bounds.left(), bounds.top(), side, side)
        angle = 0
        colors = [
            QColor(tokens.accent),
            QColor(tokens.info),
            QColor(tokens.success),
            QColor(tokens.warning),
            QColor(tokens.danger),
        ]
        for index, (label, value) in enumerate(values):
            span = round(value / total * 360 * 16)
            painter.setBrush(colors[index % len(colors)].lighter(100 + (index % 3) * 15))
            painter.setPen(QColor(tokens.surface))
            painter.drawPie(pie, angle, span)
            angle += span
        legend_x = pie.right() + 24
        painter.setPen(QColor(tokens.text))
        for index, (label, value) in enumerate(values):
            painter.setBrush(colors[index % len(colors)])
            painter.drawRect(QRectF(legend_x, bounds.top() + index * 24, 12, 12))
            painter.drawText(
                QRectF(legend_x + 18, bounds.top() + index * 24 - 3, bounds.width() - side - 42, 20),
                f"{label[:24]} · {value / total:.1%}",
            )

    def _heatmap(self, painter: QPainter, bounds: QRectF, tokens) -> None:
        x_values = [str(record.get(self.x_field, "")) for record in self.records]
        y_values = (
            [str(record.get(self.y_field, "")) for record in self.records]
            if self.y_field
            else ["count"] * len(self.records)
        )
        xs = list(dict.fromkeys(x_values))[:20]
        ys = list(dict.fromkeys(y_values))[:15]
        counts = collections.Counter(zip(x_values, y_values))
        maximum = max(counts.values(), default=1)
        cell_w = bounds.width() / max(1, len(xs))
        cell_h = bounds.height() / max(1, len(ys))
        accent = QColor(tokens.accent)
        for x_index, x in enumerate(xs):
            for y_index, y in enumerate(ys):
                alpha = round(28 + 220 * counts[(x, y)] / maximum)
                color = QColor(accent)
                color.setAlpha(alpha)
                painter.fillRect(
                    QRectF(
                        bounds.left() + x_index * cell_w,
                        bounds.top() + y_index * cell_h,
                        cell_w - 1,
                        cell_h - 1,
                    ),
                    color,
                )

    def _map(self, painter: QPainter, bounds: QRectF, tokens) -> None:
        painter.setPen(QPen(QColor(tokens.border), 1))
        for index in range(1, 6):
            painter.drawLine(
                QLineF(
                    bounds.left(),
                    bounds.top() + bounds.height() * index / 6,
                    bounds.right(),
                    bounds.top() + bounds.height() * index / 6,
                )
            )
            painter.drawLine(
                QLineF(
                    bounds.left() + bounds.width() * index / 6,
                    bounds.top(),
                    bounds.left() + bounds.width() * index / 6,
                    bounds.bottom(),
                )
            )
        painter.setPen(Qt.PenStyle.NoPen)
        accent = QColor(tokens.accent)
        accent.setAlpha(170)
        painter.setBrush(accent)
        for record in self.records:
            try:
                longitude = float(record.get(self.x_field, 0))
                latitude = float(record.get(self.y_field, 0))
            except (TypeError, ValueError):
                continue
            x = bounds.left() + (longitude + 180) / 360 * bounds.width()
            y = bounds.top() + (90 - latitude) / 180 * bounds.height()
            painter.drawEllipse(QPointF(x, y), 5, 5)


class VisualizationPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(
            PageHeader(
                "Data Visualization Studio", "结果、数据库查询或 Dataset Revision → 图表资产 → PNG/报告数据"
            )
        )
        controls = QHBoxLayout()
        self.run = ScrollSafeComboBox()
        self.run.setMinimumWidth(260)
        self.chart_type = QComboBox()
        self.chart_type.addItems(["Line", "Bar", "Pie", "Heatmap", "Timeline", "Map"])
        self.x_field = QComboBox()
        self.y_field = QComboBox()
        self.name = QLineEdit("Visualization")
        render = QPushButton("渲染")
        render.setProperty("primary", True)
        save = QPushButton("保存资产")
        export = QPushButton("导出 PNG")
        for label, control in (
            ("Run", self.run),
            ("Chart", self.chart_type),
            ("X", self.x_field),
            ("Y", self.y_field),
            ("Name", self.name),
        ):
            controls.addWidget(QLabel(label))
            controls.addWidget(control)
        controls.addWidget(render)
        controls.addWidget(save)
        controls.addWidget(export)
        layout.addLayout(controls)
        self.canvas = ChartCanvas(theme)
        layout.addWidget(self.canvas, 1)
        self.records: list[dict[str, Any]] = []
        self._load_token = 0
        self.run.currentIndexChanged.connect(self.load_fields)
        render.clicked.connect(self.render_chart)
        save.clicked.connect(self.save_asset)
        export.clicked.connect(self.export_png)

    def activated(self) -> None:
        selected = self.run.currentData()
        self.run.blockSignals(True)
        self.run.clear()
        for run in self.context.store.list_runs(limit=500):
            self.run.addItem(f"{run['created_at'][:19]} · {run['result_count']} rows", run["id"])
            if run["id"] == selected:
                self.run.setCurrentIndex(self.run.count() - 1)
        self.run.blockSignals(False)
        self.load_fields()

    def load_fields(self) -> None:
        run_id = self.run.currentData()
        self._load_token += 1
        token = self._load_token
        if not run_id:
            self.records = []
            for combo in (self.x_field, self.y_field):
                combo.clear()
            self.canvas.configure(self.chart_type.currentText(), [], "", "")
            return
        self.statusMessage.emit("正在后台加载可视化数据…")

        def completed(value: object) -> None:
            if token != self._load_token:
                return
            self.records = list(value) if isinstance(value, list) else []
            fields = list(self.records[0]) if self.records else []
            for combo in (self.x_field, self.y_field):
                current = combo.currentText()
                combo.clear()
                combo.addItems(fields)
                combo.setCurrentText(current)
            self.inspectorChanged.emit(
                "Visualization Dataset", {"run_id": run_id, "loaded": len(self.records), "fields": fields}
            )
            self.statusMessage.emit(f"已加载 {len(self.records):,} 条可视化记录")

        def failed(message: str) -> None:
            if token == self._load_token:
                QMessageBox.warning(self, "可视化数据加载失败", message)

        run_background(
            lambda: list(islice(self.context.store.iter_results(run_id, page_size=1000), 10_000)),
            completed,
            failed,
        )

    def render_chart(self) -> None:
        self.canvas.configure(
            self.chart_type.currentText(),
            self.records,
            self.x_field.currentText(),
            self.y_field.currentText(),
        )
        self.statusMessage.emit(f"已渲染 {self.chart_type.currentText()} · {len(self.records):,} records")

    def save_asset(self) -> None:
        asset = {
            "id": new_id("visual"),
            "name": self.name.text().strip() or "Visualization",
            "dataset_ref": self.run.currentData(),
            "chart_type": self.chart_type.currentText(),
            "config": {"x": self.x_field.currentText(), "y": self.y_field.currentText(), "limit": 10000},
            "created_at": utc_now(),
            "schema_version": 6,
        }
        self.context.store.save_visualization(asset)
        self.statusMessage.emit(f"已保存图表资产：{asset['name']}")

    def export_png(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "导出图表", str(self.context.paths.exports / "visualization.png"), "PNG (*.png)"
        )
        if path and not self.canvas.grab().save(path, "PNG"):
            QMessageBox.warning(self, "导出失败", "无法写入 PNG。")
