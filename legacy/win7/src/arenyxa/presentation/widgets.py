from __future__ import annotations

from collections.abc import Callable
from typing import Any

from arenyxa.qt_compat.QtCore import QAbstractTableModel, QItemSelectionModel, QModelIndex, QRectF, Qt, Signal
from arenyxa.qt_compat.QtGui import QColor, QPainter, QPen
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSlider,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from arenyxa.presentation.glass import GlassPanel
from arenyxa.presentation.language import literal_for_locale
from arenyxa.presentation.themes import ThemeManager


class ScrollSafeComboBox(QComboBox):
    








    def wheelEvent(self, event) -> None:                               
        try:
            popup_open = bool(self.view().isVisible())
        except (AttributeError, RuntimeError, TypeError):
            popup_open = False
        if popup_open:
            super().wheelEvent(event)
            return
        event.ignore()


class ScrollSafeSpinBox(QSpinBox):
    

    def wheelEvent(self, event) -> None:                               
        event.ignore()


class ScrollSafeSlider(QSlider):
    





    def wheelEvent(self, event) -> None:                               
        event.ignore()


def table_horizontal_header(table: Any) -> Any:
    







    try:
        return table.horizontalHeader()
    except (AttributeError, RuntimeError, TypeError):
        return None


def set_table_header_resize_mode(table: Any, section: int, mode: Any) -> bool:
    header = table_horizontal_header(table)
    setter = getattr(header, "setSectionResizeMode", None)
    if not callable(setter):
        return False
    try:
        setter(int(section), mode)
        return True
    except (AttributeError, RuntimeError, TypeError):
        return False


def set_table_header_stretch_last(table: Any, enabled: bool = True) -> bool:
    header = table_horizontal_header(table)
    setter = getattr(header, "setStretchLastSection", None)
    if not callable(setter):
        return False
    try:
        setter(bool(enabled))
        return True
    except (AttributeError, RuntimeError, TypeError):
        return False


def table_vertical_header(table: Any) -> Any:
    
    try:
        return table.verticalHeader()
    except (AttributeError, RuntimeError, TypeError):
        return None


def hide_table_vertical_header(table: Any) -> bool:
    header = table_vertical_header(table)
    setter = getattr(header, "setVisible", None)
    if not callable(setter):
        return False
    try:
        setter(False)
        return True
    except (AttributeError, RuntimeError, TypeError):
        return False


def table_selection_model(table: Any) -> Any:
    





    try:
        return table.selectionModel()
    except (AttributeError, RuntimeError, TypeError):
        return None


def connect_current_row_changed(table: Any, callback: Any) -> bool:
    selection = table_selection_model(table)
    signal = getattr(selection, "currentRowChanged", None)
    connector = getattr(signal, "connect", None)
    if callable(connector):
        try:
            connector(callback)
            return True
        except (AttributeError, RuntimeError, TypeError):
            pass

                                                                                          
                                                                                             
                                                                           
    clicked = getattr(table, "clicked", None)
    clicked_connect = getattr(clicked, "connect", None)
    if callable(clicked_connect):
        try:
            clicked_connect(lambda current: callback(current, QModelIndex()))
            return True
        except (AttributeError, RuntimeError, TypeError):
            pass
    return False


def format_bytes(value: int) -> str:
    number = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(number) < 1024.0 or unit == "TB":
            return f"{number:.0f} {unit}" if unit == "B" else f"{number:.1f} {unit}"
        number /= 1024.0
    return f"{value} B"


class ResponsiveActionBar(QWidget):
    







    def __init__(
        self,
        buttons: list[QPushButton] | tuple[QPushButton, ...],
        parent: QWidget | None = None,
        *,
        minimum_cell_width: int = 154,
        maximum_columns: int = 6,
    ) -> None:
        super().__init__(parent)
        self._buttons = tuple(buttons)
                                                                                            
                                                                                          
                                                                                               
                                   
        self._minimum_cell_width = max(96, int(minimum_cell_width))
        self._maximum_columns = max(1, int(maximum_columns))
        self._columns = 0
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setHorizontalSpacing(8)
        self._grid.setVerticalSpacing(8)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        for button in self._buttons:
            button.setMinimumHeight(34)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._reflow(force=True)

    def _target_columns(self) -> int:
        if not self._buttons:
            return 1
        hinted_width = max((int(button.sizeHint().width()) + 18 for button in self._buttons), default=96)
        cell_width = max(self._minimum_cell_width, hinted_width)
        width = max(cell_width, int(self.width()))
        spacing = max(0, int(self._grid.horizontalSpacing()))
                                                                                              
                                                                                                
        columns = max(1, (width + spacing) // (cell_width + spacing))
        return min(len(self._buttons), self._maximum_columns, columns)

    def _reflow(self, *, force: bool = False) -> None:
        columns = self._target_columns()
        if not force and columns == self._columns:
            return
        self._columns = columns
        for button in self._buttons:
            self._grid.removeWidget(button)
        for index, button in enumerate(self._buttons):
            row, column = divmod(index, columns)
            self._grid.addWidget(button, row, column)
        for column in range(self._maximum_columns):
            self._grid.setColumnStretch(column, 1 if column < columns else 0)
                                                                                              
                                                                                              
                                                                                          
                                                                
        self._grid.invalidate()
        self.updateGeometry()

    def resizeEvent(self, event) -> None:                               
        self._reflow()
        super().resizeEvent(event)


class PageHeader(QWidget):
    def __init__(self, title: str, subtitle: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 8)
        layout.setSpacing(3)
        self.title_label = QLabel(title)
        self.title_label.setProperty("title", True)
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setProperty("muted", True)
        self.subtitle_label.setWordWrap(True)
        layout.addWidget(self.title_label)
        if subtitle:
            layout.addWidget(self.subtitle_label)


class MetricCard(GlassPanel):
    clicked = Signal()

    def __init__(
        self,
        theme: ThemeManager,
        label: str,
        value: str,
        detail: str,
        symbol: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(theme, parent=parent)
        self.setProperty("card", True)
        self.setMinimumWidth(145)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFixedHeight(112)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 11)
        layout.setSpacing(3)
        top = QHBoxLayout()
        icon = QLabel(symbol)
        icon.setProperty("accent", True)
        icon.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.label = QLabel(label)
        self.label.setProperty("muted", True)
        top.addWidget(icon)
        top.addWidget(self.label)
        top.addStretch()
        self.value = QLabel(value)
        self.value.setStyleSheet("font-size: 23px; font-weight: 700;")
        self.detail = QLabel(detail)
        self.detail.setProperty("muted", True)
        layout.addLayout(top)
        layout.addWidget(self.value)
        layout.addWidget(self.detail)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(event)

    def set_metric(self, value: str, detail: str | None = None) -> None:
        self.value.setText(value)
        if detail is not None:
            self.detail.setText(detail)


class SectionCard(GlassPanel):
    def __init__(
        self, theme: ThemeManager, title: str, action: str = "", parent: QWidget | None = None
    ) -> None:
        super().__init__(theme, parent=parent)
        self.outer = QVBoxLayout(self)
        self.outer.setContentsMargins(14, 13, 14, 14)
        self.outer.setSpacing(10)
        header = QHBoxLayout()
        label = QLabel(title)
        label.setProperty("section", True)
        header.addWidget(label)
        header.addStretch()
        self.action = QPushButton(action) if action else None
        if self.action:
            self.action.setFlat(True)
            header.addWidget(self.action)
        self.outer.addLayout(header)
        self.body = QVBoxLayout()
        self.body.setSpacing(7)
        self.outer.addLayout(self.body, 1)


class RingGauge(QWidget):
    def __init__(
        self, theme: ThemeManager, value: float = 0, label: str = "", parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.theme = theme
        self.value = value
        self.label = label
        self.setMinimumSize(130, 130)
        self.theme.changed.connect(lambda _theme: self.update())

    def set_value(self, value: float) -> None:
        self.value = max(0.0, min(100.0, value))
        self.update()

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = self.theme.current
        side = min(self.width(), self.height()) - 24
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        base = QColor(tokens.border)
        accent = QColor(tokens.accent)
        painter.setPen(QPen(base, 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, 0, 360 * 16)
        painter.setPen(QPen(accent, 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawArc(rect, 90 * 16, -round(360 * 16 * self.value / 100))
        painter.setPen(QColor(tokens.text))
        font = painter.font()
        font.setPointSize(18)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{self.value:.0f}%")
        if self.label:
            label_rect = QRectF(rect.left(), rect.center().y() + 18, rect.width(), 26)
            font.setPointSize(9)
            font.setBold(False)
            painter.setFont(font)
            painter.setPen(QColor(tokens.text_muted))
            app = QApplication.instance()
            locale = str(app.property("arenyxa_locale") or "zh_CN") if app is not None else "zh_CN"
            painter.drawText(label_rect, Qt.AlignmentFlag.AlignHCenter, literal_for_locale(self.label, locale))


class MiniBars(QWidget):
    def __init__(
        self,
        theme: ThemeManager,
        values: list[tuple[str, float]] | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.theme = theme
        self.values = values or []
        self.setMinimumHeight(120)
        self.theme.changed.connect(lambda _theme: self.update())

    def set_values(self, values: list[tuple[str, float]]) -> None:
        self.values = values
        self.update()

    def paintEvent(self, event) -> None:
        if not self.values:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = self.theme.current
        maximum = max(value for _, value in self.values) or 1
        row_height = max(18, self.height() // len(self.values))
        for index, (label, value) in enumerate(self.values):
            y = index * row_height + 3
            painter.setPen(QColor(tokens.text_muted))
            painter.drawText(
                0, y, 92, row_height - 5, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, label
            )
            track = QRectF(96, y + 5, max(1, self.width() - 146), row_height - 11)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(tokens.background_alt))
            painter.drawRoundedRect(track, 4, 4)
            bar = QRectF(track.left(), track.top(), track.width() * value / maximum, track.height())
            painter.setBrush(QColor(tokens.accent))
            painter.drawRoundedRect(bar, 4, 4)
            painter.setPen(QColor(tokens.text))
            painter.drawText(
                self.width() - 47,
                y,
                45,
                row_height - 5,
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{value:.0f}",
            )


class PagedResultModel(QAbstractTableModel):
    def __init__(
        self, loader: Callable[[int, int], list[dict[str, Any]]], total: int = 0, page_size: int = 300
    ) -> None:
        super().__init__()
        self.loader = loader
        self.total = total
        self.page_size = page_size
        self.rows: list[dict[str, Any]] = []
        self.columns: list[str] = []
        self._loading = False

    def rowCount(
        self,
        parent: QModelIndex = QModelIndex(),                                              
    ) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(
        self,
        parent: QModelIndex = QModelIndex(),                                              
    ) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or role not in {Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole}:
            return None
        value = self.rows[index.row()].get(self.columns[index.column()])
        if isinstance(value, (dict, list)):
            import json

            value = json.dumps(value, ensure_ascii=False)
        return str(value) if value is not None else ""

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        return (
            self.columns[section]
            if orientation == Qt.Orientation.Horizontal and section < len(self.columns)
            else section + 1
        )

    def reset_query(self, total: int) -> None:
        self.beginResetModel()
        self.total = total
        self.rows.clear()
        self.columns.clear()
        self.endResetModel()
        self.fetchMore(QModelIndex())

    def canFetchMore(self, parent: QModelIndex) -> bool:
        return not parent.isValid() and len(self.rows) < self.total and not self._loading

    def fetchMore(self, parent: QModelIndex) -> None:
        if parent.isValid() or self._loading:
            return
        self._loading = True
        page = self.loader(len(self.rows), self.page_size)
        if page:
            if not self.columns:
                self.columns = list(page[0])
            start = len(self.rows)
            self.beginInsertRows(QModelIndex(), start, start + len(page) - 1)
            self.rows.extend(page)
            self.endInsertRows()
        self._loading = False
