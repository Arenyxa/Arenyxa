"""Sparse, asynchronous QAbstractTableModel for million-row result/capture browsing."""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from arenyxa.qt_compat.QtCore import QAbstractTableModel, QModelIndex, Qt
from arenyxa.presentation.background import run_background


class VirtualTableModel(QAbstractTableModel):
    """Expose the full logical row count while retaining only bounded LRU pages in memory."""

    def __init__(
        self,
        loader: Callable[[int, int], list[dict[str, Any]]],
        *,
        total: int = 0,
        page_size: int = 512,
        max_cached_pages: int = 32,
        columns: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.loader = loader
        self.total = max(0, int(total))
        self.page_size = max(64, min(4096, int(page_size)))
        self.max_cached_pages = max(2, min(256, int(max_cached_pages)))
        self.columns = list(columns or [])
        self._pages: OrderedDict[int, tuple[dict[str, Any], ...]] = OrderedDict()
        self._loading: set[int] = set()
        self._generation = 0

    @property
    def loaded_row_count(self) -> int:
        return sum(len(page) for page in self._pages.values())

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else self.total

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return max(1, len(self.columns))

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.columns[section] if section < len(self.columns) else "Loading"
        return section + 1

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid() or not 0 <= index.row() < self.total:
            return None
        if role not in {Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole}:
            return None
        row = self.row_at(index.row())
        if row is None:
            return "Loading…" if index.column() == 0 and role == Qt.ItemDataRole.DisplayRole else None
        if index.column() >= len(self.columns):
            return None
        value = row.get(self.columns[index.column()])
        if isinstance(value, (dict, list, tuple)):
            value = json.dumps(value, ensure_ascii=False, default=str)
        return "" if value is None else str(value)

    def reset_query(self, total: int) -> None:
        self.beginResetModel()
        self.total = max(0, int(total))
        self.columns.clear()
        self._pages.clear()
        self._loading.clear()
        self._generation += 1
        self.endResetModel()
        if self.total:
            self._schedule_page(0)

    def row_at(self, row_index: int, *, request: bool = True) -> dict[str, Any] | None:
        row = int(row_index)
        if row < 0 or row >= self.total:
            return None
        page_index = row // self.page_size
        page = self._pages.get(page_index)
        if page is None:
            if request:
                self._schedule_page(page_index)
            return None
        self._pages.move_to_end(page_index)
        within = row - page_index * self.page_size
        return page[within] if within < len(page) else None

    def prefetch_around(self, row_index: int) -> None:
        center = max(0, int(row_index)) // self.page_size
        for page_index in (center - 1, center, center + 1):
            if page_index >= 0 and page_index * self.page_size < self.total:
                self._schedule_page(page_index)

    def _schedule_page(self, page_index: int) -> None:
        if page_index in self._pages or page_index in self._loading:
            return
        offset = page_index * self.page_size
        if offset >= self.total:
            return
        self._loading.add(page_index)
        generation = self._generation

        def load() -> list[dict[str, Any]]:
            return list(self.loader(offset, min(self.page_size, self.total - offset)))

        def completed(value: object) -> None:
            self._loading.discard(page_index)
            if generation != self._generation or not isinstance(value, list):
                return
            rows = tuple(dict(item) for item in value if isinstance(item, dict))
            columns_changed = False
            if rows and not self.columns:
                self.columns = list(rows[0])
                columns_changed = True
            self._pages[page_index] = rows
            self._pages.move_to_end(page_index)
            while len(self._pages) > self.max_cached_pages:
                self._pages.popitem(last=False)
            if columns_changed:
                self.beginResetModel()
                self.endResetModel()
                return
            first = offset
            last = min(self.total - 1, offset + max(0, len(rows) - 1))
            if last >= first and self.columns:
                self.dataChanged.emit(
                    self.index(first, 0),
                    self.index(last, len(self.columns) - 1),
                    [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole],
                )

        def failed(_message: str) -> None:
            self._loading.discard(page_index)

        run_background(load, completed, failed)


class VirtualCaptureTableModel(VirtualTableModel):
    """Million-row capture archive projection with a fixed, stable column contract."""

    CAPTURE_COLUMNS = [
        "timestamp",
        "method",
        "status",
        "protocol",
        "host",
        "url",
        "size",
        "timing",
    ]

    def __init__(
        self,
        loader: Callable[[int, int], list[dict[str, Any]]],
        *,
        total: int = 0,
        page_size: int = 1024,
        max_cached_pages: int = 24,
    ) -> None:
        super().__init__(
            loader,
            total=total,
            page_size=page_size,
            max_cached_pages=max_cached_pages,
            columns=self.CAPTURE_COLUMNS,
        )
