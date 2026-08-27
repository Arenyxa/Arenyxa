from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
)

from arenyxa.domain.models import DatasetRevision
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PagedResultModel, PageHeader, ScrollSafeComboBox, connect_current_row_changed, set_table_header_stretch_last


class DataPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("数据管理", "分页浏览、来源追踪、版本化、流式导出与用户控制存储"), 1)
        self.run_selector = ScrollSafeComboBox()
        self.run_selector.setMinimumWidth(260)
        self.format = QComboBox()
        self.format.addItems(["CSV", "JSONL", "JSON", "XLSX"])
        self.export_button = QPushButton("导出")
        self.export_button.setProperty("primary", True)
        self.version_button = QPushButton("创建 Revision")
        header.addWidget(QLabel("Run"))
        header.addWidget(self.run_selector)
        header.addWidget(self.format)
        header.addWidget(self.export_button)
        header.addWidget(self.version_button)
        layout.addLayout(header)
        splitter = QSplitter()
        self.model = PagedResultModel(
            self._load_page, page_size=self.context.performance.result_page_size
        )
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(False)
        set_table_header_stretch_last(self.table, True)
        splitter.addWidget(self.table)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMinimumWidth(300)
        splitter.addWidget(self.detail)
        splitter.setSizes([850, 320])
        layout.addWidget(splitter, 1)
        self.footer = QLabel("0 records")
        self.footer.setProperty("muted", True)
        layout.addWidget(self.footer)
        self.run_selector.currentIndexChanged.connect(self.load_run)
        connect_current_row_changed(self.table, self.inspect_row)
        self.export_button.clicked.connect(self.export_current)
        self.version_button.clicked.connect(self.create_revision)

    def activated(self) -> None:
        selected = self.run_selector.currentData()
        self.run_selector.blockSignals(True)
        self.run_selector.clear()
        for run in self.context.store.list_runs(limit=500):
            self.run_selector.addItem(
                f"{run['created_at'][:19]} · {run['status']} · {run['result_count']} rows",
                run["id"],
            )
            if run["id"] == selected:
                self.run_selector.setCurrentIndex(self.run_selector.count() - 1)
        self.run_selector.blockSignals(False)
        self.load_run()

    def current_run_id(self) -> str | None:
        return self.run_selector.currentData()

    def load_run(self) -> None:
        run_id = self.current_run_id()
        total = self.context.store.count_results(run_id) if run_id else 0
        self.model.reset_query(total)
        self.footer.setText(f"{total:,} records · virtualized pages of {self.model.page_size}")
        self.inspectorChanged.emit("数据集", {"run_id": run_id, "records": total})

    def _load_page(self, offset: int, limit: int) -> list[dict]:
        run_id = self.current_run_id()
        return self.context.store.result_page(run_id, offset, limit) if run_id else []

    def inspect_row(self, current, previous) -> None:
        del previous
        if 0 <= current.row() < len(self.model.rows):
            row = self.model.rows[current.row()]
            self.detail.setPlainText(json.dumps(row, ensure_ascii=False, indent=2, default=str))
            self.inspectorChanged.emit("Result Record", row)

    def export_current(self) -> None:
        run_id = self.current_run_id()
        if not run_id:
            QMessageBox.information(self, "导出", "请选择包含结果的 Run。")
            return
        format_name = self.format.currentText().lower()
        extension = "xlsx" if format_name == "xlsx" else format_name
        default = self.context.paths.exports / f"{run_id}.{extension}"
        path, _ = QFileDialog.getSaveFileName(self, "导出结果", str(default), "All Files (*)")
        if not path:
            return
        self.export_button.setEnabled(False)
        self.statusMessage.emit("正在后台流式导出…")

        def completed(count: object) -> None:
            self.export_button.setEnabled(True)
            self.statusMessage.emit(f"导出完成：{int(count):,} rows → {path}")

        def failed(message: str) -> None:
            self.export_button.setEnabled(True)
            QMessageBox.critical(self, "导出失败", message)

        run_background(
            lambda: self.context.exporter.export_run(run_id, Path(path), format_name), completed, failed
        )

    def create_revision(self) -> None:
        run_id = self.current_run_id()
        if not run_id:
            return
        self.version_button.setEnabled(False)
        self.statusMessage.emit("正在后台构建数据版本…")

        def build_revision() -> tuple[DatasetRevision, int]:
            records = {
                str(row["id"]): {
                    key: value for key, value in row.items() if key not in {"id", "_quality_flags"}
                }
                for row in self.context.store.iter_results(run_id)
            }
            schema: dict[str, str] = {}
            for row in records.values():
                for key, value in row.items():
                    schema.setdefault(key, type(value).__name__)
            previous = self.context.store.list_revisions(run_id)
            revision = DatasetRevision(
                dataset_id=run_id,
                source_run_ids=[run_id],
                records=records,
                parent_revision=previous[0]["id"] if previous else None,
                schema=schema,
            )
            self.context.store.save_revision(revision)
            return revision, len(records)

        def completed(value: object) -> None:
            revision, count = value
            self.version_button.setEnabled(True)
            self.statusMessage.emit(f"已创建 Dataset Revision：{revision.id} · {count:,} records")

        def failed(message: str) -> None:
            self.version_button.setEnabled(True)
            QMessageBox.critical(self, "版本创建失败", message)

        run_background(build_revision, completed, failed)


class SearchPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(PageHeader("搜索中心", "本地搜索已索引任务、运行摘要与结构化结果"))
        bar = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("输入关键词；不向网络发送搜索内容")
        button = QPushButton("搜索")
        button.setProperty("primary", True)
        bar.addWidget(self.query, 1)
        bar.addWidget(button)
        layout.addLayout(bar)
        splitter = QSplitter()
        self.results = QListWidget()
        self.results.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        splitter.addWidget(self.results)
        splitter.addWidget(self.preview)
        splitter.setSizes([500, 600])
        layout.addWidget(splitter, 1)
        button.clicked.connect(self.search)
        self.query.returnPressed.connect(self.search)
        self.results.currentRowChanged.connect(self.show_result)
        self._items: list[dict] = []

    def search(self) -> None:
        try:
            self._items = self.context.store.search(self.query.text())
        except (sqlite3.Error, ValueError) as exc:
            QMessageBox.warning(self, "搜索失败", str(exc))
            return
        self.results.clear()
        for item in self._items:
            self.results.addItem(f"{item['title']}\n{item['object_type']} · {item['url']}")
        self.statusMessage.emit(f"本地搜索命中 {len(self._items):,} 项")

    def show_result(self, row: int) -> None:
        if 0 <= row < len(self._items):
            self.preview.setPlainText(json.dumps(self._items[row], ensure_ascii=False, indent=2))
            self.inspectorChanged.emit("搜索结果", self._items[row])


class VersionPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        layout.addWidget(PageHeader("数据版本控制", "Revision / Change / Schema 可追踪；回滚产生新 Revision"))
        self.list = QListWidget()
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        splitter = QSplitter()
        splitter.addWidget(self.list)
        splitter.addWidget(self.detail)
        splitter.setSizes([380, 760])
        layout.addWidget(splitter, 1)
        compare = QPushButton("比较所选两个 Revision")
        layout.addWidget(compare)
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.list.currentRowChanged.connect(self.show_revision)
        self.list.itemSelectionChanged.connect(self._limit_revision_selection)
        compare.clicked.connect(self.compare_selected)
        self._revisions = []
        self._revision_load_token = 0
        self._revision_selection_order: list[int] = []
        self._revision_selection_guard = False

    def activated(self) -> None:
        self._revisions = self.context.store.list_revisions()
        self._revision_selection_order.clear()
        self.list.clear()
        for revision in self._revisions:
            self.list.addItem(f"{revision['created_at'][:19]}\n{revision['dataset_id']} · {revision['id']}")

    def _limit_revision_selection(self) -> None:
        
        if self._revision_selection_guard:
            return
        selected_rows = sorted({index.row() for index in self.list.selectedIndexes()})
        selected = set(selected_rows)
        self._revision_selection_order = [
            row for row in self._revision_selection_order if row in selected
        ]
        for row in selected_rows:
            if row not in self._revision_selection_order:
                self._revision_selection_order.append(row)
        if len(self._revision_selection_order) <= 2:
            return

        keep = set(self._revision_selection_order[-2:])
        self._revision_selection_guard = True
        try:
            for row in selected_rows:
                if row not in keep:
                    item = self.list.item(row)
                    if item is not None:
                        item.setSelected(False)
        finally:
            self._revision_selection_guard = False
        self._revision_selection_order = [row for row in self._revision_selection_order if row in keep]
        self.statusMessage.emit("Revision 比较最多选择两个版本")

    def show_revision(self, row: int) -> None:
        if not (0 <= row < len(self._revisions)):
            return
        revision = dict(self._revisions[row])
        revision_id = str(revision["id"])
        self._revision_load_token += 1
        token = self._revision_load_token
        self.detail.setPlainText("正在后台读取 Revision 元数据…")

        def completed(value: object) -> None:
            if token != self._revision_load_token:
                return
            data = dict(revision)
            data["record_count"] = int(value)
            self.detail.setPlainText(json.dumps(data, ensure_ascii=False, indent=2, default=str))

        def failed(message: str) -> None:
            if token == self._revision_load_token:
                self.detail.setPlainText(f"Revision 读取失败：{message}")

        run_background(
            lambda: self.context.store.count_revision_records(revision_id),
            completed,
            failed,
        )

    def compare_selected(self) -> None:
        rows = sorted({index.row() for index in self.list.selectedIndexes()})
        if len(rows) != 2:
            QMessageBox.information(self, "比较", "请选择两个 Revision。")
            return
        left_meta, right_meta = (dict(self._revisions[index]) for index in rows)
        self.detail.setPlainText("正在后台比较两个 Revision…")

        def worker() -> dict[str, object]:
            left = DatasetRevision(
                dataset_id=left_meta["dataset_id"],
                source_run_ids=json.loads(left_meta["source_run_ids_json"]),
                records=self.context.store.load_revision_records(left_meta["id"]),
                id=left_meta["id"],
                schema=json.loads(left_meta["schema_json"]),
            )
            right = DatasetRevision(
                dataset_id=right_meta["dataset_id"],
                source_run_ids=json.loads(right_meta["source_run_ids_json"]),
                records=self.context.store.load_revision_records(right_meta["id"]),
                id=right_meta["id"],
                schema=json.loads(right_meta["schema_json"]),
            )
            diff = self.context.versioning.compare(left, right)
            return {
                "added": len(diff.added),
                "removed": len(diff.removed),
                "modified": len(diff.modified),
                "schema_added": diff.schema_added,
                "schema_removed": diff.schema_removed,
                "schema_changed": diff.schema_changed,
                "sample_changes": {
                    key: [asdict(change) for change in changes]
                    for key, changes in list(diff.modified.items())[:50]
                },
            }

        run_background(
            worker,
            lambda result: self.detail.setPlainText(
                json.dumps(result, ensure_ascii=False, indent=2, default=str)
            ),
            lambda message: self.detail.setPlainText(f"Revision 比较失败：{message}"),
        )

