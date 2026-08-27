from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from arenyxa.qt_compat.QtCore import Signal
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from arenyxa.application.crawler import CrawlerConfig, CrawlerEngine, CrawlerResultExporter, CrawlerRunResult
from arenyxa.domain.models import DEFAULT_USER_AGENT, FieldSpec
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher
from arenyxa.presentation.background import run_background
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, set_table_header_stretch_last


class CrawlerLabPage(WorkspacePage):
    """Recursive crawler workbench kept separate from Extraction Lab."""

    crawlerProgress = Signal(object)

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self._token: CancellationToken | None = None
        self._result: CrawlerRunResult | None = None
        self._running = False
        self.crawlerProgress.connect(self._on_progress)

        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader(
                "Crawler Lab",
                "Bounded recursive crawling, URL frontier discovery, robots.txt governance, extraction and export",
            ),
            1,
        )
        self.start_button = QPushButton("Start Crawl")
        self.start_button.setProperty("primary", True)
        self.pause_button = QPushButton("Pause")
        self.resume_button = QPushButton("Resume")
        self.cancel_button = QPushButton("Cancel")
        self.export_button = QPushButton("Export Results")
        header.addWidget(self.start_button)
        header.addWidget(self.pause_button)
        header.addWidget(self.resume_button)
        header.addWidget(self.cancel_button)
        header.addWidget(self.export_button)
        root.addLayout(header)

        self.seeds = QPlainTextEdit()
        self.seeds.setPlaceholderText("Seed URLs — one per line\nhttps://example.com/")
        self.seeds.setMaximumHeight(100)
        root.addWidget(QLabel("Seed URLs"))
        root.addWidget(self.seeds)

        scope_row = QHBoxLayout()
        self.allowed_domains = QLineEdit()
        self.allowed_domains.setPlaceholderText("Optional allowed domains, comma-separated (example.com, api.example.com)")
        self.same_site = QCheckBox("Same-site only")
        self.same_site.setChecked(True)
        self.include_subdomains = QCheckBox("Include subdomains")
        self.include_subdomains.setChecked(True)
        self.respect_robots = QCheckBox("Respect robots.txt")
        self.respect_robots.setChecked(True)
        scope_row.addWidget(QLabel("Scope"))
        scope_row.addWidget(self.allowed_domains, 1)
        scope_row.addWidget(self.same_site)
        scope_row.addWidget(self.include_subdomains)
        scope_row.addWidget(self.respect_robots)
        root.addLayout(scope_row)

        limits_row = QHBoxLayout()
        self.max_pages = QSpinBox()
        self.max_pages.setRange(1, 10000)
        self.max_pages.setValue(250)
        self.max_depth = QSpinBox()
        self.max_depth.setRange(0, 32)
        self.max_depth.setValue(3)
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 64)
        self.concurrency.setValue(8)
        self.delay_ms = QSpinBox()
        self.delay_ms.setRange(0, 60000)
        self.delay_ms.setValue(350)
        for label, widget in (
            ("Max pages", self.max_pages),
            ("Max depth", self.max_depth),
            ("Concurrency", self.concurrency),
            ("Per-host delay (ms)", self.delay_ms),
        ):
            limits_row.addWidget(QLabel(label))
            limits_row.addWidget(widget)
        limits_row.addStretch()
        root.addLayout(limits_row)

        filter_row = QHBoxLayout()
        self.include_globs = QLineEdit()
        self.include_globs.setPlaceholderText("Include URL globs, comma-separated; blank = all")
        self.exclude_globs = QLineEdit()
        self.exclude_globs.setPlaceholderText("Exclude URL globs, comma-separated")
        self.user_agent = QLineEdit(DEFAULT_USER_AGENT)
        self.user_agent.setMinimumWidth(190)
        filter_row.addWidget(QLabel("Include"))
        filter_row.addWidget(self.include_globs, 1)
        filter_row.addWidget(QLabel("Exclude"))
        filter_row.addWidget(self.exclude_globs, 1)
        filter_row.addWidget(QLabel("User-Agent"))
        filter_row.addWidget(self.user_agent)
        root.addLayout(filter_row)

        advanced_row = QHBoxLayout()
        self.blocked_domains = QLineEdit()
        self.blocked_domains.setPlaceholderText("Blocked domains/globs, comma-separated")
        self.http3_mode = QComboBox()
        self.http3_mode.addItem("HTTP/3 Off", "off")
        self.http3_mode.addItem("HTTP/3 Prefer", "prefer")
        self.http3_mode.addItem("HTTP/3 Require", "require")
        self.cache_mode = QComboBox()
        self.cache_mode.addItem("Cache Off", "off")
        self.cache_mode.addItem("Cache Read/Write", "read-write")
        self.cache_mode.addItem("Cache Read Only", "read")
        self.cache_mode.addItem("Cache Write Only", "write")
        self.cache_root = QLineEdit()
        self.cache_root.setPlaceholderText("Optional crawler cache directory")
        self.browser_fallback = QCheckBox("Browser fallback for JS-required pages")
        self.remote_cdp = QLineEdit()
        self.remote_cdp.setPlaceholderText("Optional Remote CDP ws(s):// or http(s):// endpoint")
        advanced_row.addWidget(QLabel("Block"))
        advanced_row.addWidget(self.blocked_domains, 1)
        advanced_row.addWidget(self.http3_mode)
        advanced_row.addWidget(self.cache_mode)
        advanced_row.addWidget(self.cache_root, 1)
        advanced_row.addWidget(self.browser_fallback)
        advanced_row.addWidget(self.remote_cdp, 1)
        root.addLayout(advanced_row)

        splitter = QSplitter()
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        field_row = QHBoxLayout()
        field_row.addWidget(QLabel("Per-page extraction fields"))
        field_row.addStretch()
        self.add_field_button = QPushButton("Add Field")
        self.remove_field_button = QPushButton("Remove Field")
        field_row.addWidget(self.add_field_button)
        field_row.addWidget(self.remove_field_button)
        left_layout.addLayout(field_row)
        self.fields = QTableWidget(0, 6)
        self.fields.setHorizontalHeaderLabels(["Name", "Selector Type", "Selector", "Target", "Attribute", "Multiple"])
        self.fields.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.fields.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        set_table_header_stretch_last(self.fields, True)
        left_layout.addWidget(self.fields, 1)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.progress = QProgressBar()
        self.progress.setRange(0, self.max_pages.value())
        self.progress.setValue(0)
        right_layout.addWidget(self.progress)
        self.output_tabs = QTabWidget()
        self.pages_table = QTableWidget(0, 8)
        self.pages_table.setHorizontalHeaderLabels([
            "Status", "Depth", "URL", "Title", "Type", "Bytes", "ms", "Links"
        ])
        self.pages_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.pages_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        set_table_header_stretch_last(self.pages_table, True)
        self.records_output = QPlainTextEdit()
        self.records_output.setReadOnly(True)
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        self.output_tabs.addTab(self.pages_table, "Pages")
        self.output_tabs.addTab(self.records_output, "Extracted Records")
        self.output_tabs.addTab(self.log_output, "Run Log")
        right_layout.addWidget(self.output_tabs, 1)
        splitter.addWidget(left)
        splitter.addWidget(right)
        splitter.setSizes([520, 760])
        root.addWidget(splitter, 1)

        safety = QLabel(
            "Crawler Lab uses a bounded URL frontier and Arenyxa's existing HTTP/DLP/network-governance stack. "
            "robots.txt is respected by default; recursion, concurrency, response size and host pacing remain bounded."
        )
        safety.setWordWrap(True)
        safety.setProperty("muted", True)
        root.addWidget(safety)

        self.start_button.clicked.connect(self.start_crawl)
        self.pause_button.clicked.connect(self.pause_crawl)
        self.resume_button.clicked.connect(self.resume_crawl)
        self.cancel_button.clicked.connect(self.cancel_crawl)
        self.export_button.clicked.connect(self.export_results)
        self.add_field_button.clicked.connect(self.add_field)
        self.remove_field_button.clicked.connect(self.remove_field)
        self.max_pages.valueChanged.connect(lambda value: self.progress.setRange(0, int(value)))
        self._set_running(False)

    def add_field(self) -> None:
        row = self.fields.rowCount()
        self.fields.insertRow(row)
        defaults = [f"field_{row + 1}", "css", "h1", "text", "", "false"]
        for column, value in enumerate(defaults):
            self.fields.setItem(row, column, QTableWidgetItem(value))
        self.fields.selectRow(row)

    def remove_field(self) -> None:
        row = self.fields.currentRow()
        if row >= 0:
            self.fields.removeRow(row)

    def _fields_from_ui(self) -> list[FieldSpec]:
        output: list[FieldSpec] = []
        for row in range(self.fields.rowCount()):
            values = []
            for column in range(6):
                item = self.fields.item(row, column)
                values.append(item.text().strip() if item is not None else "")
            name, selector_type, selector, target, attribute, multiple = values
            if not name and not selector:
                continue
            selector_type = selector_type.casefold() or "css"
            target = target.casefold() or "text"
            output.append(FieldSpec(
                name=name,
                selector=selector,
                selector_type=selector_type,
                target=target,
                attribute=attribute or None,
                multiple=multiple.casefold() in {"1", "true", "yes", "on"},
            ))
        return output

    @staticmethod
    def _csv_values(text: str) -> list[str]:
        return [part.strip() for part in str(text).replace("\n", ",").split(",") if part.strip()]

    def _config_from_ui(self) -> CrawlerConfig:
        seeds = [line.strip() for line in self.seeds.toPlainText().splitlines() if line.strip()]
        max_response = int(getattr(self.context.settings, "max_response_bytes", 32 * 1024 * 1024))
        # Construct once here only to validate the configured response budget; engine receives it in start_crawl.
        _ = max_response
        return CrawlerConfig(
            seeds=seeds,
            fields=self._fields_from_ui(),
            max_pages=self.max_pages.value(),
            max_depth=self.max_depth.value(),
            concurrency=self.concurrency.value(),
            per_host_delay_seconds=self.delay_ms.value() / 1000.0,
            respect_robots_txt=self.respect_robots.isChecked(),
            same_site_only=self.same_site.isChecked(),
            include_subdomains=self.include_subdomains.isChecked(),
            allowed_domains=self._csv_values(self.allowed_domains.text()),
            include_url_globs=self._csv_values(self.include_globs.text()),
            exclude_url_globs=self._csv_values(self.exclude_globs.text()),
            blocked_domains=self._csv_values(self.blocked_domains.text()),
            http3_mode=str(self.http3_mode.currentData() or "off"),
            cache_mode=str(self.cache_mode.currentData() or "off"),
            cache_root=self.cache_root.text().strip(),
            browser_fallback_on_js=self.browser_fallback.isChecked(),
            browser_remote_cdp_url=self.remote_cdp.text().strip(),
            user_agent=self.user_agent.text().strip() or DEFAULT_USER_AGENT,
        ).normalized()

    def start_crawl(self) -> None:
        if self._running:
            return
        try:
            config = self._config_from_ui()
        except Exception as exc:
            QMessageBox.warning(self, "Crawler Lab", str(exc))
            return
        self._token = CancellationToken()
        self._result = None
        self.pages_table.setRowCount(0)
        self.records_output.clear()
        self.log_output.clear()
        self.progress.setRange(0, config.max_pages)
        self.progress.setValue(0)
        self._set_running(True)
        self.statusMessage.emit("Crawler Lab · crawl started")
        max_response = int(getattr(self.context.settings, "max_response_bytes", 32 * 1024 * 1024))
        token = self._token

        def work() -> CrawlerRunResult:
            engine = CrawlerEngine(fetcher=HttpFetcher(max_response))
            return engine.run(config, token=token, progress=self.crawlerProgress.emit)

        run_background(work, self._crawl_finished, self._crawl_failed)

    def pause_crawl(self) -> None:
        if self._token is None or not self._running:
            return
        self._token.pause()
        self.pause_button.setEnabled(False)
        self.resume_button.setEnabled(True)
        self.statusMessage.emit("Crawler Lab · paused")

    def resume_crawl(self) -> None:
        if self._token is None or not self._running:
            return
        self._token.resume()
        self.pause_button.setEnabled(True)
        self.resume_button.setEnabled(False)
        self.statusMessage.emit("Crawler Lab · resumed")

    def cancel_crawl(self) -> None:
        if self._token is None or not self._running:
            return
        self._token.cancel()
        self.cancel_button.setEnabled(False)
        self.statusMessage.emit("Crawler Lab · cancellation requested")

    def _on_progress(self, payload: object) -> None:
        if not isinstance(payload, dict):
            return
        stage = str(payload.get("stage", ""))
        completed = int(payload.get("completed", 0) or 0)
        submitted = int(payload.get("submitted", 0) or 0)
        records = int(payload.get("records", 0) or 0)
        self.progress.setValue(min(self.progress.maximum(), completed))
        self.operationProgress.emit("Crawler", completed, max(1, self.progress.maximum()), stage)
        url = str(payload.get("url", ""))
        if stage in {"error", "robots_denied"}:
            detail = str(payload.get("error", ""))
            self.log_output.appendPlainText(f"[{stage}] {url} {detail}".rstrip())
        elif stage == "page":
            status = payload.get("status", "")
            depth = payload.get("depth", "")
            self.log_output.appendPlainText(f"[{status}] depth={depth} {url}")
        self.statusMessage.emit(f"Crawler · submitted {submitted} · completed {completed} · records {records}")

    def _crawl_finished(self, value: object) -> None:
        if not isinstance(value, CrawlerRunResult):
            self._crawl_failed("Crawler returned an unexpected result")
            return
        self._result = value
        self._set_running(False)
        self._render_result(value)
        state = "cancelled" if value.cancelled else "completed"
        self.statusMessage.emit(
            f"Crawler {state} · {value.pages_succeeded} succeeded · {value.pages_failed} failed · {len(value.records)} records"
        )
        self.inspectorChanged.emit("Crawler Run", {
            "pages_submitted": value.pages_submitted,
            "pages_succeeded": value.pages_succeeded,
            "pages_failed": value.pages_failed,
            "urls_discovered": value.urls_discovered,
            "robots_denied": value.robots_denied,
            "duplicates_removed": value.duplicates_removed,
            "duration_seconds": value.duration_seconds,
        })

    def _crawl_failed(self, message: str) -> None:
        self._set_running(False)
        self.log_output.appendPlainText(f"[fatal] {message}")
        self.statusMessage.emit("Crawler Lab · failed")
        QMessageBox.warning(self, "Crawler Lab", message)

    def _render_result(self, result: CrawlerRunResult) -> None:
        pages = result.pages[:5000]
        self.pages_table.setRowCount(len(pages))
        for row, page in enumerate(pages):
            values = [
                page.status,
                page.depth,
                page.final_url,
                page.title,
                page.content_type,
                page.bytes_received,
                page.elapsed_ms,
                page.links_discovered,
            ]
            for column, value in enumerate(values):
                self.pages_table.setItem(row, column, QTableWidgetItem(str(value)))
        preview = result.records[:500]
        self.records_output.setPlainText(json.dumps(preview, ensure_ascii=False, indent=2, default=str))
        summary = {
            "pages_submitted": result.pages_submitted,
            "pages_succeeded": result.pages_succeeded,
            "pages_failed": result.pages_failed,
            "urls_discovered": result.urls_discovered,
            "urls_skipped": result.urls_skipped,
            "duplicates_removed": result.duplicates_removed,
            "robots_denied": result.robots_denied,
            "records": len(result.records),
            "duration_seconds": result.duration_seconds,
            "cancelled": result.cancelled,
            "warnings": result.warnings,
            "errors": result.errors[:100],
        }
        self.log_output.appendPlainText("\n" + json.dumps(summary, ensure_ascii=False, indent=2, default=str))
        self.progress.setValue(min(self.progress.maximum(), len(result.pages) + result.pages_failed))

    def export_results(self) -> None:
        if self._result is None:
            QMessageBox.information(self, "Crawler Lab", "Run a crawl before exporting results.")
            return
        path, selected = QFileDialog.getSaveFileName(
            self,
            "Export Crawler Results",
            "crawler-results.json",
            "JSON (*.json);;JSON Lines (*.jsonl);;CSV (*.csv);;Excel (*.xlsx);;XML (*.xml)",
        )
        if not path:
            return
        suffix = Path(path).suffix.casefold().lstrip(".")
        if not suffix:
            suffix = "xml" if "XML" in selected else "xlsx" if "Excel" in selected else "csv" if "CSV" in selected else "jsonl" if "Lines" in selected else "json"
            path = f"{path}.{suffix}"
        result = self._result
        self.export_button.setEnabled(False)

        def work() -> tuple[int, str]:
            count = CrawlerResultExporter().export(result, Path(path), suffix)
            return count, path

        def done(value: object) -> None:
            self.export_button.setEnabled(True)
            count, target = value if isinstance(value, tuple) and len(value) == 2 else (0, path)
            self.statusMessage.emit(f"Crawler export completed · {count} rows")
            QMessageBox.information(self, "Crawler Lab", f"Exported {count} rows to:\n{target}")

        def failed(message: str) -> None:
            self.export_button.setEnabled(True)
            QMessageBox.warning(self, "Crawler Lab", message)

        run_background(work, done, failed)

    def _set_running(self, running: bool) -> None:
        self._running = bool(running)
        self.start_button.setEnabled(not running)
        self.pause_button.setEnabled(running)
        self.resume_button.setEnabled(False)
        self.cancel_button.setEnabled(running)
        self.export_button.setEnabled((not running) and self._result is not None)
        self.add_field_button.setEnabled(not running)
        self.remove_field_button.setEnabled(not running)


__all__ = ["CrawlerLabPage"]
