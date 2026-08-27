from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from arenyxa.qt_compat.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arenyxa.infrastructure.capture.proxy import InterceptingProxy, ProxyFlow, ProxySettings
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, connect_current_row_changed, set_table_header_stretch_last


class ProxyFlowModel(QAbstractTableModel):
    columns = ["#", "Time", "Method", "Host", "Path", "Status", "Length", "TLS", "Duration"]

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[ProxyFlow] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section]
        return super().headerData(section, orientation, role)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None
        flow = self.rows[index.row()]
        path = urlsplit(flow.url).path or "/"
        if urlsplit(flow.url).query:
            path += "?" + urlsplit(flow.url).query
        values = [
            flow.sequence,
            str(flow.started_at)[11:23],
            flow.method,
            flow.host,
            path,
            flow.status if flow.status is not None else "",
            flow.response_bytes,
            "MITM" if flow.tls_intercepted else "Tunnel" if flow.tunnel else "",
            f"{flow.duration_ms:.0f} ms",
        ]
        return values[index.column()]

    def replace(self, rows: list[ProxyFlow]) -> None:
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()


class ProxyPage(WorkspacePage):
    def __init__(self, context, theme, motion, parent=None) -> None:
        super().__init__(context, theme, motion, parent)
        self.proxy_root = Path(context.paths.captures) / "proxy"
        self.engine = InterceptingProxy(self.proxy_root)
        self._pending_ids: list[str] = []
        self._last_history_count = -1
        self._last_pending_signature: tuple[str, ...] = ()
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("Proxy", "HTTP / HTTPS interception proxy, history and message editor"), 1)
        self.intercept_toggle = QPushButton("Intercept is OFF")
        self.intercept_toggle.setCheckable(True)
        self.start_button = QPushButton("Start Proxy")
        self.start_button.setProperty("primary", True)
        self.stop_button = QPushButton("Stop Proxy")
        self.stop_button.setEnabled(False)
        header.addWidget(self.intercept_toggle)
        header.addWidget(self.start_button)
        header.addWidget(self.stop_button)
        root.addLayout(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_intercept_tab(), "Intercept")
        self.tabs.addTab(self._build_history_tab(), "HTTP History")
        self.tabs.addTab(self._build_settings_tab(), "Proxy Settings")
        root.addWidget(self.tabs, 1)

        self.status_label = QLabel("STOPPED · 127.0.0.1:8080 · 0 flows · 0 pending")
        self.status_label.setProperty("muted", True)
        root.addWidget(self.status_label)

        self.start_button.clicked.connect(self.start_proxy)
        self.stop_button.clicked.connect(self.stop_proxy)
        self.intercept_toggle.toggled.connect(self.set_intercept)
        self.intercept_responses.toggled.connect(lambda _enabled: self.set_intercept(self.intercept_toggle.isChecked()))
        self.forward_button.clicked.connect(self.forward_current)
        self.drop_button.clicked.connect(self.drop_current)
        self.pending_list.currentRowChanged.connect(self.load_pending)
        connect_current_row_changed(self.history_table, self.inspect_history)
        self.history_filter.textChanged.connect(self.refresh_history)
        self.export_ca_button.clicked.connect(self.export_ca)
        self.timer = QTimer(self)
        self.timer.setInterval(180)
        self.timer.timeout.connect(self.refresh_runtime)

    def _build_intercept_tab(self) -> QWidget:
        holder = QWidget()
        layout = QHBoxLayout(holder)
        splitter = QSplitter()
        self.pending_list = QListWidget()
        self.pending_list.setMinimumWidth(260)
        splitter.addWidget(self.pending_list)
        editor_holder = QWidget()
        editor_layout = QVBoxLayout(editor_holder)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        self.intercept_phase = QLabel("No intercepted message")
        self.intercept_editor = QPlainTextEdit()
        self.intercept_editor.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        buttons = QHBoxLayout()
        self.forward_button = QPushButton("Forward")
        self.forward_button.setProperty("primary", True)
        self.drop_button = QPushButton("Drop")
        self.forward_button.setEnabled(False)
        self.drop_button.setEnabled(False)
        buttons.addWidget(self.forward_button)
        buttons.addWidget(self.drop_button)
        buttons.addStretch()
        editor_layout.addWidget(self.intercept_phase)
        editor_layout.addWidget(self.intercept_editor, 1)
        editor_layout.addLayout(buttons)
        splitter.addWidget(editor_holder)
        splitter.setSizes([280, 900])
        layout.addWidget(splitter)
        return holder

    def _build_history_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        self.history_filter = QLineEdit()
        self.history_filter.setPlaceholderText("Filter by host, path, method or status")
        bar.addWidget(self.history_filter, 1)
        layout.addLayout(bar)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.history_model = ProxyFlowModel()
        self.history_table = QTableView()
        self.history_table.setModel(self.history_model)
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_table.setAlternatingRowColors(True)
        set_table_header_stretch_last(self.history_table, True)
        splitter.addWidget(self.history_table)
        details = QTabWidget()
        self.request_view = QPlainTextEdit()
        self.response_view = QPlainTextEdit()
        self.request_view.setReadOnly(True)
        self.response_view.setReadOnly(True)
        self.request_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.response_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        details.addTab(self.request_view, "Request")
        details.addTab(self.response_view, "Response")
        splitter.addWidget(details)
        splitter.setSizes([520, 330])
        layout.addWidget(splitter, 1)
        return holder

    def _build_settings_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        form = QFormLayout()
        self.bind_host = QLineEdit("127.0.0.1")
        self.bind_port = QSpinBox()
        self.bind_port.setRange(0, 65535)
        self.bind_port.setValue(8080)
        self.tls_intercept = QCheckBox("Decrypt HTTPS using Arenyxa local CA")
        self.tls_intercept.setChecked(True)
        self.intercept_responses = QCheckBox("Intercept responses too")
        self.allow_remote = QCheckBox("Allow LAN / remote clients")
        self.verify_upstream_tls = QCheckBox("Verify upstream TLS certificates")
        self.verify_upstream_tls.setChecked(True)
        form.addRow("Listener host", self.bind_host)
        form.addRow("Listener port", self.bind_port)
        form.addRow("HTTPS", self.tls_intercept)
        form.addRow("Interception", self.intercept_responses)
        form.addRow("Exposure", self.allow_remote)
        form.addRow("Upstream TLS", self.verify_upstream_tls)
        layout.addLayout(form)
        ca_row = QHBoxLayout()
        self.ca_fingerprint = QLineEdit(self.engine.ca.fingerprint())
        self.ca_fingerprint.setReadOnly(True)
        self.export_ca_button = QPushButton("Export CA Certificate")
        ca_row.addWidget(QLabel("CA SHA-256"))
        ca_row.addWidget(self.ca_fingerprint, 1)
        ca_row.addWidget(self.export_ca_button)
        layout.addLayout(ca_row)
        warning = QLabel("Only trust this CA on browsers or devices you control for authorized testing. Remote listeners are disabled by default.")
        warning.setWordWrap(True)
        warning.setProperty("muted", True)
        layout.addWidget(warning)
        layout.addStretch()
        return holder

    def activated(self) -> None:
        self.timer.start()
        self.refresh_runtime()

    def deactivated(self) -> None:
        if self.engine.running:
            self.timer.start()
        else:
            self.timer.stop()

    def start_proxy(self) -> None:
        if self.engine.running:
            return
        settings = ProxySettings(
            bind_host=self.bind_host.text().strip() or "127.0.0.1",
            bind_port=int(self.bind_port.value()),
            intercept_requests=bool(self.intercept_toggle.isChecked()),
            intercept_responses=bool(self.intercept_toggle.isChecked() and self.intercept_responses.isChecked()),
            tls_interception=bool(self.tls_intercept.isChecked()),
            allow_remote_clients=bool(self.allow_remote.isChecked()),
            verify_upstream_tls=bool(self.verify_upstream_tls.isChecked()),
        )
        try:
            settings.validate()
            if settings.allow_remote_clients:
                answer = QMessageBox.question(
                    self,
                    "Remote Proxy Listener",
                    "This will allow other devices to connect to the proxy listener. Continue only on a trusted network.",
                )
                if answer != QMessageBox.StandardButton.Yes:
                    return
            self.engine.settings = settings
            host, port = self.engine.start()
            self.bind_port.setValue(port)
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.bind_host.setEnabled(False)
            self.bind_port.setEnabled(False)
            self.tls_intercept.setEnabled(False)
            self.allow_remote.setEnabled(False)
            self.verify_upstream_tls.setEnabled(False)
            self.timer.start()
            self.statusMessage.emit(f"Proxy started on {host}:{port}")
        except Exception as exc:
            QMessageBox.critical(self, "Unable to start Proxy", str(exc))
        self.refresh_runtime()

    def stop_proxy(self) -> None:
        try:
            self.engine.stop()
        finally:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.bind_host.setEnabled(True)
            self.bind_port.setEnabled(True)
            self.tls_intercept.setEnabled(True)
            self.allow_remote.setEnabled(True)
            self.verify_upstream_tls.setEnabled(True)
            self.refresh_runtime()
            self.statusMessage.emit("Proxy stopped")

    def set_intercept(self, enabled: bool) -> None:
        self.intercept_toggle.setText("Intercept is ON" if enabled else "Intercept is OFF")
        self.engine.update_policy(bool(enabled), bool(enabled and self.intercept_responses.isChecked()))

    def refresh_runtime(self) -> None:
        status = self.engine.status()
        self.status_label.setText(
            f"{'RUNNING' if status.running else 'STOPPED'} · {status.host}:{status.port} · {status.flows:,} flows · {status.pending:,} pending"
        )
        history = self.engine.history()
        if len(history) != self._last_history_count:
            self._last_history_count = len(history)
            self.refresh_history()
        pending = self.engine.pending()
        signature = tuple(str(item["id"]) for item in pending)
        if signature != self._last_pending_signature:
            selected = self.pending_list.currentRow()
            self._last_pending_signature = signature
            self._pending_ids = list(signature)
            self.pending_list.clear()
            for item in pending:
                self.pending_list.addItem(f"{item['phase'].upper()} · {item['method']} · {item['host']} · {item['target']}")
            if self.pending_list.count():
                self.pending_list.setCurrentRow(min(max(selected, 0), self.pending_list.count() - 1))
            else:
                self.intercept_editor.clear()
                self.intercept_phase.setText("No intercepted message")
                self.forward_button.setEnabled(False)
                self.drop_button.setEnabled(False)

    def refresh_history(self) -> None:
        query = self.history_filter.text().strip().casefold()
        rows = self.engine.history()
        if query:
            rows = [
                flow
                for flow in rows
                if query in flow.host.casefold()
                or query in flow.target.casefold()
                or query in flow.method.casefold()
                or query in str(flow.status or "")
            ]
        self.history_model.replace(rows)

    def load_pending(self, row: int) -> None:
        pending = self.engine.pending()
        if row < 0 or row >= len(pending):
            self.forward_button.setEnabled(False)
            self.drop_button.setEnabled(False)
            return
        item = pending[row]
        raw = item.get("raw") or b""
        self.intercept_phase.setText(f"{item['phase'].upper()} · {item['method']} · {item['host']} · {item['target']}")
        self.intercept_editor.setPlainText(bytes(raw).decode("latin-1", "replace"))
        self.forward_button.setEnabled(True)
        self.drop_button.setEnabled(True)

    def _current_pending_id(self) -> str | None:
        row = self.pending_list.currentRow()
        if row < 0 or row >= len(self._pending_ids):
            return None
        return self._pending_ids[row]

    def forward_current(self) -> None:
        intercept_id = self._current_pending_id()
        if not intercept_id:
            return
        self.engine.resolve(intercept_id, "forward", self.intercept_editor.toPlainText())
        self.refresh_runtime()

    def drop_current(self) -> None:
        intercept_id = self._current_pending_id()
        if not intercept_id:
            return
        self.engine.resolve(intercept_id, "drop")
        self.refresh_runtime()

    def inspect_history(self, row: int) -> None:
        if row < 0 or row >= len(self.history_model.rows):
            return
        flow = self.history_model.rows[row]
        self.request_view.setPlainText(flow.request_raw.decode("latin-1", "replace"))
        self.response_view.setPlainText(flow.response_raw.decode("latin-1", "replace"))

    def export_ca(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Arenyxa Proxy CA", "arenyxa-proxy-ca.pem", "PEM Certificate (*.pem *.crt);;All Files (*)")
        if not path:
            return
        try:
            self.engine.export_ca_certificate(Path(path))
            QMessageBox.information(self, "Proxy CA", f"Certificate exported to:\n{path}")
        except Exception as exc:
            QMessageBox.warning(self, "Proxy CA", str(exc))
