from __future__ import annotations

import json
from pathlib import Path
from typing import Any
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
    QComboBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arenyxa.infrastructure.capture.proxy import InterceptingProxy, ProxyFlow, ProxySettings
from arenyxa.infrastructure.capture.professional import MessageCodec, MessageComparer
from arenyxa.application.proxy_deep_inspector import ProxyDeepInspector
from arenyxa.application.proxy_profiler import ProxyProfiler
from arenyxa.domain.errors import ArenyxaError
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, connect_current_row_changed, set_table_header_stretch_last
from arenyxa.presentation.pages.proxy_suite_panels import ProxySuitePanelsMixin


class ProxyFlowModel(QAbstractTableModel):
    columns = ["#", "Time", "Method", "Host", "Path", "Status", "Length", "TLS", "Duration"]

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[ProxyFlow] = []

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section: int, orientation: Any, role: Any = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section]
        return super().headerData(section, orientation, role)

    def data(self, index: QModelIndex, role: Any = Qt.ItemDataRole.DisplayRole) -> Any:
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


class ProxyPage(ProxySuitePanelsMixin, WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self.proxy_root = Path(context.paths.captures) / "proxy"
        self.engine = context.proxy_engine or InterceptingProxy(self.proxy_root)
        context.proxy_engine = self.engine
        self.codec = MessageCodec()
        self.comparer = MessageComparer()
        self._pending_ids: list[str] = []
        self._last_history_count = -1
        self._last_pending_signature: tuple[str, ...] = ()
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("Proxy Suite", "Professional HTTP / HTTPS interception, replay, TLS and traffic-control workbench"), 1)
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
        self.tabs.addTab(self._build_https_sessions_tab(), "HTTPS Sessions")
        self.tabs.addTab(self._build_request_editor_tab(), "Request Editor")
        self.tabs.addTab(self._build_response_viewer_tab(), "Response Viewer")
        self.tabs.addTab(self._build_repeater_tab(), "Replay")
        self.tabs.addTab(self._build_websocket_tab(), "WebSocket")
        self.tabs.addTab(self._build_tls_inspector_tab(), "TLS Inspector")
        self.tabs.addTab(self._build_session_summary_tab(), "Session Summary")
        self.tabs.addTab(self._build_profiler_tab(), "Profiler")
        self.tabs.addTab(self._build_deep_analysis_tab(), "Deep Analysis")
        self.tabs.addTab(self._build_decoder_tab(), "Decoder")
        self.tabs.addTab(self._build_comparer_tab(), "Comparer")
        self.tabs.addTab(self._build_rules_tab(), "Rules Engine")
        self.tabs.addTab(self._build_match_replace_tab(), "Match / Replace")
        self.tabs.addTab(self._build_export_center_tab(), "Export Center")
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
        self.export_har_button.clicked.connect(self.export_har)
        self.export_ca_button.clicked.connect(self.export_ca)
        self.repeater_send.clicked.connect(self.send_repeater)
        self.decoder_run.clicked.connect(self.run_decoder)
        self.compare_run.clicked.connect(self.run_compare)
        self.rule_add.clicked.connect(self.add_autoresponder_rule)
        self.rule_remove.clicked.connect(self.remove_autoresponder_rule)
        self.rewrite_add.clicked.connect(self.add_match_replace_rule)
        self.rewrite_remove.clicked.connect(self.remove_match_replace_rule)
        self.tabs.currentChanged.connect(lambda _index: self.refresh_professional_panels())
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
        self.export_har_button = QPushButton("Export HAR (Redacted)")
        bar.addWidget(self.history_filter, 1)
        bar.addWidget(self.export_har_button)
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
        self.inspector_view = QPlainTextEdit()
        self.request_view.setReadOnly(True)
        self.response_view.setReadOnly(True)
        self.inspector_view.setReadOnly(True)
        self.request_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.response_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.inspector_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        details.addTab(self.request_view, "Request")
        details.addTab(self.response_view, "Response")
        details.addTab(self.inspector_view, "Inspector")
        splitter.addWidget(details)
        splitter.setSizes([520, 330])
        layout.addWidget(splitter, 1)
        return holder

    def _build_session_summary_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        intro = QLabel("Arenyxa session-level traffic analysis: host concentration, status mix, latency and rewrite activity")
        intro.setProperty("muted", True)
        self.summary_refresh = QPushButton("Refresh Summary")
        bar.addWidget(intro, 1)
        bar.addWidget(self.summary_refresh)
        layout.addLayout(bar)
        self.session_summary_view = QPlainTextEdit()
        self.session_summary_view.setReadOnly(True)
        self.session_summary_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(self.session_summary_view, 1)
        self.summary_refresh.clicked.connect(self.refresh_session_summary)
        return holder

    def _build_profiler_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        intro = QLabel("Passive performance/security profiling of captured Proxy history: p50/p95/p99 latency, host concentration, errors and bounded findings.")
        intro.setProperty("muted", True)
        self.profiler_refresh = QPushButton("Refresh Profiler")
        self.profiler_refresh.setProperty("primary", True)
        self.profiler_refresh.clicked.connect(self.refresh_profiler)
        bar.addWidget(intro, 1)
        bar.addWidget(self.profiler_refresh)
        layout.addLayout(bar)
        self.profiler_view = QPlainTextEdit()
        self.profiler_view.setReadOnly(True)
        self.profiler_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(self.profiler_view, 1)
        return holder

    def _build_deep_analysis_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        self.deep_left_id = QLineEdit()
        self.deep_left_id.setPlaceholderText("Selected/left flow ID")
        self.deep_right_id = QLineEdit()
        self.deep_right_id.setPlaceholderText("Optional right flow ID for comparison")
        self.deep_inspect_button = QPushButton("Inspect Selected")
        self.deep_inspect_button.setProperty("primary", True)
        self.deep_compare_button = QPushButton("Compare")
        self.deep_timeline_button = QPushButton("Timeline")
        self.deep_inspect_button.clicked.connect(self.deep_inspect_selected)
        self.deep_compare_button.clicked.connect(self.deep_compare_flows)
        self.deep_timeline_button.clicked.connect(self.refresh_deep_timeline)
        bar.addWidget(self.deep_left_id, 1)
        bar.addWidget(self.deep_right_id, 1)
        bar.addWidget(self.deep_inspect_button)
        bar.addWidget(self.deep_compare_button)
        bar.addWidget(self.deep_timeline_button)
        layout.addLayout(bar)
        self.deep_output = QPlainTextEdit()
        self.deep_output.setReadOnly(True)
        self.deep_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(self.deep_output, 1)
        note = QLabel("Deep Analysis inspects parameters, cookies, content/security headers, encodings and bounded body previews without sending a new request.")
        note.setWordWrap(True)
        note.setProperty("muted", True)
        layout.addWidget(note)
        return holder

    def _flow_by_id(self, flow_id: str) -> ProxyFlow | None:
        target = str(flow_id).strip()
        return next((item for item in self.engine.history() if str(item.id) == target), None)

    def deep_inspect_selected(self) -> None:
        flow_id = self.deep_left_id.text().strip()
        if not flow_id:
            index = self.history_table.currentIndex()
            if index.isValid() and 0 <= index.row() < len(self.history_model.rows):
                flow_id = str(self.history_model.rows[index.row()].id)
                self.deep_left_id.setText(flow_id)
        flow = self._flow_by_id(flow_id)
        if flow is None:
            QMessageBox.information(self, "Proxy Deep Analysis", "Select a Proxy history flow or enter its flow ID.")
            return
        self.deep_output.setPlainText(json.dumps(ProxyDeepInspector().inspect(flow).snapshot(), ensure_ascii=False, indent=2, default=str))

    def deep_compare_flows(self) -> None:
        left = self._flow_by_id(self.deep_left_id.text())
        right = self._flow_by_id(self.deep_right_id.text())
        if left is None or right is None:
            QMessageBox.information(self, "Proxy Deep Analysis", "Enter two valid Proxy flow IDs first.")
            return
        self.deep_output.setPlainText(json.dumps(ProxyDeepInspector().compare(left, right), ensure_ascii=False, indent=2, default=str))

    def refresh_deep_timeline(self) -> None:
        rows = ProxyDeepInspector().timeline(self.engine.history()[-1000:], limit=1000)
        self.deep_output.setPlainText(json.dumps(rows, ensure_ascii=False, indent=2, default=str))

    def _build_repeater_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        target = QHBoxLayout()
        self.repeater_scheme = QComboBox()
        self.repeater_scheme.addItems(["https", "http"])
        self.repeater_host = QLineEdit()
        self.repeater_host.setPlaceholderText("example.com")
        self.repeater_port = QSpinBox()
        self.repeater_port.setRange(1, 65535)
        self.repeater_port.setValue(443)
        self.repeater_scheme.currentTextChanged.connect(lambda value: self.repeater_port.setValue(443 if value == "https" else 80))
        self.repeater_send = QPushButton("Send")
        self.repeater_send.setProperty("primary", True)
        target.addWidget(self.repeater_scheme)
        target.addWidget(self.repeater_host, 1)
        target.addWidget(self.repeater_port)
        target.addWidget(self.repeater_send)
        layout.addLayout(target)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.repeater_request = QPlainTextEdit("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Arenyxa-Repeater/8.1.1\r\nConnection: close\r\n\r\n")
        self.repeater_response = QPlainTextEdit()
        self.repeater_response.setReadOnly(True)
        self.repeater_request.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.repeater_response.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        splitter.addWidget(self.repeater_request)
        splitter.addWidget(self.repeater_response)
        layout.addWidget(splitter, 1)
        note = QLabel("Repeater sends one explicitly requested HTTP message at a time and is governed by Arenyxa network safety budgets.")
        note.setProperty("muted", True)
        note.setWordWrap(True)
        layout.addWidget(note)
        return holder

    def _build_decoder_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        controls = QHBoxLayout()
        self.decoder_mode = QComboBox()
        self.decoder_mode.addItems(["URL", "Base64", "Hex", "JSON"])
        self.decoder_operation = QComboBox()
        self.decoder_operation.addItems(["Encode", "Decode"])
        self.decoder_mode.currentTextChanged.connect(self._sync_decoder_operations)
        self.decoder_run = QPushButton("Transform")
        self.decoder_run.setProperty("primary", True)
        controls.addWidget(self.decoder_mode)
        controls.addWidget(self.decoder_operation)
        controls.addStretch()
        controls.addWidget(self.decoder_run)
        layout.addLayout(controls)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.decoder_input = QPlainTextEdit()
        self.decoder_output = QPlainTextEdit()
        self.decoder_output.setReadOnly(True)
        self.decoder_input.setPlaceholderText("Paste request data, tokens, JSON, URL-encoded text or hexadecimal text")
        self.decoder_input.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.decoder_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        splitter.addWidget(self.decoder_input)
        splitter.addWidget(self.decoder_output)
        layout.addWidget(splitter, 1)
        note = QLabel("Decoder is fully local and bounded; it does not send data to the network.")
        note.setProperty("muted", True)
        layout.addWidget(note)
        return holder

    def _build_comparer_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        editors = QSplitter(Qt.Orientation.Horizontal)
        self.compare_left = QPlainTextEdit()
        self.compare_right = QPlainTextEdit()
        self.compare_left.setPlaceholderText("Left message")
        self.compare_right.setPlaceholderText("Right message")
        self.compare_left.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        self.compare_right.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        editors.addWidget(self.compare_left)
        editors.addWidget(self.compare_right)
        layout.addWidget(editors, 1)
        row = QHBoxLayout()
        self.compare_run = QPushButton("Compare")
        self.compare_run.setProperty("primary", True)
        self.compare_summary = QLabel("No comparison yet")
        self.compare_summary.setProperty("muted", True)
        row.addWidget(self.compare_run)
        row.addWidget(self.compare_summary, 1)
        layout.addLayout(row)
        self.compare_output = QPlainTextEdit()
        self.compare_output.setReadOnly(True)
        self.compare_output.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(self.compare_output, 1)
        return holder

    def _build_rules_tab(self) -> QWidget:
        holder = QWidget()
        layout = QHBoxLayout(holder)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.rules_list = QListWidget()
        left_layout.addWidget(self.rules_list, 1)
        self.rule_remove = QPushButton("Remove Rule")
        left_layout.addWidget(self.rule_remove)
        layout.addWidget(left, 1)
        editor = QWidget()
        editor_layout = QVBoxLayout(editor)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        form = QFormLayout()
        self.rule_host = QLineEdit("api.example.com")
        self.rule_path = QLineEdit("/v1/*")
        self.rule_method = QComboBox()
        self.rule_method.addItems(["*", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
        self.rule_status = QSpinBox()
        self.rule_status.setRange(100, 599)
        self.rule_status.setValue(200)
        self.rule_reason = QLineEdit("Arenyxa AutoResponder")
        self.rule_content_type = QLineEdit("application/json; charset=utf-8")
        form.addRow("Host pattern", self.rule_host)
        form.addRow("Path pattern", self.rule_path)
        form.addRow("Method", self.rule_method)
        form.addRow("Status", self.rule_status)
        form.addRow("Reason", self.rule_reason)
        form.addRow("Content-Type", self.rule_content_type)
        editor_layout.addLayout(form)
        self.rule_body = QPlainTextEdit("{\n  \"ok\": true\n}")
        self.rule_body.setPlaceholderText("Local mock response body")
        editor_layout.addWidget(self.rule_body, 1)
        self.rule_add = QPushButton("Add AutoResponder Rule")
        self.rule_add.setProperty("primary", True)
        editor_layout.addWidget(self.rule_add)
        note = QLabel("Matching requests are answered locally and never sent upstream. Rules are bounded, persisted locally, and intended for authorized API/UI debugging and fault simulation.")
        note.setWordWrap(True)
        note.setProperty("muted", True)
        editor_layout.addWidget(note)
        layout.addWidget(editor, 2)
        self._rule_ids: list[str] = []
        self.refresh_autoresponder_rules()
        return holder

    def _build_match_replace_tab(self) -> QWidget:
        holder = QWidget()
        layout = QHBoxLayout(holder)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.rewrite_list = QListWidget()
        left_layout.addWidget(self.rewrite_list, 1)
        self.rewrite_remove = QPushButton("Remove Match/Replace Rule")
        left_layout.addWidget(self.rewrite_remove)
        layout.addWidget(left, 1)

        editor = QWidget()
        editor_layout = QVBoxLayout(editor)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        form = QFormLayout()
        self.rewrite_phase = QComboBox()
        self.rewrite_phase.addItems(["request", "response"])
        self.rewrite_scope = QComboBox()
        self.rewrite_scope.addItems(["header", "body"])
        self.rewrite_host = QLineEdit("*")
        self.rewrite_path = QLineEdit("/*")
        self.rewrite_method = QComboBox()
        self.rewrite_method.addItems(["*", "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
        self.rewrite_header = QLineEdit("*")
        self.rewrite_match = QLineEdit("old-value")
        self.rewrite_replacement = QLineEdit("new-value")
        form.addRow("Phase", self.rewrite_phase)
        form.addRow("Scope", self.rewrite_scope)
        form.addRow("Host pattern", self.rewrite_host)
        form.addRow("Path pattern", self.rewrite_path)
        form.addRow("Method", self.rewrite_method)
        form.addRow("Header name / pattern", self.rewrite_header)
        form.addRow("Literal match", self.rewrite_match)
        form.addRow("Replacement", self.rewrite_replacement)
        editor_layout.addLayout(form)
        self.rewrite_add = QPushButton("Add Match/Replace Rule")
        self.rewrite_add.setProperty("primary", True)
        editor_layout.addWidget(self.rewrite_add)
        note = QLabel("Rules use bounded literal replacement. Request rewrites are re-parsed and still pass through Arenyxa Network Governance before any upstream connection. Chunked bodies are not rewritten.")
        note.setWordWrap(True)
        note.setProperty("muted", True)
        editor_layout.addWidget(note)
        editor_layout.addStretch()
        layout.addWidget(editor, 2)
        self._rewrite_ids: list[str] = []
        self.refresh_match_replace_rules()
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
        self.network_guard_enabled = QCheckBox("Enable network governance")
        self.network_guard_enabled.setChecked(True)
        self.block_cloud_metadata = QCheckBox("Block cloud metadata endpoints")
        self.block_cloud_metadata.setChecked(True)
        self.block_private_remote = QCheckBox("Block private/loopback targets when remote listener is enabled")
        self.block_private_remote.setChecked(True)
        self.max_upstreams = QSpinBox()
        self.max_upstreams.setRange(1, 4096)
        self.max_upstreams.setValue(128)
        self.max_global_connects = QSpinBox()
        self.max_global_connects.setRange(1, 1_000_000)
        self.max_global_connects.setValue(1200)
        self.max_target_connects = QSpinBox()
        self.max_target_connects.setRange(1, 100_000)
        self.max_target_connects.setValue(240)
        self.max_distinct_targets = QSpinBox()
        self.max_distinct_targets.setRange(1, 100_000)
        self.max_distinct_targets.setValue(512)
        form.addRow("Listener host", self.bind_host)
        form.addRow("Listener port", self.bind_port)
        form.addRow("HTTPS", self.tls_intercept)
        form.addRow("Interception", self.intercept_responses)
        form.addRow("Exposure", self.allow_remote)
        form.addRow("Upstream TLS", self.verify_upstream_tls)
        form.addRow("Network governance", self.network_guard_enabled)
        form.addRow("Cloud metadata", self.block_cloud_metadata)
        form.addRow("Remote private targets", self.block_private_remote)
        form.addRow("Max concurrent upstreams", self.max_upstreams)
        form.addRow("Global connects / min", self.max_global_connects)
        form.addRow("Per-target connects / min", self.max_target_connects)
        form.addRow("Distinct targets / min", self.max_distinct_targets)
        layout.addLayout(form)
        self.governance_status = QLabel("Network governance ready")
        self.governance_status.setProperty("muted", True)
        layout.addWidget(self.governance_status)
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

    def refresh_autoresponder_rules(self) -> None:
        rules = self.engine.autoresponder_rules()
        self._rule_ids = [str(item.get("id", "")) for item in rules]
        if not hasattr(self, "rules_list"):
            return
        self.rules_list.clear()
        for item in rules:
            method = str(item.get("method", "*"))
            host = str(item.get("host_pattern", ""))
            path = str(item.get("path_pattern", "/*"))
            status = int(item.get("status", 200))
            self.rules_list.addItem(f"{method} {host}{path}  →  {status}")

    def add_autoresponder_rule(self) -> None:
        try:
            self.engine.add_autoresponder_rule(
                self.rule_host.text().strip(), self.rule_path.text().strip(),
                method=self.rule_method.currentText(), status=int(self.rule_status.value()),
                reason=self.rule_reason.text().strip(), content_type=self.rule_content_type.text().strip(),
                body=self.rule_body.toPlainText(),
            )
            self.refresh_autoresponder_rules()
            self.statusMessage.emit("AutoResponder rule added")
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid AutoResponder rule", str(exc))

    def remove_autoresponder_rule(self) -> None:
        row = self.rules_list.currentRow()
        if row < 0 or row >= len(self._rule_ids):
            return
        if self.engine.remove_autoresponder_rule(self._rule_ids[row]):
            self.refresh_autoresponder_rules()
            self.statusMessage.emit("AutoResponder rule removed")

    def refresh_match_replace_rules(self) -> None:
        rules = self.engine.match_replace_rules()
        self._rewrite_ids = [str(item.get("id", "")) for item in rules]
        if not hasattr(self, "rewrite_list"):
            return
        self.rewrite_list.clear()
        for item in rules:
            phase = str(item.get("phase", "request"))
            scope = str(item.get("scope", "header"))
            method = str(item.get("method", "*"))
            host = str(item.get("host_pattern", "*"))
            path = str(item.get("path_pattern", "/*"))
            header = str(item.get("header_name", "*"))
            self.rewrite_list.addItem(f"{phase} · {scope}:{header} · {method} {host}{path}")

    def add_match_replace_rule(self) -> None:
        try:
            self.engine.add_match_replace_rule(
                self.rewrite_phase.currentText(), self.rewrite_scope.currentText(),
                self.rewrite_match.text(), self.rewrite_replacement.text(),
                host_pattern=self.rewrite_host.text().strip() or "*",
                path_pattern=self.rewrite_path.text().strip() or "/*",
                method=self.rewrite_method.currentText(), header_name=self.rewrite_header.text().strip() or "*",
            )
            self.refresh_match_replace_rules()
            self.statusMessage.emit("Match/Replace rule added")
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid Match/Replace rule", str(exc))

    def remove_match_replace_rule(self) -> None:
        row = self.rewrite_list.currentRow()
        if row < 0 or row >= len(self._rewrite_ids):
            return
        if self.engine.remove_match_replace_rule(self._rewrite_ids[row]):
            self.refresh_match_replace_rules()
            self.statusMessage.emit("Match/Replace rule removed")

    def activated(self) -> None:
        self.timer.start()
        self.refresh_runtime()

    def deactivated(self) -> None:
        if self.engine.running:
            self.timer.start()
        else:
            self.timer.stop()

    def send_repeater(self) -> None:
        try:
            response = self.engine.repeat_raw(
                self.repeater_scheme.currentText(),
                self.repeater_host.text().strip(),
                int(self.repeater_port.value()),
                self.repeater_request.toPlainText(),
            )
            self.repeater_response.setPlainText(response.decode("latin-1", "replace"))
        except (OSError, ValueError, ArenyxaError) as exc:
            self.repeater_response.setPlainText(f"Request failed: {exc}")

    def _sync_decoder_operations(self, mode: str) -> None:
        normalized = str(mode).strip().casefold()
        desired = ["Format"] if normalized == "json" else ["Encode", "Decode"]
        current = self.decoder_operation.currentText()
        self.decoder_operation.blockSignals(True)
        self.decoder_operation.clear()
        self.decoder_operation.addItems(desired)
        if current in desired:
            self.decoder_operation.setCurrentText(current)
        self.decoder_operation.blockSignals(False)

    def run_decoder(self) -> None:
        mode = self.decoder_mode.currentText().casefold()
        operation = self.decoder_operation.currentText().casefold()
        if mode == "json":
            operation = "format"
        try:
            result = self.codec.transform(self.decoder_input.toPlainText(), mode, operation)
            self.decoder_output.setPlainText(result.output)
            self.statusMessage.emit(f"Decoder complete · {result.input_bytes:,} → {result.output_bytes:,} bytes")
        except ValueError as exc:
            self.decoder_output.setPlainText(f"Transform failed: {exc}")

    def run_compare(self) -> None:
        try:
            result = self.comparer.compare(self.compare_left.toPlainText(), self.compare_right.toPlainText())
            self.compare_summary.setText(
                "IDENTICAL" if result.equal else f"{result.changed_lines:,} changed lines · {result.left_lines:,}/{result.right_lines:,} lines"
            )
            self.compare_output.setPlainText(result.unified_diff or "No differences")
            self.statusMessage.emit("Comparer complete")
        except ValueError as exc:
            self.compare_summary.setText("Comparison failed")
            self.compare_output.setPlainText(str(exc))

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
            network_guard_enabled=bool(self.network_guard_enabled.isChecked()),
            max_concurrent_upstreams=int(self.max_upstreams.value()),
            max_upstream_connects_per_minute=int(self.max_global_connects.value()),
            max_target_connects_per_minute=int(self.max_target_connects.value()),
            max_distinct_targets_per_minute=int(self.max_distinct_targets.value()),
            max_tracked_targets=max(2048, min(1_000_000, int(self.max_distinct_targets.value()) * 4)),
            block_cloud_metadata=bool(self.block_cloud_metadata.isChecked()),
            block_private_targets_when_remote=bool(self.block_private_remote.isChecked()),
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
            self.engine.apply_settings(settings)
            host, port = self.engine.start()
            self.bind_port.setValue(port)
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.bind_host.setEnabled(False)
            self.bind_port.setEnabled(False)
            self.tls_intercept.setEnabled(False)
            self.allow_remote.setEnabled(False)
            self.verify_upstream_tls.setEnabled(False)
            self.network_guard_enabled.setEnabled(False)
            self.block_cloud_metadata.setEnabled(False)
            self.block_private_remote.setEnabled(False)
            self.max_upstreams.setEnabled(False)
            self.max_global_connects.setEnabled(False)
            self.max_target_connects.setEnabled(False)
            self.max_distinct_targets.setEnabled(False)
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
            self.network_guard_enabled.setEnabled(True)
            self.block_cloud_metadata.setEnabled(True)
            self.block_private_remote.setEnabled(True)
            self.max_upstreams.setEnabled(True)
            self.max_global_connects.setEnabled(True)
            self.max_target_connects.setEnabled(True)
            self.max_distinct_targets.setEnabled(True)
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
        guard = self.engine.network_guard.snapshot()
        if hasattr(self, "governance_status"):
            self.governance_status.setText(
                f"Governance {'ON' if guard['enabled'] else 'OFF'} · {guard['active_connections']}/{guard['max_concurrent_connections']} active · "
                f"{guard['global_connects_current_window']}/{guard['max_global_connects_per_minute']} connects/min · "
                f"{guard['distinct_targets_current_window']}/{guard['max_distinct_targets_per_minute']} targets/min"
            )
        history = self.engine.history()
        if len(history) != self._last_history_count:
            self._last_history_count = len(history)
            self.refresh_history()
            self.refresh_session_summary()
            self.refresh_professional_panels()
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

    def refresh_profiler(self) -> None:
        if not hasattr(self, "profiler_view"):
            return
        try:
            payload = ProxyProfiler().analyze(self.engine.history(), limit=5000).snapshot()
            self.profiler_view.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        except Exception as exc:
            self.profiler_view.setPlainText(f"Profiler unavailable: {type(exc).__name__}: {exc}")

    def refresh_session_summary(self) -> None:
        if not hasattr(self, "session_summary_view"):
            return
        try:
            payload = self.engine.session_summary(limit=5000)
            self.session_summary_view.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self.session_summary_view.setPlainText(f"Session summary unavailable: {exc}")

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
        if hasattr(self, "deep_left_id"):
            self.deep_left_id.setText(str(flow.id))
        self.request_view.setPlainText(flow.request_raw.decode("latin-1", "replace"))
        self.response_view.setPlainText(flow.response_raw.decode("latin-1", "replace"))
        try:
            inspection = self.engine.inspect_flow(flow.id)
            self.inspector_view.setPlainText(json.dumps(inspection, ensure_ascii=False, indent=2))
        except (KeyError, ValueError) as exc:
            self.inspector_view.setPlainText(f"Inspector unavailable: {exc}")

    def export_har(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Proxy History", "arenyxa-proxy-history.har", "HTTP Archive (*.har);;All Files (*)")
        if not path:
            return
        try:
            exported = self.engine.export_har(Path(path), redact_sensitive=True)
            QMessageBox.information(self, "Proxy HAR", f"Redacted HAR exported to:\n{exported}")
            self.statusMessage.emit("Proxy history exported as redacted HAR")
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Proxy HAR", str(exc))

    def export_ca(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Arenyxa Proxy CA", "arenyxa-proxy-ca.pem", "PEM Certificate (*.pem *.crt);;All Files (*)")
        if not path:
            return
        try:
            self.engine.export_ca_certificate(Path(path))
            QMessageBox.information(self, "Proxy CA", f"Certificate exported to:\n{path}")
        except Exception as exc:
            QMessageBox.warning(self, "Proxy CA", str(exc))
