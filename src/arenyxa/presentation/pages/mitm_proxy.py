from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from arenyxa.qt_compat.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from arenyxa.qt_compat.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
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

from arenyxa.infrastructure.capture.mitm_engine import MitmEvent, MitmEngine, MitmSettings
from arenyxa.application.mitm_analytics import MitmFlowAnalyzer
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, connect_current_row_changed, set_table_header_stretch_last


class MitmEventModel(QAbstractTableModel):
    columns = ["#", "Protocol", "Phase", "Method", "Host / URL", "Status", "Direction", "Size", "Replay"]

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[MitmEvent] = []

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
        row = self.rows[index.row()]
        values = [
            row.sequence,
            row.protocol,
            row.phase,
            row.method,
            row.url or row.host,
            row.status if row.status is not None else "",
            row.direction,
            row.size,
            row.replay,
        ]
        return values[index.column()]

    def replace(self, rows: list[MitmEvent]) -> None:
        self.beginResetModel()
        self.rows = list(rows)
        self.endResetModel()


class MitmInterceptionPage(WorkspacePage):
    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        self.engine = context.mitm_engine or MitmEngine(Path(context.paths.captures) / "mitm")
        context.mitm_engine = self.engine
        self._pending_tokens: list[str] = []
        self._last_event_count = -1
        root = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(PageHeader("MITM Proxy", "interception, replay, rules and advanced capture modes"), 1)
        self.start_button = QPushButton("Start MITM")
        self.start_button.setProperty("primary", True)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        header.addWidget(self.start_button)
        header.addWidget(self.stop_button)
        root.addLayout(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_flows_tab(), "Flows")
        self.tabs.addTab(self._build_analytics_tab(), "Analytics")
        self.tabs.addTab(self._build_intercept_tab(), "Intercept")
        self.tabs.addTab(self._build_messages_tab(), "Messages")
        self.tabs.addTab(self._build_replay_tab(), "Replay")
        self.tabs.addTab(self._build_rules_tab(), "Rules")
        self.tabs.addTab(self._build_modes_tab(), "Modes & TLS")
        self.tabs.addTab(self._build_addons_tab(), "Add-ons")
        root.addWidget(self.tabs, 1)

        self.status_label = QLabel("STOPPED · mitmdump not probed")
        self.status_label.setProperty("muted", True)
        root.addWidget(self.status_label)

        self.start_button.clicked.connect(self.start_runtime)
        self.stop_button.clicked.connect(self.stop_runtime)
        self.flow_filter.textChanged.connect(self.refresh_flows)
        self.protocol_filter.currentTextChanged.connect(self.refresh_flows)
        connect_current_row_changed(self.flow_table, self.inspect_flow)
        self.pending_list.currentRowChanged.connect(self.load_pending)
        self.forward_button.clicked.connect(self.forward_pending)
        self.drop_button.clicked.connect(self.drop_pending)
        self.client_replay_button.clicked.connect(lambda: self.run_replay("client"))
        self.server_replay_button.clicked.connect(lambda: self.run_replay("server"))
        self.pick_replay_button.clicked.connect(self.pick_replay_file)
        self.pick_executable_button.clicked.connect(self.pick_executable)
        self.pick_addon_button.clicked.connect(self.pick_addon)
        self.pick_proto_button.clicked.connect(self.pick_proto)
        self.export_flows_button.clicked.connect(self.export_flows)
        self.export_events_button.clicked.connect(self.export_events)
        self.analytics_refresh.clicked.connect(self.refresh_analytics)
        self.timeline_button.clicked.connect(self.show_flow_timeline)
        self.preview_button.clicked.connect(self.preview_command)
        self.timer = QTimer(self)
        self.timer.setInterval(200)
        self.timer.timeout.connect(self.refresh_runtime)

    def _build_flows_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        self.flow_filter = QLineEdit()
        self.flow_filter.setPlaceholderText("Search URL, host, flow ID, method or event")
        self.protocol_filter = QComboBox()
        for value in ("All", "HTTP", "WebSocket", "TCP", "UDP", "DNS"):
            self.protocol_filter.addItem(value)
        self.export_flows_button = QPushButton("Export .mitm")
        self.export_events_button = QPushButton("Export Events JSONL")
        bar.addWidget(self.flow_filter, 1)
        bar.addWidget(self.protocol_filter)
        bar.addWidget(self.export_events_button)
        bar.addWidget(self.export_flows_button)
        layout.addLayout(bar)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.flow_model = MitmEventModel()
        self.flow_table = QTableView()
        self.flow_table.setModel(self.flow_model)
        self.flow_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.flow_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.flow_table.setAlternatingRowColors(True)
        set_table_header_stretch_last(self.flow_table, True)
        splitter.addWidget(self.flow_table)
        self.flow_details = QPlainTextEdit()
        self.flow_details.setReadOnly(True)
        self.flow_details.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        splitter.addWidget(self.flow_details)
        splitter.setSizes([540, 310])
        layout.addWidget(splitter, 1)
        return holder

    def _build_analytics_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        intro = QLabel("Arenyxa flow analytics across HTTP, WebSocket, TCP, UDP and DNS events")
        intro.setProperty("muted", True)
        self.analytics_refresh = QPushButton("Refresh Analytics")
        self.analytics_refresh.setProperty("primary", True)
        self.timeline_button = QPushButton("Selected Flow Timeline")
        bar.addWidget(intro, 1)
        bar.addWidget(self.timeline_button)
        bar.addWidget(self.analytics_refresh)
        layout.addLayout(bar)
        self.analytics_view = QPlainTextEdit()
        self.analytics_view.setReadOnly(True)
        self.analytics_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(self.analytics_view, 1)
        return holder

    def refresh_analytics(self) -> None:
        rows = self.engine.events(query=self.flow_filter.text().strip(), protocol=self.protocol_filter.currentText())
        payload = MitmFlowAnalyzer().analyze(rows[-50000:], limit=50000).snapshot()
        self.analytics_view.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))

    def show_flow_timeline(self) -> None:
        row = self.flow_table.currentIndex().row()
        if row < 0 or row >= len(self.flow_model.rows):
            QMessageBox.information(self, "Flow Timeline", "Select a captured flow event first.")
            return
        flow_id = self.flow_model.rows[row].flow_id
        timeline = MitmFlowAnalyzer().flow_timeline(self.engine.poll_events(), flow_id)
        self.analytics_view.setPlainText(json.dumps({"flow_id": flow_id, "timeline": timeline}, ensure_ascii=False, indent=2, default=str))
        self.tabs.setCurrentWidget(self.analytics_view.parentWidget())

    def _build_intercept_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        filter_row = QHBoxLayout()
        self.intercept_filter = QLineEdit()
        self.intercept_filter.setPlaceholderText("MITM flow filter, e.g. ~q & ~u example\\.com")
        filter_row.addWidget(QLabel("Intercept filter"))
        filter_row.addWidget(self.intercept_filter, 1)
        layout.addLayout(filter_row)
        splitter = QSplitter()
        self.pending_list = QListWidget()
        self.pending_list.setMinimumWidth(280)
        splitter.addWidget(self.pending_list)
        editor_holder = QWidget()
        editor_layout = QVBoxLayout(editor_holder)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        self.pending_label = QLabel("No intercepted flow")
        self.pending_editor = QPlainTextEdit()
        self.pending_editor.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        actions = QHBoxLayout()
        self.forward_button = QPushButton("Forward")
        self.forward_button.setProperty("primary", True)
        self.drop_button = QPushButton("Drop")
        self.forward_button.setEnabled(False)
        self.drop_button.setEnabled(False)
        actions.addWidget(self.forward_button)
        actions.addWidget(self.drop_button)
        actions.addStretch()
        editor_layout.addWidget(self.pending_label)
        editor_layout.addWidget(self.pending_editor, 1)
        editor_layout.addLayout(actions)
        splitter.addWidget(editor_holder)
        splitter.setSizes([300, 900])
        layout.addWidget(splitter, 1)
        return holder

    def _build_messages_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        self.message_view = QPlainTextEdit()
        self.message_view.setReadOnly(True)
        self.message_view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(QLabel("WebSocket, raw TCP, UDP and DNS messages are recorded here as unified flow events."))
        layout.addWidget(self.message_view, 1)
        return holder

    def _build_replay_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        row = QHBoxLayout()
        self.replay_file = QLineEdit()
        self.replay_file.setPlaceholderText("MITM flow archive (.mitm)")
        self.pick_replay_button = QPushButton("Choose")
        row.addWidget(self.replay_file, 1)
        row.addWidget(self.pick_replay_button)
        layout.addLayout(row)
        buttons = QHBoxLayout()
        self.client_replay_button = QPushButton("Client Replay")
        self.client_replay_button.setProperty("primary", True)
        self.server_replay_button = QPushButton("Server Replay")
        buttons.addWidget(self.client_replay_button)
        buttons.addWidget(self.server_replay_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.replay_output = QPlainTextEdit()
        self.replay_output.setReadOnly(True)
        layout.addWidget(self.replay_output, 1)
        return holder

    def _build_rules_tab(self) -> QWidget:
        holder = QWidget()
        layout = QFormLayout(holder)
        self.block_list = QPlainTextEdit()
        self.map_local = QPlainTextEdit()
        self.map_remote = QPlainTextEdit()
        self.modify_headers = QPlainTextEdit()
        self.modify_body = QPlainTextEdit()
        self.ignore_hosts = QPlainTextEdit()
        self.allow_hosts = QPlainTextEdit()
        for widget in (self.block_list, self.map_local, self.map_remote, self.modify_headers, self.modify_body, self.ignore_hosts, self.allow_hosts):
            widget.setMaximumHeight(90)
        layout.addRow("Block list", self.block_list)
        layout.addRow("Map Local", self.map_local)
        layout.addRow("Map Remote", self.map_remote)
        layout.addRow("Modify Headers", self.modify_headers)
        layout.addRow("Modify Body", self.modify_body)
        layout.addRow("Ignore Hosts", self.ignore_hosts)
        layout.addRow("Allow Hosts", self.allow_hosts)
        return holder

    def _build_modes_tab(self) -> QWidget:
        holder = QWidget()
        layout = QFormLayout(holder)
        self.mode = QComboBox()
        for value in ("regular", "local", "wireguard", "reverse", "upstream", "transparent", "tun", "socks5", "dns"):
            self.mode.addItem(value)
        self.mode_spec = QLineEdit()
        self.mode_spec.setPlaceholderText("Target, process selector, WireGuard key path or TUN name")
        self.bind_host = QLineEdit("127.0.0.1")
        self.bind_port = QSpinBox()
        self.bind_port.setRange(0, 65535)
        self.bind_port.setValue(8081)
        self.allow_remote = QCheckBox("Allow LAN / remote clients")
        self.verify_tls = QCheckBox("Verify upstream TLS certificates")
        self.verify_tls.setChecked(True)
        self.http2 = QCheckBox("HTTP/2")
        self.http2.setChecked(True)
        self.http3 = QCheckBox("HTTP/3 / QUIC")
        self.http3.setChecked(True)
        self.websocket = QCheckBox("WebSocket")
        self.websocket.setChecked(True)
        self.rawtcp = QCheckBox("Raw TCP / TLS")
        self.rawtcp.setChecked(True)
        self.anticache = QCheckBox("Remove cache validators for replay/debugging")
        self.anticomp = QCheckBox("Ask upstream for uncompressed responses")
        self.connection_strategy = QComboBox()
        self.connection_strategy.addItem("eager")
        self.connection_strategy.addItem("lazy")
        layout.addRow("Mode", self.mode)
        layout.addRow("Mode specification", self.mode_spec)
        layout.addRow("Listen host", self.bind_host)
        layout.addRow("Listen port", self.bind_port)
        layout.addRow("Exposure", self.allow_remote)
        layout.addRow("TLS", self.verify_tls)
        layout.addRow("Protocols", self.http2)
        layout.addRow("", self.http3)
        layout.addRow("", self.websocket)
        layout.addRow("", self.rawtcp)
        layout.addRow("Replay", self.anticache)
        layout.addRow("Content", self.anticomp)
        layout.addRow("Connection strategy", self.connection_strategy)
        return holder

    def _build_addons_tab(self) -> QWidget:
        holder = QWidget()
        layout = QFormLayout(holder)
        executable_row = QWidget()
        executable_layout = QHBoxLayout(executable_row)
        executable_layout.setContentsMargins(0, 0, 0, 0)
        self.executable = QLineEdit()
        self.executable.setPlaceholderText("Auto-detect mitmdump from PATH")
        self.pick_executable_button = QPushButton("Choose")
        executable_layout.addWidget(self.executable, 1)
        executable_layout.addWidget(self.pick_executable_button)
        self.addon_scripts = QPlainTextEdit()
        self.addon_scripts.setMaximumHeight(120)
        self.addon_scripts.setPlaceholderText("One addon .py path per line")
        self.pick_addon_button = QPushButton("Add Script")
        proto_row = QWidget()
        proto_layout = QHBoxLayout(proto_row)
        proto_layout.setContentsMargins(0, 0, 0, 0)
        self.protobuf = QLineEdit()
        self.pick_proto_button = QPushButton("Choose .proto")
        proto_layout.addWidget(self.protobuf, 1)
        proto_layout.addWidget(self.pick_proto_button)
        self.save_filter = QLineEdit()
        self.save_filter.setPlaceholderText("Optional flow filter for .mitm archive")
        self.stream_large_bodies = QLineEdit()
        self.stream_large_bodies.setPlaceholderText("Optional threshold, e.g. 10m")
        self.preview_button = QPushButton("Preview Engine Command")
        self.command_preview = QPlainTextEdit()
        self.command_preview.setReadOnly(True)
        self.command_preview.setMaximumHeight(190)
        layout.addRow("mitmdump", executable_row)
        layout.addRow("Addon scripts", self.addon_scripts)
        layout.addRow("", self.pick_addon_button)
        layout.addRow("Protobuf definitions", proto_row)
        layout.addRow("Archive filter", self.save_filter)
        layout.addRow("Stream large bodies", self.stream_large_bodies)
        layout.addRow("", self.preview_button)
        layout.addRow("Command", self.command_preview)
        return holder

    def activated(self) -> None:
        self.timer.start()
        self.refresh_runtime()

    def deactivated(self) -> None:
        if not self.engine.running:
            self.timer.stop()

    def _lines(self, widget: QPlainTextEdit) -> list[str]:
        return [line.strip() for line in widget.toPlainText().splitlines() if line.strip()]

    def collect_settings(self) -> MitmSettings:
        return MitmSettings(
            executable=self.executable.text().strip(),
            bind_host=self.bind_host.text().strip() or "127.0.0.1",
            bind_port=int(self.bind_port.value()),
            mode=self.mode.currentText(),
            mode_spec=self.mode_spec.text().strip(),
            allow_remote_clients=bool(self.allow_remote.isChecked()),
            intercept_filter=self.intercept_filter.text().strip(),
            view_filter=self.flow_filter.text().strip() if self.flow_filter.text().strip().startswith("~") else "",
            ignore_hosts=self._lines(self.ignore_hosts),
            allow_hosts=self._lines(self.allow_hosts),
            map_local=self._lines(self.map_local),
            map_remote=self._lines(self.map_remote),
            modify_headers=self._lines(self.modify_headers),
            modify_body=self._lines(self.modify_body),
            block_list=self._lines(self.block_list),
            addon_scripts=self._lines(self.addon_scripts),
            protobuf_definitions=self.protobuf.text().strip(),
            upstream_cert=bool(self.verify_tls.isChecked()),
            http2=bool(self.http2.isChecked()),
            http3=bool(self.http3.isChecked()),
            rawtcp=bool(self.rawtcp.isChecked()),
            websocket=bool(self.websocket.isChecked()),
            anticache=bool(self.anticache.isChecked()),
            anticomp=bool(self.anticomp.isChecked()),
            stream_large_bodies=self.stream_large_bodies.text().strip(),
            connection_strategy=self.connection_strategy.currentText(),
            save_filter=self.save_filter.text().strip(),
        )

    def start_runtime(self) -> None:
        try:
            settings = self.collect_settings()
            settings.validate()
            if settings.allow_remote_clients:
                answer = QMessageBox.question(self, "Remote MITM Listener", "This exposes the MITM listener to other devices. Continue only on a trusted network you control.")
                if answer != QMessageBox.StandardButton.Yes:
                    return
            self.engine.settings = settings
            self.engine.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.timer.start()
            self.statusMessage.emit("MITM Proxy started")
        except Exception as exc:
            QMessageBox.critical(self, "Unable to start MITM Proxy", str(exc))
        self.refresh_runtime()

    def stop_runtime(self) -> None:
        self.engine.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.refresh_runtime()
        self.statusMessage.emit("MITM Proxy stopped")

    def refresh_runtime(self) -> None:
        status = self.engine.status()
        executable = status.executable or "mitmdump not found"
        state = "RUNNING" if status.running else "STOPPED"
        self.status_label.setText(f"{state} · {status.mode} · {status.bind_host}:{status.bind_port} · {status.events:,} events · {status.pending:,} pending · {executable}")
        if status.last_error:
            self.status_label.setToolTip(status.last_error)
        events = self.engine.poll_events()
        if len(events) != self._last_event_count:
            self._last_event_count = len(events)
            self.refresh_flows()
            self.refresh_messages()
        pending = self.engine.pending()
        tokens = [str(item.get("token") or "") for item in pending]
        if tokens != self._pending_tokens:
            self._pending_tokens = tokens
            selected = self.pending_list.currentRow()
            self.pending_list.clear()
            for item in pending:
                payload = item.get("payload") or {}
                label = f"{str(item.get('phase') or '').upper()} · {payload.get('method', '')} · {payload.get('host', '') or payload.get('path', '')}"
                self.pending_list.addItem(label)
            if tokens:
                self.pending_list.setCurrentRow(min(max(selected, 0), len(tokens) - 1))
            else:
                self.pending_editor.clear()
                self.pending_label.setText("No intercepted flow")
                self.forward_button.setEnabled(False)
                self.drop_button.setEnabled(False)

    def refresh_flows(self) -> None:
        protocol = self.protocol_filter.currentText()
        query = self.flow_filter.text().strip()
        rows = self.engine.events(query=query if not query.startswith("~") else "", protocol=protocol)
        self.flow_model.replace(rows[-10000:])

    def inspect_flow(self, row: int) -> None:
        if row < 0 or row >= len(self.flow_model.rows):
            self.flow_details.clear()
            return
        event = self.flow_model.rows[row]
        self.flow_details.setPlainText(json.dumps({
            "sequence": event.sequence,
            "timestamp": event.timestamp,
            "event": event.event,
            "flow_id": event.flow_id,
            "protocol": event.protocol,
            "phase": event.phase,
            "method": event.method,
            "url": event.url,
            "host": event.host,
            "status": event.status,
            "direction": event.direction,
            "size": event.size,
            "replay": event.replay,
            "intercepted": event.intercepted,
            "payload": event.payload,
        }, ensure_ascii=False, indent=2))

    def refresh_messages(self) -> None:
        rows = [row for row in self.engine.poll_events() if row.protocol in {"websocket", "tcp", "udp", "dns"}]
        payload = []
        for row in rows[-500:]:
            payload.append({"#": row.sequence, "protocol": row.protocol, "event": row.event, "direction": row.direction, "size": row.size, "payload": row.payload})
        self.message_view.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2))

    def load_pending(self, row: int) -> None:
        pending = self.engine.pending()
        if row < 0 or row >= len(pending):
            self.pending_editor.clear()
            self.forward_button.setEnabled(False)
            self.drop_button.setEnabled(False)
            return
        item = pending[row]
        self.pending_label.setText(f"{str(item.get('phase') or '').upper()} · {item.get('flow_id', '')}")
        self.pending_editor.setPlainText(json.dumps(item.get("payload") or {}, ensure_ascii=False, indent=2))
        self.forward_button.setEnabled(True)
        self.drop_button.setEnabled(True)

    def _resolve_pending(self, action: str) -> None:
        row = self.pending_list.currentRow()
        if row < 0 or row >= len(self._pending_tokens):
            return
        edited = None
        if action == "forward":
            try:
                edited = json.loads(self.pending_editor.toPlainText() or "{}")
            except json.JSONDecodeError as exc:
                QMessageBox.warning(self, "Invalid edited flow", str(exc))
                return
        try:
            self.engine.resolve(self._pending_tokens[row], action, edited)
        except Exception as exc:
            QMessageBox.critical(self, "Unable to resolve flow", str(exc))
        self.refresh_runtime()

    def forward_pending(self) -> None:
        self._resolve_pending("forward")

    def drop_pending(self) -> None:
        self._resolve_pending("drop")

    def pick_replay_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select MITM flow archive", "", "MITM flow archives (*.mitm *.flow);;All files (*)")
        if path:
            self.replay_file.setText(path)

    def run_replay(self, direction: str) -> None:
        path = Path(self.replay_file.text().strip())
        try:
            self.engine.settings = self.collect_settings()
            result = self.engine.run_replay(path, direction)
            output = (result.stdout or "") + (result.stderr or "")
            self.replay_output.setPlainText(f"exit={result.returncode}\n{output}".strip())
        except Exception as exc:
            self.replay_output.setPlainText(str(exc))

    def pick_executable(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select mitmdump executable")
        if path:
            self.executable.setText(path)

    def pick_addon(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select MITM addon", "", "Python (*.py)")
        if path:
            current = self.addon_scripts.toPlainText().strip()
            self.addon_scripts.setPlainText((current + "\n" + path).strip())

    def pick_proto(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select protobuf definitions", "", "Protocol Buffer (*.proto)")
        if path:
            self.protobuf.setText(path)

    def export_events(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export normalized MITM events", "arenyxa-mitm-events.jsonl", "JSON Lines (*.jsonl);;All files (*)")
        if not path:
            return
        try:
            query = self.flow_filter.text().strip()
            protocol = self.protocol_filter.currentText()
            self.engine.export_events(Path(path), query=query if not query.startswith("~") else "", protocol=protocol)
            self.statusMessage.emit(f"Normalized events exported to {path}")
        except Exception as exc:
            QMessageBox.warning(self, "Unable to export normalized events", str(exc))

    def export_flows(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export MITM flows", "arenyxa-flows.mitm", "MITM flow archives (*.mitm)")
        if not path:
            return
        try:
            self.engine.export_flows(Path(path))
            self.statusMessage.emit(f"Flows exported to {path}")
        except Exception as exc:
            QMessageBox.warning(self, "Unable to export flows", str(exc))

    def preview_command(self) -> None:
        try:
            settings = self.collect_settings()
            self.engine.settings = settings
            executable = self.engine.discover(settings.executable) or settings.executable or "mitmdump"
            command = self.engine.build_command(executable)
            self.command_preview.setPlainText("\n".join(command))
        except Exception as exc:
            self.command_preview.setPlainText(str(exc))
