from __future__ import annotations
from arenyxa.presentation.pages.network_capture_actions import NetworkCaptureActionsMixin
from arenyxa.presentation.pages.network_analysis_actions import NetworkAnalysisActionsMixin

import json
import shutil
from dataclasses import asdict
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlparse

from arenyxa.qt_compat.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, Signal
from arenyxa.qt_compat.QtGui import QColor, QPainter
from arenyxa.qt_compat.QtWidgets import (
    QApplication,
    QAbstractItemView,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from arenyxa.compat import strict_zip
from arenyxa.application.general_user import is_general_user, summarize_network_events
from arenyxa.domain.enums import CaptureSource, CaptureState
from arenyxa.domain.models import CaptureSession, NetworkEvent, RequestSpec, utc_now
from arenyxa.infrastructure.capture.adapters import (
    BrowserCaptureAdapter,
    ProcessNetworkMonitor,
    TsharkPacketAdapter,
)
from arenyxa.infrastructure.capture.har import HarAnalyzer
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.infrastructure.capture.inspectors import DnsAnalyzer, TlsInspector
from arenyxa.infrastructure.capture.replay import CapturedBodyResolver, RequestReplayService
from arenyxa.infrastructure.capture.professional import ProfessionalAnalysisSuite
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine
from arenyxa.presentation.background import run_background
from arenyxa.presentation.packet_intelligence_workbench import PacketIntelligenceWorkbenchDialog
from arenyxa.presentation.language import literal_for_locale
from arenyxa.presentation.pages.base import WorkspacePage, page_layout
from arenyxa.presentation.widgets import PageHeader, connect_current_row_changed, set_table_header_stretch_last

class NetworkEventModel(QAbstractTableModel):
    columns: ClassVar[list[str]] = [
        "Time",
        "Method",
        "Status",
        "Protocol",
        "Host",
        "Path",
        "Size",
        "Duration",
    ]

    def __init__(self, max_rows: int = 20_000) -> None:
        super().__init__()
        self.events: list[dict] = []
        self.max_rows = max(500, int(max_rows))

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.events)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section: int, orientation: Any, role: Any = Qt.ItemDataRole.DisplayRole) -> Any:
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.columns[section]
        return super().headerData(section, orientation, role)

    def data(self, index: QModelIndex, role: Any = Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        event = self.events[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            parsed = urlparse(event.get("url") or "")
            values = [
                str(event.get("timestamp", ""))[11:23],
                event.get("method") or "",
                event.get("status") or "",
                event.get("protocol") or "",
                event.get("host") or "",
                parsed.path or "",
                event.get("size") or 0,
                f"{event.get('timing', {}).get('total_ms', event.get('metadata', {}).get('har_total_ms', 0)):.0f} ms",
            ]
            return values[index.column()]
        if role == Qt.ItemDataRole.ForegroundRole:
            status = event.get("status") or 0
            if status >= 400:
                return QColor("#ff6570")
            if 300 <= status < 400:
                return QColor("#ffd35c")
        return None

    def replace(self, events: list[dict]) -> None:
        self.beginResetModel()
        self.events = events
        self.endResetModel()

    def append(self, events: list[NetworkEvent]) -> None:
        if not events:
            return
        start = len(self.events)
        materialized = [self._as_row(event) for event in events]
        self.beginInsertRows(QModelIndex(), start, start + len(materialized) - 1)
        self.events.extend(materialized)
        self.endInsertRows()
        if len(self.events) > self.max_rows:
            remove = len(self.events) - self.max_rows
            self.beginRemoveRows(QModelIndex(), 0, remove - 1)
            del self.events[:remove]
            self.endRemoveRows()

    @staticmethod
    def _as_row(event: NetworkEvent) -> dict:
        row = asdict(event)
        row["source_type"] = event.source_type.value
        return row

class WaterfallWidget(QWidget):
    def __init__(self, model: NetworkEventModel, theme: Any, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.model = model
        self.theme = theme
        self.setMinimumHeight(150)
        self.model.rowsInserted.connect(lambda *_: self.update())
        self.model.modelReset.connect(self.update)
        self.theme.changed.connect(lambda _theme: self.update())

    def paintEvent(self, event: Any) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        tokens = self.theme.current
        app = QApplication.instance()
        quality = str(app.property("arenyxa_motion_quality") or "balanced") if app is not None else "balanced"
        visible_count = 15 if quality == "efficiency" else 24 if quality == "balanced" else 30
        visible = self.model.events[-visible_count:]
        if not visible:
            painter.setPen(QColor(tokens.text_muted))
            app = QApplication.instance()
            locale = str(app.property("arenyxa_locale") or "zh_CN") if app is not None else "zh_CN"
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, literal_for_locale("等待网络事件", locale))
            return
        durations = [
            max(
                1.0,
                float(
                    item.get("timing", {}).get("total_ms", item.get("metadata", {}).get("har_total_ms", 1))
                ),
            )
            for item in visible
        ]
        maximum = max(durations)
        row_height = max(4, self.height() / len(visible))
        accent = QColor(tokens.accent)
        warning = QColor(tokens.warning)
        for index, (item, duration) in enumerate(strict_zip(visible, durations, strict=True)):
            y = index * row_height + 1
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(warning if (item.get("status") or 0) >= 400 else accent)
            width = max(3, (self.width() - 20) * duration / maximum)
            painter.drawRoundedRect(10, round(y), round(width), max(2, round(row_height - 2)), 2, 2)

class NetworkPage(NetworkCaptureActionsMixin, NetworkAnalysisActionsMixin, WorkspacePage):
    liveEvents = Signal(object)

    def __init__(self, context: Any, theme: Any, motion: Any, parent: QWidget | None = None) -> None:
        super().__init__(context, theme, motion, parent)
        layout = page_layout(self)
        header = QHBoxLayout()
        header.addWidget(
            PageHeader("Network Analysis", "Browser Capture / Packet Capture / HAR / Replay / TLS / DNS"), 1
        )
        self.simple_mode = is_general_user(context.settings)
        self.source = QComboBox()
        self.source.addItem("Browser Capture", CaptureSource.BROWSER)
        self.source.addItem("System Capture" if self.simple_mode else "System Packet (tshark)", CaptureSource.SYSTEM)
        self.source.addItem("Import HAR", CaptureSource.HAR_IMPORT)
        self.source.addItem("Analyze PCAP / PCAPNG" if self.simple_mode else "Import PCAP / PCAPNG", CaptureSource.PCAP_IMPORT)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText('http.host endsWith ".example.com" && http.status >= 400')
        self.filter.setMinimumWidth(250)
        self.capture_filter = QLineEdit()
        self.capture_filter.setPlaceholderText("Capture filter (BPF): tcp port 443")
        self.capture_filter.setMinimumWidth(210)
        self.start_button = QPushButton("开始捕获")
        self.start_button.setProperty("primary", True)
        self.pause_button = QPushButton("暂停")
        self.pause_button.setEnabled(False)
        self.stop_button = QPushButton("停止")
        self.stop_button.setEnabled(False)
        self.simple_advanced_button = QPushButton("高级选项")
        self.simple_advanced_button.setCheckable(True)
        self.simple_advanced_button.setVisible(self.simple_mode)
        header.addWidget(self.source)
        header.addWidget(self.filter)
        header.addWidget(self.capture_filter)
        header.addWidget(self.simple_advanced_button)
        header.addWidget(self.start_button)
        header.addWidget(self.pause_button)
        header.addWidget(self.stop_button)
        layout.addLayout(header)

        splitter = QSplitter()
        self.sessions = QListWidget()
        self.sessions.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.sessions.setMinimumWidth(190)
        self.sessions.setMaximumWidth(300)
        splitter.addWidget(self.sessions)
        center = QWidget()
        center_layout = QVBoxLayout(center)
        center_layout.setContentsMargins(0, 0, 0, 0)
        self.model = NetworkEventModel(context.performance.network_event_limit)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        set_table_header_stretch_last(self.table, True)
        center_layout.addWidget(self.table, 4)
        self.waterfall = WaterfallWidget(self.model, theme)
        center_layout.addWidget(self.waterfall, 1)
        splitter.addWidget(center)

        inspector = QTabWidget()
        inspector.setMinimumWidth(300)
        self.overview = QPlainTextEdit()
        self.overview.setReadOnly(True)
        self.headers_view = QPlainTextEdit()
        self.headers_view.setReadOnly(True)
        self.timing_view = QPlainTextEdit()
        self.timing_view.setReadOnly(True)
        self.protocol_view = QPlainTextEdit()
        self.protocol_view.setReadOnly(True)
        self.professional_view = QPlainTextEdit()
        self.professional_view.setReadOnly(True)
        self.intelligence_view = QPlainTextEdit()
        self.intelligence_view.setReadOnly(True)
        inspector.addTab(self.overview, "Overview")
        inspector.addTab(self.headers_view, "Headers")
        inspector.addTab(self.timing_view, "Timing")
        inspector.addTab(self.protocol_view, "TLS / DNS")
        inspector.addTab(self.professional_view, "Professional")
        inspector.addTab(self.intelligence_view, "Live Intelligence")
        splitter.addWidget(inspector)
        splitter.setSizes([210, 760, 340])
        layout.addWidget(splitter, 1)

        actions = QHBoxLayout()
        self.replay = QPushButton("Request Replay")
        self.tls = QPushButton("TLS Inspector")
        self.dns = QPushButton("DNS Analyzer")
        self.processes = QPushButton("Process Monitor")
        self.professional = QPushButton("Professional Analysis")
        self.packet_analysis = QPushButton("Packet Intelligence")
        self.packet_analytics = QPushButton("Advanced Analytics")
        actions.addWidget(self.replay)
        actions.addWidget(self.tls)
        actions.addWidget(self.dns)
        actions.addWidget(self.processes)
        actions.addWidget(self.professional)
        actions.addWidget(self.packet_analysis)
        actions.addWidget(self.packet_analytics)
        actions.addStretch()
        self.capture_status = QLabel("IDLE · 0 events · 0 B · Dropped 0 · 权限未要求")
        self.capture_status.setProperty("muted", True)
        actions.addWidget(self.capture_status)
        layout.addLayout(actions)

        self.start_button.clicked.connect(self.start_capture)
        self.pause_button.clicked.connect(self.toggle_pause)
        self.stop_button.clicked.connect(self.stop_capture)
        self.sessions.currentRowChanged.connect(self.load_session)
        connect_current_row_changed(self.table, self.inspect_event)
        self.replay.clicked.connect(self.replay_selected)
        self.tls.clicked.connect(self.inspect_tls)
        self.dns.clicked.connect(self.inspect_dns)
        self.processes.clicked.connect(self.process_snapshot)
        self.professional.clicked.connect(self.run_professional_analysis)
        self.packet_analysis.clicked.connect(self.open_packet_analysis_workbench)
        self.packet_analytics.clicked.connect(self.run_packet_analytics)
        self.simple_advanced_button.toggled.connect(self._set_simple_advanced_visible)
        if self.simple_mode:
            self._set_simple_advanced_visible(False)
        self.context.capture.add_listener(self._events_from_writer)
        self.liveEvents.connect(self._queue_live_events)
        self._live_buffer: list[NetworkEvent] = []
        self._session_load_token = 0
        self._visible_session_id: str | None = None
        self._needs_resync = False
        self._last_capture_state: str | None = None
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.setInterval(self.context.performance.status_refresh_ms)
        self.live_flush_timer = QTimer(self)
        self.live_flush_timer.setInterval(self.context.performance.network_ui_refresh_ms)
        self.live_flush_timer.timeout.connect(self._flush_live_events)

    def _set_simple_advanced_visible(self, enabled: bool) -> None:
        if not self.simple_mode:
            return
        advanced_widgets = (
            self.filter, self.capture_filter, self.replay, self.tls, self.dns,
            self.processes, self.professional, self.packet_analysis, self.packet_analytics,
        )
        for widget in advanced_widgets:
            widget.setVisible(bool(enabled))
        self.simple_advanced_button.setText("收起高级选项" if enabled else "高级选项")

    def _simple_summary_payload(
        self, rows: list[dict[str, Any]], *, source: str, backend: str = "Arenyxa Native"
    ) -> dict[str, Any]:
        summary = summarize_network_events(rows)
        payload = summary.snapshot()
        payload.update({
            "source": source,
            "backend": backend,
            "message": "结果为自动风险摘要；需要逐包/高级协议细节时可展开高级选项。",
        })
        return payload

    def _show_simple_summary(
        self, rows: list[dict[str, Any]], *, source: str, backend: str = "Arenyxa Native"
    ) -> None:
        if not self.simple_mode:
            return
        payload = self._simple_summary_payload(rows, source=source, backend=backend)
        self.overview.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        self.statusMessage.emit(
            f"分析完成 · Risk {payload['risk']} · Score {payload['score']}/100 · "
            f"{payload['event_count']:,} events"
        )

    def activated(self) -> None:
        self.refresh_sessions()
        self.update_status()
        if not self.status_timer.isActive():
            self.status_timer.start()
        if not self.live_flush_timer.isActive():
            self.live_flush_timer.start()
        if self._needs_resync and self.sessions.currentRow() >= 0:
            self._needs_resync = False
            self.load_session(self.sessions.currentRow())

    def deactivated(self) -> None:
        self.status_timer.stop()
        self.live_flush_timer.stop()
        self._flush_live_events()
        self._needs_resync = True





















from arenyxa.application.packet_analytics import PacketAdvancedAnalyzer
