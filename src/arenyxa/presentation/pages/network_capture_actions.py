from __future__ import annotations

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


class NetworkCaptureActionsMixin:
    def refresh_sessions(self) -> None:
        current_id = self._visible_session_id or (
            self.sessions.currentItem().data(Qt.ItemDataRole.UserRole)
            if self.sessions.currentItem()
            else None
        )
        self.sessions.blockSignals(True)
        self.sessions.clear()
        captures = self.context.store.list_captures()
        for session in captures:
            self.sessions.addItem(
                f"{session['name']}\n{session['source_type']} · {session['state']} · {session['event_count']:,}"
            )
            item = self.sessions.item(self.sessions.count() - 1)
            item.setData(Qt.ItemDataRole.UserRole, session["id"])
            item.setToolTip(session["id"])
            if session["id"] == current_id:
                self.sessions.setCurrentItem(item)
        self.sessions.blockSignals(False)

    def start_capture(self) -> None:
        source = self.source.currentData()
        session = CaptureSession(
            name=f"Capture {utc_now()[0:19]}",
            source_type=source,
            filter_expression=self.filter.text().strip(),
        )
        try:
            if source is CaptureSource.PCAP_IMPORT:
                path, _ = QFileDialog.getOpenFileName(
                    self,
                    "导入 Packet Capture",
                    "",
                    "Packet Capture (*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz *.cap.gz);;All Files (*)",
                )
                if not path:
                    return
                self._import_pcap_session(session, Path(path))
                return
            if source is CaptureSource.HAR_IMPORT:
                path, _ = QFileDialog.getOpenFileName(self, "导入 HAR", "", "HTTP Archive (*.har *.json)")
                if not path:
                    return
                session.state = CaptureState.COMPLETED
                session.started_at = utc_now()
                body_store = NetworkBodyStore.for_capture(self.context.paths.captures, session.id)
                events, summary = HarAnalyzer.load(Path(path), session, body_store=body_store)
                session.finished_at = utc_now()
                session.event_count = len(events)
                session.bytes_captured = sum(event.size for event in events)
                self.context.store.append_capture_events(session, events)
                self._visible_session_id = session.id
                rows = [NetworkEventModel._as_row(event) for event in events]
                self.model.replace(rows)
                if self.simple_mode:
                    self._show_simple_summary(rows, source="HAR Import", backend="Arenyxa HAR Analyzer")
                else:
                    self.overview.setPlainText(json.dumps(asdict(summary), ensure_ascii=False, indent=2))
                    self.statusMessage.emit(f"已导入 HAR：{len(events):,} 个请求")
                self.context.nextgen.activity.publish("capture-import", "HAR imported", details={"session_id": session.id, "events": len(events)})
                self.refresh_sessions()
                return
            if source is CaptureSource.BROWSER:
                url, ok = QInputDialog.getText(
                    self, "Browser Capture", "受控浏览器入口 URL", text="https://example.com"
                )
                if not ok or not url:
                    return
                profile = self.context.paths.profiles / session.id
                profile.mkdir(parents=True, exist_ok=True)
                adapter = BrowserCaptureAdapter(
                    url,
                    profile,
                    body_store=NetworkBodyStore.for_capture(self.context.paths.captures, session.id),
                    browser_pool=self.context.browser_pool,
                )
            else:
                interface, ok = QInputDialog.getText(
                    self, "System Packet Capture", "tshark 接口编号或名称", text="1"
                )
                if not ok:
                    return
                adapter = TsharkPacketAdapter(
                    interface,
                    capture_filter=self.capture_filter.text().strip(),
                    raw_dir=self.context.paths.captures / session.id,
                )
                session.permission_state = "required_by_driver"
            self.context.capture.prepare(session, adapter)
            self.context.capture.start()
            self._last_capture_state = session.state.value
            self.operationProgress.emit("Capture", 0, 0, "indeterminate")
            self._visible_session_id = session.id
            self._session_load_token += 1
            self.model.replace([])
            self.start_button.setEnabled(False)
            self.pause_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.statusMessage.emit(f"捕获已启动：{session.source_type.value}")
            self.context.nextgen.activity.publish("capture-start", f"Capture started: {session.source_type.value}", details={"session_id": session.id, "source": session.source_type.value})
            self.refresh_sessions()
        except Exception as exc:
            QMessageBox.critical(self, "无法开始捕获", str(exc))

    def toggle_pause(self) -> None:
        session = self.context.capture.session
        if not session:
            return
        if session.state is CaptureState.CAPTURING:
            self.context.capture.pause()
            self.context.nextgen.activity.publish("capture-pause", "Capture paused", details={"session_id": session.id})
            self.pause_button.setText("恢复")
        elif session.state is CaptureState.PAUSED:
            self.context.capture.resume()
            self.context.nextgen.activity.publish("capture-resume", "Capture resumed", details={"session_id": session.id})
            self.pause_button.setText("暂停")

    def stop_capture(self) -> None:
        self.stop_button.setEnabled(False)
        self.pause_button.setEnabled(False)

        def completed(value: object) -> None:
            session = value
            self.statusMessage.emit(
                f"捕获完成：{session.event_count:,} events，Dropped {session.dropped_events:,}"
            )
            self.context.nextgen.activity.publish("capture-stop", "Capture completed", level="warning" if session.dropped_events else "info", details={"session_id": session.id, "events": session.event_count, "dropped": session.dropped_events})
            self.start_button.setEnabled(True)
            self.pause_button.setText("暂停")
            self.operationProgress.emit("Capture", 0, 0, "clear")
            self._last_capture_state = session.state.value
            if self.simple_mode:
                rows = list(self.context.store.iter_network_events(session.id, 50_000))
                self._show_simple_summary(rows, source=session.source_type.value, backend="Arenyxa Capture")
            self.refresh_sessions()

        def failed(message: str) -> None:
            self.start_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.pause_button.setText("暂停")
            self.operationProgress.emit("Capture", 0, 0, "clear")
            session = self.context.capture.session
            self._last_capture_state = session.state.value if session is not None else None
            QMessageBox.warning(self, "停止失败", message)

        run_background(self.context.capture.stop, completed, failed)

    def _events_from_writer(self, events: list[NetworkEvent]) -> None:
        self.liveEvents.emit(events)

    def _queue_live_events(self, events: list[NetworkEvent]) -> None:
        if not events or not self.isVisible():

            return

        self._live_buffer.extend(events)
        cap = max(self.context.performance.network_event_limit * 2, 2_000)
        if len(self._live_buffer) > cap:
            del self._live_buffer[: len(self._live_buffer) - cap]
        if self.isVisible() and not self.live_flush_timer.isActive():
            self.live_flush_timer.start()

    def _flush_live_events(self) -> None:
        if not self._live_buffer:
            return
        events = self._live_buffer
        self._live_buffer = []

        if self._visible_session_id:
            selected = [event for event in events if event.session_id == self._visible_session_id]
            if selected:
                self.model.append(selected)

    def update_status(self) -> None:
        session = self.context.capture.session
        if not session:
            if self._last_capture_state is not None:
                self._last_capture_state = None
                self.operationProgress.emit("Capture", 0, 0, "clear")
            return
        state = session.state.value
        intelligence = getattr(self.context, "network_intelligence", None)
        live = intelligence.live_snapshot(session.id) if intelligence is not None else {}
        alert_count = int(live.get("alerts", 0) or 0)
        self.capture_status.setText(
            f"{state.upper()} · {session.event_count:,} events · {session.bytes_captured:,} B · "
            f"Alerts {alert_count:,} · Dropped {session.dropped_events:,} · {session.permission_state}"
        )
        if intelligence is not None:
            live_payload = dict(live)
            live_payload["recent_alerts"] = intelligence.alerts(session.id, limit=20)
            self.intelligence_view.setPlainText(json.dumps(live_payload, ensure_ascii=False, indent=2, default=str))
        terminal = state in {"completed", "failed", "cancelled", "idle"}
        if terminal and state != self._last_capture_state:

            self.start_button.setEnabled(True)
            self.pause_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.pause_button.setText("暂停")
            self.operationProgress.emit("Capture", 0, 0, "clear")
            self._flush_live_events()
            self.refresh_sessions()
        self._last_capture_state = state

    def load_session(self, row: int) -> None:
        item = self.sessions.item(row)
        if not item:
            return
        session_id = str(item.data(Qt.ItemDataRole.UserRole))
        self._visible_session_id = session_id
        self._session_load_token += 1
        token = self._session_load_token
        self.statusMessage.emit("正在后台加载捕获会话…")

        def load_payload() -> dict[str, Any]:
            events = list(
                self.context.store.iter_network_events(
                    session_id, limit=self.context.performance.network_history_limit
                )
            )
            intelligence = getattr(self.context, "network_intelligence", None)
            analysis = (
                intelligence.analyze_events(session_id, events, limit=len(events) or 1)
                if intelligence is not None else {}
            )
            return {"events": events, "intelligence": analysis}

        def completed(value: object) -> None:
            if token != self._session_load_token:
                return
            payload = value if isinstance(value, dict) else {}
            events = list(payload.get("events") or [])
            analysis = payload.get("intelligence") or {}
            self.model.replace(events)
            self.intelligence_view.setPlainText(json.dumps(analysis, ensure_ascii=False, indent=2, default=str))
            if self.simple_mode:
                self._show_simple_summary(events, source="Saved Capture", backend="Arenyxa Native")
            self.inspectorChanged.emit(
                "Capture Session",
                {"id": session_id, "visible_events": len(events), "intelligence": analysis},
            )
            self.statusMessage.emit(f"已加载 {len(events):,} 条网络事件")

        def failed(message: str) -> None:
            if token == self._session_load_token:
                QMessageBox.warning(self, "加载捕获会话失败", message)

        run_background(load_payload, completed, failed)
