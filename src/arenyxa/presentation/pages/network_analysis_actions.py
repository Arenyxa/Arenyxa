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


class NetworkAnalysisActionsMixin:
    def inspect_event(self, current: QModelIndex, previous: QModelIndex) -> None:
        del previous
        if not current.isValid() or current.row() >= len(self.model.events):
            return
        event = self.model.events[current.row()]
        overview = {
            key: event.get(key)
            for key in (
                "id",
                "timestamp",
                "source_type",
                "method",
                "url",
                "status",
                "protocol",
                "size",
                "host",
                "initiator",
                "sensitivity",
            )
        }
        self.overview.setPlainText(json.dumps(overview, ensure_ascii=False, indent=2, default=str))
        self.headers_view.setPlainText(
            json.dumps(
                {"request": event.get("request_headers", {}), "response": event.get("response_headers", {})},
                ensure_ascii=False,
                indent=2,
            )
        )
        self.timing_view.setPlainText(json.dumps(event.get("timing", {}), ensure_ascii=False, indent=2))
        self.inspectorChanged.emit("Network Event", overview)

    def selected_event(self) -> dict | None:
        row = self.table.currentIndex().row()
        return self.model.events[row] if 0 <= row < len(self.model.events) else None

    def replay_selected(self) -> None:
        event = self.selected_event()
        if not event or not event.get("url"):
            QMessageBox.information(self, "Request Replay", "请选择包含 URL 的网络请求。")
            return
        service = RequestReplayService()
        exchange = self.context.store.get_http_exchange_by_event(str(event.get("id") or ""))
        resolver = CapturedBodyResolver(self.context.store, self.context.paths.captures)
        try:
            if exchange is not None:
                draft = service.draft_from_exchange(exchange, body_resolver=resolver)
            else:
                normalized = dict(event)
                normalized["source_type"] = CaptureSource(str(normalized.get("source_type") or CaptureSource.BROWSER.value))
                draft = service.draft_from_event(
                    NetworkEvent(**{
                        key: value for key, value in normalized.items()
                        if key in NetworkEvent.__dataclass_fields__
                    })
                )
        except Exception as exc:
            QMessageBox.critical(self, "Request Replay", str(exc))
            return

        if draft.secret_refs:
            anonymous = (
                QMessageBox.question(
                    self,
                    "敏感凭据保护",
                    "该请求包含认证/Cookie 等敏感 Header。Arenyxa 不会从捕获记录自动重放明文凭据。\n\n"
                    "是否移除这些敏感字段并以匿名方式 Replay？",
                )
                == QMessageBox.StandardButton.Yes
            )
            if not anonymous:
                QMessageBox.information(
                    self,
                    "Request Replay",
                    "已取消。需要认证的 Replay 可在 HTTP Builder 中显式绑定 Secrets 后执行。",
                )
                return
            draft = service.without_secrets(draft)

        method = draft.request.method.upper()
        confirmed = method not in {"POST", "PUT", "PATCH", "DELETE"}
        if not confirmed:
            confirmed = (
                QMessageBox.question(self, "副作用确认", f"{method} 可能修改目标系统，是否继续？")
                == QMessageBox.StandardButton.Yes
            )
        if not confirmed:
            return
        if draft.request_body_truncated:
            QMessageBox.warning(
                self,
                "Request Replay",
                "捕获到的请求正文已被截断。为避免发送不完整写请求，本次 Replay 已阻止。",
            )
            return

        self.replay.setEnabled(False)

        def run_replay() -> object:
            result = service.execute(draft, confirm_side_effect=True)
            self.context.store.save_replay_run(service.persistence_record(draft, result))
            return result

        def completed(result: object) -> None:
            self.replay.setEnabled(True)
            if result.state != "completed" or result.response is None:
                QMessageBox.critical(
                    self, "Replay 失败", result.error_message or result.error_code or "Replay failed"
                )
                self.statusMessage.emit(f"Replay 失败：{result.error_code or 'unknown'}")
                return
            response = result.response
            overview = {
                "replay_id": result.id,
                "status": response.status,
                "url": response.final_url,
                "bytes": len(response.body),
                "elapsed_ms": response.elapsed_ms,
                "content_type": response.content_type,
                "request_fingerprint": result.request_fingerprint,
                "warnings": draft.warnings,
                "comparison": result.comparison,
            }
            self.overview.setPlainText(json.dumps(overview, ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit(f"Replay 完成：HTTP {response.status} · {response.elapsed_ms:.0f} ms")

        def failed(message: str) -> None:
            self.replay.setEnabled(True)
            QMessageBox.critical(self, "Replay 失败", message)

        run_background(run_replay, completed, failed)

    def _selected_host(self) -> str | None:
        event = self.selected_event()
        return str(event.get("host")) if event and event.get("host") else None

    def inspect_tls(self) -> None:
        host = self._selected_host()
        if not host:
            QMessageBox.information(self, "TLS Inspector", "请先选择包含 Host 的事件。")
            return
        self.tls.setEnabled(False)

        def completed(report: object) -> None:
            self.tls.setEnabled(True)
            self.protocol_view.setPlainText(json.dumps(asdict(report), ensure_ascii=False, indent=2))

        def failed(message: str) -> None:
            self.tls.setEnabled(True)
            QMessageBox.warning(self, "TLS 检查失败", message)

        run_background(lambda: TlsInspector.inspect(host), completed, failed)

    def inspect_dns(self) -> None:
        host = self._selected_host()
        if not host:
            QMessageBox.information(self, "DNS Analyzer", "请先选择包含 Host 的事件。")
            return
        self.dns.setEnabled(False)

        def completed(report: object) -> None:
            self.dns.setEnabled(True)
            self.protocol_view.setPlainText(json.dumps(asdict(report), ensure_ascii=False, indent=2))

        def failed(message: str) -> None:
            self.dns.setEnabled(True)
            QMessageBox.warning(self, "DNS 查询失败", message)

        run_background(lambda: DnsAnalyzer.resolve(host), completed, failed)

    def run_professional_analysis(self) -> None:
        rows = list(self.model.events)
        if not rows:
            QMessageBox.information(self, "Professional Analysis", "当前会话没有可分析的网络事件。")
            return
        events: list[NetworkEvent] = []
        for row in rows:
            normalized = dict(row)
            try:
                normalized["source_type"] = CaptureSource(str(normalized.get("source_type") or CaptureSource.BROWSER.value))
                events.append(NetworkEvent(**{
                    key: value for key, value in normalized.items()
                    if key in NetworkEvent.__dataclass_fields__
                }))
            except (TypeError, ValueError):
                continue
        if not events:
            QMessageBox.warning(self, "Professional Analysis", "当前会话的数据格式无法安全分析。")
            return
        self.professional.setEnabled(False)
        display_filter = self.filter.text().strip()
        selected = self.selected_event() or {}
        source_url = str(selected.get("url") or "")

        def run_analysis() -> object:
            return ProfessionalAnalysisSuite().analyze(events, source_url=source_url, display_filter=display_filter)

        def completed(result: object) -> None:
            self.professional.setEnabled(True)
            self.professional_view.setPlainText(json.dumps(asdict(result), ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit("Professional Analysis 已完成")

        def failed(message: str) -> None:
            self.professional.setEnabled(True)
            QMessageBox.warning(self, "Professional Analysis", message)

        run_background(run_analysis, completed, failed)

    def _import_pcap_session(self, session: CaptureSession, source_path: Path) -> None:
        self.start_button.setEnabled(False)
        self.operationProgress.emit("PCAP Import", 0, 0, "indeterminate")
        session.started_at = utc_now()
        session.state = CaptureState.CAPTURING
        capture_dir = self.context.paths.captures / session.id
        capture_dir.mkdir(parents=True, exist_ok=True)
        target = capture_dir / source_path.name
        display_filter = self.filter.text().strip()
        limit = max(1, int(self.context.performance.network_history_limit))

        def run_import() -> object:
            if source_path.resolve() != target.resolve():
                shutil.copy2(source_path, target)
            engine = PacketAnalysisEngine()
            session.permission_state = "offline_capture"
            session.bytes_captured = target.stat().st_size
            self.context.store.save_capture(session)
            preview: list[NetworkEvent] = []
            batch: list[NetworkEvent] = []
            decoded_count = 0
            batch_size = 1000
            preview_limit = max(500, int(self.model.max_rows))
            for event in engine.iter_network_events(target, session, display_filter=display_filter, limit=limit):
                batch.append(event)
                decoded_count += 1
                if len(preview) < preview_limit:
                    preview.append(event)
                if len(batch) >= batch_size:
                    self.context.store.append_network_events(batch)
                    batch.clear()
            if batch:
                self.context.store.append_network_events(batch)
            session.state = CaptureState.COMPLETED
            session.finished_at = utc_now()
            session.event_count = decoded_count
            self.context.store.save_capture(session)
            backend = "TShark + Arenyxa Native" if engine.available else "Arenyxa Native"
            return preview, decoded_count, target, backend

        def completed(value: object) -> None:
            events, decoded_count, target_path, backend = value
            self.start_button.setEnabled(True)
            self.operationProgress.emit("PCAP Import", 0, 0, "clear")
            self._visible_session_id = session.id
            rows = [NetworkEventModel._as_row(event) for event in events]
            self.model.replace(rows)
            if self.simple_mode:
                payload = self._simple_summary_payload(rows, source=str(target_path), backend=backend)
                payload.update({
                    "decoded_packets": decoded_count,
                    "visible_packets": len(events),
                    "raw_bytes": session.bytes_captured,
                })
                self.overview.setPlainText(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
                self.statusMessage.emit(
                    f"PCAP 分析完成 · Risk {payload['risk']} · Score {payload['score']}/100 · {backend}"
                )
            else:
                self.overview.setPlainText(json.dumps({
                    "capture": str(target_path),
                    "decoded_packets": decoded_count,
                    "visible_packets": len(events),
                    "raw_bytes": session.bytes_captured,
                    "display_filter": display_filter,
                    "streaming_decode": True,
                    "persistence_batch_size": 1000,
                    "backend": backend,
                }, ensure_ascii=False, indent=2))
                self.statusMessage.emit(f"PCAP 已导入：{decoded_count:,} packets · {backend}")
            self.context.nextgen.activity.publish(
                "capture-import",
                "PCAP imported",
                details={"session_id": session.id, "packets": decoded_count, "path": str(target_path)},
            )
            self.refresh_sessions()

        def failed(message: str) -> None:
            session.state = CaptureState.FAILED
            session.finished_at = utc_now()
            self.context.store.save_capture(session)
            self.start_button.setEnabled(True)
            self.operationProgress.emit("PCAP Import", 0, 0, "clear")
            self.refresh_sessions()
            QMessageBox.critical(self, "PCAP 导入失败", message)

        run_background(run_import, completed, failed)

    def _raw_capture_files(self) -> list[Path]:
        event = self.selected_event()
        if event and isinstance(event.get("metadata"), dict):
            raw_path = str(event["metadata"].get("raw_capture_path") or "")
            if raw_path:
                candidate = Path(raw_path)
                if candidate.is_file():
                    return [candidate.resolve()]
        if not self._visible_session_id:
            return []
        capture_dir = self.context.paths.captures / self._visible_session_id
        if not capture_dir.exists():
            return []
        candidates = []
        for pattern in ("*.pcapng", "*.pcapng.*", "*.pcap", "*.pcap.*", "*.cap", "*.cap.*"):
            candidates.extend(capture_dir.glob(pattern))
        unique = {path.resolve(): path.resolve() for path in candidates if path.is_file() and path.name != "analysis_merged.pcapng"}
        return sorted(unique.values(), key=lambda path: path.name.casefold())

    def open_packet_analysis_workbench(self) -> None:
        files = self._raw_capture_files()
        if not files:
            QMessageBox.information(
                self,
                "Packet Intelligence",
                "当前会话没有原始 PCAP/PCAPNG。请使用 System Packet Capture 或 Import PCAP / PCAPNG。",
            )
            return
        self.packet_analysis.setEnabled(False)

        def prepare_capture() -> Path:
            if len(files) == 1:
                return files[0]
            target = self.context.paths.captures / str(self._visible_session_id) / "analysis_merged.pcapng"
            return PacketAnalysisEngine().merge_captures(files, target)

        def completed(value: object) -> None:
            self.packet_analysis.setEnabled(True)
            dialog = PacketIntelligenceWorkbenchDialog(Path(value), self.selected_event(), self)
            dialog.exec()

        def failed(message: str) -> None:
            self.packet_analysis.setEnabled(True)
            QMessageBox.warning(self, "Packet Intelligence", message)

        run_background(prepare_capture, completed, failed)

    def run_packet_analytics(self) -> None:
        if not self._visible_session_id:
            QMessageBox.information(self, "Packet Intelligence", "Select a capture session first.")
            return
        session_id = str(self._visible_session_id)
        self.packet_analytics.setEnabled(False)
        def analyze() -> dict[str, Any]:
            events: list[NetworkEvent] = []
            for row in self.context.store.iter_network_events(session_id, 50000):
                normalized = dict(row)
                try:
                    normalized["source_type"] = CaptureSource(str(normalized.get("source_type") or CaptureSource.BROWSER.value))
                    payload = {key: value for key, value in normalized.items() if key in NetworkEvent.__dataclass_fields__}
                    events.append(NetworkEvent(**payload))
                except (TypeError, ValueError):
                    continue
            return PacketAdvancedAnalyzer().analyze(events, limit=50000).snapshot()
        def completed(value: object) -> None:
            self.packet_analytics.setEnabled(True)
            self.professional_view.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str))
            self.statusMessage.emit("Packet Intelligence advanced analytics completed")
        def failed(message: str) -> None:
            self.packet_analytics.setEnabled(True)
            QMessageBox.warning(self, "Packet Intelligence", message)
        run_background(analyze, completed, failed)

    def process_snapshot(self) -> None:
        self.processes.setEnabled(False)

        def completed(value: object) -> None:
            rows = value
            self.processes.setEnabled(True)
            self.overview.setPlainText(json.dumps(rows[:1000], ensure_ascii=False, indent=2))
            self.statusMessage.emit(f"进程连接快照：{len(rows):,} connections")

        def failed(message: str) -> None:
            self.processes.setEnabled(True)
            QMessageBox.warning(self, "进程监控失败", message)

        run_background(ProcessNetworkMonitor().snapshot, completed, failed)
