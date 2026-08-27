from __future__ import annotations

import json
from typing import Any

from arenyxa.qt_compat.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


class ProxySuitePanelsMixin:
    """Focused professional panels kept outside the already-large Proxy page."""

    @staticmethod
    def _readonly_view() -> QPlainTextEdit:
        viewer = QPlainTextEdit()
        viewer.setReadOnly(True)
        viewer.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        return viewer

    def _build_https_sessions_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Durable HTTPS CONNECT, intercepted TLS, ALPN and response metadata"), 1)
        refresh = QPushButton("Refresh HTTPS Sessions")
        refresh.clicked.connect(self.refresh_https_sessions)
        bar.addWidget(refresh)
        layout.addLayout(bar)
        self.https_sessions_view = self._readonly_view()
        layout.addWidget(self.https_sessions_view, 1)
        return holder

    def _build_request_editor_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        target = QHBoxLayout()
        self.professional_scheme = QComboBox()
        self.professional_scheme.addItems(["https", "http"])
        self.professional_host = QLineEdit()
        self.professional_host.setPlaceholderText("Authorized target host")
        self.professional_port = QSpinBox()
        self.professional_port.setRange(1, 65535)
        self.professional_port.setValue(443)
        self.professional_scheme.currentTextChanged.connect(
            lambda value: self.professional_port.setValue(443 if value == "https" else 80)
        )
        send = QPushButton("Send to Replay")
        send.setProperty("primary", True)
        send.clicked.connect(self.send_professional_request)
        target.addWidget(self.professional_scheme)
        target.addWidget(self.professional_host, 1)
        target.addWidget(self.professional_port)
        target.addWidget(send)
        layout.addLayout(target)
        self.professional_request = QPlainTextEdit(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Arenyxa-Replay/8.1\r\nConnection: close\r\n\r\n"
        )
        self.professional_request.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        layout.addWidget(self.professional_request, 1)
        return holder

    def _build_response_viewer_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        note = QLabel("Exact response from Request Editor / Replay; select HTTP History for persisted response inspection.")
        note.setProperty("muted", True)
        layout.addWidget(note)
        self.professional_response = self._readonly_view()
        layout.addWidget(self.professional_response, 1)
        return holder

    def _build_websocket_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Handshake channels, frame counts, payload references and searchable message metadata"), 1)
        refresh = QPushButton("Refresh WebSocket")
        refresh.clicked.connect(self.refresh_websocket)
        bar.addWidget(refresh)
        layout.addLayout(bar)
        self.websocket_view = self._readonly_view()
        layout.addWidget(self.websocket_view, 1)
        return holder

    def _build_tls_inspector_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        bar = QHBoxLayout()
        bar.addWidget(QLabel("TLS version, cipher, certificate chain references, SNI, ALPN and HTTP/2 negotiation"), 1)
        refresh = QPushButton("Refresh TLS Inspector")
        refresh.clicked.connect(self.refresh_tls_inspector)
        bar.addWidget(refresh)
        layout.addLayout(bar)
        self.tls_inspector_view = self._readonly_view()
        layout.addWidget(self.tls_inspector_view, 1)
        return holder

    def _build_export_center_tab(self) -> QWidget:
        holder = QWidget()
        layout = QVBoxLayout(holder)
        buttons = QHBoxLayout()
        har = QPushButton("Export Session HAR")
        ca = QPushButton("Export Root CA Certificate")
        refresh = QPushButton("History Health")
        har.clicked.connect(self.export_har)
        ca.clicked.connect(self.export_ca)
        refresh.clicked.connect(self.refresh_export_center)
        buttons.addWidget(har)
        buttons.addWidget(ca)
        buttons.addWidget(refresh)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.export_center_view = self._readonly_view()
        layout.addWidget(self.export_center_view, 1)
        return holder

    def send_professional_request(self) -> None:
        host = self.professional_host.text().strip()
        if not host:
            QMessageBox.information(self, "Request Editor", "Enter an authorized target host first.")
            return
        try:
            response = self.engine.repeat_raw(
                self.professional_scheme.currentText(),
                host,
                self.professional_port.value(),
                self.professional_request.toPlainText(),
            )
        except Exception as exc:
            QMessageBox.warning(self, "Request Editor", str(exc))
            return
        self.professional_response.setPlainText(response.decode("latin-1", errors="replace"))
        self.tabs.setCurrentWidget(self.professional_response.parentWidget())

    def refresh_https_sessions(self) -> None:
        result = self.engine.history_page(page=1, page_size=500)
        rows = []
        for flow in result.get("items", []):
            if not (flow.scheme == "https" or flow.tls_intercepted or flow.tunnel):
                continue
            rows.append({
                "id": flow.id,
                "started_at": flow.started_at,
                "method": flow.method,
                "host": flow.host,
                "port": flow.port,
                "status": flow.status,
                "tls_intercepted": flow.tls_intercepted,
                "connect_tunnel": flow.tunnel,
                "latency_ms": round(float(flow.duration_ms), 3),
            })
        self.https_sessions_view.setPlainText(json.dumps(rows, ensure_ascii=False, indent=2, default=str))

    def refresh_websocket(self) -> None:
        try:
            with self.context.store.connect() as connection:
                channels = [dict(row) for row in connection.execute(
                    "SELECT * FROM websocket_channels ORDER BY opened_at DESC,id DESC LIMIT 500"
                )]
                messages = [dict(row) for row in connection.execute(
                    "SELECT * FROM websocket_messages ORDER BY timestamp DESC,id DESC LIMIT 1000"
                )]
        except Exception as exc:
            self.websocket_view.setPlainText(json.dumps({"error_code": "WEBSOCKET_HISTORY_READ_FAILED", "message": str(exc)}, indent=2))
            return
        self.websocket_view.setPlainText(json.dumps(
            {"channels": channels, "messages": messages}, ensure_ascii=False, indent=2, default=str
        ))

    def refresh_tls_inspector(self) -> None:
        handshakes: list[dict[str, Any]] = []
        try:
            with self.context.store.connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM tls_handshakes ORDER BY timestamp DESC,id DESC LIMIT 1000"
                ).fetchall()
                handshakes = [dict(row) for row in rows]
        except Exception as exc:
            handshakes = [{"error_code": "TLS_HISTORY_READ_FAILED", "message": str(exc)}]
        value = {
            "certificate_authority": self.engine.ca.status(),
            "certificate_cache": self.engine.ca.certificates(limit=200),
            "handshakes": handshakes,
        }
        self.tls_inspector_view.setPlainText(json.dumps(value, ensure_ascii=False, indent=2, default=str))

    def refresh_export_center(self) -> None:
        self.export_center_view.setPlainText(json.dumps(
            {
                "history": self.engine.history_health(),
                "sessions": self.engine.sessions(limit=20),
                "formats": ["HAR", "Arenyxa session JSON", "Root CA certificate"],
                "sensitive_export_default": "redacted",
            },
            ensure_ascii=False,
            indent=2,
            default=str,
        ))

    def refresh_professional_panels(self) -> None:
        current = self.tabs.tabText(self.tabs.currentIndex()) if self.tabs.currentIndex() >= 0 else ""
        if current == "HTTPS Sessions":
            self.refresh_https_sessions()
        elif current == "WebSocket":
            self.refresh_websocket()
        elif current == "TLS Inspector":
            self.refresh_tls_inspector()
        elif current == "Export Center":
            self.refresh_export_center()


__all__ = ["ProxySuitePanelsMixin"]
