from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from arenyxa.qt_compat.QtCore import Qt
from arenyxa.qt_compat.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from arenyxa.infrastructure.capture.packet_analysis import PacketAnalysisEngine, PacketExecutionProfile
from arenyxa.presentation.background import run_background


class PacketIntelligenceWorkbenchDialog(QDialog):
    def __init__(self, capture_path: Path, selected_event: dict[str, Any] | None = None, parent=None) -> None:
        super().__init__(parent)
        self.capture_path = Path(capture_path).resolve()
        self.selected_event = dict(selected_event or {})
        self.engine = PacketAnalysisEngine()
        self.setWindowTitle("Arenyxa Packet Intelligence · Packet Analysis Engine")
        self.resize(1100, 760)
        root = QVBoxLayout(self)

        form = QFormLayout()
        self.display_filter = QLineEdit()
        self.display_filter.setPlaceholderText("tcp.analysis.retransmission || http.response.code >= 400")
        self.decode_as = QLineEdit()
        self.decode_as.setPlaceholderText("tcp.port==8888,http; udp.port==5353,dns")
        self.profile_name = QLineEdit()
        self.profile_name.setPlaceholderText("Optional packet-analysis configuration profile")
        self.name_resolution = QLineEdit()
        self.name_resolution.setPlaceholderText("Optional -N flags, e.g. dmNst")
        self.preferences = QLineEdit()
        self.preferences.setPlaceholderText('{"tcp.desegment_tcp_streams":"TRUE"}')
        self.tls_keylog = QLineEdit()
        self.keytab = QLineEdit()
        form.addRow("Display Filter", self.display_filter)
        form.addRow("Decode As", self.decode_as)
        form.addRow("Configuration Profile", self.profile_name)
        form.addRow("Name Resolution", self.name_resolution)
        form.addRow("Preferences", self.preferences)
        form.addRow("TLS Key Log", self._path_row(self.tls_keylog, self._choose_tls_keylog))
        form.addRow("Kerberos Keytab", self._path_row(self.keytab, self._choose_keytab))
        root.addLayout(form)

        top_actions = QHBoxLayout()
        self.capabilities_button = QPushButton("Capabilities")
        self.validate_button = QPushButton("Validate Filter")
        self.summary_button = QPushButton("Full Statistics")
        self.packet_button = QPushButton("Packet Tree + Bytes")
        self.expert_button = QPushButton("Expert")
        self.follow_button = QPushButton("Follow Stream")
        self.export_button = QPushButton("Export Filtered")
        self.objects_button = QPushButton("Export Objects")
        for button in (
            self.capabilities_button,
            self.validate_button,
            self.summary_button,
            self.packet_button,
            self.expert_button,
            self.follow_button,
            self.export_button,
            self.objects_button,
        ):
            top_actions.addWidget(button)
        root.addLayout(top_actions)

        stream_row = QHBoxLayout()
        stream_row.addWidget(QLabel("Follow"))
        self.follow_protocol = QComboBox()
        self.follow_protocol.addItems(["tcp", "udp", "tls", "dtls", "http", "http2", "quic", "dccp", "mp2t", "mpeg-pes"])
        self.follow_mode = QComboBox()
        self.follow_mode.addItems(["utf-8", "ascii", "hex", "raw", "yaml", "ebcdic"])
        self.follow_stream_id = QLineEdit()
        self.custom_tap = QLineEdit()
        self.custom_tap.setPlaceholderText("Any TShark -z tap, e.g. sip,stat or smb2,srt")
        self.follow_stream_id.setPlaceholderText("stream index or endpoint pair")
        self._prefill_stream()
        stream_row.addWidget(self.follow_protocol)
        stream_row.addWidget(self.follow_mode)
        stream_row.addWidget(self.follow_stream_id, 1)
        root.addLayout(stream_row)
        custom_row = QHBoxLayout()
        custom_row.addWidget(QLabel("Statistics Tap"))
        custom_row.addWidget(self.custom_tap, 1)
        self.custom_tap_button = QPushButton("Run Tap")
        custom_row.addWidget(self.custom_tap_button)
        root.addLayout(custom_row)

        self.tabs = QTabWidget()
        self.capabilities_view = self._view()
        self.packet_view = self._view()
        self.expert_view = self._view()
        self.statistics_view = self._view()
        self.follow_view = self._view()
        self.catalog_view = self._view()
        self.tabs.addTab(self.capabilities_view, "Capabilities")
        self.tabs.addTab(self.packet_view, "Packet")
        self.tabs.addTab(self.expert_view, "Expert")
        self.tabs.addTab(self.statistics_view, "Statistics")
        self.tabs.addTab(self.follow_view, "Follow Stream")
        self.tabs.addTab(self.catalog_view, "Protocol Catalog")
        root.addWidget(self.tabs, 1)

        bottom = QHBoxLayout()
        self.catalog_button = QPushButton("Protocol / Field Catalog")
        self.info_button = QPushButton("Capture Info")
        self.export_dissections_button = QPushButton("Export Dissections")
        self.capture_tools_button = QPushButton("Capture Tools")
        bottom.addWidget(self.catalog_button)
        bottom.addWidget(self.info_button)
        bottom.addWidget(self.export_dissections_button)
        bottom.addWidget(self.capture_tools_button)
        bottom.addStretch()
        close_button = QPushButton("Close")
        bottom.addWidget(close_button)
        root.addLayout(bottom)

        self.capabilities_button.clicked.connect(self.load_capabilities)
        self.validate_button.clicked.connect(self.validate_filter)
        self.summary_button.clicked.connect(self.load_statistics)
        self.packet_button.clicked.connect(self.load_packet)
        self.expert_button.clicked.connect(self.load_expert)
        self.follow_button.clicked.connect(self.load_follow)
        self.export_button.clicked.connect(self.export_filtered)
        self.objects_button.clicked.connect(self.export_objects)
        self.catalog_button.clicked.connect(self.load_catalog)
        self.info_button.clicked.connect(self.load_capture_info)
        self.export_dissections_button.clicked.connect(self.export_dissections)
        self.custom_tap_button.clicked.connect(self.run_custom_tap)
        self.capture_tools_button.clicked.connect(self.capture_tools)
        close_button.clicked.connect(self.accept)
        self.load_capabilities()

    @staticmethod
    def _view() -> QPlainTextEdit:
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setLineWrapMode(getattr(QPlainTextEdit, "NoWrap", 0))
        return view

    @staticmethod
    def _path_row(edit: QLineEdit, callback) -> QWidget:
        holder = QWidget()
        layout = QHBoxLayout(holder)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(edit, 1)
        button = QPushButton("Browse")
        button.clicked.connect(callback)
        layout.addWidget(button)
        return holder

    def _choose_tls_keylog(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "TLS Key Log", "", "Key Log (*.log *.txt);;All Files (*)")
        if path:
            self.tls_keylog.setText(path)

    def _choose_keytab(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Kerberos Keytab", "", "Keytab (*.keytab *.kt);;All Files (*)")
        if path:
            self.keytab.setText(path)

    def _profile(self) -> PacketExecutionProfile:
        decode_as = tuple(item.strip() for item in self.decode_as.text().split(";") if item.strip())
        preferences: dict[str, str] = {}
        raw_preferences = self.preferences.text().strip()
        if raw_preferences:
            decoded = json.loads(raw_preferences)
            if not isinstance(decoded, dict):
                raise ValueError("Preferences must be a JSON object")
            preferences = {str(key): str(value) for key, value in decoded.items()}
        return PacketExecutionProfile(
            configuration_profile=self.profile_name.text().strip(),
            decode_as=decode_as,
            preferences=preferences,
            name_resolution=self.name_resolution.text().strip(),
            keytab=self.keytab.text().strip(),
            tls_keylog=self.tls_keylog.text().strip(),
        )

    def _prefill_stream(self) -> None:
        metadata = self.selected_event.get("metadata") if isinstance(self.selected_event.get("metadata"), dict) else {}
        tcp_stream = metadata.get("tcp_stream")
        udp_stream = metadata.get("udp_stream")
        http2_stream = metadata.get("http2_stream")
        quic_stream = metadata.get("quic_stream")
        if tcp_stream is not None and http2_stream is not None:
            self.follow_protocol.setCurrentText("http2")
            self.follow_stream_id.setText(f"{tcp_stream},{http2_stream}")
        elif tcp_stream is not None:
            self.follow_protocol.setCurrentText("tcp")
            self.follow_stream_id.setText(str(tcp_stream))
        elif udp_stream is not None:
            self.follow_protocol.setCurrentText("udp")
            self.follow_stream_id.setText(str(udp_stream))
        elif quic_stream is not None:
            self.follow_protocol.setCurrentText("quic")
            self.follow_stream_id.setText(str(quic_stream))

    def _busy(self, state: bool) -> None:
        for button in (
            self.capabilities_button,
            self.validate_button,
            self.summary_button,
            self.packet_button,
            self.expert_button,
            self.follow_button,
            self.export_button,
            self.objects_button,
            self.catalog_button,
            self.info_button,
            self.export_dissections_button,
            self.custom_tap_button,
            self.capture_tools_button,
        ):
            button.setEnabled(not state)

    def _background(self, function, view: QPlainTextEdit, tab_index: int, formatter=None) -> None:
        self._busy(True)
        view.setPlainText("Running packet analysis…")
        self.tabs.setCurrentIndex(tab_index)

        def completed(value: object) -> None:
            self._busy(False)
            rendered = formatter(value) if formatter is not None else str(value)
            view.setPlainText(rendered)

        def failed(message: str) -> None:
            self._busy(False)
            view.setPlainText(message)
            QMessageBox.warning(self, "Packet Intelligence Workbench", message)

        run_background(function, completed, failed)

    def load_capabilities(self) -> None:
        self._background(
            self.engine.capabilities,
            self.capabilities_view,
            0,
            lambda value: json.dumps(asdict(value), ensure_ascii=False, indent=2, default=str),
        )

    def validate_filter(self) -> None:
        expression = self.display_filter.text().strip()
        self._background(
            lambda: self.engine.validate_display_filter(self.capture_path, expression),
            self.capabilities_view,
            0,
            lambda value: json.dumps({"valid": bool(value[0]), "diagnostic": value[1]}, ensure_ascii=False, indent=2),
        )

    def load_statistics(self) -> None:
        expression = self.display_filter.text().strip()
        self._background(
            lambda: self.engine.full_statistics(self.capture_path, expression, self._profile()),
            self.statistics_view,
            3,
            lambda value: self._statistics_text(value),
        )

    @staticmethod
    def _statistics_text(value: object) -> str:
        data = asdict(value)
        sections: list[str] = []
        for key, text in data.items():
            sections.append(f"===== {key.upper()} =====\n{text}")
        return "\n\n".join(sections)

    def load_packet(self) -> None:
        metadata = self.selected_event.get("metadata") if isinstance(self.selected_event.get("metadata"), dict) else {}
        frame_number = metadata.get("frame_number")
        if frame_number is None:
            frame_number, ok = QInputDialog.getInt(self, "Packet Detail", "Frame number", 1, 1, 2_147_483_647)
            if not ok:
                return
        self._background(
            lambda: self.engine.packet_text(self.capture_path, int(frame_number), self._profile()),
            self.packet_view,
            1,
        )

    def load_expert(self) -> None:
        expression = self.display_filter.text().strip()
        self._background(
            lambda: self.engine.expert_information(self.capture_path, expression, profile=self._profile()),
            self.expert_view,
            2,
        )

    def load_follow(self) -> None:
        protocol = self.follow_protocol.currentText()
        mode = self.follow_mode.currentText()
        stream_filter = self.follow_stream_id.text().strip()
        if not stream_filter:
            QMessageBox.information(self, "Follow Stream", "Enter a stream index or endpoint pair.")
            return
        self._background(
            lambda: self.engine.follow_stream(self.capture_path, protocol, stream_filter, mode, profile=self._profile()),
            self.follow_view,
            4,
        )

    def load_catalog(self) -> None:
        self._background(
            lambda: {
                "protocols": self.engine.protocol_catalog(),
                "fields": self.engine.field_catalog(limit=5000),
            },
            self.catalog_view,
            5,
            lambda value: json.dumps(value, ensure_ascii=False, indent=2, default=str),
        )

    def load_capture_info(self) -> None:
        self._background(
            lambda: self.engine.capture_info(self.capture_path),
            self.capabilities_view,
            0,
            lambda value: value.output,
        )

    def export_filtered(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export Filtered Capture", "filtered.pcapng", "PCAPNG (*.pcapng);;PCAP (*.pcap)")
        if not path:
            return
        expression = self.display_filter.text().strip()
        output_format = "pcap" if str(path).casefold().endswith(".pcap") else "pcapng"
        self._background(
            lambda: self.engine.export_filtered_capture(self.capture_path, path, expression, output_format, self._profile()),
            self.capabilities_view,
            0,
            lambda value: f"Exported: {value}",
        )

    def export_objects(self) -> None:
        exporters = self.engine.object_exporters()
        if not exporters:
            QMessageBox.information(self, "Export Objects", "This packet-analysis runtime did not report object exporters.")
            return
        protocol, ok = QInputDialog.getItem(self, "Export Objects", "Protocol", exporters, 0, False)
        if not ok or not protocol:
            return
        directory = QFileDialog.getExistingDirectory(self, "Export Objects")
        if not directory:
            return
        self._background(
            lambda: self.engine.export_objects(self.capture_path, protocol, directory, self._profile()),
            self.capabilities_view,
            0,
            lambda value: json.dumps([str(path) for path in value], ensure_ascii=False, indent=2),
        )


    def run_custom_tap(self) -> None:
        tap = self.custom_tap.text().strip()
        if not tap:
            QMessageBox.information(self, "Statistics Tap", "Enter a TShark -z statistics tap.")
            return
        self._background(
            lambda: self.engine.statistics_tap(self.capture_path, tap, self._profile()),
            self.statistics_view,
            3,
        )

    def capture_tools(self) -> None:
        operation, ok = QInputDialog.getItem(
            self,
            "Capture Tools",
            "Operation",
            ["Convert capture", "Reorder timestamps", "Capture info"],
            0,
            False,
        )
        if not ok:
            return
        if operation == "Capture info":
            self.load_capture_info()
            return
        if operation == "Convert capture":
            path, _ = QFileDialog.getSaveFileName(self, "Convert Capture", "converted.pcapng", "PCAPNG (*.pcapng);;PCAP (*.pcap)")
            if not path:
                return
            output_format = "pcap" if path.casefold().endswith(".pcap") else "pcapng"
            self._background(
                lambda: self.engine.convert_capture(self.capture_path, path, output_format),
                self.capabilities_view,
                0,
                lambda value: f"Converted: {value}",
            )
            return
        path, _ = QFileDialog.getSaveFileName(self, "Reorder Capture", "reordered.pcapng", "PCAPNG (*.pcapng);;All Files (*)")
        if not path:
            return
        self._background(
            lambda: self.engine.reorder_capture(self.capture_path, path),
            self.capabilities_view,
            0,
            lambda value: f"Reordered: {value}",
        )

    def export_dissections(self) -> None:
        output_format, ok = QInputDialog.getItem(self, "Export Dissections", "Format", ["json", "pdml", "psml", "text", "ek", "jsonraw"], 0, False)
        if not ok:
            return
        suffix = {"json": ".json", "pdml": ".xml", "psml": ".xml", "text": ".txt", "ek": ".ndjson", "jsonraw": ".json"}.get(output_format, ".txt")
        path, _ = QFileDialog.getSaveFileName(self, "Export Dissections", f"dissection{suffix}", "All Files (*)")
        if not path:
            return
        expression = self.display_filter.text().strip()
        self._background(
            lambda: self.engine.export_dissections(self.capture_path, path, output_format, expression, self._profile(), include_raw=True),
            self.capabilities_view,
            0,
            lambda value: f"Exported: {value}",
        )
