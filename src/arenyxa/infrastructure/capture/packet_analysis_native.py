from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import json
from collections import Counter
import shutil
from pathlib import Path
from typing import Any, Iterable, Sequence

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent
from arenyxa.infrastructure.capture.protocol_intelligence import ProtocolIntelligenceEngine
from arenyxa.infrastructure.capture.native_capture import NativeCaptureReader, NativeCapturePacket
from arenyxa.infrastructure.capture.packet_runtime import PacketRuntimeMixin
from arenyxa.infrastructure.capture.packet_forensics import PacketForensicsMixin
from arenyxa.infrastructure.capture.packet_row_projection import PacketRowProjectionMixin
from arenyxa.infrastructure.capture.tcp_reassembly import TcpReassemblyManager
from arenyxa.infrastructure.capture.protocol_registry import DynamicProtocolRegistry, ProtocolField, global_protocol_registry
from arenyxa.infrastructure.capture.packet_analysis_constants import PACKET_SUMMARY_FIELDS
from arenyxa.infrastructure.external_tools import ExternalToolProbe, ExternalToolCapability
from arenyxa.infrastructure.capture.packet_models import (
    PacketCaptureInfo,
    PacketExecutionProfile,
    PacketRecord,
    PacketStatistics,
    PacketToolCapabilities,
)


class PacketAnalysisNativeMixin:
    @staticmethod
    def _network_event_from_packet(packet: PacketRecord, session: CaptureSession, capture_path: Path) -> NetworkEvent:
        transport = (
            "tcp"
            if packet.tcp_stream is not None or (packet.source_port is not None and "tcp" in packet.protocols)
            else "udp"
            if packet.udp_stream is not None or "udp" in packet.protocols
            else "unknown"
        )
        stream_ref = (
            f"tcp:{packet.tcp_stream}"
            if packet.tcp_stream is not None
            else f"udp:{packet.udp_stream}"
            if packet.udp_stream is not None
            else str(packet.metadata.get("native_flow_key") or "") or None
        )
        url = ""
        if packet.host and packet.uri:
            scheme = "https" if any(token in packet.protocols for token in ("tls", "http2", "quic", "http3")) else "http"
            url = f"{scheme}://{packet.host}{packet.uri}"
        metadata = dict(packet.metadata)
        metadata.update({
            "frame_number": packet.frame_number,
            "captured_length": packet.captured_length,
            "frame_protocols": packet.protocols,
            "packet_info": packet.info,
            "source_address": packet.source,
            "destination_address": packet.destination,
            "source_port": packet.source_port,
            "destination_port": packet.destination_port,
            "transport": transport,
            "tcp_stream": packet.tcp_stream,
            "udp_stream": packet.udp_stream,
            "http2_stream": packet.http2_stream,
            "quic_stream": packet.quic_stream,
            "tcp_analysis": packet.tcp_analysis,
            "raw_capture_path": str(capture_path),
        })
        return NetworkEvent(
            session_id=session.id,
            source_type=session.source_type,
            protocol=packet.protocol.casefold() or "unknown",
            direction="unknown",
            size=packet.length,
            timestamp=packet.timestamp,
            flow_ref=stream_ref,
            method=packet.method or None,
            url=url or None,
            status=packet.status,
            host=packet.host or None,
            metadata=metadata,
        )

    @staticmethod
    def _native_tcp_reassembly(
        packet: NativeCapturePacket,
        decoded: Any,
        decoder: ProtocolIntelligenceEngine,
        reassembly: TcpReassemblyManager,
    ) -> dict[str, Any]:
        source = ""
        destination = ""
        tcp_layer: Any | None = None
        for layer in decoded.layers:
            fields = layer.fields if isinstance(layer.fields, dict) else {}
            if layer.name in {"ipv4", "ipv6"}:
                source = str(fields.get("source") or source)
                destination = str(fields.get("destination") or destination)
            elif layer.name == "tcp":
                tcp_layer = layer
        if tcp_layer is None or not source or not destination:
            return {}
        fields = tcp_layer.fields if isinstance(tcp_layer.fields, dict) else {}
        try:
            source_port = int(fields.get("source_port"))
            destination_port = int(fields.get("destination_port"))
            sequence = int(fields.get("sequence"))
            header_length = int(fields.get("header_length") or 20)
            payload_length = max(0, int(fields.get("payload_length") or 0))
        except (TypeError, ValueError, OverflowError):
            return {}
        flags = {str(item).casefold() for item in fields.get("flags") or ()}
        start = int(tcp_layer.offset) + header_length
        end = min(len(packet.data), start + payload_length)
        payload = packet.data[start:end] if payload_length > 0 and start < end else b""
        update = reassembly.feed(
            (source, source_port, destination, destination_port),
            sequence=sequence,
            payload=payload,
            flags=flags,
        )
        result: dict[str, Any] = {
            "contiguous_bytes": update.contiguous_bytes,
            "pending_bytes": update.pending_bytes,
            "gap": update.gap,
            "retransmission": update.retransmission,
            "out_of_order": update.out_of_order,
            "truncated": update.truncated,
            "closed": update.closed,
        }
        if not update.stream_bytes:
            return result
        stream_decode = decoder.decode_application_payload(
            update.stream_bytes,
            source_port=source_port,
            destination_port=destination_port,
            transport="tcp",
        )
        if stream_decode.application_protocol:
            result["application_protocol"] = stream_decode.application_protocol
            result["protocols"] = list(stream_decode.protocols)
            result["encrypted"] = bool(stream_decode.encrypted)
            result["warnings"] = list(stream_decode.warnings[:8])
            result["layers"] = [
                {"name": layer.name, "fields": layer.fields}
                for layer in stream_decode.layers[:8]
            ]
        return result

    @staticmethod
    def _native_tcp_analysis(decoded: Any, state: dict[tuple[str, int, str, int], int]) -> list[str]:
        source = ""
        destination = ""
        tcp_fields: dict[str, Any] | None = None
        for layer in decoded.layers:
            fields = layer.fields if isinstance(layer.fields, dict) else {}
            if layer.name in {"ipv4", "ipv6"}:
                source = str(fields.get("source") or source)
                destination = str(fields.get("destination") or destination)
            elif layer.name == "tcp":
                tcp_fields = fields
        if tcp_fields is None or not source or not destination:
            return []
        try:
            source_port = int(tcp_fields.get("source_port"))
            destination_port = int(tcp_fields.get("destination_port"))
            sequence = int(tcp_fields.get("sequence"))
            payload_length = max(0, int(tcp_fields.get("payload_length") or 0))
            window = int(tcp_fields.get("window") or 0)
        except (TypeError, ValueError, OverflowError):
            return []
        flags = {str(item).casefold() for item in tcp_fields.get("flags") or ()}
        sequence_span = payload_length + int("syn" in flags) + int("fin" in flags)
        key = (source, source_port, destination, destination_port)
        expected = state.get(key)
        indicators: list[str] = []
        if window == 0 and "rst" not in flags:
            indicators.append("zero_window")
        if expected is not None and sequence_span > 0:
            if sequence < expected:
                indicators.append("retransmission")
            elif sequence > expected:
                indicators.append("out_of_order")
        next_sequence = (sequence + sequence_span) & 0xFFFFFFFF
        if sequence_span > 0 and (expected is None or sequence >= expected):
            if len(state) < 100_000 or key in state:
                state[key] = next_sequence
        if "rst" in flags:
            indicators.append("reset")
            state.pop(key, None)
        return indicators

    @staticmethod
    def _native_link_type(link_type: str) -> str:
        value = str(link_type).casefold()
        return "raw-ip" if value in {"ipv4", "ipv6", "raw-ip"} else value

    @classmethod
    def _native_packet_record(
        cls, packet: NativeCapturePacket, decoded: Any, *, tcp_analysis: Sequence[str] = ()
    ) -> PacketRecord:
        source = ""
        destination = ""
        source_port: int | None = None
        destination_port: int | None = None
        host = ""
        method = ""
        uri = ""
        status: int | None = None
        info_parts: list[str] = []
        for layer in decoded.layers:
            fields = layer.fields if isinstance(layer.fields, dict) else {}
            if layer.name in {"ipv4", "ipv6"}:
                source = str(fields.get("source") or source)
                destination = str(fields.get("destination") or destination)
            elif layer.name == "ethernet" and not source and not destination:
                source = str(fields.get("source") or "")
                destination = str(fields.get("destination") or "")
            if layer.name in {"tcp", "udp", "sctp", "dccp"}:
                try:
                    source_port = int(fields.get("source_port")) if fields.get("source_port") is not None else source_port
                    destination_port = int(fields.get("destination_port")) if fields.get("destination_port") is not None else destination_port
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, 'PacketAnalysisEngine._native_packet_record:748')
            if layer.name in {"dns", "mdns"}:
                questions = fields.get("question_records")
                if isinstance(questions, list) and questions and isinstance(questions[0], dict):
                    host = str(questions[0].get("name") or host)
            elif layer.name == "tls":
                host = str(fields.get("server_name") or host)
            elif layer.name in {"http", "rtsp"}:
                host = str(fields.get("host") or host)
                method = str(fields.get("method") or method)
                uri = str(fields.get("target") or uri)
                try:
                    status = int(fields.get("status")) if fields.get("status") is not None else status
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, 'PacketAnalysisEngine._native_packet_record:762')
            if layer.name not in {"ethernet", "ipv4", "ipv6", "tcp", "udp"}:
                info_parts.append(layer.name)
        layers = [
            {"name": layer.name, "offset": layer.offset, "length": layer.length, "fields": layer.fields}
            for layer in decoded.layers
        ]
        expert_findings = ProtocolIntelligenceEngine.expert_findings(decoded)
        metadata: dict[str, Any] = {
            "native_decode": True,
            "native_link_type": packet.link_type,
            "native_link_type_id": packet.link_type_id,
            "native_interface_id": packet.interface_id,
            "native_flow_key": decoded.flow_key,
            "native_encrypted": bool(decoded.encrypted),
            "native_truncated": bool(decoded.truncated),
            "native_warnings": list(decoded.warnings),
            "native_layers": layers,
            "native_tcp_analysis": list(tcp_analysis),
            "native_expert_findings": expert_findings,
        }
        return PacketRecord(
            frame_number=packet.frame_number,
            timestamp=cls._float_text_to_iso(str(packet.timestamp_epoch)),
            length=packet.original_length,
            captured_length=packet.captured_length,
            protocols=":".join(decoded.protocols),
            protocol=str(decoded.application_protocol or (decoded.protocols[-1] if decoded.protocols else "unknown")),
            info=" / ".join(info_parts[:8]),
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            tcp_stream=None,
            udp_stream=None,
            http2_stream=None,
            quic_stream=None,
            host=host,
            method=method,
            uri=uri,
            status=status,
            tcp_analysis=list(tcp_analysis),
            metadata=metadata,
        )

    @staticmethod
    def _native_decode_dict(packet: NativeCapturePacket, decoded: Any, *, include_raw: bool) -> dict[str, Any]:
        payload = {
            "frame_number": packet.frame_number,
            "timestamp_epoch": packet.timestamp_epoch,
            "captured_length": packet.captured_length,
            "original_length": packet.original_length,
            "interface_id": packet.interface_id,
            "link_type": packet.link_type,
            "protocols": list(decoded.protocols),
            "application_protocol": decoded.application_protocol,
            "encrypted": bool(decoded.encrypted),
            "truncated": bool(decoded.truncated),
            "warnings": list(decoded.warnings),
            "flow_key": decoded.flow_key,
            "expert_findings": ProtocolIntelligenceEngine.expert_findings(decoded),
            "layers": [
                {"name": layer.name, "offset": layer.offset, "length": layer.length, "fields": layer.fields}
                for layer in decoded.layers
            ],
        }
        if include_raw:
            payload["raw_hex"] = packet.data.hex()
        return payload

    @staticmethod
    def _require_native_empty_filter(display_filter: str) -> None:
        if str(display_filter).strip():
            raise ArenyxaError(
                "PACKET_NATIVE_FILTER_UNSUPPORTED",
                "Native packet fallback does not implement display-filter expressions; install the external dissector runtime for filter evaluation.",
                domain="CAPTURE",
            )

    def _native_stat_text(self, capture: Path | str, section: str, display_filter: str) -> str:
        self._require_native_empty_filter(display_filter)
        snapshot = self._native_statistics_snapshot(capture)
        return json.dumps(snapshot.get(section, {}), ensure_ascii=False, indent=2, sort_keys=True)

    def _native_statistics_snapshot(self, capture: Path | str, *, limit: int = 200_000) -> dict[str, Any]:
        protocol_counts: Counter[str] = Counter()
        app_counts: Counter[str] = Counter()
        endpoint_counts: Counter[str] = Counter()
        conversation_counts: Counter[str] = Counter()
        warning_counts: Counter[str] = Counter()
        expert_counts: Counter[str] = Counter()
        expert_severity: Counter[str] = Counter()
        second_counts: Counter[int] = Counter()
        length_buckets: Counter[str] = Counter()
        flow_counts: Counter[str] = Counter()
        rtp_counts: Counter[str] = Counter()
        packet_count = 0
        byte_count = 0
        encrypted_count = 0
        truncated_count = 0
        cardinality_truncated: set[str] = set()

        def increment_bounded(counter: Counter[Any], key: Any, bucket: str, *, maximum: int = 50_000) -> None:
            if key in counter or len(counter) < maximum:
                counter[key] += 1
            else:
                cardinality_truncated.add(bucket)

        for packet in self.iter_packet_summaries(capture, limit=limit):
            packet_count += 1
            byte_count += max(0, int(packet.captured_length))
            for name in (part.strip() for part in packet.protocols.split(":")):
                if name:
                    protocol_counts[name] += 1
            app = str(packet.protocol or "unknown").casefold()
            app_counts[app] += 1
            if packet.source:
                increment_bounded(endpoint_counts, packet.source, "endpoints")
            if packet.destination:
                increment_bounded(endpoint_counts, packet.destination, "endpoints")
            if packet.source and packet.destination:
                left = f"{packet.source}:{packet.source_port}" if packet.source_port is not None else packet.source
                right = f"{packet.destination}:{packet.destination_port}" if packet.destination_port is not None else packet.destination
                increment_bounded(conversation_counts, " <-> ".join(sorted((left, right))), "conversations")
            metadata = packet.metadata if isinstance(packet.metadata, dict) else {}
            encrypted_count += int(bool(metadata.get("native_encrypted")))
            truncated_count += int(bool(metadata.get("native_truncated")))
            for warning in metadata.get("native_warnings") or ():
                increment_bounded(warning_counts, str(warning)[:240], "warnings", maximum=4096)
            for finding in metadata.get("native_expert_findings") or ():
                if isinstance(finding, dict):
                    expert_counts[str(finding.get("code") or "UNKNOWN")[:96]] += 1
                    expert_severity[str(finding.get("severity") or "info")[:32]] += 1
            flow = str(metadata.get("native_flow_key") or "")
            if flow:
                increment_bounded(flow_counts, flow, "flows")
            try:
                timestamp = self._iso_to_epoch(packet.timestamp)
            except (TypeError, ValueError, OverflowError):
                timestamp = 0.0
            if timestamp > 0:
                increment_bounded(second_counts, int(timestamp), "time_buckets", maximum=100_000)
            length = max(0, int(packet.length))
            if length <= 63:
                length_buckets["0-63"] += 1
            elif length <= 127:
                length_buckets["64-127"] += 1
            elif length <= 255:
                length_buckets["128-255"] += 1
            elif length <= 511:
                length_buckets["256-511"] += 1
            elif length <= 1023:
                length_buckets["512-1023"] += 1
            elif length <= 1518:
                length_buckets["1024-1518"] += 1
            else:
                length_buckets["1519+"] += 1
            if app in {"rtp", "rtcp"}:
                rtp_counts[app] += 1
        top = lambda counter, n=200: [{"key": key, "count": count} for key, count in counter.most_common(n)]
        return {
            "backend": "arenyxa-native",
            "packet_count": packet_count,
            "byte_count": byte_count,
            "scan_limit": min(max(0, int(limit)), 1_000_000),
            "cardinality_truncated": sorted(cardinality_truncated),
            "protocol_hierarchy": {"layers": top(protocol_counts), "applications": top(app_counts)},
            "conversations": top(conversation_counts),
            "endpoints": top(endpoint_counts),
            "expert": {
                "warnings": top(warning_counts), "findings": top(expert_counts),
                "severity": dict(expert_severity), "truncated_packets": truncated_count,
            },
            "io_graph": [{"epoch_second": second, "packets": count} for second, count in sorted(second_counts.items())[:10_000]],
            "packet_lengths": dict(sorted(length_buckets.items())),
            "flow_graph": top(flow_counts),
            "service_statistics": {"applications": top(app_counts), "encrypted_packets": encrypted_count},
            "rtp_streams": top(rtp_counts),
        }
