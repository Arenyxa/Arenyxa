from __future__ import annotations
from arenyxa.recoverable import record_current_exception

"""Projection helpers for converting external dissector rows into packet records."""

from datetime import datetime
from typing import Any, Mapping

from arenyxa.infrastructure.capture.adapters import TsharkPacketAdapter
from arenyxa.infrastructure.capture.packet_models import PacketRecord


class PacketRowProjectionMixin:
    """Bounded field normalization for TShark row projections."""

    @staticmethod
    def _unquote(value: str) -> str:
        text = str(value)
        if len(text) >= 2 and text[0] == text[-1] == '"':
            return text[1:-1].replace('""', '"')
        return text

    @staticmethod
    def _first(value: str) -> str:
        return str(value or "").split(",", 1)[0].strip()

    @classmethod
    def _int_or_none(cls, value: str) -> int | None:
        text = cls._first(value)
        try:
            return int(text) if text else None
        except (TypeError, ValueError, OverflowError):
            return None

    @classmethod
    def _float_text_to_iso(cls, value: str) -> str:
        return TsharkPacketAdapter._epoch_timestamp(cls._first(value))

    @staticmethod
    def _iso_to_epoch(value: str) -> float:
        text = str(value or "").strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return float(datetime.fromisoformat(text).timestamp())

    @classmethod
    def _packet_from_row(cls, row: Mapping[str, str]) -> PacketRecord | None:
        frame_number = cls._int_or_none(row.get("frame.number", ""))
        if frame_number is None:
            return None
        source = cls._first(row.get("ip.src", "")) or cls._first(row.get("ipv6.src", "")) or cls._first(row.get("eth.src", ""))
        destination = cls._first(row.get("ip.dst", "")) or cls._first(row.get("ipv6.dst", "")) or cls._first(row.get("eth.dst", ""))
        source_port = cls._int_or_none(row.get("tcp.srcport", ""))
        if source_port is None:
            source_port = cls._int_or_none(row.get("udp.srcport", ""))
        destination_port = cls._int_or_none(row.get("tcp.dstport", ""))
        if destination_port is None:
            destination_port = cls._int_or_none(row.get("udp.dstport", ""))
        analysis_fields = (
            "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
            "tcp.analysis.spurious_retransmission", "tcp.analysis.out_of_order",
            "tcp.analysis.lost_segment", "tcp.analysis.duplicate_ack",
            "tcp.analysis.zero_window", "tcp.analysis.window_full", "tcp.analysis.keep_alive",
        )
        tcp_analysis = [
            name[len("tcp.analysis."):] if name.startswith("tcp.analysis.") else name
            for name in analysis_fields if row.get(name, "")
        ]
        protocols = row.get("frame.protocols", "")
        protocol = cls._first(row.get("_ws.col.Protocol", "")) or (protocols.split(":")[-1] if protocols else "unknown")
        host = (
            cls._first(row.get("http.host", ""))
            or cls._first(row.get("http2.headers.authority", ""))
            or cls._first(row.get("dns.qry.name", ""))
            or cls._first(row.get("tls.handshake.extensions_server_name", ""))
        )
        metadata: dict[str, Any] = {}
        bytes_in_flight = cls._int_or_none(row.get("tcp.analysis.bytes_in_flight", ""))
        if bytes_in_flight is not None:
            metadata["tcp_bytes_in_flight"] = bytes_in_flight
        ack_rtt = cls._first(row.get("tcp.analysis.ack_rtt", ""))
        if ack_rtt:
            try:
                metadata["tcp_ack_rtt_ms"] = float(ack_rtt) * 1000.0
            except (TypeError, ValueError, OverflowError):
                record_current_exception(__name__, 'PacketRowProjectionMixin._packet_from_row:84')
        core_fields = {
            "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.protocols",
            "_ws.col.Protocol", "_ws.col.Info", "eth.src", "eth.dst", "ip.src", "ip.dst",
            "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
            "tcp.stream", "udp.stream", "http2.streamid", "quic.stream.stream_id",
            "dns.qry.name", "tls.handshake.extensions_server_name", "http.request.method",
            "http.host", "http.request.uri", "http.response.code",
        }
        dissector_fields: dict[str, str] = {}
        for name, raw_value in row.items():
            value = str(raw_value or "")
            if name in core_fields or not value:
                continue
            dissector_fields[name] = value[:4096]
            if len(dissector_fields) >= 96:
                break
        if dissector_fields:
            metadata["dissector_fields"] = dissector_fields
        return PacketRecord(
            frame_number=frame_number,
            timestamp=cls._float_text_to_iso(row.get("frame.time_epoch", "")),
            length=cls._int_or_none(row.get("frame.len", "")) or 0,
            captured_length=cls._int_or_none(row.get("frame.cap_len", "")) or 0,
            protocols=protocols,
            protocol=protocol,
            info=row.get("_ws.col.Info", ""),
            source=source,
            destination=destination,
            source_port=source_port,
            destination_port=destination_port,
            tcp_stream=cls._int_or_none(row.get("tcp.stream", "")),
            udp_stream=cls._int_or_none(row.get("udp.stream", "")),
            http2_stream=cls._int_or_none(row.get("http2.streamid", "")),
            quic_stream=cls._int_or_none(row.get("quic.stream.stream_id", "")),
            host=host,
            method=cls._first(row.get("http.request.method", "")) or cls._first(row.get("http2.headers.method", "")),
            uri=cls._first(row.get("http.request.uri", "")) or cls._first(row.get("http2.headers.path", "")),
            status=cls._int_or_none(row.get("http.response.code", "")) or cls._int_or_none(row.get("http2.headers.status", "")),
            tcp_analysis=tcp_analysis,
            metadata=metadata,
        )
