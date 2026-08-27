from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from dataclasses import field
from datetime import datetime
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_SESSIONS = 100_000
_MAX_SESSION_ROWS = 2048


def _timestamp(value: str) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _tcp_fields(packet: PacketRecord) -> dict[str, Any]:
    layers = packet.metadata.get("native_layers")
    if not isinstance(layers, list):
        return {}
    for layer in layers:
        if isinstance(layer, Mapping) and str(layer.get("name") or "").casefold() == "tcp":
            fields = layer.get("fields")
            return dict(fields) if isinstance(fields, Mapping) else {}
    return {}


def _endpoint(address: str, port: int) -> tuple[str, int]:
    return (str(address), int(port))


def _canonical_key(packet: PacketRecord) -> tuple[tuple[str, int], tuple[str, int]] | None:
    if packet.source_port is None or packet.destination_port is None or not packet.source or not packet.destination:
        return None
    left = _endpoint(packet.source, int(packet.source_port))
    right = _endpoint(packet.destination, int(packet.destination_port))
    return (left, right) if left <= right else (right, left)


@dataclass(slots=True)
class _TcpSession:
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    first_seen: float | None = None
    last_seen: float | None = None
    packets: int = 0
    bytes: int = 0
    a_to_b_packets: int = 0
    b_to_a_packets: int = 0
    a_to_b_bytes: int = 0
    b_to_a_bytes: int = 0
    initiator: tuple[str, int] | None = None
    syn_time: float | None = None
    syn_ack_time: float | None = None
    established_time: float | None = None
    reset_count: int = 0
    fin_count: int = 0
    syn_count: int = 0
    syn_ack_count: int = 0
    fin_sides: set[tuple[str, int]] = field(default_factory=set)
    retransmissions: int = 0
    out_of_order: int = 0
    zero_windows: int = 0
    max_window: int = 0
    applications: set[str] = field(default_factory=set)

    def feed(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        timestamp = _timestamp(packet.timestamp)
        if timestamp is not None:
            self.first_seen = timestamp if self.first_seen is None else min(self.first_seen, timestamp)
            self.last_seen = timestamp if self.last_seen is None else max(self.last_seen, timestamp)
        self.packets += 1
        self.bytes += max(0, int(packet.length))
        source = _endpoint(packet.source, int(packet.source_port or 0))
        if source == self.endpoint_a:
            self.a_to_b_packets += 1
            self.a_to_b_bytes += max(0, int(packet.length))
        else:
            self.b_to_a_packets += 1
            self.b_to_a_bytes += max(0, int(packet.length))
        protocol = str(packet.protocol or "").casefold()
        if protocol and protocol not in {"tcp", "unknown"} and len(self.applications) < 16:
            self.applications.add(protocol)

        flags = {str(item).casefold() for item in fields.get("flags") or ()}
        syn = "syn" in flags
        ack = "ack" in flags
        if syn and not ack:
            self.syn_count += 1
            if self.initiator is None:
                self.initiator = source
                self.syn_time = timestamp
        elif syn and ack:
            self.syn_ack_count += 1
            if self.initiator is not None and source != self.initiator and self.syn_ack_time is None:
                self.syn_ack_time = timestamp
        elif ack and not syn and self.initiator is not None and source == self.initiator and self.syn_ack_time is not None and self.established_time is None:
            self.established_time = timestamp

        if "rst" in flags:
            self.reset_count += 1
        if "fin" in flags:
            self.fin_count += 1
            self.fin_sides.add(source)
        indicators = {str(item).casefold() for item in packet.tcp_analysis}
        self.retransmissions += int("retransmission" in indicators)
        self.out_of_order += int("out_of_order" in indicators)
        self.zero_windows += int("zero_window" in indicators)
        try:
            self.max_window = max(self.max_window, int(fields.get("window") or 0))
        except (TypeError, ValueError, OverflowError):
            record_current_exception(__name__, '_TcpSession.feed:116')

    def summary(self) -> dict[str, Any]:
        syn_ack_ms = None
        handshake_ms = None
        if self.syn_time is not None and self.syn_ack_time is not None and self.syn_ack_time >= self.syn_time:
            syn_ack_ms = round((self.syn_ack_time - self.syn_time) * 1000.0, 3)
        if self.syn_time is not None and self.established_time is not None and self.established_time >= self.syn_time:
            handshake_ms = round((self.established_time - self.syn_time) * 1000.0, 3)
        duration_ms = None
        if self.first_seen is not None and self.last_seen is not None and self.last_seen >= self.first_seen:
            duration_ms = round((self.last_seen - self.first_seen) * 1000.0, 3)
        if self.reset_count:
            state = "reset"
        elif len(self.fin_sides) >= 2:
            state = "closed"
        elif self.established_time is not None:
            state = "established"
        elif self.syn_time is not None:
            state = "half-open"
        else:
            state = "midstream-observed"
        client = self.initiator
        server = None
        if client is not None:
            server = self.endpoint_b if client == self.endpoint_a else self.endpoint_a
        return {
            "endpoint_a": {"address": self.endpoint_a[0], "port": self.endpoint_a[1]},
            "endpoint_b": {"address": self.endpoint_b[0], "port": self.endpoint_b[1]},
            "initiator": (
                {"address": self.initiator[0], "port": self.initiator[1]}
                if self.initiator is not None else None
            ),
            "client": {"address": client[0], "port": client[1]} if client is not None else None,
            "server": {"address": server[0], "port": server[1]} if server is not None else None,
            "state": state,
            "packets": self.packets,
            "bytes": self.bytes,
            "a_to_b": {"packets": self.a_to_b_packets, "bytes": self.a_to_b_bytes},
            "b_to_a": {"packets": self.b_to_a_packets, "bytes": self.b_to_a_bytes},
            "duration_ms": duration_ms,
            "syn_ack_ms": syn_ack_ms,
            "handshake_ms": handshake_ms,
            "established_observed": self.established_time is not None,
            "reset_count": self.reset_count,
            "fin_count": self.fin_count,
            "syn_count": self.syn_count,
            "syn_ack_count": self.syn_ack_count,
            "bidirectional_fin_observed": len(self.fin_sides) >= 2,
            "handshake_incomplete": self.syn_time is not None and self.established_time is None,
            "retransmissions": self.retransmissions,
            "out_of_order": self.out_of_order,
            "zero_windows": self.zero_windows,
            "max_window": self.max_window,
            "applications": sorted(self.applications),
        }


class TcpSessionAnalyzer:
    """Bounded bidirectional TCP state summary for passive capture forensics."""

    def __init__(self) -> None:
        self._sessions: dict[tuple[tuple[str, int], tuple[str, int]], _TcpSession] = {}
        self._session_limit_reached = False

    def feed(self, packet: PacketRecord) -> None:
        fields = _tcp_fields(packet)
        if not fields:
            return
        key = _canonical_key(packet)
        if key is None:
            return
        session = self._sessions.get(key)
        if session is None:
            if len(self._sessions) >= _MAX_SESSIONS:
                self._session_limit_reached = True
                return
            session = _TcpSession(endpoint_a=key[0], endpoint_b=key[1])
            self._sessions[key] = session
        session.feed(packet, fields)

    @staticmethod
    def _percentile(values: list[float], fraction: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
        return round(ordered[index], 3)

    def finalize(self) -> dict[str, Any]:
        summaries = [session.summary() for session in self._sessions.values()]
        handshake = [float(row["handshake_ms"]) for row in summaries if row.get("handshake_ms") is not None]
        syn_ack = [float(row["syn_ack_ms"]) for row in summaries if row.get("syn_ack_ms") is not None]
        return {
            "schema": "arenyxa.tcp-session-analysis/v1",
            "session_count": len(summaries),
            "session_limit_reached": self._session_limit_reached,
            "established_sessions": sum(1 for row in summaries if bool(row.get("established_observed"))),
            "reset_sessions": sum(1 for row in summaries if int(row.get("reset_count") or 0) > 0),
            "closed_sessions": sum(1 for row in summaries if row.get("state") == "closed"),
            "half_open_sessions": sum(1 for row in summaries if row.get("state") == "half-open"),
            "midstream_sessions": sum(1 for row in summaries if row.get("state") == "midstream-observed"),
            "sessions_with_retransmission": sum(1 for row in summaries if int(row.get("retransmissions") or 0) > 0),
            "sessions_with_zero_window": sum(1 for row in summaries if int(row.get("zero_windows") or 0) > 0),
            "handshake_ms": {
                "p50": self._percentile(handshake, 0.50),
                "p95": self._percentile(handshake, 0.95),
                "p99": self._percentile(handshake, 0.99),
            },
            "syn_ack_ms": {
                "p50": self._percentile(syn_ack, 0.50),
                "p95": self._percentile(syn_ack, 0.95),
                "p99": self._percentile(syn_ack, 0.99),
            },
            "top_sessions": sorted(
                summaries,
                key=lambda row: (int(row.get("bytes") or 0), int(row.get("packets") or 0)),
                reverse=True,
            )[:_MAX_SESSION_ROWS],
        }
