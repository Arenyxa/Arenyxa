from __future__ import annotations

from dataclasses import field
from datetime import datetime
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_SESSIONS = 100_000
_MAX_SESSION_ROWS = 2048
_MAX_CONNECTION_IDS = 32
_MAX_ENDPOINT_PATHS = 64
_MAX_ALPN_HINTS = 16


def _timestamp(value: str) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _quic_fields(packet: PacketRecord) -> dict[str, Any]:
    layers = packet.metadata.get("native_layers")
    if not isinstance(layers, list):
        return {}
    for layer in layers:
        if isinstance(layer, Mapping) and str(layer.get("name") or "").casefold() == "quic":
            fields = layer.get("fields")
            return dict(fields) if isinstance(fields, Mapping) else {}
    return {}


def _flow_key(packet: PacketRecord) -> tuple[str, int, str, int] | None:
    if packet.source_port is None or packet.destination_port is None or not packet.source or not packet.destination:
        return None
    return (packet.source, int(packet.source_port), packet.destination, int(packet.destination_port))


def _canonical_path(packet: PacketRecord) -> tuple[tuple[str, int], tuple[str, int]] | None:
    flow = _flow_key(packet)
    if flow is None:
        return None
    left = (flow[0], flow[1])
    right = (flow[2], flow[3])
    return (left, right) if left <= right else (right, left)


def _connection_ids(fields: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for key in ("destination_connection_id", "source_connection_id"):
        value = str(fields.get(key) or "").strip().casefold()
        if value and value not in values:
            values.append(value)
    return tuple(values)


def _alpn_hints(fields: Mapping[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    for raw in fields.get("alpn_application_hints") if isinstance(fields.get("alpn_application_hints"), list) else []:
        value = str(raw or "").strip().casefold()
        if value and value not in values:
            values.append(value)
    initial = fields.get("initial_decryption") if isinstance(fields.get("initial_decryption"), Mapping) else {}
    hello = initial.get("client_hello") if isinstance(initial.get("client_hello"), Mapping) else {}
    for raw in hello.get("alpn") if isinstance(hello.get("alpn"), list) else []:
        value = str(raw or "").strip().casefold()
        if value and value not in values:
            values.append(value)
    return tuple(values[:_MAX_ALPN_HINTS])


@dataclass(slots=True)
class _QuicSession:
    session_id: int
    first_seen: float | None = None
    last_seen: float | None = None
    packets: int = 0
    bytes: int = 0
    connection_ids: set[str] = field(default_factory=set)
    endpoint_paths: set[tuple[tuple[str, int], tuple[str, int]]] = field(default_factory=set)
    versions: set[str] = field(default_factory=set)
    packet_types: dict[str, int] = field(default_factory=dict)
    alpn_hints: set[str] = field(default_factory=set)
    initial_packets: int = 0
    handshake_packets: int = 0
    zero_rtt_packets: int = 0
    retry_packets: int = 0
    version_negotiation_packets: int = 0
    public_initials_decrypted: int = 0
    fixed_bit_violations: int = 0

    def feed(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        timestamp = _timestamp(packet.timestamp)
        if timestamp is not None:
            self.first_seen = timestamp if self.first_seen is None else min(self.first_seen, timestamp)
            self.last_seen = timestamp if self.last_seen is None else max(self.last_seen, timestamp)
        self.packets += 1
        self.bytes += max(0, int(packet.length))
        for connection_id in _connection_ids(fields):
            if len(self.connection_ids) < _MAX_CONNECTION_IDS:
                self.connection_ids.add(connection_id)
        path = _canonical_path(packet)
        if path is not None and len(self.endpoint_paths) < _MAX_ENDPOINT_PATHS:
            self.endpoint_paths.add(path)
        version = str(fields.get("version_name") or fields.get("version") or "").strip()
        if version:
            self.versions.add(version)
        packet_type = str(fields.get("packet_type") or "short-header").strip() or "short-header"
        self.packet_types[packet_type] = self.packet_types.get(packet_type, 0) + 1
        normalized_type = packet_type.casefold()
        self.initial_packets += int(normalized_type == "initial")
        self.handshake_packets += int(normalized_type == "handshake")
        self.zero_rtt_packets += int(normalized_type == "0-rtt")
        self.retry_packets += int(normalized_type == "retry")
        self.version_negotiation_packets += int(normalized_type == "version negotiation")
        self.public_initials_decrypted += int(isinstance(fields.get("initial_decryption"), Mapping))
        self.fixed_bit_violations += int(fields.get("fixed_bit") is False)
        for hint in _alpn_hints(fields):
            if len(self.alpn_hints) < _MAX_ALPN_HINTS:
                self.alpn_hints.add(hint)

    def summary(self) -> dict[str, Any]:
        duration_ms = None
        if self.first_seen is not None and self.last_seen is not None and self.last_seen >= self.first_seen:
            duration_ms = round((self.last_seen - self.first_seen) * 1000.0, 3)
        paths = [
            {
                "endpoint_a": {"address": path[0][0], "port": path[0][1]},
                "endpoint_b": {"address": path[1][0], "port": path[1][1]},
            }
            for path in sorted(self.endpoint_paths)
        ]
        return {
            "session_id": self.session_id,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration_ms": duration_ms,
            "versions": sorted(self.versions),
            "packet_types": dict(sorted(self.packet_types.items())),
            "connection_ids": sorted(self.connection_ids),
            "endpoint_paths": paths,
            "path_count": len(paths),
            "migration_observed": len(paths) > 1,
            "initial_packets": self.initial_packets,
            "handshake_packets": self.handshake_packets,
            "zero_rtt_packets": self.zero_rtt_packets,
            "retry_packets": self.retry_packets,
            "version_negotiation_packets": self.version_negotiation_packets,
            "public_initials_decrypted": self.public_initials_decrypted,
            "fixed_bit_violations": self.fixed_bit_violations,
            "alpn_hints": sorted(self.alpn_hints),
        }


class QuicSessionAnalyzer:
    """Bounded passive QUIC conversation correlation using observable CIDs and paths.

    Long-header Connection IDs are treated as correlation evidence, not identity or
    authentication. Short-header packets are only associated when the capture backend
    already supplied a QUIC stream index or when their endpoint path maps unambiguously
    to an existing observed session.
    """

    def __init__(self) -> None:
        self._sessions: dict[int, _QuicSession] = {}
        self._cid_to_session: dict[str, int] = {}
        self._stream_to_session: dict[int, int] = {}
        self._path_to_sessions: dict[tuple[tuple[str, int], tuple[str, int]], set[int]] = {}
        self._next_id = 1
        self._session_limit_reached = False

    def _resolve(self, packet: PacketRecord, fields: Mapping[str, Any]) -> _QuicSession | None:
        candidates: set[int] = set()
        for connection_id in _connection_ids(fields):
            existing = self._cid_to_session.get(connection_id)
            if existing is not None:
                candidates.add(existing)
        if packet.quic_stream is not None:
            existing = self._stream_to_session.get(int(packet.quic_stream))
            if existing is not None:
                candidates.add(existing)
        path = _canonical_path(packet)
        if not candidates and path is not None:
            path_sessions = self._path_to_sessions.get(path, set())
            if len(path_sessions) == 1:
                candidates.update(path_sessions)
        if candidates:
            session_id = min(candidates)
            session = self._sessions.get(session_id)
            if session is not None:
                return session
        if len(self._sessions) >= _MAX_SESSIONS:
            self._session_limit_reached = True
            return None
        session = _QuicSession(session_id=self._next_id)
        self._sessions[session.session_id] = session
        self._next_id += 1
        return session

    def feed(self, packet: PacketRecord) -> None:
        fields = _quic_fields(packet)
        if not fields:
            return
        session = self._resolve(packet, fields)
        if session is None:
            return
        session.feed(packet, fields)
        for connection_id in _connection_ids(fields):
            self._cid_to_session.setdefault(connection_id, session.session_id)
        if packet.quic_stream is not None:
            self._stream_to_session.setdefault(int(packet.quic_stream), session.session_id)
        path = _canonical_path(packet)
        if path is not None:
            self._path_to_sessions.setdefault(path, set()).add(session.session_id)

    def finalize(self) -> dict[str, Any]:
        summaries = [session.summary() for session in self._sessions.values()]
        return {
            "schema": "arenyxa.quic-session-analysis/v1",
            "session_count": len(summaries),
            "session_limit_reached": self._session_limit_reached,
            "sessions_with_migration": sum(1 for row in summaries if bool(row.get("migration_observed"))),
            "sessions_with_zero_rtt": sum(1 for row in summaries if int(row.get("zero_rtt_packets") or 0) > 0),
            "sessions_with_retry": sum(1 for row in summaries if int(row.get("retry_packets") or 0) > 0),
            "sessions_with_version_negotiation": sum(
                1 for row in summaries if int(row.get("version_negotiation_packets") or 0) > 0
            ),
            "sessions_with_fixed_bit_violation": sum(
                1 for row in summaries if int(row.get("fixed_bit_violations") or 0) > 0
            ),
            "top_sessions": sorted(
                summaries,
                key=lambda row: (int(row.get("bytes") or 0), int(row.get("packets") or 0)),
                reverse=True,
            )[:_MAX_SESSION_ROWS],
        }
