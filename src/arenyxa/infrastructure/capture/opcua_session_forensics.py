from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_PEERS = 100_000
_MAX_PENDING = 100_000
_MAX_IDS = 65_536


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _endpoint(packet: PacketRecord, *, source: bool) -> str:
    address = packet.source if source else packet.destination
    port = packet.source_port if source else packet.destination_port
    return f"{address}:{port}" if port is not None else str(address or "")


def _pair(packet: PacketRecord) -> tuple[str, str]:
    left = _endpoint(packet, source=True)
    right = _endpoint(packet, source=False)
    return (left, right) if left <= right else (right, left)


def _epoch(packet: PacketRecord) -> float | None:
    text = str(packet.timestamp or "").strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _latency_summary(values: list[float]) -> dict[str, float | int | None]:
    ordered = sorted(value for value in values if value >= 0.0)
    if not ordered:
        return {"samples": 0, "p50": None, "p95": None, "p99": None, "max": None}

    def percentile(fraction: float) -> float:
        index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
        return round(ordered[index], 3)

    return {
        "samples": len(ordered),
        "p50": percentile(0.50),
        "p95": percentile(0.95),
        "p99": percentile(0.99),
        "max": round(ordered[-1], 3),
    }


@dataclass(slots=True)
class _OpenRequest:
    source: str
    destination: str
    request_id: int
    began: float | None
    observations: int = 1
    response_seen: bool = False


@dataclass(slots=True)
class _Peer:
    endpoint_a: str
    endpoint_b: str
    message_types: Counter[str]
    chunk_types: Counter[str]
    client_endpoint: str = ""
    server_endpoint: str = ""
    endpoint_url: str = ""
    hello: dict[str, int] | None = None
    acknowledge: dict[str, int] | None = None
    secure_channels: set[int] | None = None
    token_ids: set[int] | None = None
    opens: dict[tuple[str, str, int], _OpenRequest] | None = None
    open_latencies_ms: list[float] | None = None
    open_retransmissions: int = 0
    orphan_open_responses: int = 0
    aborted_chunks: int = 0
    intermediate_chunks: int = 0
    protected_chunks: int = 0
    connection_errors: int = 0

    def __post_init__(self) -> None:
        self.secure_channels = self.secure_channels or set()
        self.token_ids = self.token_ids or set()
        self.opens = self.opens or {}
        self.open_latencies_ms = self.open_latencies_ms or []


class OpcuaSessionForensicsAnalyzer:
    """Correlate visible OPC UA TCP negotiation and SecureConversation state without decrypting protected bodies."""

    def __init__(self) -> None:
        self._peers: dict[tuple[str, str], _Peer] = {}
        self._limits_reached: set[str] = set()

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            if str(layer.get("name") or "").casefold() != "opcua":
                continue
            self._feed_opcua(packet, _fields(layer))

    def _peer(self, packet: PacketRecord) -> _Peer | None:
        key = _pair(packet)
        state = self._peers.get(key)
        if state is None:
            if len(self._peers) >= _MAX_PEERS:
                self._limits_reached.add("peers")
                return None
            state = _Peer(key[0], key[1], Counter(), Counter())
            self._peers[key] = state
        return state

    @staticmethod
    def _connection_limits(fields: Mapping[str, Any]) -> dict[str, int]:
        row: dict[str, int] = {}
        for key in ("protocol_version", "receive_buffer_size", "send_buffer_size", "max_message_size", "max_chunk_count"):
            try:
                row[key] = max(0, int(fields.get(key) or 0))
            except (TypeError, ValueError, OverflowError):
                row[key] = 0
        return row

    def _feed_opcua(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        state = self._peer(packet)
        if state is None:
            return
        message_type = str(fields.get("message_type") or "unknown")
        chunk = str(fields.get("chunk_type") or "?")
        state.message_types[message_type] += 1
        state.chunk_types[chunk] += 1
        if chunk == "A":
            state.aborted_chunks += 1
        elif chunk == "C":
            state.intermediate_chunks += 1
        source = _endpoint(packet, source=True)
        destination = _endpoint(packet, source=False)

        connection = fields.get("connection")
        if message_type == "HEL" and isinstance(connection, Mapping):
            state.client_endpoint = source
            state.server_endpoint = destination
            state.endpoint_url = str(connection.get("endpoint_url") or "")
            state.hello = self._connection_limits(connection)
            return
        if message_type == "ACK" and isinstance(connection, Mapping):
            if not state.server_endpoint:
                state.server_endpoint = source
                state.client_endpoint = destination
            state.acknowledge = self._connection_limits(connection)
            return
        if message_type == "ERR":
            state.connection_errors += 1
            return

        secure = fields.get("secure")
        if not isinstance(secure, Mapping):
            return
        try:
            channel = int(secure.get("secure_channel_id") or 0)
        except (TypeError, ValueError, OverflowError):
            channel = 0
        assert state.secure_channels is not None
        if channel and len(state.secure_channels) < _MAX_IDS:
            state.secure_channels.add(channel)
        if "security_token_id" in secure:
            try:
                token = int(secure.get("security_token_id") or 0)
            except (TypeError, ValueError, OverflowError):
                token = 0
            assert state.token_ids is not None
            if token and len(state.token_ids) < _MAX_IDS:
                state.token_ids.add(token)
        if not bool(secure.get("sequence_header_visible")):
            state.protected_chunks += 1
            return
        if message_type != "OPN":
            return
        try:
            request_id = int(secure.get("request_id"))
        except (TypeError, ValueError, OverflowError):
            return
        self._feed_open(state, packet, source, destination, request_id)

    def _feed_open(self, state: _Peer, packet: PacketRecord, source: str, destination: str, request_id: int) -> None:
        assert state.opens is not None
        client = state.client_endpoint
        is_request = source == client if client else not any(
            row.destination == source and row.request_id == request_id for row in state.opens.values()
        )
        if is_request:
            key = (source, destination, request_id)
            existing = state.opens.get(key)
            if existing is not None and not existing.response_seen:
                existing.observations += 1
                state.open_retransmissions += 1
                return
            if len(state.opens) >= _MAX_PENDING:
                self._limits_reached.add("open_transactions")
                return
            state.opens[key] = _OpenRequest(source, destination, request_id, _epoch(packet))
            return
        request = state.opens.get((destination, source, request_id))
        if request is None:
            state.orphan_open_responses += 1
            return
        if request.response_seen:
            return
        request.response_seen = True
        ended = _epoch(packet)
        if request.began is not None and ended is not None and ended >= request.began:
            assert state.open_latencies_ms is not None
            if len(state.open_latencies_ms) < _MAX_PENDING:
                state.open_latencies_ms.append((ended - request.began) * 1000.0)

    @staticmethod
    def _negotiation(state: _Peer) -> dict[str, Any]:
        hello = state.hello or {}
        ack = state.acknowledge or {}
        complete = bool(hello and ack)
        violations: list[str] = []
        if complete:
            if ack.get("receive_buffer_size", 0) > hello.get("send_buffer_size", 0) > 0:
                violations.append("ack-receive-exceeds-hello-send")
            if ack.get("send_buffer_size", 0) > hello.get("receive_buffer_size", 0) > 0:
                violations.append("ack-send-exceeds-hello-receive")
        return {"complete": complete, "hello": hello, "acknowledge": ack, "constraint_findings": violations}

    def finalize(self) -> dict[str, Any]:
        peers: list[dict[str, Any]] = []
        for state in sorted(self._peers.values(), key=lambda row: (row.endpoint_a, row.endpoint_b)):
            opens = list((state.opens or {}).values())
            peers.append({
                "endpoints": [state.endpoint_a, state.endpoint_b],
                "client_endpoint": state.client_endpoint,
                "server_endpoint": state.server_endpoint,
                "endpoint_url": state.endpoint_url,
                "message_types": dict(state.message_types.most_common()),
                "chunk_types": dict(state.chunk_types.most_common()),
                "negotiation": self._negotiation(state),
                "secure_channel_ids": sorted(state.secure_channels or ()),
                "security_token_ids": sorted(state.token_ids or ()),
                "open_secure_channel_requests": len(opens),
                "open_secure_channel_correlated": sum(1 for row in opens if row.response_seen),
                "open_secure_channel_retransmissions": state.open_retransmissions,
                "orphan_open_secure_channel_responses": state.orphan_open_responses,
                "open_secure_channel_latency_ms": _latency_summary(state.open_latencies_ms or []),
                "intermediate_chunks": state.intermediate_chunks,
                "aborted_chunks": state.aborted_chunks,
                "protected_chunks_not_interpreted": state.protected_chunks,
                "connection_errors": state.connection_errors,
            })
        return {
            "schema": "arenyxa.opcua-session-forensics/v1",
            "peer_count": len(peers),
            "peers": peers,
            "limits_reached": sorted(self._limits_reached),
            "protected_service_payloads_interpreted_without_verified_decryption": False,
            "interpretation": (
                "OPC UA negotiation, SecureChannel identifiers, chunk state, and visible SecurityPolicy#None OPN IDs are passive evidence. "
                "Protected MSG/CLO service bodies and sequence headers are intentionally not interpreted without verified decryption context."
            ),
        }
