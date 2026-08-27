from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_PEERS = 100_000
_MAX_TRANSACTIONS = 200_000
_MAX_BLOCKS = 65_536


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _endpoint(address: str, port: int | None) -> str:
    return f"{address}:{port}" if port is not None else str(address or "")


def _pair(packet: PacketRecord) -> tuple[str, str]:
    left = _endpoint(packet.source, packet.source_port)
    right = _endpoint(packet.destination, packet.destination_port)
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
class _Request:
    source: str
    destination: str
    token_hash: str
    message_id: int
    method: str
    confirmable: bool
    began: float | None
    observations: int = 1
    acknowledged: bool = False
    reset: bool = False
    response_seen: bool = False


@dataclass(slots=True)
class _Peer:
    endpoint_a: str
    endpoint_b: str
    messages: Counter[str]
    requests: dict[tuple[str, str, str, int], _Request]
    token_index: dict[tuple[str, str, str], tuple[str, str, str, int]]
    ack_index: dict[tuple[str, str, int], tuple[str, str, str, int]]
    response_latencies_ms: list[float]
    retransmissions: int = 0
    orphan_responses: int = 0
    orphan_acks: int = 0
    resets: int = 0
    observe_messages: int = 0
    block_messages: int = 0
    block_numbers: set[tuple[int, int]] | None = None

    def __post_init__(self) -> None:
        self.block_numbers = self.block_numbers or set()


class CoapSessionForensicsAnalyzer:
    """Correlate CoAP token/message-ID state without retaining token or payload plaintext."""

    def __init__(self) -> None:
        self._peers: dict[tuple[str, str], _Peer] = {}
        self._limits_reached: set[str] = set()

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            if str(layer.get("name") or "").casefold() != "coap":
                continue
            self._feed_coap(packet, _fields(layer))

    def _peer(self, packet: PacketRecord) -> _Peer | None:
        key = _pair(packet)
        state = self._peers.get(key)
        if state is None:
            if len(self._peers) >= _MAX_PEERS:
                self._limits_reached.add("peers")
                return None
            state = _Peer(key[0], key[1], Counter(), {}, {}, {}, [])
            self._peers[key] = state
        return state

    def _feed_coap(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        state = self._peer(packet)
        if state is None:
            return
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        try:
            message_id = int(fields.get("message_id") or 0)
            code_class = int(fields.get("code_class") or 0)
            code_detail = int(fields.get("code_detail") or 0)
            message_type = int(fields.get("type") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        token_hash = str(fields.get("token_sha256") or "")
        code_name = str(fields.get("code_name") or f"{code_class}.{code_detail:02d}")
        state.messages[code_name] += 1
        if fields.get("observe_values"):
            state.observe_messages += 1
        self._feed_blocks(state, fields)
        if code_class == 0 and 1 <= code_detail <= 4:
            self._request(state, source, destination, token_hash, message_id, code_name, message_type, packet)
        elif code_class >= 2:
            self._response(state, source, destination, token_hash, packet)
        elif code_class == 0 and code_detail == 0 and message_type in {2, 3}:
            self._ack_or_reset(state, source, destination, message_id, reset=message_type == 3)

    def _request(
        self,
        state: _Peer,
        source: str,
        destination: str,
        token_hash: str,
        message_id: int,
        method: str,
        message_type: int,
        packet: PacketRecord,
    ) -> None:
        identity = token_hash or f"mid:{message_id}"
        key = (source, destination, identity, message_id)
        existing = state.requests.get(key)
        if existing is not None:
            existing.observations += 1
            state.retransmissions += 1
            return
        if len(state.requests) >= _MAX_TRANSACTIONS:
            self._limits_reached.add("transactions")
            return
        request = _Request(source, destination, token_hash, message_id, method, message_type == 0, _epoch(packet))
        state.requests[key] = request
        state.token_index[(source, destination, identity)] = key
        state.ack_index[(source, destination, message_id)] = key

    def _response(self, state: _Peer, source: str, destination: str, token_hash: str, packet: PacketRecord) -> None:
        if not token_hash:
            state.orphan_responses += 1
            return
        key = state.token_index.get((destination, source, token_hash))
        request = state.requests.get(key) if key is not None else None
        if request is None:
            state.orphan_responses += 1
            return
        if request.response_seen:
            return
        request.response_seen = True
        observed = _epoch(packet)
        if request.began is not None and observed is not None and observed >= request.began:
            if len(state.response_latencies_ms) < _MAX_TRANSACTIONS:
                state.response_latencies_ms.append((observed - request.began) * 1000.0)

    def _ack_or_reset(self, state: _Peer, source: str, destination: str, message_id: int, *, reset: bool) -> None:
        key = state.ack_index.get((destination, source, message_id))
        request = state.requests.get(key) if key is not None else None
        if request is None:
            state.orphan_acks += 1
            return
        if reset:
            request.reset = True
            state.resets += 1
        else:
            request.acknowledged = True

    def _feed_blocks(self, state: _Peer, fields: Mapping[str, Any]) -> None:
        blocks = fields.get("block_options") if isinstance(fields.get("block_options"), list) else []
        if not blocks:
            return
        state.block_messages += 1
        assert state.block_numbers is not None
        for block in blocks[:16]:
            if not isinstance(block, Mapping):
                continue
            try:
                option = int(block.get("number") or 0)
                number = int(block.get("block_number") or 0)
            except (TypeError, ValueError, OverflowError):
                continue
            if len(state.block_numbers) < _MAX_BLOCKS:
                state.block_numbers.add((option, number))

    def finalize(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for state in sorted(self._peers.values(), key=lambda item: (item.endpoint_a, item.endpoint_b)):
            requests = list(state.requests.values())
            rows.append({
                "endpoints": [state.endpoint_a, state.endpoint_b],
                "message_counts": dict(state.messages.most_common()),
                "request_count": len(requests),
                "confirmable_requests": sum(1 for row in requests if row.confirmable),
                "acknowledged_requests": sum(1 for row in requests if row.acknowledged),
                "reset_requests": sum(1 for row in requests if row.reset),
                "responses_correlated": sum(1 for row in requests if row.response_seen),
                "request_retransmissions": state.retransmissions,
                "orphan_responses": state.orphan_responses,
                "orphan_ack_or_reset": state.orphan_acks,
                "response_latency_ms": _latency_summary(state.response_latencies_ms),
                "observe_messages": state.observe_messages,
                "block_messages": state.block_messages,
                "unique_block_numbers": len(state.block_numbers or ()),
            })
        return {
            "schema": "arenyxa.coap-session-forensics/v1",
            "peer_count": len(rows),
            "peers": rows,
            "limits_reached": sorted(self._limits_reached),
            "token_values_retained": False,
            "payload_values_retained": False,
            "interpretation": (
                "Token/message-ID correlation, retransmission, Observe, and block-wise state are passive capture evidence. "
                "Asymmetric capture, proxies, multicast, and token reuse can make a partial trace look incomplete."
            ),
        }
