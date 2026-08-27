from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from collections import Counter
from datetime import datetime
from typing import Any, Tuple, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_PEERS = 100_000
_MAX_TRANSACTIONS = 200_000
_MAX_VALUES = 4096


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


_Transaction = Tuple[str, str, str, int]


@dataclass(slots=True)
class _Peer:
    endpoint_a: str
    endpoint_b: str
    messages: Counter[str]
    requests: set[_Transaction]
    responses: set[_Transaction]
    request_started: dict[_Transaction, float]
    transaction_latencies_ms: list[float]
    request_retransmissions: int = 0
    response_retransmissions: int = 0
    error_codes: Counter[int] | None = None
    mapped_addresses: set[tuple[str, int]] | None = None
    relayed_addresses: set[tuple[str, int]] | None = None
    peer_addresses: set[tuple[str, int]] | None = None
    allocation_lifetimes: set[int] | None = None
    channels: set[int] | None = None
    channel_data_packets: int = 0
    channel_data_bytes: int = 0
    ice_nominations: int = 0
    ice_controlling: int = 0
    ice_controlled: int = 0
    unknown_required: set[int] | None = None

    def __post_init__(self) -> None:
        self.error_codes = self.error_codes or Counter()
        self.mapped_addresses = self.mapped_addresses or set()
        self.relayed_addresses = self.relayed_addresses or set()
        self.peer_addresses = self.peer_addresses or set()
        self.allocation_lifetimes = self.allocation_lifetimes or set()
        self.channels = self.channels or set()
        self.unknown_required = self.unknown_required or set()


class StunTurnSessionForensicsAnalyzer:
    """Correlate STUN/ICE/TURN transactions and relay state without credential/data plaintext."""

    def __init__(self) -> None:
        self._peers: dict[tuple[str, str], _Peer] = {}
        self._limits_reached: set[str] = set()

    def _peer(self, packet: PacketRecord) -> _Peer | None:
        key = _pair(packet)
        state = self._peers.get(key)
        if state is None:
            if len(self._peers) >= _MAX_PEERS:
                self._limits_reached.add("peers")
                return None
            state = _Peer(key[0], key[1], Counter(), set(), set(), {}, [])
            self._peers[key] = state
        return state

    def feed(self, packet: PacketRecord) -> None:
        state = self._peer(packet)
        if state is None:
            return
        for layer in _layers(packet):
            name = str(layer.get("name") or "").casefold()
            fields = _fields(layer)
            if name == "stun":
                self._feed_stun(state, packet, fields)
            elif name == "turn-channel-data":
                self._feed_channel(state, fields)

    def _feed_stun(self, state: _Peer, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        transaction = str(fields.get("transaction_id_sha256") or "")
        try:
            method = int(fields.get("method") or 0)
            message_class = int(fields.get("class") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        method_name = str(fields.get("method_name") or f"method-0x{method:03x}")
        class_name = str(fields.get("class_name") or message_class)
        state.messages[f"{method_name}-{class_name}"] += 1
        observed = _epoch(packet)
        if transaction:
            if message_class == 0:
                key: _Transaction = (source, destination, transaction, method)
                if key in state.requests:
                    state.request_retransmissions += 1
                elif len(state.requests) < _MAX_TRANSACTIONS:
                    state.requests.add(key)
                    if observed is not None:
                        state.request_started.setdefault(key, observed)
            elif message_class in {2, 3}:
                key = (destination, source, transaction, method)
                if key in state.responses:
                    state.response_retransmissions += 1
                elif len(state.responses) < _MAX_TRANSACTIONS:
                    state.responses.add(key)
                    began = state.request_started.get(key)
                    if began is not None and observed is not None and observed >= began and len(state.transaction_latencies_ms) < _MAX_TRANSACTIONS:
                        state.transaction_latencies_ms.append((observed - began) * 1000.0)
        self._feed_attributes(state, fields)

    @staticmethod
    def _feed_attributes(state: _Peer, fields: Mapping[str, Any]) -> None:
        unknown = fields.get("unknown_comprehension_required") if isinstance(fields.get("unknown_comprehension_required"), list) else []
        assert state.unknown_required is not None
        for value in unknown[:128]:
            if len(state.unknown_required) < _MAX_VALUES:
                try:
                    state.unknown_required.add(int(value))
                except (TypeError, ValueError, OverflowError):
                    record_current_exception(__name__, 'StunTurnSessionForensicsAnalyzer._feed_attributes:172')
        attributes = fields.get("attributes") if isinstance(fields.get("attributes"), list) else []
        for attr in attributes[:512]:
            if not isinstance(attr, Mapping):
                continue
            try:
                attr_type = int(attr.get("type") or 0)
            except (TypeError, ValueError, OverflowError):
                continue
            if attr_type == 0x0025:
                state.ice_nominations += 1
            elif attr_type == 0x802A:
                state.ice_controlling += 1
            elif attr_type == 0x8029:
                state.ice_controlled += 1
            elif attr_type == 0x0009 and attr.get("error_code") is not None:
                assert state.error_codes is not None
                state.error_codes[int(attr["error_code"])] += 1
            elif attr_type in {0x0001, 0x0020}:
                StunTurnSessionForensicsAnalyzer._add_address(state.mapped_addresses, attr)
            elif attr_type == 0x0016:
                StunTurnSessionForensicsAnalyzer._add_address(state.relayed_addresses, attr)
            elif attr_type == 0x0012:
                StunTurnSessionForensicsAnalyzer._add_address(state.peer_addresses, attr)
            elif attr_type == 0x000D and attr.get("lifetime_seconds") is not None:
                assert state.allocation_lifetimes is not None
                if len(state.allocation_lifetimes) < _MAX_VALUES:
                    state.allocation_lifetimes.add(int(attr["lifetime_seconds"]))
            elif attr_type == 0x000C and attr.get("channel_number") is not None:
                assert state.channels is not None
                if len(state.channels) < _MAX_VALUES:
                    state.channels.add(int(attr["channel_number"]))

    @staticmethod
    def _add_address(target: set[tuple[str, int]] | None, attr: Mapping[str, Any]) -> None:
        if target is None or len(target) >= _MAX_VALUES or not attr.get("address"):
            return
        try:
            target.add((str(attr["address"]), int(attr.get("port") or 0)))
        except (TypeError, ValueError, OverflowError):
            return

    @staticmethod
    def _feed_channel(state: _Peer, fields: Mapping[str, Any]) -> None:
        state.channel_data_packets += 1
        try:
            state.channel_data_bytes += max(0, int(fields.get("data_bytes") or 0))
            channel = int(fields.get("channel_number") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        assert state.channels is not None
        if channel and len(state.channels) < _MAX_VALUES:
            state.channels.add(channel)

    def finalize(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for state in sorted(self._peers.values(), key=lambda item: (item.endpoint_a, item.endpoint_b)):
            paired = state.requests & state.responses
            methods = Counter(str(tx[3]) for tx in paired)
            rows.append({
                "endpoints": [state.endpoint_a, state.endpoint_b],
                "message_counts": dict(state.messages.most_common()),
                "paired_transactions": len(paired),
                "paired_method_codes": dict(methods.most_common()),
                "outstanding_requests": len(state.requests - state.responses),
                "orphan_responses": len(state.responses - state.requests),
                "request_retransmissions": state.request_retransmissions,
                "response_retransmissions": state.response_retransmissions,
                "transaction_latency_ms": _latency_summary(state.transaction_latencies_ms),
                "error_codes": {str(key): value for key, value in (state.error_codes or Counter()).most_common()},
                "mapped_addresses": [{"address": address, "port": port} for address, port in sorted(state.mapped_addresses or ())],
                "relayed_addresses": [{"address": address, "port": port} for address, port in sorted(state.relayed_addresses or ())],
                "peer_addresses": [{"address": address, "port": port} for address, port in sorted(state.peer_addresses or ())],
                "allocation_lifetimes_seconds": sorted(state.allocation_lifetimes or ()),
                "channel_numbers": sorted(state.channels or ()),
                "channel_data_packets": state.channel_data_packets,
                "channel_data_bytes": state.channel_data_bytes,
                "ice_nominations": state.ice_nominations,
                "ice_controlling_messages": state.ice_controlling,
                "ice_controlled_messages": state.ice_controlled,
                "unknown_comprehension_required": sorted(state.unknown_required or ()),
            })
        return {
            "schema": "arenyxa.stun-turn-session-forensics/v1",
            "peer_count": len(rows),
            "peers": rows,
            "limits_reached": sorted(self._limits_reached),
            "credential_values_retained": False,
            "integrity_values_retained": False,
            "relay_data_values_retained": False,
            "interpretation": (
                "STUN transaction, ICE nomination, and TURN allocation/channel state are passive capture evidence. "
                "NAT rebinding, anycast, proxies, asymmetric capture, and transaction reuse must be considered before treating this as a complete connectivity lifecycle."
            ),
        }
