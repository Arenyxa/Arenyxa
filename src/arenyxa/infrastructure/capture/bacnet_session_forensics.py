from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_PEERS = 100_000
_MAX_PENDING = 200_000
_MAX_LATENCIES = 200_000


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
    invoke_id: int
    service: str
    began: float | None
    observations: int = 1
    response_kind: str = ""


@dataclass(slots=True)
class _Peer:
    endpoint_a: str
    endpoint_b: str
    bvlc_functions: Counter[str]
    apdu_types: Counter[str]
    services: Counter[str]
    network_messages: Counter[str]
    requests: dict[tuple[str, str, int], _Request]
    response_latencies_ms: list[float]
    retransmissions: int = 0
    orphan_responses: int = 0
    segmented_messages: int = 0
    who_is: int = 0
    i_am: int = 0
    forwarded_npdus: int = 0
    foreign_registrations: int = 0
    foreign_registration_ttl_max: int = 0


class BacnetSessionForensicsAnalyzer:
    """Correlate visible BACnet/IP discovery, transaction, BBMD, and APDU state."""

    def __init__(self) -> None:
        self._peers: dict[tuple[str, str], _Peer] = {}
        self._limits_reached: set[str] = set()

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            if str(layer.get("name") or "").casefold() != "bacnet-ip":
                continue
            self._feed_bacnet(packet, _fields(layer))

    def _peer(self, packet: PacketRecord) -> _Peer | None:
        key = _pair(packet)
        state = self._peers.get(key)
        if state is None:
            if len(self._peers) >= _MAX_PEERS:
                self._limits_reached.add("peers")
                return None
            state = _Peer(key[0], key[1], Counter(), Counter(), Counter(), Counter(), {}, [])
            self._peers[key] = state
        return state

    def _feed_bacnet(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        state = self._peer(packet)
        if state is None:
            return
        function = str(fields.get("bvlc_function_name") or "unknown")
        state.bvlc_functions[function] += 1
        if function == "forwarded-npdu":
            state.forwarded_npdus += 1
        if function == "register-foreign-device":
            state.foreign_registrations += 1
            try:
                ttl = max(0, int(fields.get("foreign_device_ttl_seconds") or 0))
            except (TypeError, ValueError, OverflowError):
                ttl = 0
            state.foreign_registration_ttl_max = max(state.foreign_registration_ttl_max, ttl)

        npdu = fields.get("npdu")
        if not isinstance(npdu, Mapping):
            return
        if bool(npdu.get("network_layer_message")):
            name = str(npdu.get("network_message_name") or "unknown")
            state.network_messages[name] += 1
            return
        apdu = npdu.get("apdu")
        if not isinstance(apdu, Mapping):
            return
        self._feed_apdu(state, packet, apdu)

    def _feed_apdu(self, state: _Peer, packet: PacketRecord, apdu: Mapping[str, Any]) -> None:
        pdu = str(apdu.get("pdu_type_name") or "unknown")
        service = str(apdu.get("service_name") or "")
        state.apdu_types[pdu] += 1
        if service:
            state.services[service] += 1
        if bool(apdu.get("segmented_message")):
            state.segmented_messages += 1
        if service == "who-is":
            state.who_is += 1
        elif service == "i-am":
            state.i_am += 1

        if pdu == "confirmed-request":
            self._request(state, packet, apdu, service)
        elif pdu in {"simple-ack", "complex-ack", "error", "reject", "abort"}:
            self._response(state, packet, apdu, pdu)

    def _request(self, state: _Peer, packet: PacketRecord, apdu: Mapping[str, Any], service: str) -> None:
        try:
            invoke_id = int(apdu.get("invoke_id"))
        except (TypeError, ValueError, OverflowError):
            return
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        key = (source, destination, invoke_id)
        existing = state.requests.get(key)
        if existing is not None and not existing.response_kind:
            existing.observations += 1
            state.retransmissions += 1
            return
        if len(state.requests) >= _MAX_PENDING:
            self._limits_reached.add("transactions")
            return
        state.requests[key] = _Request(source, destination, invoke_id, service, _epoch(packet))

    def _response(self, state: _Peer, packet: PacketRecord, apdu: Mapping[str, Any], response_kind: str) -> None:
        try:
            invoke_id = int(apdu.get("invoke_id"))
        except (TypeError, ValueError, OverflowError):
            return
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        request = state.requests.get((destination, source, invoke_id))
        if request is None:
            state.orphan_responses += 1
            return
        if request.response_kind:
            return
        request.response_kind = response_kind
        began = request.began
        ended = _epoch(packet)
        if began is not None and ended is not None and ended >= began and len(state.response_latencies_ms) < _MAX_LATENCIES:
            state.response_latencies_ms.append((ended - began) * 1000.0)

    def finalize(self) -> dict[str, Any]:
        peers: list[dict[str, Any]] = []
        total_requests = 0
        total_correlated = 0
        for state in sorted(self._peers.values(), key=lambda row: (row.endpoint_a, row.endpoint_b)):
            requests = list(state.requests.values())
            correlated = sum(1 for row in requests if row.response_kind)
            total_requests += len(requests)
            total_correlated += correlated
            peers.append({
                "endpoints": [state.endpoint_a, state.endpoint_b],
                "bvlc_functions": dict(state.bvlc_functions.most_common()),
                "apdu_types": dict(state.apdu_types.most_common()),
                "services": dict(state.services.most_common()),
                "network_messages": dict(state.network_messages.most_common()),
                "confirmed_requests": len(requests),
                "correlated_responses": correlated,
                "pending_requests": sum(1 for row in requests if not row.response_kind),
                "request_retransmissions": state.retransmissions,
                "orphan_responses": state.orphan_responses,
                "response_latency_ms": _latency_summary(state.response_latencies_ms),
                "segmented_messages": state.segmented_messages,
                "discovery": {"who_is": state.who_is, "i_am": state.i_am},
                "bbmd": {
                    "forwarded_npdus": state.forwarded_npdus,
                    "foreign_registrations": state.foreign_registrations,
                    "max_requested_ttl_seconds": state.foreign_registration_ttl_max,
                },
            })
        return {
            "schema": "arenyxa.bacnet-session-forensics/v1",
            "peer_count": len(peers),
            "confirmed_requests": total_requests,
            "correlated_responses": total_correlated,
            "peers": peers,
            "limits_reached": sorted(self._limits_reached),
            "service_payload_values_retained": False,
            "interpretation": (
                "BACnet transaction, discovery, BBMD, and routing state is passive capture evidence. "
                "Asymmetric capture, NAT, BBMD forwarding, invoke-ID reuse, and segmented traffic can make a partial trace incomplete."
            ),
        }
