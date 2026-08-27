from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from collections import Counter
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_TUNNELS = 100_000
_MAX_CALLS = 200_000
_MAX_SEQUENCE_TRACK = 65_536


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _endpoint(address: str, port: int | None) -> str:
    host = str(address or "")
    return f"{host}:{port}" if port is not None else host


def _assigned_id(fields: Mapping[str, Any], attr_type: int) -> int | None:
    avps = fields.get("avps") if isinstance(fields.get("avps"), list) else []
    for avp in avps[:256]:
        if not isinstance(avp, Mapping) or int(avp.get("vendor_id") or 0) != 0:
            continue
        if int(avp.get("attribute_type") or -1) != attr_type or avp.get("value") is None:
            continue
        try:
            return int(avp["value"])
        except (TypeError, ValueError, OverflowError):
            return None
    return None


@dataclass(slots=True)
class _ModuloSequence:
    observations: int = 0
    highest: int = -1
    seen: set[int] | None = None
    duplicates: int = 0
    backwards: int = 0
    estimated_gaps: int = 0
    wraps: int = 0

    def __post_init__(self) -> None:
        if self.seen is None:
            self.seen = set()

    def observe(self, value: int) -> None:
        value &= 0xFFFF
        self.observations += 1
        seen = self.seen
        assert seen is not None
        if value in seen:
            self.duplicates += 1
            return
        if len(seen) < _MAX_SEQUENCE_TRACK:
            seen.add(value)
        if self.highest >= 0:
            if self.highest > 0xF000 and value < 0x1000:
                self.wraps += 1
            elif value < self.highest:
                self.backwards += 1
            elif value > self.highest + 1:
                self.estimated_gaps += value - self.highest - 1
        if not (self.highest > 0xF000 and value < 0x1000):
            self.highest = max(self.highest, value)
        else:
            self.highest = value

    def as_dict(self) -> dict[str, Any]:
        return {
            "observations": self.observations,
            "highest_ns_observed": self.highest,
            "unique_values_tracked": len(self.seen or ()),
            "duplicate_observations": self.duplicates,
            "backwards_observations": self.backwards,
            "estimated_gaps": self.estimated_gaps,
            "wrap_observations": self.wraps,
        }


@dataclass(slots=True)
class _Call:
    internal_id: int
    kind: str
    requester: str
    responder: str
    local_session_ids: dict[str, int]
    message_counts: Counter[str]
    data_packets: Counter[str]
    data_bytes: Counter[str]
    data_sequences: dict[str, _ModuloSequence]


@dataclass(slots=True)
class _Tunnel:
    internal_id: int
    initiator: str
    responder: str
    local_tunnel_ids: dict[str, int]
    message_counts: Counter[str]
    control_sequences: dict[str, _ModuloSequence]
    calls: dict[int, _Call]
    next_call_id: int = 1


class L2tpSessionForensicsAnalyzer:
    """Correlate RFC 2661 local Tunnel/Session IDs without retaining PPP payloads."""

    def __init__(self) -> None:
        self._tunnels: dict[int, _Tunnel] = {}
        self._tunnel_by_recipient_id: dict[tuple[str, int], int] = {}
        self._call_by_recipient_id: dict[tuple[int, str, int], int] = {}
        self._next_tunnel_id = 1
        self._call_count = 0
        self._tunnel_limit_reached = False
        self._call_limit_reached = False
        self._orphan_control_packets = 0
        self._orphan_data_packets = 0

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            if str(layer.get("name") or "").casefold() != "l2tp":
                continue
            fields = _fields(layer)
            if bool(fields.get("control")):
                self._feed_control(packet, fields)
            else:
                self._feed_data(packet, fields)

    def _new_tunnel(self, source: str, destination: str, assigned_id: int) -> _Tunnel | None:
        if len(self._tunnels) >= _MAX_TUNNELS:
            self._tunnel_limit_reached = True
            return None
        internal = self._next_tunnel_id
        self._next_tunnel_id += 1
        state = _Tunnel(internal, source, destination, {source: assigned_id}, Counter(), {}, {})
        self._tunnels[internal] = state
        self._tunnel_by_recipient_id[(source, assigned_id)] = internal
        return state

    def _tunnel_for_control(self, source: str, destination: str, fields: Mapping[str, Any]) -> _Tunnel | None:
        try:
            tunnel_id = int(fields.get("tunnel_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return None
        message_name = str(fields.get("message_name") or "")
        assigned = _assigned_id(fields, 9)
        if message_name == "SCCRQ" and tunnel_id == 0 and assigned is not None:
            existing = self._tunnel_by_recipient_id.get((source, assigned))
            if existing is not None:
                return self._tunnels.get(existing)
            return self._new_tunnel(source, destination, assigned)
        internal = self._tunnel_by_recipient_id.get((destination, tunnel_id))
        state = self._tunnels.get(internal) if internal is not None else None
        if state is not None and assigned is not None and message_name in {"SCCRP", "SCCRQ"}:
            state.local_tunnel_ids[source] = assigned
            self._tunnel_by_recipient_id[(source, assigned)] = state.internal_id
        return state

    def _feed_control(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        state = self._tunnel_for_control(source, destination, fields)
        if state is None:
            self._orphan_control_packets += 1
            return
        message_name = str(fields.get("message_name") or "unknown")
        state.message_counts[message_name] += 1
        if fields.get("ns") is not None:
            try:
                sequence = state.control_sequences.setdefault(source, _ModuloSequence())
                sequence.observe(int(fields["ns"]))
            except (TypeError, ValueError, OverflowError):
                record_current_exception(__name__, 'L2tpSessionForensicsAnalyzer._feed_control:184')
        if message_name in {"ICRQ", "OCRQ", "ICRP", "OCRP", "ICCN", "OCCN", "CDN"}:
            self._feed_call_control(state, source, destination, message_name, fields)

    def _new_call(self, tunnel: _Tunnel, source: str, destination: str, kind: str, local_id: int) -> _Call | None:
        if self._call_count >= _MAX_CALLS:
            self._call_limit_reached = True
            return None
        internal = tunnel.next_call_id
        tunnel.next_call_id += 1
        call = _Call(internal, kind, source, destination, {source: local_id}, Counter(), Counter(), Counter(), {})
        tunnel.calls[internal] = call
        self._call_count += 1
        self._call_by_recipient_id[(tunnel.internal_id, source, local_id)] = internal
        return call

    def _feed_call_control(
        self,
        tunnel: _Tunnel,
        source: str,
        destination: str,
        message_name: str,
        fields: Mapping[str, Any],
    ) -> None:
        try:
            header_session_id = int(fields.get("session_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        assigned = _assigned_id(fields, 14)
        call: _Call | None = None
        if message_name in {"ICRQ", "OCRQ"} and assigned is not None:
            existing = self._call_by_recipient_id.get((tunnel.internal_id, source, assigned))
            call = tunnel.calls.get(existing) if existing is not None else None
            if call is None:
                call = self._new_call(tunnel, source, destination, "incoming" if message_name == "ICRQ" else "outgoing", assigned)
        elif header_session_id:
            internal = self._call_by_recipient_id.get((tunnel.internal_id, destination, header_session_id))
            call = tunnel.calls.get(internal) if internal is not None else None
        if call is None:
            return
        call.message_counts[message_name] += 1
        if assigned is not None and message_name in {"ICRP", "OCRP"}:
            call.local_session_ids[source] = assigned
            self._call_by_recipient_id[(tunnel.internal_id, source, assigned)] = call.internal_id

    def _feed_data(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        try:
            tunnel_id = int(fields.get("tunnel_id") or 0)
            session_id = int(fields.get("session_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        internal = self._tunnel_by_recipient_id.get((destination, tunnel_id))
        tunnel = self._tunnels.get(internal) if internal is not None else None
        if tunnel is None or not session_id:
            self._orphan_data_packets += 1
            return
        call_internal = self._call_by_recipient_id.get((tunnel.internal_id, destination, session_id))
        call = tunnel.calls.get(call_internal) if call_internal is not None else None
        if call is None:
            self._orphan_data_packets += 1
            return
        direction = f"{source}->{destination}"
        call.data_packets[direction] += 1
        call.data_bytes[direction] += int(fields.get("decoded_length") or packet.length or 0)
        if fields.get("ns") is not None:
            try:
                call.data_sequences.setdefault(direction, _ModuloSequence()).observe(int(fields["ns"]))
            except (TypeError, ValueError, OverflowError):
                record_current_exception(__name__, 'L2tpSessionForensicsAnalyzer._feed_data:254')

    def finalize(self) -> dict[str, Any]:
        tunnel_rows: list[dict[str, Any]] = []
        call_count = 0
        for tunnel in sorted(self._tunnels.values(), key=lambda item: item.internal_id):
            calls: list[dict[str, Any]] = []
            for call in sorted(tunnel.calls.values(), key=lambda item: item.internal_id):
                call_count += 1
                connected = bool(call.message_counts.get("ICCN") or call.message_counts.get("OCCN"))
                disconnected = bool(call.message_counts.get("CDN"))
                calls.append({
                    "kind": call.kind,
                    "requester": call.requester,
                    "responder": call.responder,
                    "local_session_ids": dict(sorted(call.local_session_ids.items())),
                    "message_counts": dict(call.message_counts.most_common()),
                    "connected_signal_observed": connected,
                    "disconnect_signal_observed": disconnected,
                    "data_packets": dict(call.data_packets.most_common()),
                    "data_bytes": dict(call.data_bytes.most_common()),
                    "data_sequences": {key: value.as_dict() for key, value in sorted(call.data_sequences.items())},
                })
            tunnel_rows.append({
                "initiator": tunnel.initiator,
                "responder": tunnel.responder,
                "local_tunnel_ids": dict(sorted(tunnel.local_tunnel_ids.items())),
                "message_counts": dict(tunnel.message_counts.most_common()),
                "sccrq_observed": bool(tunnel.message_counts.get("SCCRQ")),
                "sccrp_observed": bool(tunnel.message_counts.get("SCCRP")),
                "scccn_observed": bool(tunnel.message_counts.get("SCCCN")),
                "stopccn_observed": bool(tunnel.message_counts.get("StopCCN")),
                "control_handshake_signals_complete": all(tunnel.message_counts.get(name) for name in ("SCCRQ", "SCCRP", "SCCCN")),
                "control_sequences": {key: value.as_dict() for key, value in sorted(tunnel.control_sequences.items())},
                "calls": calls,
            })
        return {
            "schema": "arenyxa.l2tp-session-forensics/v1",
            "tunnel_count": len(tunnel_rows),
            "call_count": call_count,
            "tunnel_limit_reached": self._tunnel_limit_reached,
            "call_limit_reached": self._call_limit_reached,
            "orphan_control_packets": self._orphan_control_packets,
            "orphan_data_packets": self._orphan_data_packets,
            "tunnels": tunnel_rows,
            "ppp_payload_retained": False,
            "interpretation": (
                "L2TP Tunnel ID and Session ID values have local significance. Correlation therefore follows recipient-local IDs learned from visible "
                "Assigned Tunnel/Session ID AVPs; hidden or missing AVPs are not guessed. Handshake/message presence is capture evidence, not proof "
                "that the underlying PPP authentication or user session succeeded."
            ),
        }
