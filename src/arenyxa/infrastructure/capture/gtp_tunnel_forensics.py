from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from collections import Counter
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_CONTROL_SESSIONS = 100_000
_MAX_USER_TUNNELS = 200_000
_MAX_TRANSACTION_KEYS = 200_000
_MAX_METADATA_VALUES = 1024
_MAX_SEQUENCE_TRACK = 65_536

_REQUEST_TO_RESPONSE = {
    1: 2,
    32: 33,
    34: 35,
    36: 37,
    38: 39,
    64: 65,
    68: 69,
    95: 96,
    97: 98,
    99: 100,
    170: 171,
    176: 177,
}
_RESPONSE_TO_REQUEST = {response: request for request, response in _REQUEST_TO_RESPONSE.items()}


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _endpoint(address: str, port: int | None) -> str:
    host = str(address or "")
    return f"{host}:{port}" if port is not None else host


def _pair(packet: PacketRecord) -> tuple[str, str]:
    left = _endpoint(packet.source, packet.source_port)
    right = _endpoint(packet.destination, packet.destination_port)
    return (left, right) if left <= right else (right, left)


@dataclass(slots=True)
class _SequenceState:
    observations: int = 0
    highest: int = -1
    unique: set[int] | None = None
    duplicates: int = 0
    out_of_order: int = 0
    estimated_gaps: int = 0

    def __post_init__(self) -> None:
        if self.unique is None:
            self.unique = set()

    def observe(self, value: int) -> None:
        self.observations += 1
        seen = self.unique
        assert seen is not None
        if value in seen:
            self.duplicates += 1
            return
        if len(seen) < _MAX_SEQUENCE_TRACK:
            seen.add(value)
        if self.highest >= 0:
            if value < self.highest:
                self.out_of_order += 1
            elif value > self.highest + 1:
                self.estimated_gaps += value - self.highest - 1
        self.highest = max(self.highest, value)

    def as_dict(self) -> dict[str, Any]:
        return {
            "observations": self.observations,
            "highest_sequence_observed": self.highest,
            "unique_sequences_tracked": len(self.unique or ()),
            "duplicate_sequence_observations": self.duplicates,
            "out_of_order_sequence_observations": self.out_of_order,
            "estimated_missing_sequences": self.estimated_gaps,
        }


@dataclass(slots=True)
class _ControlSession:
    endpoint_a: str
    endpoint_b: str
    message_counts: Counter[str]
    request_keys: set[tuple[int, int]]
    response_keys: set[tuple[int, int]]
    request_retransmissions: int = 0
    response_retransmissions: int = 0
    apns: set[str] | None = None
    rats: set[str] | None = None
    subscriber_hashes: set[str] | None = None
    fteids: set[tuple[int, int, str, str]] | None = None
    accepted_causes: Counter[int] | None = None
    rejected_causes: Counter[int] | None = None
    observations: int = 0

    def __post_init__(self) -> None:
        if self.apns is None:
            self.apns = set()
        if self.rats is None:
            self.rats = set()
        if self.subscriber_hashes is None:
            self.subscriber_hashes = set()
        if self.fteids is None:
            self.fteids = set()
        if self.accepted_causes is None:
            self.accepted_causes = Counter()
        if self.rejected_causes is None:
            self.rejected_causes = Counter()


@dataclass(slots=True)
class _UserTunnel:
    source: str
    destination: str
    teid: int
    message_counts: Counter[str]
    packets: int = 0
    bytes: int = 0
    sequence: _SequenceState | None = None
    extension_types: Counter[int] | None = None
    inner_endpoints: set[tuple[str, str]] | None = None

    def __post_init__(self) -> None:
        if self.sequence is None:
            self.sequence = _SequenceState()
        if self.extension_types is None:
            self.extension_types = Counter()
        if self.inner_endpoints is None:
            self.inner_endpoints = set()


class GtpTunnelForensicsAnalyzer:
    """Correlate bounded GTPv2-C transactions with observed GTPv1-U TEIDs."""

    def __init__(self) -> None:
        self._control: dict[tuple[str, str], _ControlSession] = {}
        self._user: dict[tuple[str, str, int], _UserTunnel] = {}
        self._control_limit_reached = False
        self._user_limit_reached = False

    def feed(self, packet: PacketRecord) -> None:
        layers = _layers(packet)
        for index, layer in enumerate(layers):
            if str(layer.get("name") or "").casefold() != "gtp":
                continue
            fields = _fields(layer)
            try:
                version = int(fields.get("version") or 0)
            except (TypeError, ValueError, OverflowError):
                continue
            if version == 2:
                self._control_packet(packet, fields)
            elif version == 1:
                self._user_packet(packet, fields, layers[index + 1:])

    def _control_packet(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        key = _pair(packet)
        state = self._control.get(key)
        if state is None:
            if len(self._control) >= _MAX_CONTROL_SESSIONS:
                self._control_limit_reached = True
                return
            state = _ControlSession(key[0], key[1], Counter(), set(), set())
            self._control[key] = state
        state.observations += 1
        try:
            message_type = int(fields.get("message_type") or 0)
            sequence = int(fields.get("sequence_number") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        message_name = str(fields.get("message_name") or f"message-{message_type}")
        state.message_counts[message_name] += 1
        if message_type in _REQUEST_TO_RESPONSE:
            tx_key = (sequence, message_type)
            if tx_key in state.request_keys:
                state.request_retransmissions += 1
            elif len(state.request_keys) < _MAX_TRANSACTION_KEYS:
                state.request_keys.add(tx_key)
        elif message_type in _RESPONSE_TO_REQUEST:
            tx_key = (sequence, _RESPONSE_TO_REQUEST[message_type])
            if tx_key in state.response_keys:
                state.response_retransmissions += 1
            elif len(state.response_keys) < _MAX_TRANSACTION_KEYS:
                state.response_keys.add(tx_key)
        ies = fields.get("information_elements") if isinstance(fields.get("information_elements"), list) else []
        for ie in ies[:512]:
            if not isinstance(ie, Mapping):
                continue
            ie_type = int(ie.get("type") or 0)
            if ie_type == 71 and ie.get("apn") and len(state.apns or ()) < _MAX_METADATA_VALUES:
                assert state.apns is not None
                state.apns.add(str(ie["apn"]))
            elif ie_type == 82 and ie.get("rat_name") and len(state.rats or ()) < _MAX_METADATA_VALUES:
                assert state.rats is not None
                state.rats.add(str(ie["rat_name"]))
            elif ie_type in {1, 75, 76}:
                digest = str(ie.get("imsi_sha256") or ie.get("mei_sha256") or ie.get("msisdn_sha256") or "")
                if digest and len(state.subscriber_hashes or ()) < _MAX_METADATA_VALUES:
                    assert state.subscriber_hashes is not None
                    state.subscriber_hashes.add(digest)
            elif ie_type == 87 and ie.get("teid") is not None and len(state.fteids or ()) < _MAX_METADATA_VALUES:
                assert state.fteids is not None
                state.fteids.add((
                    int(ie.get("interface_type") or 0),
                    int(ie.get("teid") or 0),
                    str(ie.get("ipv4") or ""),
                    str(ie.get("ipv6") or ""),
                ))
            elif ie_type == 2 and ie.get("cause") is not None:
                cause = int(ie.get("cause") or 0)
                if bool(ie.get("response_accepted")):
                    assert state.accepted_causes is not None
                    state.accepted_causes[cause] += 1
                else:
                    assert state.rejected_causes is not None
                    state.rejected_causes[cause] += 1

    def _user_packet(self, packet: PacketRecord, fields: Mapping[str, Any], following_layers: list[Mapping[str, Any]]) -> None:
        try:
            teid = int(fields.get("teid") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        key = (source, destination, teid)
        state = self._user.get(key)
        if state is None:
            if len(self._user) >= _MAX_USER_TUNNELS:
                self._user_limit_reached = True
                return
            state = _UserTunnel(source, destination, teid, Counter())
            self._user[key] = state
        state.packets += 1
        state.bytes += int(fields.get("decoded_length") or packet.length or 0)
        state.message_counts[str(fields.get("message_name") or fields.get("message_type") or "unknown")] += 1
        if fields.get("sequence_number") is not None:
            try:
                assert state.sequence is not None
                state.sequence.observe(int(fields["sequence_number"]))
            except (TypeError, ValueError, OverflowError):
                record_current_exception(__name__, 'GtpTunnelForensicsAnalyzer._user_packet:255')
        extensions = fields.get("extension_headers") if isinstance(fields.get("extension_headers"), list) else []
        for extension in extensions[:64]:
            if isinstance(extension, Mapping):
                try:
                    extension_type = int(extension.get("type") or 0)
                except (TypeError, ValueError, OverflowError):
                    continue
                assert state.extension_types is not None
                state.extension_types[extension_type] += 1
        for layer in following_layers:
            name = str(layer.get("name") or "").casefold()
            if name not in {"ipv4", "ipv6"}:
                continue
            values = _fields(layer)
            inner_source = str(values.get("source") or "")
            inner_destination = str(values.get("destination") or "")
            if inner_source or inner_destination:
                assert state.inner_endpoints is not None
                if len(state.inner_endpoints) < _MAX_METADATA_VALUES:
                    state.inner_endpoints.add((inner_source, inner_destination))
            break

    def finalize(self) -> dict[str, Any]:
        advertised: dict[int, list[dict[str, Any]]] = {}
        control_rows: list[dict[str, Any]] = []
        for state in sorted(self._control.values(), key=lambda item: (item.endpoint_a, item.endpoint_b)):
            paired = state.request_keys & state.response_keys
            fteids = state.fteids or set()
            fteid_rows = [
                {"interface_type": interface, "teid": teid, "ipv4": ipv4, "ipv6": ipv6}
                for interface, teid, ipv4, ipv6 in sorted(fteids)
            ]
            for row in fteid_rows:
                advertised.setdefault(int(row["teid"]), []).append({
                    "control_endpoints": [state.endpoint_a, state.endpoint_b],
                    **row,
                })
            control_rows.append({
                "endpoints": [state.endpoint_a, state.endpoint_b],
                "observations": state.observations,
                "message_counts": dict(state.message_counts.most_common()),
                "paired_transactions": len(paired),
                "outstanding_requests": len(state.request_keys - state.response_keys),
                "orphan_responses": len(state.response_keys - state.request_keys),
                "request_retransmissions": state.request_retransmissions,
                "response_retransmissions": state.response_retransmissions,
                "apns": sorted(state.apns or ()),
                "rat_types": sorted(state.rats or ()),
                "subscriber_identity_hashes": sorted(state.subscriber_hashes or ()),
                "advertised_fteids": fteid_rows,
                "accepted_causes": dict((state.accepted_causes or Counter()).most_common()),
                "rejected_causes": dict((state.rejected_causes or Counter()).most_common()),
            })

        user_rows: list[dict[str, Any]] = []
        matched_directions = 0
        for state in sorted(self._user.values(), key=lambda item: (item.source, item.destination, item.teid)):
            matches = advertised.get(state.teid, [])
            if matches:
                matched_directions += 1
            assert state.sequence is not None and state.extension_types is not None and state.inner_endpoints is not None
            user_rows.append({
                "source": state.source,
                "destination": state.destination,
                "teid": state.teid,
                "teid_hex": f"0x{state.teid:08x}",
                "packets": state.packets,
                "bytes": state.bytes,
                "message_counts": dict(state.message_counts.most_common()),
                "sequence": state.sequence.as_dict(),
                "extension_types": {str(key): value for key, value in state.extension_types.most_common()},
                "inner_endpoints": [list(item) for item in sorted(state.inner_endpoints)],
                "control_plane_fteid_matches": matches[:64],
                "control_plane_match": bool(matches),
            })
        return {
            "schema": "arenyxa.gtp-tunnel-forensics/v1",
            "control_session_count": len(control_rows),
            "user_tunnel_direction_count": len(user_rows),
            "control_session_limit_reached": self._control_limit_reached,
            "user_tunnel_limit_reached": self._user_limit_reached,
            "control_plane_matched_user_directions": matched_directions,
            "control_sessions": control_rows,
            "user_tunnels": user_rows,
            "subscriber_identifier_values_retained": False,
            "interpretation": (
                "F-TEID/TEID matches are passive control-plane/user-plane correlation evidence. Interface roles, mobility, capture vantage point, "
                "TEID reuse, and incomplete captures must be considered before treating a match as a complete bearer lifecycle."
            ),
        }
