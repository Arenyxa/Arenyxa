from __future__ import annotations

from collections import Counter
from typing import Any, Tuple, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_SESSIONS = 100_000
_MAX_INDEX_CANDIDATES = 16
_MAX_COUNTER_TRACK = 65_536
_MAX_PATHS_PER_SESSION = 128


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _endpoint(address: str, port: int | None) -> str:
    host = str(address or "")
    return f"{host}:{port}" if port is not None else host


@dataclass(slots=True)
class _CounterState:
    packets: int = 0
    highest: int = -1
    unique: set[int] | None = None
    duplicate: int = 0
    out_of_order: int = 0
    estimated_gaps: int = 0

    def __post_init__(self) -> None:
        if self.unique is None:
            self.unique = set()

    def observe(self, counter: int) -> None:
        self.packets += 1
        values = self.unique
        assert values is not None
        if counter in values:
            self.duplicate += 1
            return
        if len(values) < _MAX_COUNTER_TRACK:
            values.add(counter)
        if self.highest >= 0:
            if counter < self.highest:
                self.out_of_order += 1
            elif counter > self.highest + 1:
                self.estimated_gaps += counter - self.highest - 1
        self.highest = max(self.highest, counter)

    def as_dict(self) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "highest_counter_observed": self.highest,
            "unique_counters_tracked": len(self.unique or ()),
            "duplicate_counter_observations": self.duplicate,
            "out_of_order_counter_observations": self.out_of_order,
            "estimated_missing_counters": self.estimated_gaps,
            "possible_replay_evidence": self.duplicate > 0,
        }


@dataclass(slots=True)
class _WireGuardSession:
    initiator: str
    responder: str
    initiator_index: int
    responder_index: int | None = None
    initiation_observations: int = 0
    initiation_retransmissions: int = 0
    response_observations: int = 0
    response_retransmissions: int = 0
    cookie_replies: int = 0
    initiator_to_responder: _CounterState | None = None
    responder_to_initiator: _CounterState | None = None
    initiator_to_responder_paths: set[tuple[str, str]] | None = None
    responder_to_initiator_paths: set[tuple[str, str]] | None = None

    def __post_init__(self) -> None:
        if self.initiator_to_responder is None:
            self.initiator_to_responder = _CounterState()
        if self.responder_to_initiator is None:
            self.responder_to_initiator = _CounterState()
        if self.initiator_to_responder_paths is None:
            self.initiator_to_responder_paths = set()
        if self.responder_to_initiator_paths is None:
            self.responder_to_initiator_paths = set()


SessionKey = Tuple[str, str, int]


class WireGuardSessionAnalyzer:
    """Bounded passive WireGuard handshake/transport correlation.

    Receiver/sender indices and transport counters are correlation evidence, not
    cryptographic authentication proof. Encrypted handshake and transport bytes
    are never retained by this analyzer.
    """

    def __init__(self) -> None:
        self._sessions: dict[SessionKey, _WireGuardSession] = {}
        self._index_candidates: dict[int, set[SessionKey]] = {}
        self._session_limit_reached = False
        self._index_candidate_limit_reached = False
        self._orphan_responses = 0
        self._orphan_cookies = 0
        self._orphan_transport_packets = 0
        self._ambiguous_correlations = 0

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            if str(layer.get("name") or "").casefold() != "wireguard":
                continue
            fields = _fields(layer)
            try:
                message_type = int(fields.get("message_type") or 0)
            except (TypeError, ValueError, OverflowError):
                continue
            if message_type == 1:
                self._initiation(packet, fields)
            elif message_type == 2:
                self._response(packet, fields)
            elif message_type == 3:
                self._cookie(packet, fields)
            elif message_type == 4:
                self._transport(packet, fields)

    def _register_index(self, index: int, key: SessionKey) -> None:
        candidates = self._index_candidates.setdefault(index, set())
        if len(candidates) >= _MAX_INDEX_CANDIDATES and key not in candidates:
            self._index_candidate_limit_reached = True
            return
        candidates.add(key)

    def _initiation(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        try:
            sender_index = int(fields.get("sender_index"))
        except (TypeError, ValueError, OverflowError):
            return
        initiator = _endpoint(packet.source, packet.source_port)
        responder = _endpoint(packet.destination, packet.destination_port)
        key = (initiator, responder, sender_index)
        state = self._sessions.get(key)
        if state is None:
            if len(self._sessions) >= _MAX_SESSIONS:
                self._session_limit_reached = True
                return
            state = _WireGuardSession(initiator, responder, sender_index)
            self._sessions[key] = state
            self._register_index(sender_index, key)
        elif state.initiation_observations:
            state.initiation_retransmissions += 1
        state.initiation_observations += 1

    def _candidate_sessions(
        self,
        receiver_index: int,
        packet: PacketRecord,
        *,
        expect_response: bool = False,
    ) -> list[tuple[SessionKey, _WireGuardSession]]:
        keys = self._index_candidates.get(receiver_index, set())
        rows = [(key, self._sessions[key]) for key in keys if key in self._sessions]
        if not rows:
            return []
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        if expect_response:
            matched = [row for row in rows if row[1].initiator == destination and row[1].responder == source]
            if matched:
                rows = matched
        else:
            matched: list[tuple[SessionKey, _WireGuardSession]] = []
            for row in rows:
                state = row[1]
                if receiver_index == state.initiator_index and destination == state.initiator:
                    matched.append(row)
                elif state.responder_index is not None and receiver_index == state.responder_index and destination == state.responder:
                    matched.append(row)
            if matched:
                rows = matched
        return rows

    def _response(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        try:
            sender_index = int(fields.get("sender_index"))
            receiver_index = int(fields.get("receiver_index"))
        except (TypeError, ValueError, OverflowError):
            return
        candidates = self._candidate_sessions(receiver_index, packet, expect_response=True)
        if len(candidates) != 1:
            if candidates:
                self._ambiguous_correlations += 1
            else:
                self._orphan_responses += 1
            return
        key, state = candidates[0]
        if state.response_observations:
            if state.responder_index == sender_index:
                state.response_retransmissions += 1
            elif state.responder_index is not None:
                self._ambiguous_correlations += 1
                return
        state.response_observations += 1
        state.responder_index = sender_index
        self._register_index(sender_index, key)

    def _cookie(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        try:
            receiver_index = int(fields.get("receiver_index"))
        except (TypeError, ValueError, OverflowError):
            return
        candidates = self._candidate_sessions(receiver_index, packet)
        if len(candidates) == 1:
            candidates[0][1].cookie_replies += 1
        elif candidates:
            self._ambiguous_correlations += 1
        else:
            self._orphan_cookies += 1

    def _transport(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        try:
            receiver_index = int(fields.get("receiver_index"))
            counter = int(fields.get("counter"))
        except (TypeError, ValueError, OverflowError):
            return
        candidates = self._candidate_sessions(receiver_index, packet)
        if len(candidates) != 1:
            if candidates:
                self._ambiguous_correlations += 1
            else:
                self._orphan_transport_packets += 1
            return
        _key, state = candidates[0]
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        if receiver_index == state.initiator_index:
            direction = state.responder_to_initiator
            paths = state.responder_to_initiator_paths
        elif state.responder_index is not None and receiver_index == state.responder_index:
            direction = state.initiator_to_responder
            paths = state.initiator_to_responder_paths
        else:
            self._orphan_transport_packets += 1
            return
        assert direction is not None and paths is not None
        if len(paths) < _MAX_PATHS_PER_SESSION:
            paths.add((source, destination))
        direction.observe(counter)

    @staticmethod
    def _state(row: _WireGuardSession) -> str:
        forward = row.initiator_to_responder
        reverse = row.responder_to_initiator
        assert forward is not None and reverse is not None
        if forward.packets or reverse.packets:
            return "transport-observed" if row.response_observations else "transport-without-correlated-response"
        if row.response_observations:
            return "handshake-response-observed"
        if row.cookie_replies:
            return "cookie-challenged"
        return "initiation-only"

    def finalize(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        for state in sorted(self._sessions.values(), key=lambda item: (item.initiator, item.responder, item.initiator_index)):
            forward = state.initiator_to_responder
            reverse = state.responder_to_initiator
            forward_paths = state.initiator_to_responder_paths
            reverse_paths = state.responder_to_initiator_paths
            assert forward is not None and reverse is not None
            assert forward_paths is not None and reverse_paths is not None
            rows.append({
                "initiator": state.initiator,
                "responder": state.responder,
                "initiator_sender_index": state.initiator_index,
                "responder_sender_index": state.responder_index,
                "state": self._state(state),
                "initiation_observations": state.initiation_observations,
                "initiation_retransmissions": state.initiation_retransmissions,
                "response_observations": state.response_observations,
                "response_retransmissions": state.response_retransmissions,
                "cookie_replies": state.cookie_replies,
                "initiator_to_responder": forward.as_dict(),
                "responder_to_initiator": reverse.as_dict(),
                "transport_paths": {
                    "initiator_to_responder": [list(item) for item in sorted(forward_paths)],
                    "responder_to_initiator": [list(item) for item in sorted(reverse_paths)],
                },
                "path_count": len(forward_paths) + len(reverse_paths),
                "path_change_evidence": len(forward_paths) > 1 or len(reverse_paths) > 1,
                "possible_replay_evidence": forward.duplicate > 0 or reverse.duplicate > 0,
            })
        return {
            "schema": "arenyxa.wireguard-session-forensics/v1",
            "session_count": len(rows),
            "session_limit_reached": self._session_limit_reached,
            "index_candidate_limit_reached": self._index_candidate_limit_reached,
            "orphan_responses": self._orphan_responses,
            "orphan_cookie_replies": self._orphan_cookies,
            "orphan_transport_packets": self._orphan_transport_packets,
            "ambiguous_correlations": self._ambiguous_correlations,
            "sessions": rows,
            "sensitive_material_retained": False,
            "interpretation": (
                "WireGuard indices/counters are passive correlation evidence only. Duplicate counters can also be caused by "
                "capture duplication, and path changes can reflect legitimate roaming; neither is proof of compromise or replay."
            ),
        }
