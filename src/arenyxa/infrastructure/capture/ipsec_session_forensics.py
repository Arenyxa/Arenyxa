from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_IKE_SESSIONS = 100_000
_MAX_IPSEC_SAS = 200_000
_MAX_SEQUENCE_TRACK = 65_536


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


@dataclass(slots=True)
class _IkeSession:
    initiator_spi: str
    responder_spis: set[str]
    endpoints: set[tuple[str, str]]
    exchanges: Counter[str]
    request_keys: set[tuple[int, int]]
    response_keys: set[tuple[int, int]]
    request_retransmissions: int = 0
    response_retransmissions: int = 0
    encrypted_messages: int = 0
    error_notifications: Counter[str] | None = None
    highest_request_id: int = -1
    request_message_id_regressions: int = 0
    observations: int = 0
    visible_delete_payloads: int = 0
    visible_deleted_spis: set[str] | None = None
    rekey_notifications: int = 0
    mobike_notifications: int = 0
    fragmentation_support_notifications: int = 0

    def __post_init__(self) -> None:
        if self.error_notifications is None:
            self.error_notifications = Counter()
        if self.visible_deleted_spis is None:
            self.visible_deleted_spis = set()


@dataclass(slots=True)
class _IpsecSa:
    protocol: str
    source: str
    destination: str
    spi: int
    observations: int = 0
    highest_sequence: int = -1
    unique_sequences: set[int] | None = None
    duplicate_sequences: int = 0
    out_of_order_sequences: int = 0
    estimated_sequence_gaps: int = 0
    sequence_wrap_observations: int = 0

    def __post_init__(self) -> None:
        if self.unique_sequences is None:
            self.unique_sequences = set()


class IpsecSessionAnalyzer:
    """Bounded passive IKEv2/IPsec state analysis without decryption or key capture."""

    def __init__(self) -> None:
        self._ike: dict[str, _IkeSession] = {}
        self._sas: dict[tuple[str, str, str, int], _IpsecSa] = {}
        self._ike_limit_reached = False
        self._sa_limit_reached = False

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            name = str(layer.get("name") or "").casefold()
            fields = _fields(layer)
            if name == "ike":
                self._feed_ike(packet, fields)
            elif name in {"esp", "ah"}:
                self._feed_sa(packet, name, fields)

    def _feed_ike(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        initiator_spi = str(fields.get("initiator_spi") or "")
        if not initiator_spi:
            return
        session = self._ike.get(initiator_spi)
        if session is None:
            if len(self._ike) >= _MAX_IKE_SESSIONS:
                self._ike_limit_reached = True
                return
            session = _IkeSession(initiator_spi, set(), set(), Counter(), set(), set())
            self._ike[initiator_spi] = session
        session.observations += 1
        session.endpoints.add((str(packet.source or ""), str(packet.destination or "")))
        responder_spi = str(fields.get("responder_spi") or "")
        if responder_spi and responder_spi != "0000000000000000":
            session.responder_spis.add(responder_spi)
        exchange = int(fields.get("exchange_type") or 0)
        exchange_name = str(fields.get("exchange_name") or f"exchange-{exchange}")
        message_id = int(fields.get("message_id") or 0)
        session.exchanges[exchange_name] += 1
        response = bool(fields.get("response_flag"))
        key = (message_id, exchange)
        if response:
            if key in session.response_keys:
                session.response_retransmissions += 1
            session.response_keys.add(key)
        else:
            if key in session.request_keys:
                session.request_retransmissions += 1
            elif session.highest_request_id >= 0 and message_id < session.highest_request_id:
                session.request_message_id_regressions += 1
            session.request_keys.add(key)
            session.highest_request_id = max(session.highest_request_id, message_id)
        if bool(fields.get("encrypted_payload_present")):
            session.encrypted_messages += 1
        payloads = fields.get("payloads") if isinstance(fields.get("payloads"), list) else []
        for payload in payloads[:256]:
            if not isinstance(payload, Mapping):
                continue
            payload_name = str(payload.get("name") or "")
            if payload_name == "NOTIFY":
                notify_name = str(payload.get("notify_name") or payload.get("notify_type") or "unknown")
                if bool(payload.get("error_notification")):
                    assert session.error_notifications is not None
                    session.error_notifications[notify_name] += 1
                if notify_name == "REKEY_SA":
                    session.rekey_notifications += 1
                elif notify_name in {"MOBIKE_SUPPORTED", "UPDATE_SA_ADDRESSES"}:
                    session.mobike_notifications += 1
                elif notify_name == "IKEV2_FRAGMENTATION_SUPPORTED":
                    session.fragmentation_support_notifications += 1
            elif payload_name == "DELETE":
                session.visible_delete_payloads += 1
                deleted = session.visible_deleted_spis
                assert deleted is not None
                raw_spis = payload.get("spis") if isinstance(payload.get("spis"), list) else []
                for spi_value in raw_spis[:256]:
                    if len(deleted) >= 1024:
                        break
                    text = str(spi_value or "")
                    if text:
                        deleted.add(text)

    def _feed_sa(self, packet: PacketRecord, protocol: str, fields: Mapping[str, Any]) -> None:
        try:
            spi = int(fields.get("spi") or 0)
            sequence = int(fields.get("sequence") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        key = (protocol, str(packet.source or ""), str(packet.destination or ""), spi)
        state = self._sas.get(key)
        if state is None:
            if len(self._sas) >= _MAX_IPSEC_SAS:
                self._sa_limit_reached = True
                return
            state = _IpsecSa(protocol, key[1], key[2], spi)
            self._sas[key] = state
        state.observations += 1
        sequences = state.unique_sequences
        assert sequences is not None
        if sequence in sequences:
            state.duplicate_sequences += 1
            return
        if len(sequences) < _MAX_SEQUENCE_TRACK:
            sequences.add(sequence)
        if state.highest_sequence >= 0:
            if sequence < state.highest_sequence:
                if state.highest_sequence > 0xF0000000 and sequence < 0x0FFFFFFF:
                    state.sequence_wrap_observations += 1
                else:
                    state.out_of_order_sequences += 1
            elif sequence > state.highest_sequence + 1:
                state.estimated_sequence_gaps += sequence - state.highest_sequence - 1
        state.highest_sequence = max(state.highest_sequence, sequence)

    def finalize(self) -> dict[str, Any]:
        ike_rows: list[dict[str, Any]] = []
        for state in sorted(self._ike.values(), key=lambda item: item.initiator_spi):
            paired_keys = state.request_keys & state.response_keys
            paired = len(paired_keys)
            paired_by_exchange = Counter(exchange for _message_id, exchange in paired_keys)
            orphan_responses = len(state.response_keys - state.request_keys)
            outstanding_requests = len(state.request_keys - state.response_keys)
            deleted = state.visible_deleted_spis
            assert deleted is not None
            lifecycle_evidence: list[str] = []
            if paired_by_exchange.get(34, 0):
                lifecycle_evidence.append("ike-sa-init-pair-observed")
            if paired_by_exchange.get(35, 0):
                lifecycle_evidence.append("ike-auth-pair-observed")
            if paired_by_exchange.get(36, 0):
                lifecycle_evidence.append("create-child-sa-pair-observed")
            if state.rekey_notifications:
                lifecycle_evidence.append("rekey-notify-observed")
            if state.visible_delete_payloads:
                lifecycle_evidence.append("visible-delete-observed")
            if state.mobike_notifications:
                lifecycle_evidence.append("mobike-signal-observed")
            ike_rows.append({
                "initiator_spi": state.initiator_spi,
                "responder_spis": sorted(state.responder_spis),
                "endpoint_directions": [list(item) for item in sorted(state.endpoints)],
                "exchange_counts": dict(state.exchanges.most_common()),
                "request_response_pairs": paired,
                "paired_exchanges": {
                    "IKE_SA_INIT": paired_by_exchange.get(34, 0),
                    "IKE_AUTH": paired_by_exchange.get(35, 0),
                    "CREATE_CHILD_SA": paired_by_exchange.get(36, 0),
                    "INFORMATIONAL": paired_by_exchange.get(37, 0),
                },
                "lifecycle_evidence": lifecycle_evidence,
                "outstanding_requests": outstanding_requests,
                "orphan_responses": orphan_responses,
                "request_retransmissions": state.request_retransmissions,
                "response_retransmissions": state.response_retransmissions,
                "request_message_id_regressions": state.request_message_id_regressions,
                "encrypted_messages": state.encrypted_messages,
                "error_notifications": dict((state.error_notifications or Counter()).most_common()),
                "visible_delete_payloads": state.visible_delete_payloads,
                "visible_deleted_spis": sorted(deleted),
                "rekey_notifications": state.rekey_notifications,
                "mobike_notifications": state.mobike_notifications,
                "fragmentation_support_notifications": state.fragmentation_support_notifications,
                "observations": state.observations,
            })
        sa_rows = [
            {
                "protocol": state.protocol,
                "source": state.source,
                "destination": state.destination,
                "spi": state.spi,
                "spi_hex": f"0x{state.spi:08x}",
                "packets": state.observations,
                "highest_sequence_observed": state.highest_sequence,
                "unique_sequences_tracked": len(state.unique_sequences or ()),
                "duplicate_sequence_observations": state.duplicate_sequences,
                "out_of_order_sequence_observations": state.out_of_order_sequences,
                "estimated_missing_sequence_numbers": state.estimated_sequence_gaps,
                "sequence_wrap_observations": state.sequence_wrap_observations,
                "possible_replay_evidence": state.duplicate_sequences > 0,
            }
            for state in sorted(self._sas.values(), key=lambda item: (item.protocol, item.source, item.destination, item.spi))
        ]
        return {
            "schema": "arenyxa.ipsec-session-forensics/v1",
            "ike_session_count": len(ike_rows),
            "ipsec_sa_direction_count": len(sa_rows),
            "ike_session_limit_reached": self._ike_limit_reached,
            "ipsec_sa_limit_reached": self._sa_limit_reached,
            "ike_sessions": ike_rows,
            "security_associations": sa_rows,
            "interpretation": (
                "IKE exchange pairing and visible Notify/Delete payloads are lifecycle evidence only; encrypted SK payload contents are not inferred. "
                "Duplicate/out-of-order IPsec sequence observations are passive capture evidence only; packet duplication, capture artifacts, "
                "ESN context, and reordering must be considered before inferring replay."
            ),
        }
