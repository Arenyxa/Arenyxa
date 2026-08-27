from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Iterable, Mapping, Tuple

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.mobile_core_qos import build_pfcp_gtpu_qos_correlations
from arenyxa.infrastructure.capture.packet_models import PacketRecord
from arenyxa.infrastructure.capture.pfcp_rule_graph import extract_pfcp_rule_observations


_MAX_PEERS = 100_000
_MAX_KEYS = 200_000
_MAX_VALUES = 4096

_PFCP_REQUEST_TO_RESPONSE = {
    1: 2, 3: 4, 5: 6, 7: 8, 9: 10, 12: 13, 14: 15, 16: 17,
    50: 51, 52: 53, 54: 55, 56: 57,
}
_PFCP_RESPONSE_TO_REQUEST = {response: request for request, response in _PFCP_REQUEST_TO_RESPONSE.items()}
_PFCP_PROCEDURES = {
    1: "heartbeat", 3: "pfd-management", 5: "association-setup", 7: "association-update",
    9: "association-release", 12: "node-report", 14: "session-set-deletion",
    16: "session-set-modification", 50: "session-establishment", 52: "session-modification",
    54: "session-deletion", 56: "session-report",
}

_PfcpTransaction = Tuple[str, str, int, int]
_DiameterTransaction = Tuple[str, str, int, int, int, int]


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
    ordered = sorted((left, right))
    return ordered[0], ordered[1]




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


def _walk_ie_rows(rows: Any, *, depth: int = 0) -> Iterable[Mapping[str, Any]]:
    if depth > 4 or not isinstance(rows, list):
        return
    for row in rows[:1024]:
        if not isinstance(row, Mapping):
            continue
        yield row
        children = row.get("children")
        if isinstance(children, list):
            yield from _walk_ie_rows(children, depth=depth + 1)


def _pfcp_response_accepted(fields: Mapping[str, Any]) -> bool | None:
    for row in _walk_ie_rows(fields.get("information_elements")):
        try:
            ie_type = int(row.get("type") or 0)
        except (TypeError, ValueError, OverflowError):
            continue
        if ie_type == 19 and row.get("cause") is not None:
            return bool(row.get("request_accepted"))
    return None


def _walk_diameter_avps(rows: Any, *, depth: int = 0) -> Iterable[Mapping[str, Any]]:
    if depth > 4 or not isinstance(rows, list):
        return
    for row in rows[:1024]:
        if not isinstance(row, Mapping):
            continue
        yield row
        children = row.get("children")
        if isinstance(children, list):
            yield from _walk_diameter_avps(children, depth=depth + 1)


@dataclass(slots=True)
class _PfcpPeer:
    endpoint_a: str
    endpoint_b: str
    messages: Counter[str]
    requests: set[_PfcpTransaction]
    responses: set[_PfcpTransaction]
    request_retransmissions: int = 0
    response_retransmissions: int = 0
    header_seids: set[int] | None = None
    fseids: set[tuple[int, str, str]] | None = None
    fteids: set[tuple[int, str, str]] | None = None
    nodes: set[str] | None = None
    network_instances: set[str] | None = None
    accepted_causes: Counter[int] | None = None
    rejected_causes: Counter[int] | None = None
    request_started: dict[_PfcpTransaction, float] | None = None
    transaction_latencies_ms: list[float] | None = None
    pending_rule_ops: dict[_PfcpTransaction, list[dict[str, Any]]] | None = None
    confirmed_rule_ops: list[dict[str, Any]] | None = None
    unconfirmed_rule_ops: list[dict[str, Any]] | None = None
    rejected_rule_op_count: int = 0

    def __post_init__(self) -> None:
        self.header_seids = self.header_seids or set()
        self.fseids = self.fseids or set()
        self.fteids = self.fteids or set()
        self.nodes = self.nodes or set()
        self.network_instances = self.network_instances or set()
        self.accepted_causes = self.accepted_causes or Counter()
        self.rejected_causes = self.rejected_causes or Counter()
        self.request_started = self.request_started or {}
        self.transaction_latencies_ms = self.transaction_latencies_ms or []
        self.pending_rule_ops = self.pending_rule_ops or {}
        self.confirmed_rule_ops = self.confirmed_rule_ops or []
        self.unconfirmed_rule_ops = self.unconfirmed_rule_ops or []


@dataclass(slots=True)
class _DiameterPeer:
    endpoint_a: str
    endpoint_b: str
    messages: Counter[str]
    requests: set[_DiameterTransaction]
    answers: set[_DiameterTransaction]
    request_retransmissions: int = 0
    answer_retransmissions: int = 0
    retransmission_flag_observations: int = 0
    application_ids: Counter[int] | None = None
    result_codes: Counter[int] | None = None
    vendor_ids: set[int] | None = None
    origin_hosts: set[str] | None = None
    origin_realms: set[str] | None = None
    destination_hosts: set[str] | None = None
    destination_realms: set[str] | None = None
    session_hashes: set[str] | None = None
    request_started: dict[_DiameterTransaction, float] | None = None
    transaction_latencies_ms: list[float] | None = None

    def __post_init__(self) -> None:
        self.application_ids = self.application_ids or Counter()
        self.result_codes = self.result_codes or Counter()
        self.vendor_ids = self.vendor_ids or set()
        self.origin_hosts = self.origin_hosts or set()
        self.origin_realms = self.origin_realms or set()
        self.destination_hosts = self.destination_hosts or set()
        self.destination_realms = self.destination_realms or set()
        self.session_hashes = self.session_hashes or set()
        self.request_started = self.request_started or {}
        self.transaction_latencies_ms = self.transaction_latencies_ms or []


class MobileCoreForensicsAnalyzer:
    """Correlate PFCP, GTP-U and Diameter control evidence without subscriber plaintext."""

    def __init__(self) -> None:
        self._pfcp: dict[tuple[str, str], _PfcpPeer] = {}
        self._diameter: dict[tuple[str, str], _DiameterPeer] = {}
        self._gtpu_teids: Counter[int] = Counter()
        self._gtpu_qfis: dict[int, Counter[int]] = {}
        self._limits_reached: set[str] = set()

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            name = str(layer.get("name") or "").casefold()
            fields = _fields(layer)
            if name == "pfcp":
                self._feed_pfcp(packet, fields)
            elif name == "diameter":
                self._feed_diameter(packet, fields)
            elif name == "gtp" and int(fields.get("version") or 0) == 1:
                self._feed_gtpu(fields)

    def _feed_gtpu(self, fields: Mapping[str, Any]) -> None:
        try:
            teid = int(fields.get("teid") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        if teid:
            self._gtpu_teids[teid] += 1
            raw_extensions = fields.get("extension_headers")
            if isinstance(raw_extensions, list):
                for extension in raw_extensions[:64]:
                    if not isinstance(extension, Mapping):
                        continue
                    try:
                        extension_type = int(extension.get("type") or 0)
                        qfi = int(extension.get("qfi")) if extension.get("qfi") is not None else None
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if extension_type == 0x85 and qfi is not None and 0 <= qfi <= 63:
                        self._gtpu_qfis.setdefault(teid, Counter())[qfi] += 1

    def _feed_pfcp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        key = _pair(packet)
        state = self._pfcp.get(key)
        if state is None:
            if len(self._pfcp) >= _MAX_PEERS:
                self._limits_reached.add("pfcp-peers")
                return
            state = _PfcpPeer(key[0], key[1], Counter(), set(), set())
            self._pfcp[key] = state
        try:
            message_type = int(fields.get("message_type") or 0)
            sequence = int(fields.get("sequence_number") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        state.messages[str(fields.get("message_name") or f"message-{message_type}")] += 1
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        observed_at = _epoch(packet)
        rule_ops = extract_pfcp_rule_observations(fields.get("information_elements"))
        if message_type in _PFCP_REQUEST_TO_RESPONSE:
            tx: _PfcpTransaction = (source, destination, sequence, message_type)
            if tx in state.requests:
                state.request_retransmissions += 1
            elif len(state.requests) < _MAX_KEYS:
                state.requests.add(tx)
                if observed_at is not None:
                    assert state.request_started is not None
                    state.request_started.setdefault(tx, observed_at)
                if rule_ops:
                    assert state.pending_rule_ops is not None
                    enriched: list[dict[str, Any]] = []
                    for operation in rule_ops:
                        if len(enriched) >= 1024:
                            self._limits_reached.add("pfcp-rule-ops-per-request")
                            break
                        event = dict(operation)
                        event.update({
                            "request_message_type": message_type,
                            "request_sequence": sequence,
                            "request_seid": fields.get("seid"),
                        })
                        enriched.append(event)
                    if enriched:
                        state.pending_rule_ops[tx] = enriched
        elif message_type in _PFCP_RESPONSE_TO_REQUEST:
            tx = (destination, source, sequence, _PFCP_RESPONSE_TO_REQUEST[message_type])
            if tx in state.responses:
                state.response_retransmissions += 1
            elif len(state.responses) < _MAX_KEYS:
                state.responses.add(tx)
                assert state.request_started is not None
                assert state.transaction_latencies_ms is not None
                began = state.request_started.get(tx)
                if began is not None and observed_at is not None and observed_at >= began and len(state.transaction_latencies_ms) < _MAX_KEYS:
                    state.transaction_latencies_ms.append((observed_at - began) * 1000.0)
                assert state.pending_rule_ops is not None
                pending = state.pending_rule_ops.pop(tx, [])
                if pending:
                    accepted = _pfcp_response_accepted(fields)
                    if accepted is True:
                        assert state.confirmed_rule_ops is not None
                        room = max(0, _MAX_KEYS - len(state.confirmed_rule_ops))
                        for event in pending[:room]:
                            committed = dict(event)
                            committed["confirmed_by_response_type"] = message_type
                            committed["confirmation"] = "accepted-response"
                            state.confirmed_rule_ops.append(committed)
                        if len(pending) > room:
                            self._limits_reached.add("pfcp-confirmed-rule-events")
                    elif accepted is False:
                        state.rejected_rule_op_count += len(pending)
                    else:
                        assert state.unconfirmed_rule_ops is not None
                        room = max(0, _MAX_KEYS - len(state.unconfirmed_rule_ops))
                        state.unconfirmed_rule_ops.extend(pending[:room])
                        if len(pending) > room:
                            self._limits_reached.add("pfcp-unconfirmed-rule-events")
        if fields.get("seid") is not None and len(state.header_seids or ()) < _MAX_VALUES:
            assert state.header_seids is not None
            state.header_seids.add(int(fields["seid"]))
        for ie in _walk_ie_rows(fields.get("information_elements")):
            self._pfcp_ie(state, ie)

    @staticmethod
    def _pfcp_ie(state: _PfcpPeer, ie: Mapping[str, Any]) -> None:
        try:
            ie_type = int(ie.get("type") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        if ie_type == 57 and ie.get("seid") is not None and len(state.fseids or ()) < _MAX_VALUES:
            assert state.fseids is not None
            state.fseids.add((int(ie["seid"]), str(ie.get("ipv4") or ""), str(ie.get("ipv6") or "")))
        elif ie_type == 21 and ie.get("teid") is not None and len(state.fteids or ()) < _MAX_VALUES:
            assert state.fteids is not None
            state.fteids.add((int(ie["teid"]), str(ie.get("ipv4") or ""), str(ie.get("ipv6") or "")))
        elif ie_type == 60 and ie.get("node_id") and len(state.nodes or ()) < _MAX_VALUES:
            assert state.nodes is not None
            state.nodes.add(str(ie["node_id"]))
        elif ie_type == 22 and ie.get("network_instance") and len(state.network_instances or ()) < _MAX_VALUES:
            assert state.network_instances is not None
            state.network_instances.add(str(ie["network_instance"]))
        elif ie_type == 19 and ie.get("cause") is not None:
            cause = int(ie["cause"])
            target = state.accepted_causes if bool(ie.get("request_accepted")) else state.rejected_causes
            assert target is not None
            target[cause] += 1

    def _feed_diameter(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        key = _pair(packet)
        state = self._diameter.get(key)
        if state is None:
            if len(self._diameter) >= _MAX_PEERS:
                self._limits_reached.add("diameter-peers")
                return
            state = _DiameterPeer(key[0], key[1], Counter(), set(), set())
            self._diameter[key] = state
        try:
            command = int(fields.get("command_code") or 0)
            hop = int(fields.get("hop_by_hop_id") or 0)
            end = int(fields.get("end_to_end_id") or 0)
            application = int(fields.get("application_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        state.messages[str(fields.get("command_name") or f"command-{command}")] += 1
        assert state.application_ids is not None
        state.application_ids[application] += 1
        source = _endpoint(packet.source, packet.source_port)
        destination = _endpoint(packet.destination, packet.destination_port)
        observed_at = _epoch(packet)
        request = bool(fields.get("request"))
        tx: _DiameterTransaction = (
            source if request else destination,
            destination if request else source,
            hop, end, command, application,
        )
        if request:
            if tx in state.requests:
                state.request_retransmissions += 1
            elif len(state.requests) < _MAX_KEYS:
                state.requests.add(tx)
                if observed_at is not None:
                    assert state.request_started is not None
                    state.request_started.setdefault(tx, observed_at)
        else:
            if tx in state.answers:
                state.answer_retransmissions += 1
            elif len(state.answers) < _MAX_KEYS:
                state.answers.add(tx)
                assert state.request_started is not None
                assert state.transaction_latencies_ms is not None
                began = state.request_started.get(tx)
                if began is not None and observed_at is not None and observed_at >= began and len(state.transaction_latencies_ms) < _MAX_KEYS:
                    state.transaction_latencies_ms.append((observed_at - began) * 1000.0)
        if bool(fields.get("potential_retransmission")):
            state.retransmission_flag_observations += 1
        for avp in _walk_diameter_avps(fields.get("avps")):
            self._diameter_avp(state, avp)

    @staticmethod
    def _diameter_avp(state: _DiameterPeer, avp: Mapping[str, Any]) -> None:
        try:
            code = int(avp.get("code") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        if code == 263 and avp.get("session_id_sha256") and len(state.session_hashes or ()) < _MAX_VALUES:
            assert state.session_hashes is not None
            state.session_hashes.add(str(avp["session_id_sha256"]))
        elif code == 264 and avp.get("text") and len(state.origin_hosts or ()) < _MAX_VALUES:
            assert state.origin_hosts is not None
            state.origin_hosts.add(str(avp["text"]))
        elif code == 296 and avp.get("text") and len(state.origin_realms or ()) < _MAX_VALUES:
            assert state.origin_realms is not None
            state.origin_realms.add(str(avp["text"]))
        elif code == 293 and avp.get("text") and len(state.destination_hosts or ()) < _MAX_VALUES:
            assert state.destination_hosts is not None
            state.destination_hosts.add(str(avp["text"]))
        elif code == 283 and avp.get("text") and len(state.destination_realms or ()) < _MAX_VALUES:
            assert state.destination_realms is not None
            state.destination_realms.add(str(avp["text"]))
        elif code in {265, 266} and avp.get("unsigned32") is not None and len(state.vendor_ids or ()) < _MAX_VALUES:
            assert state.vendor_ids is not None
            state.vendor_ids.add(int(avp["unsigned32"]))
        elif code == 268 and avp.get("unsigned32") is not None:
            assert state.result_codes is not None
            state.result_codes[int(avp["unsigned32"])] += 1

    def finalize(self) -> dict[str, Any]:
        pfcp_rows: list[dict[str, Any]] = []
        pfcp_teids: set[int] = set()
        confirmed_rule_events: list[dict[str, Any]] = []
        for state in sorted(self._pfcp.values(), key=lambda item: (item.endpoint_a, item.endpoint_b)):
            fteids = sorted(state.fteids or ())
            pfcp_teids.update(teid for teid, _ipv4, _ipv6 in fteids)
            paired = state.requests & state.responses
            paired_procedures = Counter(_PFCP_PROCEDURES.get(tx[3], f"message-{tx[3]}") for tx in paired)
            state_confirmed = list(state.confirmed_rule_ops or ())
            confirmed_rule_events.extend(state_confirmed)
            pfcp_rows.append({
                "endpoints": [state.endpoint_a, state.endpoint_b],
                "message_counts": dict(state.messages.most_common()),
                "paired_transactions": len(paired),
                "paired_procedures": dict(paired_procedures.most_common()),
                "transaction_latency_ms": _latency_summary(state.transaction_latencies_ms or []),
                "outstanding_requests": len(state.requests - state.responses),
                "orphan_responses": len(state.responses - state.requests),
                "request_retransmissions": state.request_retransmissions,
                "response_retransmissions": state.response_retransmissions,
                "header_seids": [f"0x{value:016x}" for value in sorted(state.header_seids or ())],
                "fseids": [{"seid": f"0x{seid:016x}", "ipv4": ipv4, "ipv6": ipv6} for seid, ipv4, ipv6 in sorted(state.fseids or ())],
                "fteids": [{"teid": teid, "teid_hex": f"0x{teid:08x}", "ipv4": ipv4, "ipv6": ipv6} for teid, ipv4, ipv6 in fteids],
                "node_ids": sorted(state.nodes or ()),
                "network_instances": sorted(state.network_instances or ()),
                "accepted_causes": dict((state.accepted_causes or Counter()).most_common()),
                "rejected_causes": dict((state.rejected_causes or Counter()).most_common()),
                "confirmed_rule_event_count": len(state_confirmed),
                "confirmed_rule_events": state_confirmed[:512],
                "pending_rule_event_count": sum(len(value) for value in (state.pending_rule_ops or {}).values()),
                "unconfirmed_rule_event_count": len(state.unconfirmed_rule_ops or ()),
                "rejected_rule_event_count": state.rejected_rule_op_count,
            })
        diameter_rows: list[dict[str, Any]] = []
        for state in sorted(self._diameter.values(), key=lambda item: (item.endpoint_a, item.endpoint_b)):
            paired = state.requests & state.answers
            paired_commands = Counter(str(tx[4]) for tx in paired)
            diameter_rows.append({
                "endpoints": [state.endpoint_a, state.endpoint_b],
                "message_counts": dict(state.messages.most_common()),
                "paired_transactions": len(paired),
                "paired_command_codes": dict(paired_commands.most_common()),
                "transaction_latency_ms": _latency_summary(state.transaction_latencies_ms or []),
                "outstanding_requests": len(state.requests - state.answers),
                "orphan_answers": len(state.answers - state.requests),
                "request_retransmissions": state.request_retransmissions,
                "answer_retransmissions": state.answer_retransmissions,
                "retransmission_flag_observations": state.retransmission_flag_observations,
                "application_ids": {str(key): value for key, value in (state.application_ids or Counter()).most_common()},
                "result_codes": {str(key): value for key, value in (state.result_codes or Counter()).most_common()},
                "vendor_ids": sorted(state.vendor_ids or ()),
                "origin_hosts": sorted(state.origin_hosts or ()),
                "origin_realms": sorted(state.origin_realms or ()),
                "destination_hosts": sorted(state.destination_hosts or ()),
                "destination_realms": sorted(state.destination_realms or ()),
                "session_id_hashes": sorted(state.session_hashes or ()),
            })
        matched_teids = sorted(pfcp_teids & set(self._gtpu_teids))
        qos_correlations = build_pfcp_gtpu_qos_correlations(confirmed_rule_events, self._gtpu_teids, self._gtpu_qfis)
        return {
            "schema": "arenyxa.mobile-core-forensics/v1",
            "pfcp_peer_count": len(pfcp_rows),
            "diameter_peer_count": len(diameter_rows),
            "observed_gtpu_teid_count": len(self._gtpu_teids),
            "pfcp_advertised_teid_count": len(pfcp_teids),
            "pfcp_gtpu_matched_teids": [{"teid": value, "teid_hex": f"0x{value:08x}", "gtpu_packets": self._gtpu_teids[value]} for value in matched_teids],
            "pfcp_gtpu_matched_teid_count": len(matched_teids),
            "gtpu_qfi_observations": {
                f"0x{teid:08x}": {str(qfi): count for qfi, count in counter.most_common()}
                for teid, counter in sorted(self._gtpu_qfis.items())
            },
            "pfcp_gtpu_qos_correlations": qos_correlations,
            "pfcp_gtpu_qos_correlation_count": len(qos_correlations),
            "pfcp_peers": pfcp_rows,
            "diameter_peers": diameter_rows,
            "limits_reached": sorted(self._limits_reached),
            "subscriber_identity_values_retained": False,
            "interpretation": (
                "PFCP F-TEID/QER-QFI to GTP-U TEID/PDU-Session-QFI equality and Diameter request/answer pairing are passive correlation evidence. "
                "PFCP rule changes are promoted to confirmed evidence only after an observed accepted response. TEID reuse, mobility, asymmetric capture, proxying, realm routing, and incomplete observation must be considered before inferring a complete subscriber or session lifecycle."
            ),
        }
