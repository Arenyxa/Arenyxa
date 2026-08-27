from __future__ import annotations

from collections import Counter
from dataclasses import field
from datetime import datetime
from typing import Any, Mapping, Tuple

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord

_MAX_FLOWS = 100_000
_MAX_PENDING = 200_000
_MAX_ROWS = 2048
_MAX_IDENTITIES = 256

FlowKey = Tuple[Tuple[str, int], Tuple[str, int]]


def _timestamp(value: str) -> float | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, OverflowError):
        return None


def _layer(packet: PacketRecord, name: str) -> dict[str, Any]:
    layers = packet.metadata.get("native_layers")
    if not isinstance(layers, list):
        return {}
    wanted = name.casefold()
    for layer in layers:
        if not isinstance(layer, Mapping) or str(layer.get("name") or "").casefold() != wanted:
            continue
        fields = layer.get("fields")
        return dict(fields) if isinstance(fields, Mapping) else {}
    return {}


def _flow(packet: PacketRecord) -> FlowKey | None:
    if packet.source_port is None or packet.destination_port is None or not packet.source or not packet.destination:
        return None
    left = (str(packet.source), int(packet.source_port))
    right = (str(packet.destination), int(packet.destination_port))
    return (left, right) if left <= right else (right, left)


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * fraction))))
    return round(ordered[index], 3)


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


@dataclass(slots=True)
class _SmbFlow:
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    packets: int = 0
    bytes: int = 0
    requests: int = 0
    responses: int = 0
    errors: int = 0
    signed_packets: int = 0
    unsigned_packets: int = 0
    commands: Counter[str] = field(default_factory=Counter)
    session_ids: set[int] = field(default_factory=set)
    tree_ids: set[int] = field(default_factory=set)
    response_latencies_ms: list[float] = field(default_factory=list)
    ntlm_messages: Counter[str] = field(default_factory=Counter)
    identity_hashes: set[str] = field(default_factory=set)
    correlation_mismatches: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "endpoint_a": {"address": self.endpoint_a[0], "port": self.endpoint_a[1]},
            "endpoint_b": {"address": self.endpoint_b[0], "port": self.endpoint_b[1]},
            "packets": self.packets,
            "bytes": self.bytes,
            "requests": self.requests,
            "responses": self.responses,
            "errors": self.errors,
            "signed_packets": self.signed_packets,
            "unsigned_packets": self.unsigned_packets,
            "commands": dict(self.commands.most_common()),
            "session_ids": sorted(self.session_ids)[:128],
            "tree_ids": sorted(self.tree_ids)[:256],
            "ntlm_messages": dict(self.ntlm_messages.most_common()),
            "identity_hashes": sorted(self.identity_hashes)[:_MAX_IDENTITIES],
            "correlation_mismatches": self.correlation_mismatches,
            "response_latency_ms": {
                "p50": _percentile(self.response_latencies_ms, 0.50),
                "p95": _percentile(self.response_latencies_ms, 0.95),
                "p99": _percentile(self.response_latencies_ms, 0.99),
            },
        }


@dataclass(slots=True)
class _LdapFlow:
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    packets: int = 0
    operations: Counter[str] = field(default_factory=Counter)
    non_success_results: int = 0
    response_latencies_ms: list[float] = field(default_factory=list)
    target_hashes: set[str] = field(default_factory=set)
    correlation_mismatches: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "endpoint_a": {"address": self.endpoint_a[0], "port": self.endpoint_a[1]},
            "endpoint_b": {"address": self.endpoint_b[0], "port": self.endpoint_b[1]},
            "packets": self.packets,
            "operations": dict(self.operations.most_common()),
            "non_success_results": self.non_success_results,
            "target_hashes": sorted(self.target_hashes)[:_MAX_IDENTITIES],
            "correlation_mismatches": self.correlation_mismatches,
            "response_latency_ms": {
                "p50": _percentile(self.response_latencies_ms, 0.50),
                "p95": _percentile(self.response_latencies_ms, 0.95),
                "p99": _percentile(self.response_latencies_ms, 0.99),
            },
        }


@dataclass(slots=True)
class _KerberosFlow:
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    packets: int = 0
    messages: Counter[str] = field(default_factory=Counter)
    errors: Counter[str] = field(default_factory=Counter)
    inconsistent_message_types: int = 0

    def summary(self) -> dict[str, Any]:
        return {
            "endpoint_a": {"address": self.endpoint_a[0], "port": self.endpoint_a[1]},
            "endpoint_b": {"address": self.endpoint_b[0], "port": self.endpoint_b[1]},
            "packets": self.packets,
            "messages": dict(self.messages.most_common()),
            "errors": dict(self.errors.most_common()),
            "inconsistent_message_types": self.inconsistent_message_types,
        }


class EnterpriseAuthForensicsAnalyzer:
    """Bounded SMB/NTLM, LDAP and Kerberos cross-packet correlation.

    User/domain/DN values are represented by hashes produced by the native
    decoders; this analyzer never reconstructs or logs credential plaintext.
    """

    def __init__(self) -> None:
        self._smb: dict[tuple[tuple[str, int], tuple[str, int]], _SmbFlow] = {}
        self._ldap: dict[tuple[tuple[str, int], tuple[str, int]], _LdapFlow] = {}
        self._kerberos: dict[tuple[tuple[str, int], tuple[str, int]], _KerberosFlow] = {}
        self._smb_pending: dict[tuple[tuple[tuple[str, int], tuple[str, int]], int], tuple[float | None, str]] = {}
        self._ldap_pending: dict[tuple[tuple[tuple[str, int], tuple[str, int]], int], tuple[float | None, str]] = {}
        self._host_protocols: dict[tuple[str, str], set[str]] = {}
        self._flow_limit_reached = False
        self._pending_limit_reached = False

    def _host_pair(self, packet: PacketRecord, protocol: str) -> None:
        if not packet.source or not packet.destination:
            return
        pair = tuple(sorted((str(packet.source), str(packet.destination))))
        self._host_protocols.setdefault(pair, set()).add(protocol)

    def _smb_flow(self, key: FlowKey) -> _SmbFlow | None:
        item = self._smb.get(key)
        if item is None:
            if len(self._smb) >= _MAX_FLOWS:
                self._flow_limit_reached = True
                return None
            item = _SmbFlow(key[0], key[1])
            self._smb[key] = item
        return item

    def _ldap_flow(self, key: FlowKey) -> _LdapFlow | None:
        item = self._ldap.get(key)
        if item is None:
            if len(self._ldap) >= _MAX_FLOWS:
                self._flow_limit_reached = True
                return None
            item = _LdapFlow(key[0], key[1])
            self._ldap[key] = item
        return item

    def _kerberos_flow(self, key: FlowKey) -> _KerberosFlow | None:
        item = self._kerberos.get(key)
        if item is None:
            if len(self._kerberos) >= _MAX_FLOWS:
                self._flow_limit_reached = True
                return None
            item = _KerberosFlow(key[0], key[1])
            self._kerberos[key] = item
        return item

    def feed(self, packet: PacketRecord) -> None:
        key = _flow(packet)
        if key is None:
            return
        smb = _layer(packet, "smb")
        if smb:
            self._feed_smb(packet, key, smb)
        ldap = _layer(packet, "ldap")
        if ldap:
            self._feed_ldap(packet, key, ldap)
        kerberos = _layer(packet, "kerberos")
        if kerberos:
            self._feed_kerberos(packet, key, kerberos)

    def _feed_smb(self, packet: PacketRecord, key: FlowKey, fields: Mapping[str, Any]) -> None:
        state = self._smb_flow(key)
        if state is None:
            return
        self._host_pair(packet, "smb")
        state.packets += 1
        state.bytes += max(0, int(packet.length))
        command = str(fields.get("command_name") or fields.get("command") or "unknown")
        state.commands[command] += 1
        signed = bool(fields.get("signed"))
        state.signed_packets += int(signed)
        state.unsigned_packets += int(not signed)
        session_id = _safe_int(fields.get("session_id"))
        tree_id = _safe_int(fields.get("tree_id"))
        if session_id:
            state.session_ids.add(session_id)
        if tree_id:
            state.tree_ids.add(tree_id)
        body = fields.get("body") if isinstance(fields.get("body"), Mapping) else {}
        ntlm = body.get("ntlmssp") if isinstance(body, Mapping) and isinstance(body.get("ntlmssp"), Mapping) else {}
        if ntlm:
            state.ntlm_messages[str(ntlm.get("message_name") or "unknown")] += 1
            for name in ("domain_sha256", "user_sha256", "workstation_sha256", "target_name_sha256"):
                value = str(ntlm.get(name) or "")
                if value and len(state.identity_hashes) < _MAX_IDENTITIES:
                    state.identity_hashes.add(value)
            self._host_pair(packet, "ntlmssp")
        message_id = _safe_int(fields.get("message_id"))
        pending_key = (key, message_id)
        timestamp = _timestamp(packet.timestamp)
        if bool(fields.get("response")):
            state.responses += 1
            if _safe_int(fields.get("status")) != 0:
                state.errors += 1
            pending = self._smb_pending.pop(pending_key, None)
            if pending is not None:
                began, expected_command = pending
                if expected_command != command:
                    state.correlation_mismatches += 1
                if began is not None and timestamp is not None and timestamp >= began:
                    state.response_latencies_ms.append((timestamp - began) * 1000.0)
        else:
            state.requests += 1
            if len(self._smb_pending) < _MAX_PENDING:
                self._smb_pending[pending_key] = (timestamp, command)
            else:
                self._pending_limit_reached = True

    def _feed_ldap(self, packet: PacketRecord, key: FlowKey, fields: Mapping[str, Any]) -> None:
        state = self._ldap_flow(key)
        if state is None:
            return
        self._host_pair(packet, "ldap")
        state.packets += 1
        operation = str(fields.get("operation") or "unknown")
        state.operations[operation] += 1
        for name in ("bind_name_sha256", "base_dn_sha256", "target_dn_sha256"):
            value = str(fields.get(name) or "")
            if value and len(state.target_hashes) < _MAX_IDENTITIES:
                state.target_hashes.add(value)
        message_id = _safe_int(fields.get("message_id"))
        pending_key = (key, message_id)
        timestamp = _timestamp(packet.timestamp)
        request_ops = {
            "bind-request", "search-request", "modify-request", "add-request", "delete-request",
            "modify-dn-request", "compare-request", "extended-request",
        }
        terminal_response = operation.endswith("-response") or operation == "search-done"
        if operation in request_ops:
            if len(self._ldap_pending) < _MAX_PENDING:
                self._ldap_pending[pending_key] = (timestamp, operation)
            else:
                self._pending_limit_reached = True
        elif terminal_response:
            if _safe_int(fields.get("result_code")) != 0:
                state.non_success_results += 1
            pending = self._ldap_pending.pop(pending_key, None)
            if pending is not None:
                began, request_operation = pending
                expected_prefix = request_operation.removesuffix("-request")
                if operation != "search-done" and not operation.startswith(expected_prefix):
                    state.correlation_mismatches += 1
                if began is not None and timestamp is not None and timestamp >= began:
                    state.response_latencies_ms.append((timestamp - began) * 1000.0)

    def _feed_kerberos(self, packet: PacketRecord, key: FlowKey, fields: Mapping[str, Any]) -> None:
        state = self._kerberos_flow(key)
        if state is None:
            return
        self._host_pair(packet, "kerberos")
        state.packets += 1
        name = str(fields.get("message_name") or "unknown")
        state.messages[name] += 1
        if fields.get("message_type_consistent") is False:
            state.inconsistent_message_types += 1
        if name == "error":
            state.errors[str(fields.get("error_name") or fields.get("error_code") or "unknown")] += 1

    def finalize(self) -> dict[str, Any]:
        smb_rows = [item.summary() for item in self._smb.values()]
        ldap_rows = [item.summary() for item in self._ldap.values()]
        kerberos_rows = [item.summary() for item in self._kerberos.values()]
        auth_paths = [
            {
                "host_a": pair[0],
                "host_b": pair[1],
                "protocols": sorted(protocols),
                "windows_auth_chain_observed": "smb" in protocols and ("kerberos" in protocols or "ntlmssp" in protocols),
                "directory_auth_chain_observed": "ldap" in protocols and "kerberos" in protocols,
            }
            for pair, protocols in sorted(self._host_protocols.items())
            if len(protocols) > 1
        ]
        return {
            "schema": "arenyxa.enterprise-auth-forensics/v1",
            "flow_limit_reached": self._flow_limit_reached,
            "pending_limit_reached": self._pending_limit_reached,
            "unmatched_smb_requests": len(self._smb_pending),
            "unmatched_ldap_requests": len(self._ldap_pending),
            "smb_flow_count": len(smb_rows),
            "ldap_flow_count": len(ldap_rows),
            "kerberos_flow_count": len(kerberos_rows),
            "smb": sorted(smb_rows, key=lambda row: int(row.get("bytes") or 0), reverse=True)[:_MAX_ROWS],
            "ldap": sorted(ldap_rows, key=lambda row: int(row.get("packets") or 0), reverse=True)[:_MAX_ROWS],
            "kerberos": sorted(kerberos_rows, key=lambda row: int(row.get("packets") or 0), reverse=True)[:_MAX_ROWS],
            "auth_paths": auth_paths[:_MAX_ROWS],
            "sensitive_identity_plaintext_retained": False,
        }
