from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_BGP_ROUTES = 200_000
_MAX_PREFIX_CHURN = 4096
_MAX_OSPF_ROUTERS = 100_000
_MAX_ADJACENCIES = 200_000
_MAX_ISIS_SYSTEMS = 100_000
_MAX_ISIS_LSPS = 200_000
_MAX_LDP_SPEAKERS = 100_000
_MAX_LDP_LABELS = 200_000
_MAX_BFD_SESSIONS = 200_000
_MAX_VRRP_ROUTERS = 100_000


def _native_fields(packet: PacketRecord, name: str) -> dict[str, Any]:
    layers = packet.metadata.get("native_layers")
    if not isinstance(layers, list):
        return {}
    for layer in layers:
        if isinstance(layer, Mapping) and str(layer.get("name") or "").casefold() == name:
            fields = layer.get("fields")
            return dict(fields) if isinstance(fields, Mapping) else {}
    return {}


def _as_path(fields: Mapping[str, Any]) -> list[int]:
    attributes = fields.get("path_attributes") if isinstance(fields.get("path_attributes"), list) else []
    # RFC 6793 AS4_PATH carries the authoritative 4-octet representation when present.
    for preferred in ("AS4_PATH", "AS_PATH"):
        for attribute in attributes:
            if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != preferred:
                continue
            path: list[int] = []
            segments = attribute.get("segments") if isinstance(attribute.get("segments"), list) else []
            for segment in segments:
                if not isinstance(segment, Mapping):
                    continue
                values = segment.get("asns") if isinstance(segment.get("asns"), list) else []
                for value in values:
                    try:
                        path.append(int(value))
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if len(path) >= 256:
                        return path
            if path:
                return path
    return []


def _path_fingerprint(path: list[int]) -> str:
    canonical = json.dumps(path, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"arenyxa-bgp-path/v1\x00" + canonical).hexdigest()


def _bgp_update_prefixes(fields: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    announced = [str(value) for value in fields.get("nlri", [])] if isinstance(fields.get("nlri"), list) else []
    withdrawn = (
        [str(value) for value in fields.get("withdrawn_routes", [])]
        if isinstance(fields.get("withdrawn_routes"), list)
        else []
    )
    attributes = fields.get("path_attributes") if isinstance(fields.get("path_attributes"), list) else []
    for attribute in attributes:
        if not isinstance(attribute, Mapping):
            continue
        name = str(attribute.get("name") or "")
        if (
            name == "MP_REACH_NLRI"
            and int(attribute.get("afi") or 0) in {1, 2}
            and int(attribute.get("safi") or 0) == 1
            and isinstance(attribute.get("nlri"), list)
        ):
            announced.extend(str(value) for value in attribute["nlri"] if isinstance(value, str))
        elif (
            name == "MP_UNREACH_NLRI"
            and int(attribute.get("afi") or 0) in {1, 2}
            and int(attribute.get("safi") or 0) == 1
            and isinstance(attribute.get("withdrawn_nlri"), list)
        ):
            withdrawn.extend(str(value) for value in attribute["withdrawn_nlri"] if isinstance(value, str))
    return list(dict.fromkeys(announced)), list(dict.fromkeys(withdrawn))


def _tlv_rows(fields: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = fields.get("tlvs")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


@dataclass(slots=True)
class _BgpRouteState:
    path_fingerprint: str
    path: tuple[int, ...]
    observations: int = 1


@dataclass(slots=True)
class _IsisLspState:
    sequence_number: str
    checksum: str
    observations: int = 1


@dataclass(slots=True)
class _BfdSessionState:
    state: str
    transitions: int = 0
    packets: int = 1
    min_detection_floor_us: int = 0


class RoutingControlPlaneAnalyzer:
    """Bounded passive routing, HA, and label-distribution control-plane analysis."""

    def __init__(self) -> None:
        self._bgp_messages: Counter[str] = Counter()
        self._bgp_peer_as: dict[str, int] = {}
        self._bgp_routes: dict[tuple[str, str], _BgpRouteState] = {}
        self._bgp_route_limit_reached = False
        self._bgp_announcements = 0
        self._bgp_withdrawals = 0
        self._bgp_path_changes = 0
        self._bgp_notifications = 0
        self._prefix_churn: Counter[str] = Counter()
        self._ospf_packet_types: Counter[str] = Counter()
        self._ospf_lsa_types: Counter[str] = Counter()
        self._ospf_routers: set[str] = set()
        self._ospf_adjacencies: set[tuple[str, str]] = set()
        self._ospf_malformed_lsas = 0
        self._isis_pdu_types: Counter[str] = Counter()
        self._isis_tlv_types: Counter[str] = Counter()
        self._isis_systems: set[str] = set()
        self._isis_hostnames: dict[str, str] = {}
        self._isis_addresses: dict[str, set[str]] = {}
        self._isis_prefixes: dict[str, set[str]] = {}
        self._isis_adjacencies: set[tuple[str, str]] = set()
        self._isis_lsps: dict[str, _IsisLspState] = {}
        self._isis_lsp_changes = 0
        self._isis_malformed_vectors = 0
        self._ldp_messages: Counter[str] = Counter()
        self._ldp_speakers: dict[str, str] = {}
        self._ldp_labels: set[tuple[str, int]] = set()
        self._ldp_bindings: set[tuple[str, str, int]] = set()
        self._ldp_addresses: dict[str, set[str]] = {}
        self._ldp_notifications = 0
        self._ldp_malformed_vectors = 0
        self._bfd_states: Counter[str] = Counter()
        self._bfd_sessions: dict[tuple[str, str, int, int], _BfdSessionState] = {}
        self._bfd_session_limit_reached = False
        self._bfd_down_observations = 0
        self._vrrp_versions: Counter[str] = Counter()
        self._vrrp_routers: dict[tuple[str, int], dict[str, Any]] = {}
        self._vrrp_relinquishments = 0

    def feed(self, packet: PacketRecord) -> None:
        for name, handler in (
            ("bgp", self._feed_bgp),
            ("ospf", self._feed_ospf),
            ("isis", self._feed_isis),
            ("ldp", self._feed_ldp),
            ("bfd", self._feed_bfd),
            ("vrrp", self._feed_vrrp),
        ):
            fields = _native_fields(packet, name)
            if fields:
                handler(packet, fields)

    def _feed_bgp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        message = str(fields.get("message_name") or "unknown")
        self._bgp_messages[message] += 1
        if message == "open":
            self._observe_bgp_open(packet, fields)
            return
        if message == "notification":
            self._bgp_notifications += 1
            return
        if message != "update":
            return
        path = _as_path(fields)
        path_fp = _path_fingerprint(path)
        peer = str(packet.source or "unknown")
        announced, withdrawn = _bgp_update_prefixes(fields)
        for prefix in announced:
            self._bgp_announcements += 1
            self._prefix_churn[prefix] += 1
            self._observe_bgp_route(peer, prefix, path, path_fp)
        for prefix in withdrawn:
            self._bgp_withdrawals += 1
            self._prefix_churn[prefix] += 1
            self._bgp_routes.pop((peer, prefix), None)

    def _observe_bgp_open(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        try:
            asn = int(fields.get("asn") or 0)
        except (TypeError, ValueError, OverflowError):
            asn = 0
        capabilities = fields.get("capabilities") if isinstance(fields.get("capabilities"), list) else []
        for capability in capabilities:
            if isinstance(capability, Mapping) and str(capability.get("name") or "") == "four-octet-asn":
                try:
                    asn = int(capability.get("asn4") or asn)
                except (TypeError, ValueError, OverflowError):
                    continue
        if asn and packet.source and len(self._bgp_peer_as) < 100_000:
            self._bgp_peer_as[packet.source] = asn

    def _observe_bgp_route(self, peer: str, prefix: str, path: list[int], path_fp: str) -> None:
        key = (peer, prefix)
        current = self._bgp_routes.get(key)
        if current is None:
            if len(self._bgp_routes) >= _MAX_BGP_ROUTES:
                self._bgp_route_limit_reached = True
                return
            self._bgp_routes[key] = _BgpRouteState(path_fp, tuple(path))
        elif current.path_fingerprint != path_fp:
            self._bgp_path_changes += 1
            current.path_fingerprint = path_fp
            current.path = tuple(path)
            current.observations += 1
        else:
            current.observations += 1

    def _feed_ospf(self, _packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        packet_type = str(fields.get("packet_type_name") or "unknown")
        self._ospf_packet_types[packet_type] += 1
        router = str(fields.get("router_id") or "")
        if router and len(self._ospf_routers) < _MAX_OSPF_ROUTERS:
            self._ospf_routers.add(router)
        if packet_type == "hello":
            neighbors = fields.get("neighbors") if isinstance(fields.get("neighbors"), list) else []
            for raw_neighbor in neighbors[:256]:
                neighbor = str(raw_neighbor or "")
                if not router or not neighbor or len(self._ospf_adjacencies) >= _MAX_ADJACENCIES:
                    continue
                self._ospf_adjacencies.add(tuple(sorted((router, neighbor))))
        lsas = fields.get("lsas") if isinstance(fields.get("lsas"), list) else []
        for lsa in lsas[:256]:
            if not isinstance(lsa, Mapping):
                continue
            self._ospf_lsa_types[str(lsa.get("ls_type_name") or "unknown")] += 1
            advertising = str(lsa.get("advertising_router") or "")
            if advertising and len(self._ospf_routers) < _MAX_OSPF_ROUTERS:
                self._ospf_routers.add(advertising)
            if bool(lsa.get("body_malformed")):
                self._ospf_malformed_lsas += 1

    def _feed_isis(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        pdu_type = str(fields.get("pdu_type_name") or "unknown")
        self._isis_pdu_types[pdu_type] += 1
        source_id = str(fields.get("source_id") or "")
        if source_id and len(self._isis_systems) < _MAX_ISIS_SYSTEMS:
            self._isis_systems.add(source_id)
        identity = source_id or str(packet.source or "")
        for tlv in _tlv_rows(fields):
            name = str(tlv.get("name") or "unknown")
            self._isis_tlv_types[name] += 1
            if name == "dynamic-hostname" and identity:
                hostname = str(tlv.get("hostname") or "")
                if hostname:
                    self._isis_hostnames[identity] = hostname[:255]
            if name in {"ipv4-interface-addresses", "ipv6-interface-addresses"} and identity:
                addresses = tlv.get("addresses") if isinstance(tlv.get("addresses"), list) else []
                bucket = self._isis_addresses.setdefault(identity, set())
                for address in addresses[:128]:
                    if len(bucket) < 256:
                        bucket.add(str(address))
            if name in {"extended-ipv4-reachability", "ipv6-reachability"} and identity:
                prefixes = tlv.get("prefixes") if isinstance(tlv.get("prefixes"), list) else []
                bucket = self._isis_prefixes.setdefault(identity, set())
                for prefix_row in prefixes[:256]:
                    if isinstance(prefix_row, Mapping) and prefix_row.get("prefix") and len(bucket) < 4096:
                        bucket.add(str(prefix_row["prefix"]))
            if name == "extended-is-reachability" and identity:
                neighbors = tlv.get("neighbors") if isinstance(tlv.get("neighbors"), list) else []
                for neighbor_row in neighbors[:128]:
                    if not isinstance(neighbor_row, Mapping) or len(self._isis_adjacencies) >= _MAX_ADJACENCIES:
                        continue
                    neighbor = str(neighbor_row.get("neighbor_id") or "")
                    if neighbor:
                        self._isis_adjacencies.add(tuple(sorted((identity, neighbor))))
        if bool(fields.get("tlvs_truncated")):
            self._isis_malformed_vectors += 1
        lsp_id = str(fields.get("lsp_id") or "")
        if lsp_id:
            if len(self._isis_lsps) >= _MAX_ISIS_LSPS and lsp_id not in self._isis_lsps:
                return
            sequence = str(fields.get("sequence_number") or "")
            checksum = str(fields.get("checksum") or "")
            current = self._isis_lsps.get(lsp_id)
            if current is None:
                self._isis_lsps[lsp_id] = _IsisLspState(sequence, checksum)
            elif current.sequence_number != sequence or current.checksum != checksum:
                self._isis_lsp_changes += 1
                current.sequence_number = sequence
                current.checksum = checksum
                current.observations += 1
            else:
                current.observations += 1

    def _feed_ldp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        lsr_id = str(fields.get("lsr_id") or "")
        if lsr_id and packet.source and len(self._ldp_speakers) < _MAX_LDP_SPEAKERS:
            self._ldp_speakers[str(packet.source)] = lsr_id
        if bool(fields.get("messages_truncated")):
            self._ldp_malformed_vectors += 1
        messages = fields.get("messages") if isinstance(fields.get("messages"), list) else []
        for message in messages[:256]:
            if not isinstance(message, Mapping):
                continue
            name = str(message.get("type_name") or "unknown")
            self._ldp_messages[name] += 1
            if name == "notification":
                self._ldp_notifications += 1
            if bool(message.get("malformed")):
                self._ldp_malformed_vectors += 1
            tlvs = message.get("tlvs") if isinstance(message.get("tlvs"), list) else []
            labels: list[int] = []
            fec_prefixes: list[str] = []
            for tlv in tlvs[:512]:
                if not isinstance(tlv, Mapping):
                    continue
                if "label" in tlv and lsr_id:
                    try:
                        label = int(tlv["label"])
                    except (TypeError, ValueError, OverflowError):
                        label = -1
                    if label >= 0:
                        labels.append(label)
                        if len(self._ldp_labels) < _MAX_LDP_LABELS:
                            self._ldp_labels.add((lsr_id, label))
                if str(tlv.get("name") or "") == "fec":
                    elements = tlv.get("elements") if isinstance(tlv.get("elements"), list) else []
                    for element in elements[:256]:
                        if isinstance(element, Mapping) and element.get("prefix"):
                            fec_prefixes.append(str(element["prefix"]))
                if str(tlv.get("name") or "") == "address-list" and lsr_id:
                    addresses = tlv.get("addresses") if isinstance(tlv.get("addresses"), list) else []
                    bucket = self._ldp_addresses.setdefault(lsr_id, set())
                    for address in addresses[:256]:
                        if len(bucket) < 1024:
                            bucket.add(str(address))
            if lsr_id and name == "label-mapping":
                for prefix in fec_prefixes:
                    for label in labels:
                        if len(self._ldp_bindings) < _MAX_LDP_LABELS:
                            self._ldp_bindings.add((lsr_id, prefix, label))
            elif lsr_id and name in {"label-withdraw", "label-release"} and fec_prefixes:
                wanted = set(fec_prefixes)
                self._ldp_bindings = {row for row in self._ldp_bindings if not (row[0] == lsr_id and row[1] in wanted)}

    def _feed_bfd(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        state = str(fields.get("state_name") or "unknown")
        self._bfd_states[state] += 1
        if state in {"admin-down", "down"}:
            self._bfd_down_observations += 1
        try:
            my_disc = int(fields.get("my_discriminator") or 0)
            your_disc = int(fields.get("your_discriminator") or 0)
            detection = int(fields.get("detection_time_floor_us") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        endpoints = tuple(sorted((str(packet.source or ""), str(packet.destination or ""))))
        key = (endpoints[0], endpoints[1], min(my_disc, your_disc), max(my_disc, your_disc))
        current = self._bfd_sessions.get(key)
        if current is None:
            if len(self._bfd_sessions) >= _MAX_BFD_SESSIONS:
                self._bfd_session_limit_reached = True
                return
            self._bfd_sessions[key] = _BfdSessionState(state=state, min_detection_floor_us=detection)
            return
        current.packets += 1
        if state != current.state:
            current.transitions += 1
            current.state = state
        if detection > 0 and (current.min_detection_floor_us <= 0 or detection < current.min_detection_floor_us):
            current.min_detection_floor_us = detection

    def _feed_vrrp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        version = str(fields.get("version") or "unknown")
        self._vrrp_versions[version] += 1
        try:
            vrid = int(fields.get("virtual_router_id") or 0)
            priority = int(fields.get("priority") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        if priority == 0:
            self._vrrp_relinquishments += 1
        key = (str(packet.source or "unknown"), vrid)
        if key not in self._vrrp_routers and len(self._vrrp_routers) >= _MAX_VRRP_ROUTERS:
            return
        self._vrrp_routers[key] = {
            "source": key[0],
            "virtual_router_id": vrid,
            "version": version,
            "priority": priority,
            "addresses": [str(value) for value in fields.get("addresses", [])[:64]]
            if isinstance(fields.get("addresses"), list)
            else [],
            "advertisement_interval_seconds": fields.get("advertisement_interval_seconds")
            or fields.get("max_advertisement_interval_seconds"),
        }

    def _finalize_bgp(self) -> dict[str, Any]:
        top_churn = [{"prefix": prefix, "events": count} for prefix, count in self._prefix_churn.most_common(_MAX_PREFIX_CHURN)]
        route_rows = [
            {
                "peer": peer,
                "prefix": prefix,
                "as_path": list(state.path),
                "path_fingerprint_sha256": state.path_fingerprint,
                "observations": state.observations,
            }
            for (peer, prefix), state in self._bgp_routes.items()
        ]
        route_rows.sort(key=lambda row: (row["peer"], row["prefix"]))
        return {
            "messages": dict(self._bgp_messages.most_common()),
            "peer_as": dict(sorted(self._bgp_peer_as.items())),
            "active_route_count": len(self._bgp_routes),
            "route_limit_reached": self._bgp_route_limit_reached,
            "announcements": self._bgp_announcements,
            "withdrawals": self._bgp_withdrawals,
            "path_changes": self._bgp_path_changes,
            "notifications": self._bgp_notifications,
            "top_prefix_churn": top_churn,
            "routes": route_rows[:4096],
        }

    def finalize(self) -> dict[str, Any]:
        return {
            "schema": "arenyxa.routing-control-plane/v2",
            "bgp": self._finalize_bgp(),
            "ospf": {
                "packet_types": dict(self._ospf_packet_types.most_common()),
                "router_count": len(self._ospf_routers),
                "routers": sorted(self._ospf_routers)[:4096],
                "adjacency_count": len(self._ospf_adjacencies),
                "adjacencies": [list(row) for row in sorted(self._ospf_adjacencies)[:4096]],
                "lsa_types": dict(self._ospf_lsa_types.most_common()),
                "malformed_lsa_bodies": self._ospf_malformed_lsas,
            },
            "isis": {
                "pdu_types": dict(self._isis_pdu_types.most_common()),
                "system_count": len(self._isis_systems),
                "systems": sorted(self._isis_systems)[:4096],
                "hostnames": dict(sorted(self._isis_hostnames.items())),
                "interface_addresses": {key: sorted(value) for key, value in sorted(self._isis_addresses.items())},
                "reachable_prefixes": {key: sorted(value) for key, value in sorted(self._isis_prefixes.items())},
                "adjacency_count": len(self._isis_adjacencies),
                "adjacencies": [list(row) for row in sorted(self._isis_adjacencies)[:4096]],
                "lsp_count": len(self._isis_lsps),
                "lsp_changes": self._isis_lsp_changes,
                "tlv_types": dict(self._isis_tlv_types.most_common()),
                "malformed_tlv_vectors": self._isis_malformed_vectors,
            },
            "ldp": {
                "messages": dict(self._ldp_messages.most_common()),
                "speakers": dict(sorted(self._ldp_speakers.items())),
                "observed_label_count": len(self._ldp_labels),
                "labels": [{"lsr_id": lsr_id, "label": label} for lsr_id, label in sorted(self._ldp_labels)[:4096]],
                "active_binding_count": len(self._ldp_bindings),
                "bindings": [
                    {"lsr_id": lsr_id, "fec_prefix": prefix, "label": label}
                    for lsr_id, prefix, label in sorted(self._ldp_bindings)[:4096]
                ],
                "addresses": {key: sorted(value) for key, value in sorted(self._ldp_addresses.items())},
                "notifications": self._ldp_notifications,
                "malformed_vectors": self._ldp_malformed_vectors,
            },
            "bfd": {
                "states": dict(self._bfd_states.most_common()),
                "session_count": len(self._bfd_sessions),
                "session_limit_reached": self._bfd_session_limit_reached,
                "down_observations": self._bfd_down_observations,
                "state_transitions": sum(row.transitions for row in self._bfd_sessions.values()),
                "minimum_detection_floor_us": min(
                    (row.min_detection_floor_us for row in self._bfd_sessions.values() if row.min_detection_floor_us > 0),
                    default=0,
                ),
            },
            "vrrp": {
                "versions": dict(self._vrrp_versions.most_common()),
                "virtual_router_count": len(self._vrrp_routers),
                "master_relinquishments": self._vrrp_relinquishments,
                "routers": [self._vrrp_routers[key] for key in sorted(self._vrrp_routers)[:4096]],
            },
        }
