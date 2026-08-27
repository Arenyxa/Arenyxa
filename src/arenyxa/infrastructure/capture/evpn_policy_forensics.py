from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_ACTIVE_ROUTES = 200_000
_MAX_POLICY_DOMAINS = 50_000
_MAX_BINDINGS_PER_DOMAIN = 8192


def _layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _communities(fields: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    attributes = fields.get("path_attributes") if isinstance(fields.get("path_attributes"), list) else []
    rows: list[Mapping[str, Any]] = []
    for attribute in attributes[:512]:
        if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "EXTENDED_COMMUNITIES":
            continue
        values = attribute.get("communities") if isinstance(attribute.get("communities"), list) else []
        rows.extend(value for value in values[:512] if isinstance(value, Mapping))
    return rows[:1024]


def _route_policy(fields: Mapping[str, Any]) -> tuple[set[str], set[str], set[str]]:
    targets: set[str] = set()
    origins: set[str] = set()
    encapsulations: set[str] = set()
    for row in _communities(fields):
        name = str(row.get("name") or "")
        value = str(row.get("value") or "")
        if name == "route-target" and value:
            targets.add(value)
        elif name == "route-origin" and value:
            origins.add(value)
        elif name == "encapsulation" and row.get("tunnel_type_name"):
            encapsulations.add(str(row["tunnel_type_name"]))
    attributes = fields.get("path_attributes") if isinstance(fields.get("path_attributes"), list) else []
    for attribute in attributes[:512]:
        if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "TUNNEL_ENCAPSULATION":
            continue
        tunnels = attribute.get("tunnels") if isinstance(attribute.get("tunnels"), list) else []
        for tunnel in tunnels[:128]:
            if isinstance(tunnel, Mapping) and not bool(tunnel.get("malformed")) and tunnel.get("tunnel_type_name"):
                encapsulations.add(str(tunnel["tunnel_type_name"]))
    return targets, origins, encapsulations


def _rd_value(route: Mapping[str, Any]) -> str:
    raw = route.get("route_distinguisher")
    if not isinstance(raw, Mapping):
        return ""
    if raw.get("value"):
        return str(raw["value"])
    if raw.get("administrator") is not None and raw.get("assigned") is not None:
        return f"{raw['administrator']}:{raw['assigned']}"
    return str(raw.get("hex") or "")


def _esi_value(route: Mapping[str, Any]) -> str:
    raw = route.get("ethernet_segment_identifier")
    return str(raw.get("value_hex") or "") if isinstance(raw, Mapping) else ""


def _route_key(route: Mapping[str, Any]) -> str:
    route_type = int(route.get("route_type") or 0)
    rd = _rd_value(route)
    tag = str(route.get("ethernet_tag_id") or 0)
    if route_type == 1:
        identity = f"{rd}|{_esi_value(route)}|{tag}"
    elif route_type == 2:
        identity = f"{rd}|{_esi_value(route)}|{tag}|{str(route.get('mac_address') or '').casefold()}|{route.get('ip_address') or ''}"
    elif route_type == 3:
        identity = f"{rd}|{tag}|{route.get('originating_router_ip') or ''}"
    elif route_type == 4:
        identity = f"{rd}|{_esi_value(route)}|{route.get('originating_router_ip') or ''}"
    elif route_type == 5:
        identity = f"{rd}|{_esi_value(route)}|{tag}|{route.get('ip_prefix') or ''}"
    else:
        identity = f"{rd}|{tag}|{route.get('payload_sha256') or route.get('length') or ''}"
    return f"rt{route_type}:{identity}"


def _service_ids(route: Mapping[str, Any]) -> set[int]:
    values: set[int] = set()
    for key in ("service", "service2"):
        raw = route.get(key)
        if not isinstance(raw, Mapping) or raw.get("service_id_24") is None:
            continue
        try:
            value = int(raw["service_id_24"])
        except (TypeError, ValueError, OverflowError):
            continue
        if 0 <= value <= 0xFFFFFF:
            values.add(value)
    return values


@dataclass(slots=True)
class _PeerPolicy:
    route_targets: set[str]
    route_origins: set[str]
    encapsulations: set[str]
    next_hops: set[str]


@dataclass(slots=True)
class _RouteState:
    route_type: int
    route_type_name: str
    route_distinguisher: str
    ethernet_tag_id: int
    service_ids: set[int]
    mac_addresses: set[str]
    ip_addresses: set[str]
    prefixes: set[str]
    origins: set[str]
    peer_policy: dict[str, _PeerPolicy]


class EvpnPolicyDomainAnalyzer:
    """Track bounded active EVPN policy domains from passive BGP evidence.

    Route Target/Origin membership is stored per advertising peer so an
    MP_UNREACH from one peer cannot erase another peer's active policy binding,
    and withdrawn policy evidence is not presented as current ownership.
    """

    def __init__(self) -> None:
        self._routes: dict[str, _RouteState] = {}
        self._route_limit_reached = False
        self._vxlan_vnis: Counter[int] = Counter()

    def feed(self, packet: PacketRecord) -> None:
        for layer in _layers(packet):
            name = str(layer.get("name") or "").casefold()
            fields = _fields(layer)
            if name == "bgp":
                self._feed_bgp(packet, fields)
            elif name == "vxlan":
                try:
                    vni = int(fields.get("vni"))
                except (TypeError, ValueError, OverflowError):
                    continue
                if 0 <= vni <= 0xFFFFFF:
                    self._vxlan_vnis[vni] += 1

    def _feed_bgp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        if str(fields.get("message_name") or "") != "update":
            return
        peer = str(packet.source or "unknown")
        targets, origins, encapsulations = _route_policy(fields)
        attributes = fields.get("path_attributes") if isinstance(fields.get("path_attributes"), list) else []
        for attribute in attributes[:512]:
            if not isinstance(attribute, Mapping):
                continue
            name = str(attribute.get("name") or "")
            if name not in {"MP_REACH_NLRI", "MP_UNREACH_NLRI"}:
                continue
            if int(attribute.get("afi") or 0) != 25 or int(attribute.get("safi") or 0) != 70:
                continue
            key = "nlri" if name == "MP_REACH_NLRI" else "withdrawn_nlri"
            routes = attribute.get(key) if isinstance(attribute.get(key), list) else []
            next_hops = {
                str(item) for item in attribute.get("next_hops", [])
                if isinstance(attribute.get("next_hops"), list) and str(item)
            }
            for route in routes[:4096]:
                if not isinstance(route, Mapping) or bool(route.get("malformed")):
                    continue
                route_key = _route_key(route)
                if name == "MP_UNREACH_NLRI":
                    current = self._routes.get(route_key)
                    if current is not None:
                        current.peer_policy.pop(peer, None)
                        if not current.peer_policy:
                            self._routes.pop(route_key, None)
                    continue
                state = self._routes.get(route_key)
                if state is None:
                    if len(self._routes) >= _MAX_ACTIVE_ROUTES:
                        self._route_limit_reached = True
                        continue
                    state = self._state_from_route(route)
                    self._routes[route_key] = state
                state.peer_policy[peer] = _PeerPolicy(set(targets), set(origins), set(encapsulations), set(next_hops))

    @staticmethod
    def _state_from_route(route: Mapping[str, Any]) -> _RouteState:
        try:
            tag = int(route.get("ethernet_tag_id") or 0)
        except (TypeError, ValueError, OverflowError):
            tag = 0
        mac = str(route.get("mac_address") or "").casefold()
        address = str(route.get("ip_address") or "")
        prefix = str(route.get("ip_prefix") or "")
        origin = str(route.get("originating_router_ip") or "")
        return _RouteState(
            route_type=int(route.get("route_type") or 0),
            route_type_name=str(route.get("route_type_name") or ""),
            route_distinguisher=_rd_value(route),
            ethernet_tag_id=tag,
            service_ids=_service_ids(route),
            mac_addresses={mac} if mac else set(),
            ip_addresses={address} if address else set(),
            prefixes={prefix} if prefix else set(),
            origins={origin} if origin else set(),
            peer_policy={},
        )

    def finalize(self) -> dict[str, Any]:
        domains: dict[str, dict[str, Any]] = {}
        origin_counts: Counter[str] = Counter()
        unscoped = 0
        for route_key, state in self._routes.items():
            route_targets = {target for policy in state.peer_policy.values() for target in policy.route_targets}
            route_origins = {origin for policy in state.peer_policy.values() for origin in policy.route_origins}
            for origin in route_origins:
                origin_counts[origin] += 1
            if not route_targets:
                unscoped += 1
            for target in sorted(route_targets):
                if target not in domains and len(domains) >= _MAX_POLICY_DOMAINS:
                    continue
                row = domains.setdefault(target, {
                    "route_target": target,
                    "route_keys": set(),
                    "route_types": Counter(),
                    "route_distinguishers": set(),
                    "ethernet_tags": set(),
                    "service_ids_24": set(),
                    "mac_addresses": set(),
                    "ip_addresses": set(),
                    "prefixes": set(),
                    "originating_routers": set(),
                    "advertising_peers": set(),
                    "next_hops": set(),
                    "encapsulations": set(),
                })
                if len(row["route_keys"]) < _MAX_BINDINGS_PER_DOMAIN:
                    row["route_keys"].add(route_key)
                row["route_types"][state.route_type_name or f"route-type-{state.route_type}"] += 1
                if state.route_distinguisher:
                    row["route_distinguishers"].add(state.route_distinguisher)
                row["ethernet_tags"].add(state.ethernet_tag_id)
                row["service_ids_24"].update(state.service_ids)
                row["mac_addresses"].update(state.mac_addresses)
                row["ip_addresses"].update(state.ip_addresses)
                row["prefixes"].update(state.prefixes)
                row["originating_routers"].update(state.origins)
                for peer, policy in state.peer_policy.items():
                    if target not in policy.route_targets:
                        continue
                    row["advertising_peers"].add(peer)
                    row["next_hops"].update(policy.next_hops)
                    row["encapsulations"].update(policy.encapsulations)
        vxlan_vnis = set(self._vxlan_vnis)
        rows: list[dict[str, Any]] = []
        for target, row in sorted(domains.items()):
            service_ids = set(row["service_ids_24"])
            rows.append({
                "route_target": target,
                "active_route_count": len(row["route_keys"]),
                "route_types": dict(row["route_types"].most_common()),
                "route_distinguishers": sorted(row["route_distinguishers"]),
                "ethernet_tags": sorted(row["ethernet_tags"]),
                "service_ids_24": sorted(service_ids),
                "mac_addresses": sorted(row["mac_addresses"])[:2048],
                "ip_addresses": sorted(row["ip_addresses"])[:2048],
                "prefixes": sorted(row["prefixes"])[:2048],
                "originating_routers": sorted(row["originating_routers"])[:2048],
                "advertising_peers": sorted(row["advertising_peers"])[:2048],
                "next_hops": sorted(row["next_hops"])[:2048],
                "encapsulations": sorted(row["encapsulations"]),
                "observed_vxlan_vni_matches": sorted(service_ids & vxlan_vnis),
            })
        return {
            "schema": "arenyxa.evpn-policy-domain-forensics/v1",
            "active_route_count": len(self._routes),
            "active_route_target_count": len(rows),
            "unscoped_active_routes": unscoped,
            "route_limit_reached": self._route_limit_reached,
            "policy_domain_limit_reached": len(domains) >= _MAX_POLICY_DOMAINS,
            "route_origins": dict(origin_counts.most_common()),
            "observed_vxlan_vnis": dict(sorted(self._vxlan_vnis.items())),
            "policy_domains": rows,
            "semantics": "Policy domains represent active per-peer EVPN reachability. MP_UNREACH removes only the withdrawing peer binding; historical withdrawn Route Targets are not retained as active ownership.",
        }
