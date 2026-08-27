from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord


_MAX_MAC_ROUTES = 200_000
_MAX_PREFIX_ROUTES = 200_000
_MAX_IMET_ORIGINS = 100_000
_MAX_DATA_VNIS = 100_000
_MAX_MACS_PER_VNI = 8192


def _native_layers(packet: PacketRecord) -> list[Mapping[str, Any]]:
    raw = packet.metadata.get("native_layers")
    return [row for row in raw if isinstance(row, Mapping)] if isinstance(raw, list) else []


def _fields(layer: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = layer.get("fields")
    return raw if isinstance(raw, Mapping) else {}


def _service_id(route: Mapping[str, Any]) -> int | None:
    service = route.get("service")
    if not isinstance(service, Mapping):
        return None
    try:
        return int(service.get("service_id_24"))
    except (TypeError, ValueError, OverflowError):
        return None


def _evpn_attributes(fields: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = fields.get("path_attributes")
    if not isinstance(raw, list):
        return []
    return [
        row for row in raw
        if isinstance(row, Mapping)
        and str(row.get("name") or "") in {"MP_REACH_NLRI", "MP_UNREACH_NLRI"}
        and int(row.get("afi") or 0) == 25
        and int(row.get("safi") or 0) == 70
    ]




def _extended_communities(fields: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = fields.get("path_attributes")
    if not isinstance(raw, list):
        return []
    rows: list[Mapping[str, Any]] = []
    for attribute in raw:
        if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "EXTENDED_COMMUNITIES":
            continue
        communities = attribute.get("communities") if isinstance(attribute.get("communities"), list) else []
        rows.extend(row for row in communities if isinstance(row, Mapping))
    return rows[:512]


def _tunnel_attributes(fields: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    raw = fields.get("path_attributes")
    if not isinstance(raw, list):
        return []
    rows: list[Mapping[str, Any]] = []
    for attribute in raw:
        if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "TUNNEL_ENCAPSULATION":
            continue
        tunnels = attribute.get("tunnels") if isinstance(attribute.get("tunnels"), list) else []
        rows.extend(row for row in tunnels if isinstance(row, Mapping) and not bool(row.get("malformed")))
    return rows[:256]


def _encapsulations(fields: Mapping[str, Any]) -> set[str]:
    names = {
        str(row.get("tunnel_type_name") or "")
        for row in _extended_communities(fields)
        if str(row.get("name") or "") == "encapsulation" and str(row.get("tunnel_type_name") or "")
    }
    names.update(
        str(row.get("tunnel_type_name") or "")
        for row in _tunnel_attributes(fields)
        if str(row.get("tunnel_type_name") or "")
    )
    return names


def _tunnel_attribute_vnis(fields: Mapping[str, Any]) -> set[int]:
    result: set[int] = set()
    for tunnel in _tunnel_attributes(fields):
        if str(tunnel.get("tunnel_type_name") or "") != "vxlan":
            continue
        sub_tlvs = tunnel.get("sub_tlvs") if isinstance(tunnel.get("sub_tlvs"), list) else []
        for row in sub_tlvs:
            if not isinstance(row, Mapping) or str(row.get("name") or "") != "encapsulation":
                continue
            if not bool(row.get("vni_present")):
                continue
            try:
                value = int(row.get("virtual_network_id"))
            except (TypeError, ValueError, OverflowError):
                continue
            if 0 <= value <= 0xFFFFFF:
                result.add(value)
    return result




def _pmsi_tunnel(fields: Mapping[str, Any]) -> Mapping[str, Any] | None:
    raw = fields.get("path_attributes")
    if not isinstance(raw, list):
        return None
    for attribute in raw:
        if isinstance(attribute, Mapping) and str(attribute.get("name") or "") == "PMSI_TUNNEL":
            return attribute
    return None

def _mac_mobility(fields: Mapping[str, Any]) -> tuple[int | None, bool]:
    for row in _extended_communities(fields):
        if str(row.get("name") or "") != "mac-mobility":
            continue
        try:
            return int(row.get("sequence")), bool(row.get("sticky"))
        except (TypeError, ValueError, OverflowError):
            return None, bool(row.get("sticky"))
    return None, False


def _policy_communities(fields: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    route_targets: set[str] = set()
    route_origins: set[str] = set()
    for row in _extended_communities(fields):
        value = str(row.get("value") or "")
        if not value:
            continue
        name = str(row.get("name") or "")
        if name == "route-target":
            route_targets.add(value)
        elif name == "route-origin":
            route_origins.add(value)
    return route_targets, route_origins


@dataclass(slots=True)
class _MacRoute:
    ethernet_tag_id: int
    mac_address: str
    esi: str
    service_ids: set[int]
    ip_addresses: set[str]
    advertising_peers: set[str]
    encapsulations: set[str]
    mobility_sequence: int | None = None
    sticky: bool = False
    observations: int = 0


@dataclass(slots=True)
class _EthernetAdRoute:
    route_distinguisher: str
    ethernet_tag_id: int
    esi: str
    service_ids: set[int]
    advertising_peers: set[str]
    encapsulations: set[str]
    observations: int = 0


@dataclass(slots=True)
class _ImetRoute:
    ethernet_tag_id: int
    originating_router_ip: str
    advertising_peers: set[str]
    encapsulations: set[str]
    pmsi_tunnel_types: set[str]
    pmsi_field24_values: set[int]
    tunnel_endpoints: set[str]
    pim_tree_ids: set[str]
    observations: int = 0


@dataclass(slots=True)
class _PrefixRoute:
    prefix: str
    ethernet_tag_id: int
    gateway_ips: set[str]
    service_ids: set[int]
    advertising_peers: set[str]
    encapsulations: set[str]
    observations: int = 0


class EvpnOverlayAnalyzer:
    """Bounded passive EVPN/VXLAN control-plane and data-plane correlation.

    The analyzer never assumes that every 24-bit EVPN service field is a VXLAN
    VNI. It reports an exact numeric match as correlation evidence and leaves
    the encapsulation decision to independently observed data-plane traffic or
    additional BGP encapsulation attributes.
    """

    def __init__(self) -> None:
        self._route_types: Counter[str] = Counter()
        self._malformed_routes = 0
        self._mac_routes: dict[tuple[int, str], _MacRoute] = {}
        self._mac_route_limit_reached = False
        self._ethernet_ad_routes: dict[tuple[str, int, str], _EthernetAdRoute] = {}
        self._prefix_routes: dict[tuple[int, str], _PrefixRoute] = {}
        self._prefix_route_limit_reached = False
        self._imet_origins: dict[tuple[int, str], _ImetRoute] = {}
        self._ethernet_segments: dict[tuple[str, str], set[str]] = {}
        self._vxlan_vnis: Counter[int] = Counter()
        self._vxlan_vteps: Counter[tuple[str, str, int]] = Counter()
        self._vxlan_inner_macs: dict[int, set[str]] = {}
        self._data_vni_limit_reached = False
        self._mac_location_variants = 0
        self._mac_mobility_events = 0
        self._sticky_mac_location_conflicts = 0
        self._encapsulation_counts: Counter[str] = Counter()
        self._tunnel_attribute_vnis: Counter[int] = Counter()
        self._observed_route_targets: Counter[str] = Counter()
        self._observed_route_origins: Counter[str] = Counter()

    def feed(self, packet: PacketRecord) -> None:
        layers = _native_layers(packet)
        for index, layer in enumerate(layers):
            name = str(layer.get("name") or "").casefold()
            fields = _fields(layer)
            if name == "bgp":
                self._feed_bgp(packet, fields)
            elif name == "vxlan":
                self._feed_vxlan(packet, fields, layers[index + 1:])

    def _feed_bgp(self, packet: PacketRecord, fields: Mapping[str, Any]) -> None:
        if str(fields.get("message_name") or "") != "update":
            return
        peer = str(packet.source or "unknown")
        encapsulations = _encapsulations(fields)
        mobility_sequence, sticky = _mac_mobility(fields)
        route_targets, route_origins = _policy_communities(fields)
        pmsi = _pmsi_tunnel(fields)
        for encapsulation in encapsulations:
            self._encapsulation_counts[encapsulation] += 1
        for vni in _tunnel_attribute_vnis(fields):
            self._tunnel_attribute_vnis[vni] += 1
        for attribute in _evpn_attributes(fields):
            name = str(attribute.get("name") or "")
            key = "nlri" if name == "MP_REACH_NLRI" else "withdrawn_nlri"
            routes = attribute.get(key) if isinstance(attribute.get(key), list) else []
            for route in routes[:4096]:
                if not isinstance(route, Mapping):
                    continue
                route_name = str(route.get("route_type_name") or f"route-type-{route.get('route_type')}")
                self._route_types[f"{'withdraw-' if name == 'MP_UNREACH_NLRI' else ''}{route_name}"] += 1
                if bool(route.get("malformed")):
                    self._malformed_routes += 1
                    continue
                for value in route_targets:
                    self._observed_route_targets[value] += 1
                for value in route_origins:
                    self._observed_route_origins[value] += 1
                route_type = int(route.get("route_type") or 0)
                if name == "MP_UNREACH_NLRI":
                    self._withdraw(route_type, route, peer)
                elif route_type == 1:
                    self._observe_ethernet_ad(route, peer, encapsulations)
                elif route_type == 2:
                    self._observe_mac_route(route, peer, encapsulations, mobility_sequence, sticky)
                elif route_type == 3:
                    self._observe_imet(route, peer, encapsulations, pmsi)
                elif route_type == 4:
                    self._observe_ethernet_segment(route, peer)
                elif route_type == 5:
                    self._observe_prefix_route(route, peer, encapsulations)

    def _observe_mac_route(
        self, route: Mapping[str, Any], peer: str, encapsulations: set[str], mobility_sequence: int | None, sticky: bool
    ) -> None:
        mac = str(route.get("mac_address") or "").casefold()
        if not mac:
            return
        try:
            tag = int(route.get("ethernet_tag_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        key = (tag, mac)
        esi_raw = route.get("ethernet_segment_identifier")
        esi = str(esi_raw.get("value_hex") or "") if isinstance(esi_raw, Mapping) else ""
        current = self._mac_routes.get(key)
        if current is None:
            if len(self._mac_routes) >= _MAX_MAC_ROUTES:
                self._mac_route_limit_reached = True
                return
            current = _MacRoute(tag, mac, esi, set(), set(), set(), set())
            self._mac_routes[key] = current
        elif peer not in current.advertising_peers and current.advertising_peers:
            self._mac_location_variants += 1
            if current.sticky or sticky:
                self._sticky_mac_location_conflicts += 1
        if mobility_sequence is not None:
            if current.mobility_sequence is not None and mobility_sequence > current.mobility_sequence:
                self._mac_mobility_events += 1
            current.mobility_sequence = max(current.mobility_sequence or 0, mobility_sequence)
        current.sticky = current.sticky or sticky
        current.encapsulations.update(encapsulations)
        current.observations += 1
        current.advertising_peers.add(peer)
        if route.get("ip_address"):
            current.ip_addresses.add(str(route["ip_address"]))
        service_id = _service_id(route)
        if service_id is not None:
            current.service_ids.add(service_id)

    def _observe_ethernet_ad(
        self, route: Mapping[str, Any], peer: str, encapsulations: set[str]
    ) -> None:
        esi_raw = route.get("ethernet_segment_identifier")
        esi = str(esi_raw.get("value_hex") or "") if isinstance(esi_raw, Mapping) else ""
        rd_raw = route.get("route_distinguisher")
        rd = str(rd_raw.get("hex") or "") if isinstance(rd_raw, Mapping) else ""
        try:
            tag = int(route.get("ethernet_tag_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        key = (rd, tag, esi)
        current = self._ethernet_ad_routes.get(key)
        if current is None:
            if len(self._ethernet_ad_routes) >= _MAX_PREFIX_ROUTES:
                self._prefix_route_limit_reached = True
                return
            current = _EthernetAdRoute(rd, tag, esi, set(), set(), set())
            self._ethernet_ad_routes[key] = current
        current.observations += 1
        current.advertising_peers.add(peer)
        current.encapsulations.update(encapsulations)
        service_id = _service_id(route)
        if service_id is not None:
            current.service_ids.add(service_id)

    def _observe_imet(
        self,
        route: Mapping[str, Any],
        peer: str,
        encapsulations: set[str],
        pmsi: Mapping[str, Any] | None,
    ) -> None:
        try:
            tag = int(route.get("ethernet_tag_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        origin = str(route.get("originating_router_ip") or "")
        if not origin:
            return
        key = (tag, origin)
        current = self._imet_origins.get(key)
        if current is None:
            if len(self._imet_origins) >= _MAX_IMET_ORIGINS:
                return
            current = _ImetRoute(tag, origin, set(), set(), set(), set(), set(), set())
            self._imet_origins[key] = current
        current.observations += 1
        current.advertising_peers.add(peer)
        current.encapsulations.update(encapsulations)
        if not isinstance(pmsi, Mapping) or bool(pmsi.get("malformed")):
            return
        tunnel_name = str(pmsi.get("tunnel_type_name") or "")
        if tunnel_name:
            current.pmsi_tunnel_types.add(tunnel_name)
        try:
            field24 = int(pmsi.get("field24") or 0)
        except (TypeError, ValueError, OverflowError):
            field24 = 0
        if field24:
            current.pmsi_field24_values.add(field24)
        endpoint = str(pmsi.get("tunnel_endpoint") or "")
        if endpoint:
            current.tunnel_endpoints.add(endpoint)
        source = str(pmsi.get("tree_source") or "")
        group = str(pmsi.get("multicast_group") or "")
        if source and group:
            current.pim_tree_ids.add(f"{source}->{group}")

    def _observe_ethernet_segment(self, route: Mapping[str, Any], peer: str) -> None:
        esi_raw = route.get("ethernet_segment_identifier")
        esi = str(esi_raw.get("value_hex") or "") if isinstance(esi_raw, Mapping) else ""
        origin = str(route.get("originating_router_ip") or "")
        if not esi or not origin:
            return
        key = (esi, origin)
        if key not in self._ethernet_segments and len(self._ethernet_segments) >= _MAX_IMET_ORIGINS:
            return
        self._ethernet_segments.setdefault(key, set()).add(peer)

    def _observe_prefix_route(
        self, route: Mapping[str, Any], peer: str, encapsulations: set[str]
    ) -> None:
        prefix = str(route.get("ip_prefix") or "")
        if not prefix:
            return
        try:
            tag = int(route.get("ethernet_tag_id") or 0)
        except (TypeError, ValueError, OverflowError):
            return
        key = (tag, prefix)
        current = self._prefix_routes.get(key)
        if current is None:
            if len(self._prefix_routes) >= _MAX_PREFIX_ROUTES:
                self._prefix_route_limit_reached = True
                return
            current = _PrefixRoute(prefix, tag, set(), set(), set(), set())
            self._prefix_routes[key] = current
        current.observations += 1
        current.advertising_peers.add(peer)
        current.encapsulations.update(encapsulations)
        gateway = str(route.get("gateway_ip") or "")
        if gateway and gateway not in {"0.0.0.0", "::"}:
            current.gateway_ips.add(gateway)
        service_id = _service_id(route)
        if service_id is not None:
            current.service_ids.add(service_id)

    def _withdraw(self, route_type: int, route: Mapping[str, Any], peer: str) -> None:
        if route_type == 1:
            esi_raw = route.get("ethernet_segment_identifier")
            esi = str(esi_raw.get("value_hex") or "") if isinstance(esi_raw, Mapping) else ""
            rd_raw = route.get("route_distinguisher")
            rd = str(rd_raw.get("hex") or "") if isinstance(rd_raw, Mapping) else ""
            try:
                tag = int(route.get("ethernet_tag_id") or 0)
            except (TypeError, ValueError, OverflowError):
                return
            key = (rd, tag, esi)
            current = self._ethernet_ad_routes.get(key)
            if current is not None:
                current.advertising_peers.discard(peer)
                if not current.advertising_peers:
                    self._ethernet_ad_routes.pop(key, None)
        elif route_type == 2:
            mac = str(route.get("mac_address") or "").casefold()
            try:
                tag = int(route.get("ethernet_tag_id") or 0)
            except (TypeError, ValueError, OverflowError):
                return
            current = self._mac_routes.get((tag, mac))
            if current is not None:
                current.advertising_peers.discard(peer)
                if not current.advertising_peers:
                    self._mac_routes.pop((tag, mac), None)
        elif route_type == 3:
            try:
                tag = int(route.get("ethernet_tag_id") or 0)
            except (TypeError, ValueError, OverflowError):
                return
            origin = str(route.get("originating_router_ip") or "")
            key = (tag, origin)
            current = self._imet_origins.get(key)
            if current is not None:
                current.advertising_peers.discard(peer)
                if not current.advertising_peers:
                    self._imet_origins.pop(key, None)
        elif route_type == 4:
            esi_raw = route.get("ethernet_segment_identifier")
            esi = str(esi_raw.get("value_hex") or "") if isinstance(esi_raw, Mapping) else ""
            origin = str(route.get("originating_router_ip") or "")
            key = (esi, origin)
            peers = self._ethernet_segments.get(key)
            if peers is not None:
                peers.discard(peer)
                if not peers:
                    self._ethernet_segments.pop(key, None)
        elif route_type == 5:
            prefix = str(route.get("ip_prefix") or "")
            try:
                tag = int(route.get("ethernet_tag_id") or 0)
            except (TypeError, ValueError, OverflowError):
                return
            current = self._prefix_routes.get((tag, prefix))
            if current is not None:
                current.advertising_peers.discard(peer)
                if not current.advertising_peers:
                    self._prefix_routes.pop((tag, prefix), None)

    def _feed_vxlan(
        self,
        packet: PacketRecord,
        fields: Mapping[str, Any],
        following_layers: list[Mapping[str, Any]],
    ) -> None:
        try:
            vni = int(fields.get("vni"))
        except (TypeError, ValueError, OverflowError):
            return
        if vni < 0 or vni > 0xFFFFFF:
            return
        if vni not in self._vxlan_vnis and len(self._vxlan_vnis) >= _MAX_DATA_VNIS:
            self._data_vni_limit_reached = True
            return
        self._vxlan_vnis[vni] += 1
        self._vxlan_vteps[(str(packet.source or ""), str(packet.destination or ""), vni)] += 1
        bucket = self._vxlan_inner_macs.setdefault(vni, set())
        if len(bucket) >= _MAX_MACS_PER_VNI:
            return
        for layer in following_layers:
            if str(layer.get("name") or "").casefold() != "ethernet":
                continue
            inner = _fields(layer)
            for key in ("source", "destination"):
                mac = str(inner.get(key) or "").casefold()
                if mac:
                    bucket.add(mac)
            break

    def _route_rows(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], Counter[int]]:
        active: Counter[int] = Counter()
        for collection in (self._ethernet_ad_routes.values(), self._mac_routes.values(), self._prefix_routes.values()):
            for state in collection:
                for service_id in state.service_ids:
                    active[service_id] += 1
        mac_rows = [{"ethernet_tag_id": s.ethernet_tag_id, "mac_address": s.mac_address, "esi": s.esi,
                     "ip_addresses": sorted(s.ip_addresses), "service_ids_24": sorted(s.service_ids),
                     "advertising_peers": sorted(s.advertising_peers), "encapsulations": sorted(s.encapsulations),
                     "mobility_sequence": s.mobility_sequence, "sticky": s.sticky, "observations": s.observations}
                    for s in self._mac_routes.values()]
        ad_rows = [{"route_distinguisher": s.route_distinguisher, "ethernet_tag_id": s.ethernet_tag_id, "esi": s.esi,
                    "service_ids_24": sorted(s.service_ids), "advertising_peers": sorted(s.advertising_peers),
                    "encapsulations": sorted(s.encapsulations), "observations": s.observations}
                   for s in self._ethernet_ad_routes.values()]
        prefix_rows = [{"ethernet_tag_id": s.ethernet_tag_id, "prefix": s.prefix, "gateway_ips": sorted(s.gateway_ips),
                        "service_ids_24": sorted(s.service_ids), "advertising_peers": sorted(s.advertising_peers),
                        "encapsulations": sorted(s.encapsulations), "observations": s.observations}
                       for s in self._prefix_routes.values()]
        mac_rows.sort(key=lambda r: (r["ethernet_tag_id"], r["mac_address"])); ad_rows.sort(key=lambda r: (r["route_distinguisher"], r["ethernet_tag_id"], r["esi"])); prefix_rows.sort(key=lambda r: (r["ethernet_tag_id"], r["prefix"]))
        return mac_rows, ad_rows, prefix_rows, active

    def _correlation(self, active: Counter[int]) -> tuple[dict[str, Any], Counter[str], set[int]]:
        pmsi_counts: Counter[str] = Counter(); pmsi_vnis: set[int] = set()
        for state in self._imet_origins.values():
            pmsi_counts.update(state.pmsi_tunnel_types)
            if "vxlan" in state.encapsulations:
                pmsi_vnis.update(state.pmsi_field24_values)
        control_ids, data_ids = set(active) | pmsi_vnis, set(self._vxlan_vnis)
        matched = sorted(control_ids & data_ids)
        proven_ids = {sid for states in (self._ethernet_ad_routes.values(), self._mac_routes.values(), self._prefix_routes.values())
                      for state in states if "vxlan" in state.encapsulations for sid in state.service_ids}
        control_macs: dict[int, set[str]] = {}
        for state in self._mac_routes.values():
            for sid in state.service_ids:
                control_macs.setdefault(sid, set()).add(state.mac_address)
        mac_matches = []
        for vni in matched[:4096]:
            advertised, observed = control_macs.get(vni, set()), self._vxlan_inner_macs.get(vni, set())
            if advertised or observed:
                mac_matches.append({"service_id_24": vni, "advertised_mac_count": len(advertised), "observed_inner_mac_count": len(observed),
                                    "matched_mac_count": len(advertised & observed), "advertised_not_observed": sorted(advertised - observed)[:256],
                                    "observed_not_advertised": sorted(observed - advertised)[:256]})
        return ({"service_id_matches_vxlan_vni": matched[:8192], "control_plane_proven_vxlan_vni_matches": sorted(proven_ids & data_ids)[:8192],
                 "tunnel_attribute_vni_matches": sorted(set(self._tunnel_attribute_vnis) & data_ids)[:8192],
                 "pmsi_vxlan_vni_matches": sorted(pmsi_vnis & data_ids)[:8192], "evpn_service_without_observed_vxlan": sorted(control_ids - data_ids)[:8192],
                 "vxlan_vni_without_observed_evpn_service": sorted(data_ids - control_ids)[:8192], "mac_control_data_matches": mac_matches,
                 "interpretation": "A matching 24-bit EVPN service field and VXLAN VNI is correlation evidence; the analyzer does not infer encapsulation from the numeric field alone."}, pmsi_counts, pmsi_vnis)

    def _imet_rows(self) -> list[dict[str, Any]]:
        return [{"ethernet_tag_id": s.ethernet_tag_id, "originating_router_ip": s.originating_router_ip,
                 "advertising_peers": sorted(s.advertising_peers), "encapsulations": sorted(s.encapsulations),
                 "pmsi_tunnel_types": sorted(s.pmsi_tunnel_types), "pmsi_field24_values": sorted(s.pmsi_field24_values),
                 "tunnel_endpoints": sorted(s.tunnel_endpoints), "pim_tree_ids": sorted(s.pim_tree_ids), "observations": s.observations}
                for s in sorted(self._imet_origins.values(), key=lambda item: (item.ethernet_tag_id, item.originating_router_ip))][:8192]

    def finalize(self) -> dict[str, Any]:
        mac_rows, ad_rows, prefix_rows, active = self._route_rows()
        correlation, pmsi_counts, pmsi_vnis = self._correlation(active)
        return {
            "schema": "arenyxa.evpn-overlay-forensics/v1",
            "evpn": {"route_type_counts": dict(self._route_types.most_common()), "malformed_routes": self._malformed_routes,
                     "service_ids_24": dict(sorted(active.items())), "ethernet_ad_routes": ad_rows[:8192], "mac_ip_routes": mac_rows[:8192],
                     "mac_route_limit_reached": self._mac_route_limit_reached, "mac_location_variants": self._mac_location_variants,
                     "mac_mobility_events": self._mac_mobility_events, "sticky_mac_location_conflicts": self._sticky_mac_location_conflicts,
                     "encapsulation_counts": dict(self._encapsulation_counts.most_common()), "tunnel_attribute_vnis": dict(sorted(self._tunnel_attribute_vnis.items())),
                     "observed_route_target_counts": dict(sorted(self._observed_route_targets.items())), "observed_route_origin_counts": dict(sorted(self._observed_route_origins.items())),
                     "route_policy_scope": "observed UPDATE evidence; Route Target/Origin counts are not presented as active-state ownership after withdrawal",
                     "imet_origins": self._imet_rows(), "pmsi_tunnel_type_counts": dict(pmsi_counts.most_common()), "pmsi_vxlan_vnis": sorted(pmsi_vnis)[:8192],
                     "ethernet_segments": [{"esi": esi, "originating_router_ip": origin, "advertising_peers": sorted(peers)} for (esi, origin), peers in sorted(self._ethernet_segments.items())][:8192],
                     "ip_prefix_routes": prefix_rows[:8192], "prefix_route_limit_reached": self._prefix_route_limit_reached},
            "vxlan": {"vnis": dict(sorted(self._vxlan_vnis.items())), "vtep_paths": [{"source": source, "destination": destination, "vni": vni, "packets": count}
                      for (source, destination, vni), count in self._vxlan_vteps.most_common(8192)], "data_vni_limit_reached": self._data_vni_limit_reached},
            "correlation": correlation,
        }
