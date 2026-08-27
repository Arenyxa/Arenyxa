from __future__ import annotations

import hashlib
from typing import Any, Mapping

from arenyxa.compat import dataclass
from arenyxa.infrastructure.capture.packet_models import PacketRecord
from arenyxa.infrastructure.capture.pfcp_rule_graph import extract_pfcp_rule_observations


_MAX_NODES = 20_000
_MAX_EDGES = 50_000
_MAX_SAN_NAMES = 128
_MAX_DNS_ANSWERS = 256
_MAX_OSPF_NEIGHBORS = 256
_MAX_TLS_FLOWS = 100_000


@dataclass(slots=True)
class _Node:
    id: str
    kind: str
    value: str
    observations: int = 0


@dataclass(slots=True)
class _Edge:
    source: str
    target: str
    relation: str
    observations: int = 0
    first_frame: int = 0
    last_frame: int = 0


def _node_id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"arenyxa-evidence-node/v1\x00{kind}\x00{value}".encode("utf-8", "replace")).hexdigest()
    return digest[:24]


def _native_layers(packet: PacketRecord) -> list[dict[str, Any]]:
    raw = packet.metadata.get("native_layers")
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def _fields(layer: Mapping[str, Any]) -> dict[str, Any]:
    raw = layer.get("fields")
    return dict(raw) if isinstance(raw, Mapping) else {}


class NetworkEvidenceGraphBuilder:
    """Build a bounded passive graph from packet metadata and protocol evidence.

    The graph records identities and relationships, not opaque application
    payload. Node/edge budgets make the feature safe on hostile or very large
    captures; overflow is reported explicitly rather than growing memory without
    bound.
    """

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], _Node] = {}
        self._edges: dict[tuple[str, str, str], _Edge] = {}
        self._node_limit_reached = False
        self._edge_limit_reached = False
        self._tls_sni_by_flow: dict[tuple[tuple[str, int], tuple[str, int]], str] = {}
        self._tls_client_fp_by_flow: dict[tuple[tuple[str, int], tuple[str, int]], str] = {}

    def _node(self, kind: str, value: object) -> str | None:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        key = (str(kind), normalized)
        existing = self._nodes.get(key)
        if existing is not None:
            existing.observations += 1
            return existing.id
        if len(self._nodes) >= _MAX_NODES:
            self._node_limit_reached = True
            return None
        node = _Node(id=_node_id(key[0], key[1]), kind=key[0], value=key[1], observations=1)
        self._nodes[key] = node
        return node.id

    def _edge(self, source: str | None, target: str | None, relation: str, frame: int) -> None:
        if not source or not target or source == target:
            return
        key = (source, target, relation)
        existing = self._edges.get(key)
        if existing is not None:
            existing.observations += 1
            existing.last_frame = max(existing.last_frame, frame)
            return
        if len(self._edges) >= _MAX_EDGES:
            self._edge_limit_reached = True
            return
        self._edges[key] = _Edge(
            source=source,
            target=target,
            relation=relation,
            observations=1,
            first_frame=frame,
            last_frame=frame,
        )

    def feed(self, packet: PacketRecord) -> None:
        frame = max(0, int(packet.frame_number))
        source = self._node("ip", packet.source)
        destination = self._node("ip", packet.destination)
        if source and destination:
            self._edge(source, destination, "communicates-with", frame)

        for layer in _native_layers(packet):
            name = str(layer.get("name") or "").casefold()
            fields = _fields(layer)
            if name in {"dns", "mdns"}:
                self._dns(fields, frame)
            elif name == "tls":
                self._tls(packet, fields, source, destination, frame)
            elif name == "quic":
                self._quic(fields, source, destination, frame)
            elif name == "lldp":
                self._lldp(fields, frame)
            elif name == "cdp":
                self._cdp(fields, frame)
            elif name == "lacp":
                self._lacp(fields, frame)
            elif name in {"stp", "rstp", "mstp"}:
                self._spanning_tree(fields, frame)
            elif name == "ospf":
                self._ospf(fields, frame)
            elif name == "isis":
                self._isis(fields, frame)
            elif name == "ldp":
                self._ldp(fields, source, destination, frame)
            elif name == "bgp":
                self._bgp(fields, source, destination, frame)
            elif name == "dhcp":
                self._dhcp(fields, frame)
            elif name == "dhcpv6":
                self._dhcpv6(fields, frame)
            elif name == "radius":
                self._radius(fields, source, destination, frame)
            elif name == "snmp":
                self._snmp(fields, source, destination, frame)
            elif name == "mpls":
                self._mpls(fields, source, destination, frame)
            elif name == "vxlan":
                self._vxlan(fields, source, destination, frame)
            elif name == "geneve":
                self._geneve(fields, source, destination, frame)
            elif name == "gtp":
                self._gtp(fields, source, destination, frame)
            elif name == "pfcp":
                self._pfcp(fields, source, destination, frame)
            elif name == "diameter":
                self._diameter(fields, source, destination, frame)
            elif name == "smb":
                self._smb(fields, source, destination, frame)
            elif name == "ldap":
                self._ldap(fields, source, destination, frame)
            elif name == "kerberos":
                self._kerberos(fields, source, destination, frame)

    def _dns(self, fields: Mapping[str, Any], frame: int) -> None:
        questions = fields.get("question_records") if isinstance(fields.get("question_records"), list) else []
        answers = fields.get("answer_records") if isinstance(fields.get("answer_records"), list) else []
        names = [
            self._node("hostname", str(row.get("name") or "").rstrip("."))
            for row in questions[:32]
            if isinstance(row, Mapping)
        ]
        primary = next((item for item in names if item), None)
        for row in answers[:_MAX_DNS_ANSWERS]:
            if not isinstance(row, Mapping):
                continue
            answer_name = self._node("hostname", str(row.get("name") or "").rstrip(".")) or primary
            address = row.get("address")
            if address:
                self._edge(answer_name, self._node("ip", address), "dns-resolves-to", frame)
            canonical = str(row.get("cname") or row.get("target") or "").rstrip(".")
            if canonical:
                self._edge(answer_name, self._node("hostname", canonical), "dns-alias-to", frame)

    @staticmethod
    def _transport_flow(packet: PacketRecord) -> tuple[tuple[str, int], tuple[str, int]] | None:
        if packet.source_port is None or packet.destination_port is None or not packet.source or not packet.destination:
            return None
        left = (packet.source, int(packet.source_port))
        right = (packet.destination, int(packet.destination_port))
        return (left, right) if left <= right else (right, left)

    def _tls(
        self,
        packet: PacketRecord,
        fields: Mapping[str, Any],
        source_ip: str | None,
        destination_ip: str | None,
        frame: int,
    ) -> None:
        try:
            handshake_type = int(fields.get("handshake_type") or 0)
        except (TypeError, ValueError, OverflowError):
            handshake_type = 0
        if handshake_type == 1 or (handshake_type == 0 and fields.get("server_name")):
            client_ip, server_ip = source_ip, destination_ip
        elif handshake_type in {2, 11}:
            client_ip, server_ip = destination_ip, source_ip
        else:
            client_ip, server_ip = None, None
        flow = self._transport_flow(packet)
        sni = self._node("hostname", fields.get("server_name"))
        if sni and server_ip:
            self._edge(sni, server_ip, "tls-served-by", frame)
        client_fp = self._node("tls-ja3", fields.get("ja3_md5") or fields.get("ja3"))
        client_ja4 = self._node("tls-ja4", fields.get("ja4"))
        server_fp = self._node("tls-ja3s", fields.get("ja3s_md5") or fields.get("ja3s"))
        self._edge(client_ip, client_fp, "tls-client-fingerprint", frame)
        self._edge(client_ip, client_ja4, "tls-client-ja4-fingerprint", frame)
        self._edge(server_ip, server_fp, "tls-server-fingerprint", frame)
        if sni and client_fp:
            self._edge(client_fp, sni, "tls-client-offers-sni", frame)
        if sni and client_ja4:
            self._edge(client_ja4, sni, "tls-ja4-offers-sni", frame)
        if flow is not None and len(self._tls_sni_by_flow) < _MAX_TLS_FLOWS:
            if sni:
                self._tls_sni_by_flow[flow] = sni
            elif flow in self._tls_sni_by_flow:
                sni = self._tls_sni_by_flow[flow]
            if client_fp:
                self._tls_client_fp_by_flow[flow] = client_fp
            elif flow in self._tls_client_fp_by_flow:
                client_fp = self._tls_client_fp_by_flow[flow]
        if server_fp and sni:
            self._edge(server_fp, sni, "tls-server-fingerprint-serves-sni", frame)
        if client_fp and server_fp:
            self._edge(client_fp, server_fp, "tls-client-server-fingerprint-pair", frame)
        chain = fields.get("certificate_chain") if isinstance(fields.get("certificate_chain"), list) else []
        if not chain:
            return
        leaf = chain[0] if isinstance(chain[0], Mapping) else {}
        certificate = self._node("certificate-sha256", leaf.get("sha256"))
        if certificate and server_ip:
            self._edge(server_ip, certificate, "presents-certificate", frame)
        if certificate and sni:
            self._edge(sni, certificate, "uses-certificate", frame)
        sans = leaf.get("san_dns") if isinstance(leaf.get("san_dns"), list) else []
        for value in sans[:_MAX_SAN_NAMES]:
            self._edge(certificate, self._node("hostname", str(value).rstrip(".")), "certificate-asserts-name", frame)
        previous_certificate: str | None = None
        for item in chain[:16]:
            if not isinstance(item, Mapping):
                continue
            current = self._node("certificate-sha256", item.get("sha256"))
            subject = self._node("certificate-subject", item.get("subject"))
            issuer = self._node("certificate-issuer", item.get("issuer"))
            self._edge(current, subject, "certificate-subject", frame)
            self._edge(current, issuer, "certificate-issuer", frame)
            if previous_certificate and current:
                self._edge(previous_certificate, current, "certificate-issued-by", frame)
            if current:
                previous_certificate = current

    def _quic(
        self,
        fields: Mapping[str, Any],
        source_ip: str | None,
        destination_ip: str | None,
        frame: int,
    ) -> None:
        dcid = self._node("quic-cid", fields.get("destination_connection_id"))
        scid = self._node("quic-cid", fields.get("source_connection_id"))
        self._edge(source_ip, scid, "quic-source-connection-id", frame)
        self._edge(dcid, destination_ip, "quic-destination-connection-id", frame)
        self._edge(scid, dcid, "quic-cid-pair", frame)
        version = self._node("quic-version", fields.get("version_name") or fields.get("version"))
        self._edge(scid or source_ip, version, "quic-version", frame)
        initial = fields.get("initial_decryption") if isinstance(fields.get("initial_decryption"), Mapping) else {}
        hello = initial.get("client_hello") if isinstance(initial.get("client_hello"), Mapping) else {}
        sni = self._node("hostname", hello.get("server_name"))
        if sni:
            self._edge(source_ip, sni, "quic-client-offers-sni", frame)
            self._edge(sni, destination_ip, "quic-served-by", frame)
        fingerprint = self._node("tls-ja3", hello.get("ja3_md5") or hello.get("ja3"))
        ja4 = self._node("tls-ja4", hello.get("ja4"))
        self._edge(source_ip, fingerprint, "quic-tls-client-fingerprint", frame)
        self._edge(source_ip, ja4, "quic-tls-client-ja4-fingerprint", frame)
        self._edge(fingerprint, sni, "quic-fingerprint-offers-sni", frame)
        self._edge(ja4, sni, "quic-ja4-offers-sni", frame)

    def _lldp(self, fields: Mapping[str, Any], frame: int) -> None:
        system = self._node("lldp-system", fields.get("system_name"))
        chassis_raw = fields.get("chassis_id") if isinstance(fields.get("chassis_id"), Mapping) else {}
        chassis_value = chassis_raw.get("mac_address") or chassis_raw.get("text") or chassis_raw.get("value")
        chassis = self._node("lldp-chassis", chassis_value)
        self._edge(system, chassis, "lldp-chassis-id", frame)
        addresses = fields.get("management_addresses") if isinstance(fields.get("management_addresses"), list) else []
        for row in addresses[:64]:
            if isinstance(row, Mapping):
                self._edge(system or chassis, self._node("ip", row.get("address")), "lldp-management-address", frame)

    def _cdp(self, fields: Mapping[str, Any], frame: int) -> None:
        device = self._node("cdp-device", fields.get("device_id"))
        platform = self._node("platform", fields.get("platform"))
        self._edge(device, platform, "cdp-platform", frame)
        for address in fields.get("addresses") if isinstance(fields.get("addresses"), list) else []:
            self._edge(device, self._node("ip", address), "cdp-management-address", frame)
        if fields.get("native_vlan") is not None:
            self._edge(device, self._node("vlan", fields.get("native_vlan")), "cdp-native-vlan", frame)

    def _lacp(self, fields: Mapping[str, Any], frame: int) -> None:
        actor = fields.get("actor") if isinstance(fields.get("actor"), Mapping) else {}
        partner = fields.get("partner") if isinstance(fields.get("partner"), Mapping) else {}
        actor_system = self._node("lacp-system", actor.get("system_id"))
        partner_system = self._node("lacp-system", partner.get("system_id"))
        self._edge(actor_system, partner_system, "lacp-partner", frame)

    def _spanning_tree(self, fields: Mapping[str, Any], frame: int) -> None:
        bridge_raw = fields.get("bridge_id") if isinstance(fields.get("bridge_id"), Mapping) else {}
        root_raw = fields.get("root_id") if isinstance(fields.get("root_id"), Mapping) else {}
        bridge = self._node("bridge", bridge_raw.get("mac_address"))
        root = self._node("bridge", root_raw.get("mac_address"))
        self._edge(bridge, root, "spanning-tree-root", frame)

    def _ospf(self, fields: Mapping[str, Any], frame: int) -> None:
        router = self._node("ospf-router", fields.get("router_id"))
        if str(fields.get("packet_type_name") or "") == "hello":
            neighbors = fields.get("neighbors") if isinstance(fields.get("neighbors"), list) else []
            for neighbor in neighbors[:_MAX_OSPF_NEIGHBORS]:
                self._edge(router, self._node("ospf-router", neighbor), "ospf-hello-neighbor", frame)
        lsas = fields.get("lsas") if isinstance(fields.get("lsas"), list) else []
        for lsa in lsas[:256]:
            if not isinstance(lsa, Mapping):
                continue
            advertising = self._node("ospf-router", lsa.get("advertising_router"))
            body = lsa.get("body") if isinstance(lsa.get("body"), Mapping) else {}
            attached = body.get("attached_routers") if isinstance(body.get("attached_routers"), list) else []
            for neighbor in attached[:_MAX_OSPF_NEIGHBORS]:
                self._edge(advertising, self._node("ospf-router", neighbor), "ospf-lsa-attached-router", frame)
            links = body.get("links") if isinstance(body.get("links"), list) else []
            for link in links[:_MAX_OSPF_NEIGHBORS]:
                if isinstance(link, Mapping) and link.get("neighbor_router_id"):
                    self._edge(advertising, self._node("ospf-router", link.get("neighbor_router_id")), "ospf-lsa-neighbor", frame)

    def _isis(self, fields: Mapping[str, Any], frame: int) -> None:
        system = self._node("isis-system", fields.get("source_id") or fields.get("lsp_id"))
        tlvs = fields.get("tlvs") if isinstance(fields.get("tlvs"), list) else []
        for row in tlvs[:256]:
            if not isinstance(row, Mapping):
                continue
            if str(row.get("name") or "") == "dynamic-hostname":
                self._edge(system, self._node("hostname", row.get("hostname")), "isis-hostname", frame)
            addresses = row.get("addresses") if isinstance(row.get("addresses"), list) else []
            for address in addresses[:128]:
                self._edge(system, self._node("ip", address), "isis-interface-address", frame)

    def _ldp(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        lsr = self._node("ldp-lsr", fields.get("lsr_id"))
        self._edge(source_ip, lsr, "ldp-speaker-id", frame)
        if source_ip and destination_ip:
            self._edge(source_ip, destination_ip, "ldp-session-peer", frame)
        messages = fields.get("messages") if isinstance(fields.get("messages"), list) else []
        for message in messages[:256]:
            if not isinstance(message, Mapping) or str(message.get("type_name") or "") != "label-mapping":
                continue
            tlvs = message.get("tlvs") if isinstance(message.get("tlvs"), list) else []
            prefixes: list[str] = []
            labels: list[int] = []
            for tlv in tlvs[:512]:
                if not isinstance(tlv, Mapping):
                    continue
                if str(tlv.get("name") or "") == "fec":
                    elements = tlv.get("elements") if isinstance(tlv.get("elements"), list) else []
                    prefixes.extend(str(row.get("prefix")) for row in elements[:256] if isinstance(row, Mapping) and row.get("prefix"))
                if tlv.get("label") is not None:
                    try:
                        labels.append(int(tlv["label"]))
                    except (TypeError, ValueError, OverflowError):
                        continue
            for prefix in prefixes:
                prefix_node = self._node("ip-prefix", prefix)
                for label in labels:
                    label_node = self._node("mpls-label", label)
                    self._edge(prefix_node, label_node, "ldp-fec-label-binding", frame)
                    self._edge(lsr, label_node, "ldp-advertises-label", frame)

    def _bgp(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        message = str(fields.get("message_name") or "")
        if message == "open":
            asn = fields.get("my_as") or fields.get("asn") or fields.get("autonomous_system")
            speaker = self._node("bgp-asn", asn)
            self._edge(source_ip, speaker, "bgp-speaker-asn", frame)
            if source_ip and destination_ip:
                self._edge(source_ip, destination_ip, "bgp-session-peer", frame)
            return
        if message != "update":
            return
        attributes = fields.get("path_attributes") if isinstance(fields.get("path_attributes"), list) else []
        route_targets: list[str] = []
        route_origins: list[str] = []
        for attribute in attributes[:512]:
            if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "EXTENDED_COMMUNITIES":
                continue
            communities = attribute.get("communities") if isinstance(attribute.get("communities"), list) else []
            for community in communities[:512]:
                if not isinstance(community, Mapping):
                    continue
                value = str(community.get("value") or "")
                if not value:
                    continue
                name = str(community.get("name") or "")
                if name == "route-target":
                    route_targets.append(value)
                elif name == "route-origin":
                    route_origins.append(value)
        for value in dict.fromkeys(route_targets):
            self._edge(source_ip, self._node("bgp-route-target", value), "bgp-observes-route-target", frame)
        for value in dict.fromkeys(route_origins):
            self._edge(source_ip, self._node("bgp-route-origin", value), "bgp-observes-route-origin", frame)

        for attribute in attributes[:512]:
            if not isinstance(attribute, Mapping) or str(attribute.get("name") or "") != "MP_REACH_NLRI":
                continue
            if int(attribute.get("afi") or 0) != 25 or int(attribute.get("safi") or 0) != 70:
                continue
            next_hops = attribute.get("next_hops") if isinstance(attribute.get("next_hops"), list) else []
            peer = self._node("ip", next_hops[0]) if next_hops else source_ip
            routes = attribute.get("nlri") if isinstance(attribute.get("nlri"), list) else []
            for route in routes[:4096]:
                if not isinstance(route, Mapping) or bool(route.get("malformed")):
                    continue
                try:
                    route_type = int(route.get("route_type") or 0)
                except (TypeError, ValueError, OverflowError):
                    continue
                service = route.get("service") if isinstance(route.get("service"), Mapping) else {}
                service_id = service.get("service_id_24")
                service_node = self._node("evpn-service-id-24", service_id)
                route_node = None
                if route_type == 1:
                    rd_raw = route.get("route_distinguisher") if isinstance(route.get("route_distinguisher"), Mapping) else {}
                    route_node = self._node("evpn-route", f"rt1:{rd_raw.get('hex')}:{route.get('ethernet_tag_id')}:{route.get('ethernet_segment_identifier')}")
                elif route_type == 2:
                    route_node = self._node("evpn-route", f"rt2:{route.get('ethernet_tag_id')}:{str(route.get('mac_address') or '').casefold()}:{route.get('ip_address') or ''}")
                elif route_type == 3:
                    route_node = self._node("evpn-route", f"rt3:{route.get('ethernet_tag_id')}:{route.get('originating_router_ip')}")
                elif route_type == 4:
                    esi_raw = route.get("ethernet_segment_identifier") if isinstance(route.get("ethernet_segment_identifier"), Mapping) else {}
                    route_node = self._node("evpn-route", f"rt4:{esi_raw.get('value_hex')}:{route.get('originating_router_ip')}")
                elif route_type == 5:
                    route_node = self._node("evpn-route", f"rt5:{route.get('ethernet_tag_id')}:{route.get('ip_prefix')}")
                for value in dict.fromkeys(route_targets):
                    self._edge(route_node, self._node("bgp-route-target", value), "evpn-route-target", frame)
                for value in dict.fromkeys(route_origins):
                    self._edge(route_node, self._node("bgp-route-origin", value), "evpn-route-origin", frame)
                if route_type == 2:
                    mac = self._node("mac", str(route.get("mac_address") or "").casefold())
                    address = self._node("ip", route.get("ip_address"))
                    self._edge(peer, mac, "evpn-advertises-mac", frame)
                    self._edge(service_node, mac, "evpn-service-mac", frame)
                    self._edge(mac, address, "evpn-mac-ip-binding", frame)
                elif route_type == 3:
                    origin = self._node("ip", route.get("originating_router_ip"))
                    tag = self._node("ethernet-tag", route.get("ethernet_tag_id"))
                    self._edge(tag, origin, "evpn-imet-origin", frame)
                elif route_type == 4:
                    esi_raw = route.get("ethernet_segment_identifier") if isinstance(route.get("ethernet_segment_identifier"), Mapping) else {}
                    esi = self._node("evpn-esi", esi_raw.get("value_hex"))
                    origin = self._node("ip", route.get("originating_router_ip"))
                    self._edge(esi, origin, "evpn-ethernet-segment-origin", frame)
                elif route_type == 5:
                    prefix = self._node("ip-prefix", route.get("ip_prefix"))
                    gateway = self._node("ip", route.get("gateway_ip"))
                    self._edge(peer, prefix, "evpn-advertises-prefix", frame)
                    self._edge(service_node, prefix, "evpn-service-prefix", frame)
                    self._edge(prefix, gateway, "evpn-prefix-overlay-gateway", frame)

    def _vxlan(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        vni = self._node("vxlan-vni", fields.get("vni"))
        self._edge(source_ip, vni, "vxlan-source-vtep-vni", frame)
        self._edge(vni, destination_ip, "vxlan-vni-destination-vtep", frame)

    def _geneve(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        vni = self._node("geneve-vni", fields.get("vni"))
        self._edge(source_ip, vni, "geneve-source-endpoint-vni", frame)
        self._edge(vni, destination_ip, "geneve-vni-destination-endpoint", frame)
        options = fields.get("options") if isinstance(fields.get("options"), list) else []
        for row in options[:128]:
            if not isinstance(row, Mapping):
                continue
            option = self._node("geneve-option", f"{row.get('class')}:{row.get('type')}")
            self._edge(vni, option, "geneve-vni-option", frame)


    def _gtp(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        if int(fields.get("version") or 0) != 1 or fields.get("teid") is None:
            return
        teid = self._node("gtp-teid", f"0x{int(fields['teid']):08x}")
        self._edge(source_ip, teid, "gtpu-source-teid", frame)
        self._edge(teid, destination_ip, "gtpu-teid-destination", frame)
        extensions = fields.get("extension_headers") if isinstance(fields.get("extension_headers"), list) else []
        for extension in extensions[:64]:
            if not isinstance(extension, Mapping) or int(extension.get("type") or 0) != 0x85 or extension.get("qfi") is None:
                continue
            qfi = self._node("qos-flow-qfi", extension.get("qfi"))
            self._edge(teid, qfi, "gtpu-pdu-session-qfi", frame)

    def _pfcp(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        def visit(rows: object, depth: int = 0) -> None:
            if depth > 4 or not isinstance(rows, list):
                return
            for row in rows[:1024]:
                if not isinstance(row, Mapping):
                    continue
                ie_type = int(row.get("type") or 0)
                if ie_type == 21 and row.get("teid") is not None:
                    teid = self._node("gtp-teid", f"0x{int(row['teid']):08x}")
                    endpoint = self._node("ip", row.get("ipv4") or row.get("ipv6"))
                    self._edge(source_ip, teid, "pfcp-advertises-fteid", frame)
                    self._edge(teid, endpoint, "pfcp-fteid-endpoint", frame)
                elif ie_type == 57 and row.get("seid") is not None:
                    seid = self._node("pfcp-seid", f"0x{int(row['seid']):016x}")
                    endpoint = self._node("ip", row.get("ipv4") or row.get("ipv6"))
                    self._edge(source_ip, seid, "pfcp-advertises-fseid", frame)
                    self._edge(seid, endpoint, "pfcp-fseid-endpoint", frame)
                elif ie_type == 60 and row.get("node_id"):
                    node = self._node("pfcp-node", row.get("node_id"))
                    self._edge(source_ip, node, "pfcp-node-identity", frame)
                elif ie_type == 22 and row.get("network_instance"):
                    network = self._node("pfcp-network-instance", row.get("network_instance"))
                    self._edge(source_ip, network, "pfcp-network-instance", frame)
                visit(row.get("children"), depth + 1)

        raw_ies = fields.get("information_elements")
        visit(raw_ies)
        for rule in extract_pfcp_rule_observations(raw_ies):
            kind = str(rule.get("rule_kind") or "")
            rule_nodes = [self._node(f"pfcp-{kind}", value) for value in rule.get("rule_ids", ())]
            rule_nodes = [value for value in rule_nodes if value]
            if kind == "pdr":
                for rule_node in rule_nodes:
                    for far_id in rule.get("far_ids", ()):
                        self._edge(rule_node, self._node("pfcp-far", far_id), "pfcp-observed-pdr-far", frame)
                    for qer_id in rule.get("qer_ids", ()):
                        self._edge(rule_node, self._node("pfcp-qer", qer_id), "pfcp-observed-pdr-qer", frame)
                    for fteid in rule.get("fteids", ()):
                        if isinstance(fteid, Mapping) and fteid.get("teid") is not None:
                            self._edge(rule_node, self._node("gtp-teid", f"0x{int(fteid['teid']):08x}"), "pfcp-observed-pdr-fteid", frame)
                    for network in rule.get("network_instances", ()):
                        self._edge(rule_node, self._node("pfcp-network-instance", network), "pfcp-observed-pdr-network", frame)
            if kind == "qer":
                for rule_node in rule_nodes:
                    for qfi in rule.get("qfis", ()):
                        self._edge(rule_node, self._node("qos-flow-qfi", qfi), "pfcp-observed-qer-qfi", frame)
        if fields.get("seid") is not None:
            seid = self._node("pfcp-seid", f"0x{int(fields['seid']):016x}")
            self._edge(source_ip, seid, "pfcp-session-source", frame)
            self._edge(seid, destination_ip, "pfcp-session-destination", frame)

    def _diameter(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        origin_host = None
        origin_realm = None
        destination_host = None
        destination_realm = None
        sessions: list[str] = []

        def visit(rows: object, depth: int = 0) -> None:
            nonlocal origin_host, origin_realm, destination_host, destination_realm
            if depth > 4 or not isinstance(rows, list):
                return
            for row in rows[:1024]:
                if not isinstance(row, Mapping):
                    continue
                code = int(row.get("code") or 0)
                if code == 263 and row.get("session_id_sha256"):
                    sessions.append(str(row["session_id_sha256"]))
                elif code == 264 and row.get("text"):
                    origin_host = self._node("diameter-host", row.get("text"))
                elif code == 296 and row.get("text"):
                    origin_realm = self._node("diameter-realm", row.get("text"))
                elif code == 293 and row.get("text"):
                    destination_host = self._node("diameter-host", row.get("text"))
                elif code == 283 and row.get("text"):
                    destination_realm = self._node("diameter-realm", row.get("text"))
                visit(row.get("children"), depth + 1)

        visit(fields.get("avps"))
        self._edge(source_ip, origin_host, "diameter-origin-host", frame)
        self._edge(origin_host, origin_realm, "diameter-host-realm", frame)
        self._edge(destination_host, destination_realm, "diameter-host-realm", frame)
        self._edge(destination_host, destination_ip, "diameter-destination-host", frame)
        for digest in sessions[:64]:
            session = self._node("diameter-session-sha256", digest)
            self._edge(origin_host or source_ip, session, "diameter-session-origin", frame)
            self._edge(session, destination_host or destination_ip, "diameter-session-destination", frame)

    def _mpls(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        labels = fields.get("labels") if isinstance(fields.get("labels"), list) else []
        for index, row in enumerate(labels[:64]):
            if not isinstance(row, Mapping) or row.get("label") is None:
                continue
            label = self._node("mpls-label", row.get("label"))
            if index == 0:
                self._edge(source_ip, label, "mpls-top-label", frame)
            if destination_ip:
                self._edge(label, destination_ip, "mpls-carried-toward", frame)
            if bool(row.get("entropy_label")):
                self._edge(label, self._node("mpls-role", "entropy-label"), "mpls-label-role", frame)

    @staticmethod
    def _valid_ip(value: object) -> str:
        text = str(value or "").strip()
        return "" if text in {"", "0.0.0.0", "::"} else text

    def _dhcp(self, fields: Mapping[str, Any], frame: int) -> None:
        client = self._node("mac", fields.get("client_mac"))
        hostname = self._node("hostname", fields.get("hostname"))
        self._edge(client, hostname, "dhcp-client-hostname", frame)
        options = fields.get("options") if isinstance(fields.get("options"), list) else []
        client_id = None
        for row in options[:256]:
            if not isinstance(row, Mapping):
                continue
            name = str(row.get("name") or "")
            if name == "client-identifier":
                client_id = self._node("dhcp-client-id-sha256", row.get("sha256"))
            elif name == "dns-servers":
                for address in row.get("addresses") if isinstance(row.get("addresses"), list) else []:
                    self._edge(client or client_id, self._node("ip", address), "dhcp-dns-server", frame)
            elif name == "classless-static-routes":
                routes = row.get("routes") if isinstance(row.get("routes"), list) else []
                for route in routes[:128]:
                    if isinstance(route, Mapping):
                        route_node = self._node("ip-prefix", route.get("prefix"))
                        router = self._node("ip", route.get("router"))
                        self._edge(route_node, router, "dhcp-route-via", frame)
        self._edge(client, client_id, "dhcp-client-identifier", frame)
        subject = client or client_id
        for key in ("your_ip", "requested_ip", "client_ip"):
            address = self._valid_ip(fields.get(key))
            if address:
                self._edge(subject, self._node("ip", address), "dhcp-address", frame)
        server = self._valid_ip(fields.get("server_identifier") or fields.get("server_ip"))
        if server:
            self._edge(subject, self._node("ip", server), "dhcp-server", frame)

    def _dhcpv6(self, fields: Mapping[str, Any], frame: int) -> None:
        duids: list[str] = []
        addresses: list[str] = []

        def visit(options: object, depth: int = 0) -> None:
            if depth > 5 or not isinstance(options, list):
                return
            for row in options[:256]:
                if not isinstance(row, Mapping):
                    continue
                if str(row.get("name") or "") in {"client-id", "server-id"} and row.get("duid_sha256"):
                    duids.append(str(row["duid_sha256"]))
                if row.get("address"):
                    addresses.append(str(row["address"]))
                visit(row.get("options"), depth + 1)
                message = row.get("message")
                if isinstance(message, Mapping):
                    visit(message.get("options"), depth + 1)

        visit(fields.get("options"))
        identity = self._node("dhcpv6-duid-sha256", duids[0]) if duids else None
        for address in dict.fromkeys(addresses):
            self._edge(identity, self._node("ip", address), "dhcpv6-address", frame)
        for key in ("link_address", "peer_address"):
            address = self._valid_ip(fields.get(key))
            if address:
                self._edge(identity, self._node("ip", address), f"dhcpv6-{key.replace('_', '-')}", frame)

    def _radius(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        attributes = fields.get("attributes") if isinstance(fields.get("attributes"), list) else []
        principal = None
        nas_ip = None
        framed_ip = None
        for row in attributes[:256]:
            if not isinstance(row, Mapping):
                continue
            name = str(row.get("name") or "")
            if name == "user-name" and row.get("value_sha256"):
                principal = self._node("radius-principal-sha256", row.get("value_sha256"))
            elif name == "nas-ip-address":
                nas_ip = self._node("ip", row.get("address"))
            elif name == "framed-ip-address":
                framed_ip = self._node("ip", row.get("address"))
        self._edge(source_ip, nas_ip, "radius-nas-identity", frame)
        self._edge(principal, framed_ip, "radius-framed-address", frame)
        if principal:
            self._edge(principal, destination_ip, "radius-auth-server", frame)

    def _snmp(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        target = destination_ip if str(fields.get("pdu_type") or "").endswith("request") else source_ip
        varbinds = fields.get("varbinds") if isinstance(fields.get("varbinds"), list) else []
        for row in varbinds[:256]:
            if isinstance(row, Mapping) and row.get("oid"):
                self._edge(target, self._node("snmp-oid", row.get("oid")), "snmp-observes-oid", frame)

    def _smb(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        session_id = fields.get("session_id")
        session = self._node("smb-session", f"0x{int(session_id):016x}") if session_id else None
        self._edge(source_ip, session, "smb-participates-in", frame)
        self._edge(destination_ip, session, "smb-participates-in", frame)
        tree_id = fields.get("tree_id")
        tree = self._node("smb-tree", f"0x{int(tree_id):08x}") if tree_id else None
        self._edge(session, tree, "smb-uses-tree", frame)
        body = fields.get("body") if isinstance(fields.get("body"), Mapping) else {}
        ntlm = body.get("ntlmssp") if isinstance(body, Mapping) and isinstance(body.get("ntlmssp"), Mapping) else {}
        for key in ("user_sha256", "domain_sha256", "workstation_sha256", "target_name_sha256"):
            digest = str(ntlm.get(key) or "") if isinstance(ntlm, Mapping) else ""
            if digest:
                identity = self._node(f"ntlm-{key.replace('_sha256', '')}-sha256", digest)
                self._edge(session or source_ip, identity, "ntlm-observed-identity", frame)

    def _ldap(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        operation = self._node("ldap-operation", fields.get("operation"))
        self._edge(source_ip, operation, "ldap-sends", frame)
        self._edge(operation, destination_ip, "ldap-targets", frame)
        for key in ("bind_name_sha256", "base_dn_sha256", "target_dn_sha256"):
            digest = str(fields.get(key) or "")
            if digest:
                self._edge(operation, self._node("ldap-dn-sha256", digest), "ldap-references-dn", frame)

    def _kerberos(self, fields: Mapping[str, Any], source_ip: str | None, destination_ip: str | None, frame: int) -> None:
        message = self._node("kerberos-message", fields.get("message_name"))
        self._edge(source_ip, message, "kerberos-sends", frame)
        self._edge(message, destination_ip, "kerberos-targets", frame)
        if fields.get("error_code") is not None:
            error = self._node("kerberos-error", f"{fields.get('error_code')}:{fields.get('error_name') or 'unknown'}")
            self._edge(message, error, "kerberos-result", frame)

    def finalize(self) -> dict[str, Any]:
        nodes = sorted(self._nodes.values(), key=lambda row: (row.kind, row.value))
        edges = sorted(self._edges.values(), key=lambda row: (row.relation, row.source, row.target))
        return {
            "schema": "arenyxa.network-evidence-graph/v1",
            "node_count": len(nodes),
            "edge_count": len(edges),
            "node_limit_reached": self._node_limit_reached,
            "edge_limit_reached": self._edge_limit_reached,
            "nodes": [
                {"id": row.id, "kind": row.kind, "value": row.value, "observations": row.observations}
                for row in nodes
            ],
            "edges": [
                {
                    "source": row.source,
                    "target": row.target,
                    "relation": row.relation,
                    "observations": row.observations,
                    "first_frame": row.first_frame,
                    "last_frame": row.last_frame,
                }
                for row in edges
            ],
        }
