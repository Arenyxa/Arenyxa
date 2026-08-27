from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_TUNNEL_TYPES = {
    1: "l2tpv3-over-ip",
    2: "gre",
    7: "ip-in-ip",
    8: "vxlan",
    9: "nvgre",
    10: "mpls",
    11: "mpls-in-gre",
    12: "vxlan-gpe",
}

_ETHERTYPES = {
    0x0800: "ipv4",
    0x0806: "arp",
    0x8100: "802.1q",
    0x86DD: "ipv6",
    0x8847: "mpls-unicast",
    0x8848: "mpls-multicast",
}


def _need(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"truncated {label}")


def _digest(value: bytes, domain: bytes) -> str:
    return hashlib.sha256(domain + b"\x00" + value).hexdigest()


def _mac(raw: bytes) -> str:
    if len(raw) != 6:
        raise ValueError("invalid MAC address length")
    return ":".join(f"{part:02x}" for part in raw)


def _decode_vxlan_or_nvgre_encapsulation(tunnel_type: int, value: bytes) -> dict[str, Any]:
    if len(value) != 12:
        raise ValueError("VXLAN/NVGRE Encapsulation sub-TLV must be 12 octets")
    flags = value[0]
    vni = int.from_bytes(value[1:4], "big")
    mac_raw = value[4:10]
    reserved = value[10:12]
    vni_present = bool(flags & 0x80)
    mac_present = bool(flags & 0x40)
    return {
        "name": "encapsulation",
        "vni_present": vni_present,
        "mac_present": mac_present,
        "reserved_flag_bits_nonzero": bool(flags & 0x3F),
        "virtual_network_id": vni if vni_present else None,
        "virtual_network_id_field_nonzero_without_v_flag": (not vni_present and vni != 0),
        "router_mac": _mac(mac_raw) if mac_present else None,
        "router_mac_field_nonzero_without_m_flag": (not mac_present and any(mac_raw)),
        "reserved_bytes_nonzero": any(reserved),
        "tunnel_type": tunnel_type,
        "tunnel_type_name": _TUNNEL_TYPES.get(tunnel_type, f"tunnel-{tunnel_type}"),
    }


def _decode_egress_endpoint(value: bytes) -> dict[str, Any]:
    _need(value, 0, 6, "Tunnel Egress Endpoint sub-TLV")
    reserved = value[:4]
    afi = struct.unpack_from("!H", value, 4)[0]
    if afi == 0:
        if len(value) != 6:
            raise ValueError("next-hop Tunnel Egress Endpoint must be 6 octets")
        address = None
        source = "bgp-next-hop"
    elif afi == 1:
        if len(value) != 10:
            raise ValueError("IPv4 Tunnel Egress Endpoint must be 10 octets")
        address = str(ipaddress.IPv4Address(value[6:10]))
        source = "explicit-ipv4"
    elif afi == 2:
        if len(value) != 22:
            raise ValueError("IPv6 Tunnel Egress Endpoint must be 22 octets")
        address = str(ipaddress.IPv6Address(value[6:22]))
        source = "explicit-ipv6"
    else:
        return {
            "name": "tunnel-egress-endpoint",
            "address_family": afi,
            "unrecognized_address_family": True,
            "reserved_nonzero": any(reserved),
            "value_bytes": len(value),
            "value_sha256": _digest(value[6:], b"arenyxa-bgp-tunnel-egress-unknown-v1"),
            "value_retained": False,
        }
    return {
        "name": "tunnel-egress-endpoint",
        "address_family": afi,
        "address": address,
        "address_source": source,
        "reserved_nonzero": any(reserved),
    }


def _decode_mpls_stack(value: bytes) -> dict[str, Any]:
    if len(value) == 0 or len(value) % 4:
        raise ValueError("MPLS Label Stack sub-TLV length must be a non-zero multiple of 4")
    labels: list[dict[str, int | bool]] = []
    for (entry,) in struct.iter_unpack("!I", value):
        labels.append({
            "label": (entry >> 12) & 0xFFFFF,
            "traffic_class": (entry >> 9) & 0x7,
            "bottom_of_stack": bool((entry >> 8) & 0x1),
            "ttl": entry & 0xFF,
        })
    return {"name": "mpls-label-stack", "labels": labels[:64], "label_count": len(labels)}


def _decode_sub_tlv(tunnel_type: int, sub_type: int, value: bytes) -> dict[str, Any]:
    row: dict[str, Any] = {"type": sub_type, "length": len(value)}
    if sub_type == 1:
        if tunnel_type in {8, 9}:
            row.update(_decode_vxlan_or_nvgre_encapsulation(tunnel_type, value))
        else:
            row.update({
                "name": "encapsulation",
                "value_sha256": _digest(value, b"arenyxa-bgp-tunnel-encapsulation-v1"),
                "value_retained": False,
            })
    elif sub_type == 2:
        if len(value) != 2:
            raise ValueError("Protocol Type sub-TLV must be 2 octets")
        ethertype = struct.unpack("!H", value)[0]
        row.update({
            "name": "protocol-type",
            "ethertype": f"0x{ethertype:04x}",
            "protocol_name": _ETHERTYPES.get(ethertype, f"ethertype-0x{ethertype:04x}"),
            "reserved_value": ethertype == 0xFFFF,
        })
    elif sub_type == 4:
        if len(value) == 8 and value[:2] == b"\x03\x0b":
            row.update({
                "name": "color",
                "color": struct.unpack_from("!I", value, 4)[0],
                "reserved_nonzero": any(value[2:4]),
            })
        else:
            row.update({
                "name": "unrecognized-color",
                "value_sha256": _digest(value, b"arenyxa-bgp-tunnel-color-v1"),
                "value_retained": False,
            })
    elif sub_type == 6:
        row.update(_decode_egress_endpoint(value))
    elif sub_type == 7:
        if len(value) != 1:
            raise ValueError("DS Field sub-TLV must be 1 octet")
        row.update({"name": "ds-field", "value": value[0]})
    elif sub_type == 8:
        if len(value) != 2:
            raise ValueError("UDP Destination Port sub-TLV must be 2 octets")
        port = struct.unpack("!H", value)[0]
        row.update({"name": "udp-destination-port", "port": port, "malformed_reserved_zero": port == 0})
    elif sub_type == 9:
        if len(value) != 1:
            raise ValueError("Embedded Label Handling sub-TLV must be 1 octet")
        handling = value[0]
        row.update({
            "name": "embedded-label-handling",
            "value": handling,
            "meaning": {
                1: "embedded-label-at-top-of-payload-mpls-stack",
                2: "embedded-label-used-for-vni-or-ignored",
            }.get(handling, "invalid"),
            "malformed": handling not in {1, 2},
        })
    elif sub_type == 10:
        row.update(_decode_mpls_stack(value))
    else:
        row.update({
            "name": "sub-tlv",
            "value_sha256": _digest(value, b"arenyxa-bgp-tunnel-subtlv-v1"),
            "value_retained": False,
        })
    return row


def _decode_sub_tlvs(tunnel_type: int, data: bytes) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    malformed = False
    while cursor < len(data) and len(rows) < 512:
        try:
            _need(data, cursor, 2, "Tunnel Encapsulation sub-TLV header")
            sub_type = data[cursor]
            cursor += 1
            length_width = 2 if sub_type >= 128 else 1
            _need(data, cursor, length_width, "Tunnel Encapsulation sub-TLV length")
            length = struct.unpack_from("!H", data, cursor)[0] if length_width == 2 else data[cursor]
            cursor += length_width
            _need(data, cursor, length, "Tunnel Encapsulation sub-TLV value")
            value = data[cursor:cursor + length]
            cursor += length
            try:
                rows.append(_decode_sub_tlv(tunnel_type, sub_type, value))
            except (ValueError, struct.error, ipaddress.AddressValueError) as exc:
                rows.append({
                    "type": sub_type,
                    "length": length,
                    "malformed": True,
                    "parse_error": str(exc),
                    "value_sha256": _digest(value, b"arenyxa-bgp-tunnel-malformed-subtlv-v1"),
                    "value_retained": False,
                })
                malformed = True
        except (ValueError, struct.error):
            malformed = True
            break
    if cursor != len(data):
        malformed = True
    return rows, malformed


def decode_bgp_tunnel_encapsulation_attribute(data: bytes) -> dict[str, Any]:
    """Decode RFC 9012 Tunnel Encapsulation attribute without retaining opaque values."""
    tunnels: list[dict[str, Any]] = []
    cursor = 0
    malformed = False
    while cursor < len(data) and len(tunnels) < 256:
        try:
            _need(data, cursor, 4, "Tunnel Encapsulation TLV header")
            tunnel_type, length = struct.unpack_from("!HH", data, cursor)
            cursor += 4
            _need(data, cursor, length, "Tunnel Encapsulation TLV value")
            value = data[cursor:cursor + length]
            cursor += length
            sub_tlvs, sub_malformed = _decode_sub_tlvs(tunnel_type, value)
            endpoint_count = sum(1 for row in sub_tlvs if row.get("name") == "tunnel-egress-endpoint")
            tunnels.append({
                "tunnel_type": tunnel_type,
                "tunnel_type_name": _TUNNEL_TYPES.get(tunnel_type, f"tunnel-{tunnel_type}"),
                "length": length,
                "sub_tlvs": sub_tlvs,
                "tunnel_egress_endpoint_count": endpoint_count,
                "malformed": sub_malformed,
            })
            malformed = malformed or sub_malformed
        except (ValueError, struct.error):
            malformed = True
            break
    if cursor != len(data):
        malformed = True
    return {"tunnels": tunnels, "malformed": malformed, "tunnel_count": len(tunnels)}

_PMSI_TUNNEL_TYPES = {
    0: "no-tunnel-information",
    1: "rsvp-te-p2mp-lsp",
    2: "mldp-p2mp-lsp",
    3: "pim-ssm-tree",
    4: "pim-sm-tree",
    5: "bidir-pim-tree",
    6: "ingress-replication",
    7: "mldp-mp2mp-lsp",
    8: "transport-tunnel",
    10: "assisted-replication-tunnel",
    11: "bier",
    12: "sr-mpls-p2mp-tree",
    13: "srv6-p2mp-tree",
}


def _pmsi_ip(value: bytes) -> str:
    if len(value) == 4:
        return str(ipaddress.IPv4Address(value))
    if len(value) == 16:
        return str(ipaddress.IPv6Address(value))
    raise ValueError("PMSI tunnel identifier is not an IPv4 or IPv6 address")


def decode_pmsi_tunnel_attribute(data: bytes) -> dict[str, Any]:
    """Decode the RFC 6514 PMSI Tunnel attribute with bounded identifiers."""
    if len(data) < 5:
        return {
            "malformed": True,
            "parse_error": "PMSI Tunnel attribute is shorter than 5 octets",
            "value_bytes": len(data),
            "value_sha256": _digest(data, b"arenyxa-pmsi-malformed-v1"),
            "value_retained": False,
        }
    flags = data[0]
    tunnel_type = data[1]
    label24 = int.from_bytes(data[2:5], "big")
    identifier = data[5:]
    row: dict[str, Any] = {
        "flags": flags,
        "leaf_information_required": bool(flags & 0x01),
        "extension_flag": bool(flags & 0x40),
        "leaf_information_required_per_flow": bool(flags & 0x20),
        "broadcast_multicast_flag": bool(flags & 0x04),
        "unknown_unicast_flag": bool(flags & 0x02),
        "tunnel_type": tunnel_type,
        "tunnel_type_name": _PMSI_TUNNEL_TYPES.get(tunnel_type, f"tunnel-{tunnel_type}"),
        "label20": label24 >> 4,
        "field24": label24,
        "tunnel_identifier_bytes": len(identifier),
        "malformed": False,
    }
    try:
        if tunnel_type == 0:
            if identifier:
                raise ValueError("No-tunnel-information PMSI must not carry a tunnel identifier")
            row["tunnel_identifier_kind"] = "none"
        elif tunnel_type == 6:
            row.update({
                "tunnel_identifier_kind": "unicast-endpoint",
                "tunnel_endpoint": _pmsi_ip(identifier),
            })
        elif tunnel_type in {3, 4, 5}:
            if len(identifier) not in {8, 32}:
                raise ValueError("PIM PMSI tunnel identifier must contain two same-family IP addresses")
            width = len(identifier) // 2
            source = _pmsi_ip(identifier[:width])
            group = _pmsi_ip(identifier[width:])
            row.update({
                "tunnel_identifier_kind": "pim-tree",
                "tree_source": source,
                "multicast_group": group,
            })
        elif tunnel_type in _PMSI_TUNNEL_TYPES:
            row.update({
                "tunnel_identifier_kind": "opaque-standardized",
                "tunnel_identifier_sha256": _digest(identifier, b"arenyxa-pmsi-standardized-id-v1"),
                "tunnel_identifier_retained": False,
            })
        else:
            row.update({
                "malformed": True,
                "parse_error": "undefined PMSI tunnel type",
                "tunnel_identifier_kind": "unknown",
                "tunnel_identifier_sha256": _digest(identifier, b"arenyxa-pmsi-unknown-id-v1"),
                "tunnel_identifier_retained": False,
            })
    except (ValueError, ipaddress.AddressValueError) as exc:
        row.update({
            "malformed": True,
            "parse_error": str(exc),
            "tunnel_identifier_sha256": _digest(identifier, b"arenyxa-pmsi-malformed-id-v1"),
            "tunnel_identifier_retained": False,
        })
    return row
