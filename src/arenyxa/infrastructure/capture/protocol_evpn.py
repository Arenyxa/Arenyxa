from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_ROUTE_NAMES = {
    1: "ethernet-auto-discovery",
    2: "mac-ip-advertisement",
    3: "inclusive-multicast-ethernet-tag",
    4: "ethernet-segment",
    5: "ip-prefix",
}


def _need(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"truncated {label}")


def _rd(raw: bytes) -> dict[str, Any]:
    if len(raw) != 8:
        raise ValueError("invalid EVPN route distinguisher length")
    kind = struct.unpack_from("!H", raw, 0)[0]
    row: dict[str, Any] = {"type": kind, "hex": raw.hex()}
    if kind == 0:
        row.update({"administrator": struct.unpack_from("!H", raw, 2)[0], "assigned": struct.unpack_from("!I", raw, 4)[0]})
    elif kind == 1:
        row.update({"administrator": str(ipaddress.IPv4Address(raw[2:6])), "assigned": struct.unpack_from("!H", raw, 6)[0]})
    elif kind == 2:
        row.update({"administrator": struct.unpack_from("!I", raw, 2)[0], "assigned": struct.unpack_from("!H", raw, 6)[0]})
    if row.get("administrator") is not None and row.get("assigned") is not None:
        row["value"] = f"{row['administrator']}:{row['assigned']}"
    return row


def _esi(raw: bytes) -> dict[str, Any]:
    if len(raw) != 10:
        raise ValueError("invalid EVPN ESI length")
    return {
        "type": raw[0],
        "value_hex": raw.hex(),
        "zero": not any(raw),
    }


def _service_label(raw: bytes) -> dict[str, int]:
    if len(raw) != 3:
        raise ValueError("invalid EVPN service-label length")
    value24 = int.from_bytes(raw, "big")
    return {
        "label20": value24 >> 4,
        "service_id_24": value24,
    }


def _mac(raw: bytes) -> str:
    if len(raw) != 6:
        raise ValueError("invalid EVPN MAC length")
    return ":".join(f"{part:02x}" for part in raw)


def _ip(raw: bytes) -> str:
    if len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    raise ValueError("invalid EVPN IP address length")


def _route1(value: bytes) -> dict[str, Any]:
    if len(value) != 25:
        raise ValueError("invalid EVPN Ethernet A-D route length")
    return {
        "route_distinguisher": _rd(value[:8]),
        "ethernet_segment_identifier": _esi(value[8:18]),
        "ethernet_tag_id": struct.unpack_from("!I", value, 18)[0],
        "service": _service_label(value[22:25]),
    }


def _route2(value: bytes) -> dict[str, Any]:
    _need(value, 0, 30, "EVPN MAC/IP Advertisement route")
    mac_bits = value[22]
    if mac_bits != 48:
        raise ValueError("unsupported EVPN MAC address length")
    mac_address = _mac(value[23:29])
    ip_bits = value[29]
    if ip_bits not in {0, 32, 128}:
        raise ValueError("invalid EVPN MAC/IP address length")
    ip_octets = {0: 0, 32: 4, 128: 16}[ip_bits]
    labels_offset = 30 + ip_octets
    _need(value, labels_offset, 3, "EVPN MAC/IP service label")
    remaining = len(value) - labels_offset
    if remaining not in {3, 6}:
        raise ValueError("invalid EVPN MAC/IP label vector length")
    row: dict[str, Any] = {
        "route_distinguisher": _rd(value[:8]),
        "ethernet_segment_identifier": _esi(value[8:18]),
        "ethernet_tag_id": struct.unpack_from("!I", value, 18)[0],
        "mac_address_length": mac_bits,
        "mac_address": mac_address,
        "ip_address_length": ip_bits,
        "service": _service_label(value[labels_offset:labels_offset + 3]),
    }
    if ip_octets:
        row["ip_address"] = _ip(value[30:30 + ip_octets])
    if remaining == 6:
        row["service2"] = _service_label(value[labels_offset + 3:labels_offset + 6])
    return row


def _route3(value: bytes) -> dict[str, Any]:
    _need(value, 0, 13, "EVPN IMET route")
    ip_bits = value[12]
    if ip_bits not in {32, 128}:
        raise ValueError("invalid EVPN IMET originator address length")
    octets = 4 if ip_bits == 32 else 16
    if len(value) != 13 + octets:
        raise ValueError("invalid EVPN IMET route length")
    return {
        "route_distinguisher": _rd(value[:8]),
        "ethernet_tag_id": struct.unpack_from("!I", value, 8)[0],
        "ip_address_length": ip_bits,
        "originating_router_ip": _ip(value[13:]),
    }


def _route4(value: bytes) -> dict[str, Any]:
    _need(value, 0, 19, "EVPN Ethernet Segment route")
    ip_bits = value[18]
    if ip_bits not in {32, 128}:
        raise ValueError("invalid EVPN Ethernet Segment originator address length")
    octets = 4 if ip_bits == 32 else 16
    if len(value) != 19 + octets:
        raise ValueError("invalid EVPN Ethernet Segment route length")
    return {
        "route_distinguisher": _rd(value[:8]),
        "ethernet_segment_identifier": _esi(value[8:18]),
        "ip_address_length": ip_bits,
        "originating_router_ip": _ip(value[19:]),
    }


def _route5(value: bytes) -> dict[str, Any]:
    if len(value) not in {34, 58}:
        raise ValueError("invalid EVPN IP Prefix route length")
    address_size = 4 if len(value) == 34 else 16
    prefix_bits = value[22]
    max_bits = address_size * 8
    if prefix_bits > max_bits:
        raise ValueError("invalid EVPN IP Prefix length")
    prefix_raw = value[23:23 + address_size]
    gateway_offset = 23 + address_size
    gateway_raw = value[gateway_offset:gateway_offset + address_size]
    service_offset = gateway_offset + address_size
    network = ipaddress.ip_network(f"{_ip(prefix_raw)}/{prefix_bits}", strict=False)
    gateway = _ip(gateway_raw)
    esi = _esi(value[8:18])
    service = _service_label(value[service_offset:service_offset + 3])
    overlay_index = ""
    if not esi["zero"]:
        overlay_index = "esi"
    elif int(ipaddress.ip_address(gateway)) != 0:
        overlay_index = "gateway-ip"
    elif service["service_id_24"] == 0:
        overlay_index = "unresolved-or-router-mac"
    return {
        "route_distinguisher": _rd(value[:8]),
        "ethernet_segment_identifier": esi,
        "ethernet_tag_id": struct.unpack_from("!I", value, 18)[0],
        "ip_prefix_length": prefix_bits,
        "ip_prefix": str(network),
        "gateway_ip": gateway,
        "service": service,
        "overlay_index_kind": overlay_index,
    }


def decode_evpn_nlri(payload: bytes, *, limit: int = 4096) -> list[dict[str, Any]]:
    """Decode a bounded AFI=25/SAFI=70 EVPN NLRI vector.

    Unknown route types are retained as type/length/digest metadata only so a
    capture cannot cause opaque control-plane payload to be copied into reports.
    """
    rows: list[dict[str, Any]] = []
    cursor = 0
    while cursor < len(payload) and len(rows) < limit:
        _need(payload, cursor, 2, "EVPN NLRI header")
        route_type = payload[cursor]
        length = payload[cursor + 1]
        cursor += 2
        _need(payload, cursor, length, "EVPN route")
        value = payload[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {
            "route_type": route_type,
            "route_type_name": _ROUTE_NAMES.get(route_type, f"route-type-{route_type}"),
            "length": length,
        }
        try:
            if route_type == 1:
                row.update(_route1(value))
            elif route_type == 2:
                row.update(_route2(value))
            elif route_type == 3:
                row.update(_route3(value))
            elif route_type == 4:
                row.update(_route4(value))
            elif route_type == 5:
                row.update(_route5(value))
            else:
                row.update({
                    "payload_bytes": length,
                    "payload_sha256": hashlib.sha256(b"arenyxa-evpn-unknown/v1\x00" + value).hexdigest(),
                    "payload_retained": False,
                })
        except (ValueError, struct.error, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
            row.update({
                "malformed": True,
                "parse_error": str(exc),
                "payload_bytes": length,
                "payload_sha256": hashlib.sha256(b"arenyxa-evpn-malformed/v1\x00" + value).hexdigest(),
                "payload_retained": False,
            })
        rows.append(row)
    if cursor != len(payload):
        raise ValueError("EVPN NLRI exceeds bounded route count")
    return rows
