from __future__ import annotations

import ipaddress
import struct
from typing import Any


_MAX_ROUTER_LINKS = 256
_MAX_ATTACHED_ROUTERS = 512
_MAX_PREFIXES = 512
_MAX_TOS_METRICS = 64


_V2_LINK_TYPE_NAMES = {
    1: "point-to-point",
    2: "transit-network",
    3: "stub-network",
    4: "virtual-link",
}

_V3_LINK_TYPE_NAMES = {
    1: "point-to-point",
    2: "transit-network",
    3: "reserved",
    4: "virtual-link",
}


def _router_id(raw: bytes) -> str:
    if len(raw) != 4:
        raise ValueError("OSPF router-id field must be four bytes")
    return str(ipaddress.IPv4Address(raw))


def _prefix_options(value: int) -> dict[str, Any]:
    return {
        "raw": f"0x{value:02x}",
        "no_unicast": bool(value & 0x01),
        "local_address": bool(value & 0x02),
        "multicast": bool(value & 0x04),
        "propagate": bool(value & 0x08),
        "down": bool(value & 0x10),
    }


def _read_ipv6_prefix(data: bytes, cursor: int, prefix_length: int) -> tuple[str, int]:
    if not 0 <= prefix_length <= 128:
        raise ValueError("invalid OSPFv3 IPv6 prefix length")
    encoded_bytes = ((prefix_length + 31) // 32) * 4
    if cursor + encoded_bytes > len(data):
        raise ValueError("truncated OSPFv3 IPv6 prefix")
    raw = data[cursor:cursor + encoded_bytes] + b"\x00" * (16 - encoded_bytes)
    address = ipaddress.IPv6Address(raw)
    network = ipaddress.IPv6Network((address, prefix_length), strict=False)
    return str(network), cursor + encoded_bytes


def _decode_v2_router(body: bytes) -> dict[str, Any]:
    if len(body) < 4:
        raise ValueError("truncated OSPFv2 Router-LSA body")
    flags = body[0]
    link_count = struct.unpack_from("!H", body, 2)[0]
    cursor = 4
    links: list[dict[str, Any]] = []
    malformed = False
    while len(links) < min(link_count, _MAX_ROUTER_LINKS):
        if cursor + 12 > len(body):
            malformed = True
            break
        link_id = _router_id(body[cursor:cursor + 4])
        link_data = str(ipaddress.IPv4Address(body[cursor + 4:cursor + 8]))
        link_type = body[cursor + 8]
        tos_count = body[cursor + 9]
        metric = struct.unpack_from("!H", body, cursor + 10)[0]
        cursor += 12
        tos_metrics: list[dict[str, int]] = []
        if tos_count > _MAX_TOS_METRICS:
            malformed = True
            break
        for _ in range(tos_count):
            if cursor + 4 > len(body):
                malformed = True
                break
            tos = body[cursor]
            tos_metric = int.from_bytes(body[cursor + 1:cursor + 4], "big")
            tos_metrics.append({"tos": tos, "metric": tos_metric})
            cursor += 4
        links.append({
            "link_id": link_id,
            "link_data": link_data,
            "link_type": link_type,
            "link_type_name": _V2_LINK_TYPE_NAMES.get(link_type, "unknown"),
            "metric": metric,
            "tos_metric_count": len(tos_metrics),
            "tos_metrics": tos_metrics,
        })
        if malformed:
            break
    return {
        "flags": f"0x{flags:02x}",
        "virtual_link_endpoint": bool(flags & 0x04),
        "as_boundary_router": bool(flags & 0x02),
        "area_border_router": bool(flags & 0x01),
        "advertised_link_count": link_count,
        "decoded_link_count": len(links),
        "links": links,
        "link_limit_reached": link_count > _MAX_ROUTER_LINKS,
        "body_malformed": malformed or (len(links) != link_count and link_count <= _MAX_ROUTER_LINKS),
        "trailing_bytes": max(0, len(body) - cursor),
    }


def _decode_v2_network(body: bytes) -> dict[str, Any]:
    if len(body) < 4:
        raise ValueError("truncated OSPFv2 Network-LSA body")
    mask = str(ipaddress.IPv4Address(body[:4]))
    cursor = 4
    routers: list[str] = []
    while cursor + 4 <= len(body) and len(routers) < _MAX_ATTACHED_ROUTERS:
        routers.append(_router_id(body[cursor:cursor + 4]))
        cursor += 4
    return {
        "network_mask": mask,
        "attached_router_count": len(routers),
        "attached_routers": routers,
        "router_limit_reached": cursor + 4 <= len(body),
        "body_malformed": cursor != len(body),
    }


def _decode_v2_summary(body: bytes) -> dict[str, Any]:
    if len(body) < 8:
        raise ValueError("truncated OSPFv2 Summary-LSA body")
    return {
        "network_mask": str(ipaddress.IPv4Address(body[:4])),
        "tos": body[4],
        "metric": int.from_bytes(body[5:8], "big"),
        "trailing_tos_metric_bytes": max(0, len(body) - 8),
        "body_malformed": (len(body) - 8) % 4 != 0,
    }


def _decode_v2_external(body: bytes) -> dict[str, Any]:
    if len(body) < 16:
        raise ValueError("truncated OSPFv2 External-LSA body")
    tos_metric = body[4]
    return {
        "network_mask": str(ipaddress.IPv4Address(body[:4])),
        "external_metric_type_2": bool(tos_metric & 0x80),
        "tos": tos_metric & 0x7F,
        "metric": int.from_bytes(body[5:8], "big"),
        "forwarding_address": str(ipaddress.IPv4Address(body[8:12])),
        "external_route_tag": f"0x{struct.unpack_from('!I', body, 12)[0]:08x}",
        "trailing_tos_route_bytes": max(0, len(body) - 16),
        "body_malformed": (len(body) - 16) % 12 != 0,
    }


def _decode_v3_router(body: bytes) -> dict[str, Any]:
    if len(body) < 4:
        raise ValueError("truncated OSPFv3 Router-LSA body")
    flags = body[0]
    options = int.from_bytes(body[1:4], "big")
    cursor = 4
    links: list[dict[str, Any]] = []
    while cursor + 16 <= len(body) and len(links) < _MAX_ROUTER_LINKS:
        link_type = body[cursor]
        metric = struct.unpack_from("!H", body, cursor + 2)[0]
        links.append({
            "link_type": link_type,
            "link_type_name": _V3_LINK_TYPE_NAMES.get(link_type, "unknown"),
            "metric": metric,
            "interface_id": struct.unpack_from("!I", body, cursor + 4)[0],
            "neighbor_interface_id": struct.unpack_from("!I", body, cursor + 8)[0],
            "neighbor_router_id": _router_id(body[cursor + 12:cursor + 16]),
        })
        cursor += 16
    return {
        "flags": f"0x{flags:02x}",
        "virtual_link_endpoint": bool(flags & 0x04),
        "as_boundary_router": bool(flags & 0x02),
        "area_border_router": bool(flags & 0x01),
        "options": f"0x{options:06x}",
        "decoded_link_count": len(links),
        "links": links,
        "link_limit_reached": len(links) >= _MAX_ROUTER_LINKS and cursor + 16 <= len(body),
        "body_malformed": cursor != len(body),
        "trailing_bytes": max(0, len(body) - cursor),
    }


def _decode_v3_network(body: bytes) -> dict[str, Any]:
    if len(body) < 4:
        raise ValueError("truncated OSPFv3 Network-LSA body")
    reserved = body[0]
    options = int.from_bytes(body[1:4], "big")
    cursor = 4
    routers: list[str] = []
    while cursor + 4 <= len(body) and len(routers) < _MAX_ATTACHED_ROUTERS:
        routers.append(_router_id(body[cursor:cursor + 4]))
        cursor += 4
    return {
        "reserved": reserved,
        "options": f"0x{options:06x}",
        "attached_router_count": len(routers),
        "attached_routers": routers,
        "router_limit_reached": cursor + 4 <= len(body),
        "body_malformed": cursor != len(body),
    }


def _decode_v3_link(body: bytes) -> dict[str, Any]:
    if len(body) < 24:
        raise ValueError("truncated OSPFv3 Link-LSA body")
    priority = body[0]
    options = int.from_bytes(body[1:4], "big")
    link_local = str(ipaddress.IPv6Address(body[4:20]))
    advertised = struct.unpack_from("!I", body, 20)[0]
    cursor = 24
    prefixes: list[dict[str, Any]] = []
    malformed = False
    while len(prefixes) < min(advertised, _MAX_PREFIXES):
        if cursor + 4 > len(body):
            malformed = True
            break
        prefix_length = body[cursor]
        options_raw = body[cursor + 1]
        cursor += 4
        try:
            prefix, cursor = _read_ipv6_prefix(body, cursor, prefix_length)
        except ValueError:
            malformed = True
            break
        prefixes.append({
            "prefix": prefix,
            "prefix_length": prefix_length,
            "prefix_options": _prefix_options(options_raw),
        })
    return {
        "router_priority": priority,
        "options": f"0x{options:06x}",
        "link_local_address": link_local,
        "advertised_prefix_count": advertised,
        "decoded_prefix_count": len(prefixes),
        "prefixes": prefixes,
        "prefix_limit_reached": advertised > _MAX_PREFIXES,
        "body_malformed": malformed or (len(prefixes) != advertised and advertised <= _MAX_PREFIXES),
        "trailing_bytes": max(0, len(body) - cursor),
    }


def _decode_v3_intra_area_prefix(body: bytes) -> dict[str, Any]:
    if len(body) < 12:
        raise ValueError("truncated OSPFv3 Intra-Area-Prefix-LSA body")
    advertised = struct.unpack_from("!H", body, 0)[0]
    referenced_type = struct.unpack_from("!H", body, 2)[0]
    referenced_link_state_id = _router_id(body[4:8])
    referenced_advertising_router = _router_id(body[8:12])
    cursor = 12
    prefixes: list[dict[str, Any]] = []
    malformed = False
    while len(prefixes) < min(advertised, _MAX_PREFIXES):
        if cursor + 4 > len(body):
            malformed = True
            break
        prefix_length = body[cursor]
        options_raw = body[cursor + 1]
        metric = struct.unpack_from("!H", body, cursor + 2)[0]
        cursor += 4
        try:
            prefix, cursor = _read_ipv6_prefix(body, cursor, prefix_length)
        except ValueError:
            malformed = True
            break
        prefixes.append({
            "prefix": prefix,
            "prefix_length": prefix_length,
            "prefix_options": _prefix_options(options_raw),
            "metric": metric,
        })
    return {
        "advertised_prefix_count": advertised,
        "decoded_prefix_count": len(prefixes),
        "referenced_ls_type": referenced_type,
        "referenced_link_state_id": referenced_link_state_id,
        "referenced_advertising_router": referenced_advertising_router,
        "prefixes": prefixes,
        "prefix_limit_reached": advertised > _MAX_PREFIXES,
        "body_malformed": malformed or (len(prefixes) != advertised and advertised <= _MAX_PREFIXES),
        "trailing_bytes": max(0, len(body) - cursor),
    }


def decode_ospf_lsa_body(version: int, ls_type: int, body: bytes) -> dict[str, Any] | None:
    """Decode bounded high-value LSA body structure without retaining opaque payload bytes."""
    if version == 2:
        if ls_type == 1:
            return _decode_v2_router(body)
        if ls_type == 2:
            return _decode_v2_network(body)
        if ls_type in {3, 4}:
            return _decode_v2_summary(body)
        if ls_type in {5, 7}:
            return _decode_v2_external(body)
        return None
    if version == 3:
        if ls_type == 0x2001:
            return _decode_v3_router(body)
        if ls_type == 0x2002:
            return _decode_v3_network(body)
        if ls_type == 0x0008:
            return _decode_v3_link(body)
        if ls_type == 0x2009:
            return _decode_v3_intra_area_prefix(body)
        return None
    raise ValueError(f"unsupported OSPF version: {version}")
