from __future__ import annotations

import ipaddress
import struct
from typing import Any

from arenyxa.infrastructure.capture.protocol_ospf_lsa import decode_ospf_lsa_body


_PACKET_NAMES = {
    1: "hello",
    2: "database-description",
    3: "link-state-request",
    4: "link-state-update",
    5: "link-state-acknowledgment",
}
_MAX_NEIGHBORS = 256
_MAX_LSA_HEADERS = 256
_MAX_LS_REQUESTS = 256


def _router_id(raw: bytes) -> str:
    return str(ipaddress.IPv4Address(raw))


def _lsa_type_name(version: int, ls_type: int) -> str:
    if version == 2:
        return {
            1: "router-lsa",
            2: "network-lsa",
            3: "summary-network-lsa",
            4: "summary-asbr-lsa",
            5: "as-external-lsa",
            7: "nssa-external-lsa",
            9: "opaque-link-lsa",
            10: "opaque-area-lsa",
            11: "opaque-as-lsa",
        }.get(ls_type, "unknown")
    return {
        0x2001: "router-lsa",
        0x2002: "network-lsa",
        0x2003: "inter-area-prefix-lsa",
        0x2004: "inter-area-router-lsa",
        0x4005: "as-external-lsa",
        0x2007: "nssa-lsa",
        0x0008: "link-lsa",
        0x2009: "intra-area-prefix-lsa",
    }.get(ls_type, "unknown")


def _parse_lsa_header(data: bytes, offset: int, version: int) -> dict[str, Any]:
    if offset < 0 or offset + 20 > len(data):
        raise ValueError("truncated OSPF LSA header")
    age = struct.unpack_from("!H", data, offset)[0]
    if version == 2:
        options = data[offset + 2]
        ls_type = data[offset + 3]
    else:
        options = None
        ls_type = struct.unpack_from("!H", data, offset + 2)[0]
    link_state_id = _router_id(data[offset + 4:offset + 8])
    advertising_router = _router_id(data[offset + 8:offset + 12])
    sequence = struct.unpack_from("!I", data, offset + 12)[0]
    checksum, length = struct.unpack_from("!HH", data, offset + 16)
    row: dict[str, Any] = {
        "age_seconds": age,
        "ls_type": ls_type,
        "ls_type_name": _lsa_type_name(version, ls_type),
        "link_state_id": link_state_id,
        "advertising_router": advertising_router,
        "sequence_number": f"0x{sequence:08x}",
        "checksum": f"0x{checksum:04x}",
        "length": length,
    }
    if options is not None:
        row["options"] = f"0x{options:02x}"
    else:
        row["u_bit"] = bool(ls_type & 0x8000)
        row["flooding_scope"] = (ls_type >> 13) & 0x3
        row["function_code"] = ls_type & 0x1FFF
    return row


def _parse_lsa_header_list(data: bytes, offset: int, version: int) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    while offset + 20 <= len(data) and len(rows) < _MAX_LSA_HEADERS:
        rows.append(_parse_lsa_header(data, offset, version))
        offset += 20
    truncated = offset != len(data)
    return rows, truncated


def _parse_hello(data: bytes, version: int, header_len: int) -> dict[str, Any]:
    body = header_len
    if version == 2:
        if len(data) < body + 20:
            raise ValueError("truncated OSPFv2 Hello body")
        network_mask = str(ipaddress.IPv4Address(data[body:body + 4]))
        hello_interval = struct.unpack_from("!H", data, body + 4)[0]
        options = data[body + 6]
        priority = data[body + 7]
        dead_interval = struct.unpack_from("!I", data, body + 8)[0]
        designated = _router_id(data[body + 12:body + 16])
        backup = _router_id(data[body + 16:body + 20])
        cursor = body + 20
        result: dict[str, Any] = {
            "network_mask": network_mask,
            "hello_interval_seconds": hello_interval,
            "options": f"0x{options:02x}",
            "router_priority": priority,
            "router_dead_interval_seconds": dead_interval,
            "designated_router": designated,
            "backup_designated_router": backup,
        }
    else:
        if len(data) < body + 20:
            raise ValueError("truncated OSPFv3 Hello body")
        interface_id = struct.unpack_from("!I", data, body)[0]
        priority = data[body + 4]
        options = int.from_bytes(data[body + 5:body + 8], "big")
        hello_interval, dead_interval = struct.unpack_from("!HH", data, body + 8)
        designated = _router_id(data[body + 12:body + 16])
        backup = _router_id(data[body + 16:body + 20])
        cursor = body + 20
        result = {
            "interface_id": interface_id,
            "router_priority": priority,
            "options": f"0x{options:06x}",
            "hello_interval_seconds": hello_interval,
            "router_dead_interval_seconds": dead_interval,
            "designated_router_id": designated,
            "backup_designated_router_id": backup,
        }
    neighbors: list[str] = []
    while cursor + 4 <= len(data) and len(neighbors) < _MAX_NEIGHBORS:
        neighbors.append(_router_id(data[cursor:cursor + 4]))
        cursor += 4
    result["neighbors"] = neighbors
    result["neighbor_count"] = len(neighbors)
    result["neighbors_truncated"] = cursor < len(data)
    return result


def _parse_database_description(data: bytes, version: int, header_len: int) -> dict[str, Any]:
    body = header_len
    if version == 2:
        if len(data) < body + 8:
            raise ValueError("truncated OSPFv2 Database Description body")
        mtu = struct.unpack_from("!H", data, body)[0]
        options = data[body + 2]
        flags = data[body + 3]
        sequence = struct.unpack_from("!I", data, body + 4)[0]
        cursor = body + 8
        options_text = f"0x{options:02x}"
    else:
        if len(data) < body + 12:
            raise ValueError("truncated OSPFv3 Database Description body")
        options = int.from_bytes(data[body + 1:body + 4], "big")
        mtu = struct.unpack_from("!H", data, body + 4)[0]
        flags = data[body + 7]
        sequence = struct.unpack_from("!I", data, body + 8)[0]
        cursor = body + 12
        options_text = f"0x{options:06x}"
    headers, truncated = _parse_lsa_header_list(data, cursor, version)
    return {
        "interface_mtu": mtu,
        "options": options_text,
        "flags": f"0x{flags:02x}",
        "init": bool(flags & 0x04),
        "more": bool(flags & 0x02),
        "master": bool(flags & 0x01),
        "dd_sequence_number": sequence,
        "lsa_header_count": len(headers),
        "lsa_headers": headers,
        "lsa_headers_truncated": truncated,
    }


def _parse_link_state_requests(data: bytes, version: int, header_len: int) -> dict[str, Any]:
    cursor = header_len
    requests: list[dict[str, Any]] = []
    while cursor + 12 <= len(data) and len(requests) < _MAX_LS_REQUESTS:
        if version == 2:
            ls_type = struct.unpack_from("!I", data, cursor)[0]
        else:
            ls_type = struct.unpack_from("!H", data, cursor + 2)[0]
        requests.append({
            "ls_type": ls_type,
            "ls_type_name": _lsa_type_name(version, ls_type),
            "link_state_id": _router_id(data[cursor + 4:cursor + 8]),
            "advertising_router": _router_id(data[cursor + 8:cursor + 12]),
        })
        cursor += 12
    return {
        "request_count": len(requests),
        "requests": requests,
        "requests_truncated": cursor != len(data),
    }


def _parse_link_state_update(data: bytes, version: int, header_len: int) -> dict[str, Any]:
    if len(data) < header_len + 4:
        raise ValueError("truncated OSPF Link State Update body")
    advertised_count = struct.unpack_from("!I", data, header_len)[0]
    cursor = header_len + 4
    lsas: list[dict[str, Any]] = []
    invalid_length = False
    while cursor + 20 <= len(data) and len(lsas) < min(advertised_count, _MAX_LSA_HEADERS):
        header = _parse_lsa_header(data, cursor, version)
        lsa_length = int(header["length"])
        if lsa_length < 20 or cursor + lsa_length > len(data):
            invalid_length = True
            break
        header["payload_bytes"] = lsa_length - 20
        packet_body = data[cursor + 20:cursor + lsa_length]
        try:
            decoded_body = decode_ospf_lsa_body(version, int(header["ls_type"]), packet_body)
        except ValueError as exc:
            header["body_malformed"] = True
            header["body_error"] = str(exc)[:256]
        else:
            if decoded_body is not None:
                header["body"] = decoded_body
                header["body_decoded"] = True
                if bool(decoded_body.get("body_malformed")):
                    header["body_malformed"] = True
            else:
                header["body_decoded"] = False
        lsas.append(header)
        cursor += lsa_length
    return {
        "advertised_lsa_count": advertised_count,
        "decoded_lsa_count": len(lsas),
        "lsas": lsas,
        "lsa_limit_reached": advertised_count > _MAX_LSA_HEADERS,
        "invalid_lsa_length": invalid_length,
        "trailing_bytes": max(0, len(data) - cursor),
    }


def decode_ospf_packet(data: bytes) -> dict[str, Any]:
    """Decode bounded OSPFv2/v3 control-plane structure without mutating state."""
    if len(data) < 16:
        raise ValueError("truncated OSPF header")
    version, packet_type, packet_length = struct.unpack_from("!BBH", data, 0)
    if version not in {2, 3}:
        raise ValueError(f"unsupported OSPF version: {version}")
    header_len = 24 if version == 2 else 16
    if len(data) < header_len:
        raise ValueError(f"truncated OSPFv{version} header")
    if packet_length < header_len:
        raise ValueError("invalid OSPF packet length")
    effective = min(packet_length, len(data))
    packet = data[:effective]
    result: dict[str, Any] = {
        "version": version,
        "packet_type": packet_type,
        "packet_type_name": _PACKET_NAMES.get(packet_type, "unknown"),
        "packet_length": packet_length,
        "captured_length": len(packet),
        "truncated": packet_length > len(data),
        "router_id": _router_id(packet[4:8]),
        "area_id": _router_id(packet[8:12]),
        "checksum": f"0x{struct.unpack_from('!H', packet, 12)[0]:04x}",
    }
    if version == 2:
        result["auth_type"] = struct.unpack_from("!H", packet, 14)[0]
        result["authentication_present"] = any(packet[16:24])
    else:
        result["instance_id"] = packet[14]
        result["reserved"] = packet[15]

    if effective < packet_length:
        return result
    try:
        if packet_type == 1:
            result.update(_parse_hello(packet, version, header_len))
        elif packet_type == 2:
            result.update(_parse_database_description(packet, version, header_len))
        elif packet_type == 3:
            result.update(_parse_link_state_requests(packet, version, header_len))
        elif packet_type == 4:
            result.update(_parse_link_state_update(packet, version, header_len))
        elif packet_type == 5:
            headers, truncated = _parse_lsa_header_list(packet, header_len, version)
            result.update({
                "lsa_header_count": len(headers),
                "lsa_headers": headers,
                "lsa_headers_truncated": truncated,
            })
    except ValueError as exc:
        # Preserve a structurally valid OSPF header even when the typed body is
        # truncated/malformed. Packet Intelligence can still correlate the
        # router/area/type while Expert reports the body evidence boundary.
        result["body_malformed"] = True
        result["body_error"] = str(exc)[:256]
    return result
