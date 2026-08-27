from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_MAX_ISIS_TLVS = 512
_MAX_LDP_MESSAGES = 256
_MAX_LDP_TLVS = 512

_ISIS_PDU_NAMES = {
    15: "l1-lan-hello",
    16: "l2-lan-hello",
    17: "point-to-point-hello",
    18: "l1-lsp",
    20: "l2-lsp",
    24: "l1-csnp",
    25: "l2-csnp",
    26: "l1-psnp",
    27: "l2-psnp",
}
_LDP_MESSAGE_NAMES = {
    0x0001: "notification",
    0x0100: "hello",
    0x0200: "initialization",
    0x0201: "keepalive",
    0x0300: "address",
    0x0301: "address-withdraw",
    0x0400: "label-mapping",
    0x0401: "label-request",
    0x0402: "label-withdraw",
    0x0403: "label-release",
    0x0404: "label-abort-request",
}
_LDP_TLV_NAMES = {
    0x0100: "fec",
    0x0101: "address-list",
    0x0200: "generic-label",
    0x0300: "status",
    0x0400: "common-hello-parameters",
    0x0401: "ipv4-transport-address",
    0x0402: "configuration-sequence-number",
    0x0500: "common-session-parameters",
    0x0501: "ipv4-transport-address-session",
}


def _system_id(raw: bytes) -> str:
    return ".".join(raw[index:index + 2].hex() for index in range(0, len(raw), 2))




def _prefix_from_bits(raw: bytes, prefix_length: int, *, version: int) -> str:
    width = 4 if version == 4 else 16
    if prefix_length < 0 or prefix_length > width * 8:
        raise ValueError("invalid prefix length")
    needed = (prefix_length + 7) // 8
    if len(raw) < needed:
        raise ValueError("truncated prefix")
    address = ipaddress.ip_address(raw[:needed] + b"\x00" * (width - needed))
    return str(ipaddress.ip_network(f"{address}/{prefix_length}", strict=False))


def _decode_isis_subtlvs(value: bytes) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    malformed = False
    while cursor + 2 <= len(value) and len(rows) < 128:
        sub_type, length = value[cursor], value[cursor + 1]
        cursor += 2
        if cursor + length > len(value):
            malformed = True
            break
        raw = value[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"type": sub_type, "length": length}
        if sub_type == 3 and length == 4:
            row.update({"name": "administrative-group", "value": f"0x{struct.unpack('!I', raw)[0]:08x}"})
        elif sub_type == 6 and length == 4:
            row.update({"name": "ipv4-interface-address", "address": str(ipaddress.IPv4Address(raw))})
        elif sub_type == 8 and length == 4:
            row.update({"name": "ipv4-neighbor-address", "address": str(ipaddress.IPv4Address(raw))})
        elif sub_type in {9, 10} and length == 4:
            row.update({
                "name": "maximum-link-bandwidth" if sub_type == 9 else "maximum-reservable-link-bandwidth",
                "bytes_per_second": float(struct.unpack("!f", raw)[0]),
            })
        elif sub_type == 11 and length == 32:
            row.update({
                "name": "unreserved-bandwidth",
                "bytes_per_second_by_priority": [float(value) for value in struct.unpack("!8f", raw)],
            })
        elif sub_type == 18 and length == 3:
            row.update({"name": "te-default-metric", "metric": int.from_bytes(raw, "big")})
        else:
            row.update({"name": "unknown", "value_sha256": hashlib.sha256(raw).hexdigest()})
        rows.append(row)
    if cursor != len(value):
        malformed = True
    return rows, malformed


def _decode_isis_extended_is_reachability(value: bytes) -> dict[str, Any]:
    cursor = 0
    neighbors: list[dict[str, Any]] = []
    malformed = False
    while cursor + 11 <= len(value) and len(neighbors) < 128:
        neighbor_id = _system_id(value[cursor:cursor + 7])
        metric = int.from_bytes(value[cursor + 7:cursor + 10], "big")
        sub_length = value[cursor + 10]
        cursor += 11
        if cursor + sub_length > len(value):
            malformed = True
            break
        subtlvs, sub_malformed = _decode_isis_subtlvs(value[cursor:cursor + sub_length])
        cursor += sub_length
        neighbors.append({
            "neighbor_id": neighbor_id,
            "metric": metric,
            "sub_tlv_bytes": sub_length,
            "sub_tlvs": subtlvs,
            "sub_tlvs_malformed": sub_malformed,
        })
        malformed = malformed or sub_malformed
    if cursor != len(value):
        malformed = True
    return {"neighbors": neighbors, "neighbor_count": len(neighbors), "malformed": malformed}


def _decode_isis_ipv4_reachability(value: bytes) -> dict[str, Any]:
    cursor = 0
    prefixes: list[dict[str, Any]] = []
    malformed = False
    while cursor + 5 <= len(value) and len(prefixes) < 256:
        metric = struct.unpack_from("!I", value, cursor)[0]
        control = value[cursor + 4]
        cursor += 5
        prefix_length = control & 0x3F
        needed = (prefix_length + 7) // 8
        if prefix_length > 32 or cursor + needed > len(value):
            malformed = True
            break
        prefix = _prefix_from_bits(value[cursor:cursor + needed], prefix_length, version=4)
        cursor += needed
        row: dict[str, Any] = {
            "prefix": prefix,
            "metric": metric,
            "up_down": bool(control & 0x80),
            "sub_tlvs_present": bool(control & 0x40),
        }
        if control & 0x40:
            if cursor >= len(value):
                malformed = True
                break
            sub_length = value[cursor]
            cursor += 1
            if cursor + sub_length > len(value):
                malformed = True
                break
            subtlvs, sub_malformed = _decode_isis_subtlvs(value[cursor:cursor + sub_length])
            cursor += sub_length
            row.update({"sub_tlv_bytes": sub_length, "sub_tlvs": subtlvs, "sub_tlvs_malformed": sub_malformed})
            malformed = malformed or sub_malformed
        prefixes.append(row)
    if cursor != len(value):
        malformed = True
    return {"prefixes": prefixes, "prefix_count": len(prefixes), "malformed": malformed}


def _decode_isis_ipv6_reachability(value: bytes) -> dict[str, Any]:
    cursor = 0
    prefixes: list[dict[str, Any]] = []
    malformed = False
    while cursor + 6 <= len(value) and len(prefixes) < 256:
        metric = struct.unpack_from("!I", value, cursor)[0]
        flags = value[cursor + 4]
        prefix_length = value[cursor + 5]
        cursor += 6
        needed = (prefix_length + 7) // 8
        if prefix_length > 128 or cursor + needed > len(value):
            malformed = True
            break
        prefix = _prefix_from_bits(value[cursor:cursor + needed], prefix_length, version=6)
        cursor += needed
        row: dict[str, Any] = {
            "prefix": prefix,
            "metric": metric,
            "up_down": bool(flags & 0x80),
            "external": bool(flags & 0x40),
            "sub_tlvs_present": bool(flags & 0x20),
            "reserved": flags & 0x1F,
        }
        if flags & 0x20:
            if cursor >= len(value):
                malformed = True
                break
            sub_length = value[cursor]
            cursor += 1
            if cursor + sub_length > len(value):
                malformed = True
                break
            subtlvs, sub_malformed = _decode_isis_subtlvs(value[cursor:cursor + sub_length])
            cursor += sub_length
            row.update({"sub_tlv_bytes": sub_length, "sub_tlvs": subtlvs, "sub_tlvs_malformed": sub_malformed})
            malformed = malformed or sub_malformed
        prefixes.append(row)
    if cursor != len(value):
        malformed = True
    return {"prefixes": prefixes, "prefix_count": len(prefixes), "malformed": malformed}


def _decode_ldp_fec(value: bytes) -> dict[str, Any]:
    cursor = 0
    elements: list[dict[str, Any]] = []
    malformed = False
    while cursor < len(value) and len(elements) < 256:
        element_type = value[cursor]
        cursor += 1
        if element_type == 1:
            elements.append({"type": 1, "type_name": "wildcard"})
            continue
        if element_type != 2:
            elements.append({
                "type": element_type,
                "type_name": "unknown",
                "remaining_bytes": len(value) - cursor,
                "remaining_sha256": hashlib.sha256(value[cursor:]).hexdigest(),
            })
            cursor = len(value)
            break
        if cursor + 3 > len(value):
            malformed = True
            break
        address_family = struct.unpack_from("!H", value, cursor)[0]
        prefix_length = value[cursor + 2]
        cursor += 3
        version = 4 if address_family == 1 else 6 if address_family == 2 else 0
        width = 32 if version == 4 else 128 if version == 6 else 0
        needed = (prefix_length + 7) // 8
        if not version or prefix_length > width or cursor + needed > len(value):
            malformed = True
            break
        prefix = _prefix_from_bits(value[cursor:cursor + needed], prefix_length, version=version)
        cursor += needed
        elements.append({
            "type": 2,
            "type_name": "prefix",
            "address_family": address_family,
            "address_family_name": "ipv4" if version == 4 else "ipv6",
            "prefix": prefix,
        })
    if cursor != len(value):
        malformed = True
    return {"elements": elements, "element_count": len(elements), "malformed": malformed}


def _decode_ldp_address_list(value: bytes) -> dict[str, Any]:
    if len(value) < 2:
        return {"malformed": True, "addresses": []}
    address_family = struct.unpack_from("!H", value, 0)[0]
    size = 4 if address_family == 1 else 16 if address_family == 2 else 0
    if not size or (len(value) - 2) % size:
        return {"address_family": address_family, "malformed": True, "addresses": []}
    addresses = [str(ipaddress.ip_address(value[pos:pos + size])) for pos in range(2, len(value), size)][:256]
    return {
        "address_family": address_family,
        "address_family_name": "ipv4" if address_family == 1 else "ipv6",
        "addresses": addresses,
        "malformed": False,
    }


def _decode_isis_tlvs(data: bytes, cursor: int) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    truncated = False
    while cursor + 2 <= len(data) and len(rows) < _MAX_ISIS_TLVS:
        tlv_type, length = data[cursor], data[cursor + 1]
        cursor += 2
        if cursor + length > len(data):
            truncated = True
            break
        value = data[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"type": tlv_type, "length": length}
        if tlv_type == 1:
            row["name"] = "area-addresses"
            areas: list[str] = []
            pos = 0
            while pos < len(value) and len(areas) < 64:
                area_len = value[pos]
                pos += 1
                if area_len == 0 or pos + area_len > len(value):
                    row["malformed"] = True
                    break
                areas.append(value[pos:pos + area_len].hex("."))
                pos += area_len
            row["areas"] = areas
        elif tlv_type == 129:
            row.update({"name": "protocols-supported", "nlpids": [f"0x{item:02x}" for item in value[:128]]})
        elif tlv_type == 132 and length % 4 == 0:
            row.update({"name": "ipv4-interface-addresses", "addresses": [str(ipaddress.IPv4Address(value[pos:pos + 4])) for pos in range(0, length, 4)][:128]})
        elif tlv_type == 137:
            row.update({"name": "dynamic-hostname", "hostname": value[:255].decode("utf-8", errors="replace")})
        elif tlv_type == 232 and length % 16 == 0:
            row.update({"name": "ipv6-interface-addresses", "addresses": [str(ipaddress.IPv6Address(value[pos:pos + 16])) for pos in range(0, length, 16)][:128]})
        elif tlv_type == 22:
            row.update({"name": "extended-is-reachability", **_decode_isis_extended_is_reachability(value)})
        elif tlv_type == 135:
            row.update({"name": "extended-ipv4-reachability", **_decode_isis_ipv4_reachability(value)})
        elif tlv_type == 236:
            row.update({"name": "ipv6-reachability", **_decode_isis_ipv6_reachability(value)})
        elif tlv_type == 242:
            row.update({"name": "router-capability", "value_sha256": hashlib.sha256(value).hexdigest()})
        else:
            row.update({"name": "unknown", "value_sha256": hashlib.sha256(value).hexdigest()})
        rows.append(row)
    if cursor != len(data):
        truncated = True
    return rows, truncated


def decode_isis_pdu(payload: bytes) -> dict[str, Any]:
    """Decode bounded IS-IS common/PDU headers and high-value TLVs after LLC."""
    if len(payload) < 8:
        raise ValueError("truncated IS-IS common header")
    discriminator, header_length, version_ext, id_length, pdu_type_raw, version, reserved, max_area = struct.unpack_from("!BBBBBBBB", payload, 0)
    if discriminator != 0x83:
        raise ValueError("invalid IS-IS intradomain routing discriminator")
    pdu_type = pdu_type_raw & 0x1F
    result: dict[str, Any] = {
        "intradomain_routing_protocol_discriminator": f"0x{discriminator:02x}",
        "header_length": header_length,
        "version_protocol_id_extension": version_ext,
        "system_id_length": 6 if id_length == 0 else id_length,
        "pdu_type": pdu_type,
        "pdu_type_name": _ISIS_PDU_NAMES.get(pdu_type, "unknown"),
        "version": version,
        "reserved": reserved,
        "maximum_area_addresses": max_area,
    }
    cursor = 8
    if pdu_type in {15, 16}:
        if len(payload) < 27:
            raise ValueError("truncated IS-IS LAN Hello")
        circuit_type = payload[cursor]
        source_id = _system_id(payload[cursor + 1:cursor + 7])
        holding, pdu_length = struct.unpack_from("!HH", payload, cursor + 7)
        priority = payload[cursor + 11]
        designated = _system_id(payload[cursor + 12:cursor + 19])
        result.update({
            "circuit_type": circuit_type,
            "source_id": source_id,
            "holding_timer_seconds": holding,
            "pdu_length": pdu_length,
            "priority": priority,
            "designated_is": designated,
        })
        cursor += 19
    elif pdu_type == 17:
        if len(payload) < 20:
            raise ValueError("truncated IS-IS point-to-point Hello")
        circuit_type = payload[cursor]
        source_id = _system_id(payload[cursor + 1:cursor + 7])
        holding, pdu_length = struct.unpack_from("!HH", payload, cursor + 7)
        local_circuit_id = payload[cursor + 11]
        result.update({
            "circuit_type": circuit_type,
            "source_id": source_id,
            "holding_timer_seconds": holding,
            "pdu_length": pdu_length,
            "local_circuit_id": local_circuit_id,
        })
        cursor += 12
    elif pdu_type in {18, 20}:
        if len(payload) < 27:
            raise ValueError("truncated IS-IS LSP")
        pdu_length, remaining_lifetime = struct.unpack_from("!HH", payload, cursor)
        lsp_id = _system_id(payload[cursor + 4:cursor + 12])
        sequence, checksum = struct.unpack_from("!IH", payload, cursor + 12)
        type_block = payload[cursor + 18]
        result.update({
            "pdu_length": pdu_length,
            "remaining_lifetime_seconds": remaining_lifetime,
            "lsp_id": lsp_id,
            "sequence_number": f"0x{sequence:08x}",
            "checksum": f"0x{checksum:04x}",
            "type_block": f"0x{type_block:02x}",
        })
        cursor += 19
    elif pdu_type in {24, 25}:
        if len(payload) < 33:
            raise ValueError("truncated IS-IS CSNP")
        pdu_length = struct.unpack_from("!H", payload, cursor)[0]
        source_id = _system_id(payload[cursor + 2:cursor + 9])
        result.update({
            "pdu_length": pdu_length,
            "source_id": source_id,
            "start_lsp_id": _system_id(payload[cursor + 9:cursor + 17]),
            "end_lsp_id": _system_id(payload[cursor + 17:cursor + 25]),
        })
        cursor += 25
    elif pdu_type in {26, 27}:
        if len(payload) < 17:
            raise ValueError("truncated IS-IS PSNP")
        pdu_length = struct.unpack_from("!H", payload, cursor)[0]
        result.update({"pdu_length": pdu_length, "source_id": _system_id(payload[cursor + 2:cursor + 9])})
        cursor += 9
    if header_length >= 8 and header_length <= len(payload):
        cursor = max(cursor, header_length)
    tlvs, truncated = _decode_isis_tlvs(payload, cursor)
    result["tlvs"] = tlvs
    result["tlv_count"] = len(tlvs)
    result["tlvs_truncated"] = truncated
    return result


def _decode_ldp_tlvs(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 4 <= len(data) and len(rows) < _MAX_LDP_TLVS:
        raw_type, length = struct.unpack_from("!HH", data, cursor)
        cursor += 4
        if cursor + length > len(data):
            rows.append({"type": raw_type & 0x3FFF, "length": length, "malformed": True})
            break
        value = data[cursor:cursor + length]
        cursor += length
        tlv_type = raw_type & 0x3FFF
        row: dict[str, Any] = {
            "type": tlv_type,
            "name": _LDP_TLV_NAMES.get(tlv_type, "unknown"),
            "length": length,
            "unknown_tlv_bit": bool(raw_type & 0x8000),
            "forward_unknown_bit": bool(raw_type & 0x4000),
        }
        if tlv_type == 0x0100:
            row.update(_decode_ldp_fec(value))
        elif tlv_type == 0x0101:
            row.update(_decode_ldp_address_list(value))
        elif tlv_type == 0x0200 and length == 4:
            row["label"] = struct.unpack("!I", value)[0] & 0x000FFFFF
        elif tlv_type in {0x0401, 0x0501} and length == 4:
            row["address"] = str(ipaddress.IPv4Address(value))
        elif tlv_type == 0x0402 and length == 4:
            row["configuration_sequence_number"] = struct.unpack("!I", value)[0]
        elif tlv_type == 0x0400 and length >= 4:
            hold_time, flags = struct.unpack_from("!HH", value, 0)
            row.update({"hold_time_seconds": hold_time, "targeted_hello": bool(flags & 0x8000), "request_targeted_hello": bool(flags & 0x4000)})
        elif tlv_type == 0x0500 and length >= 14:
            version, keepalive, flags, path_vector_limit = struct.unpack_from("!HHBB", value, 0)
            row.update({
                "protocol_version": version,
                "keepalive_time_seconds": keepalive,
                "downstream_on_demand": bool(flags & 0x80),
                "loop_detection": bool(flags & 0x40),
                "path_vector_limit": path_vector_limit,
            })
        elif value:
            row["value_sha256"] = hashlib.sha256(value).hexdigest()
        rows.append(row)
    return rows


def decode_ldp_pdu(payload: bytes) -> dict[str, Any]:
    """Decode bounded MPLS LDP PDU/messages and selected operational TLVs."""
    if len(payload) < 10:
        raise ValueError("truncated LDP PDU header")
    version, pdu_length = struct.unpack_from("!HH", payload, 0)
    total_length = pdu_length + 4
    if version != 1 or pdu_length < 6 or total_length > len(payload):
        raise ValueError("invalid LDP PDU header")
    lsr_id = str(ipaddress.IPv4Address(payload[4:8]))
    label_space = struct.unpack_from("!H", payload, 8)[0]
    cursor = 10
    messages: list[dict[str, Any]] = []
    while cursor + 8 <= total_length and len(messages) < _MAX_LDP_MESSAGES:
        raw_type, message_length, message_id = struct.unpack_from("!HHI", payload, cursor)
        message_total = message_length + 4
        if message_length < 4 or cursor + message_total > total_length:
            messages.append({"type": raw_type & 0x7FFF, "message_id": message_id, "malformed": True})
            break
        message_type = raw_type & 0x7FFF
        value = payload[cursor + 8:cursor + message_total]
        messages.append({
            "type": message_type,
            "type_name": _LDP_MESSAGE_NAMES.get(message_type, "unknown"),
            "unknown_message_bit": bool(raw_type & 0x8000),
            "message_id": message_id,
            "length": message_length,
            "tlvs": _decode_ldp_tlvs(value),
        })
        cursor += message_total
    return {
        "version": version,
        "pdu_length": pdu_length,
        "lsr_id": lsr_id,
        "label_space_id": label_space,
        "message_count": len(messages),
        "messages": messages,
        "messages_truncated": cursor != total_length,
    }
