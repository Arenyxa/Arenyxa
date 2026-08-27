from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_PFCP_MESSAGES = {
    1: "heartbeat-request",
    2: "heartbeat-response",
    3: "pfd-management-request",
    4: "pfd-management-response",
    5: "association-setup-request",
    6: "association-setup-response",
    7: "association-update-request",
    8: "association-update-response",
    9: "association-release-request",
    10: "association-release-response",
    11: "version-not-supported-response",
    12: "node-report-request",
    13: "node-report-response",
    14: "session-set-deletion-request",
    15: "session-set-deletion-response",
    16: "session-set-modification-request",
    17: "session-set-modification-response",
    50: "session-establishment-request",
    51: "session-establishment-response",
    52: "session-modification-request",
    53: "session-modification-response",
    54: "session-deletion-request",
    55: "session-deletion-response",
    56: "session-report-request",
    57: "session-report-response",
}

_PFCP_IE_NAMES = {
    1: "create-pdr",
    2: "pdi",
    3: "create-far",
    4: "forwarding-parameters",
    5: "duplicating-parameters",
    6: "create-urr",
    7: "create-qer",
    8: "created-pdr",
    9: "update-pdr",
    10: "update-far",
    11: "update-forwarding-parameters",
    12: "update-bar-pfcp-session-report-response",
    13: "update-urr",
    14: "update-qer",
    15: "remove-pdr",
    16: "remove-far",
    17: "remove-urr",
    18: "remove-qer",
    19: "cause",
    20: "source-interface",
    21: "f-teid",
    22: "network-instance",
    23: "sdf-filter",
    24: "application-id",
    25: "gate-status",
    40: "offending-ie",
    52: "sequence-number",
    53: "metric",
    55: "timer",
    56: "pdr-id",
    57: "f-seid",
    60: "node-id",
    108: "far-id",
    109: "qer-id",
    124: "qfi",
}

_PFCP_GROUPED_IES = frozenset(range(1, 19))
_PFCP_MAX_IES = 1024
_PFCP_MAX_GROUP_DEPTH = 3

_DIAMETER_COMMANDS = {
    257: "capabilities-exchange",
    258: "re-auth",
    271: "accounting",
    274: "abort-session",
    275: "session-termination",
    280: "device-watchdog",
    282: "disconnect-peer",
}

_DIAMETER_AVP_NAMES = {
    1: "user-name",
    257: "host-ip-address",
    258: "auth-application-id",
    259: "acct-application-id",
    260: "vendor-specific-application-id",
    263: "session-id",
    264: "origin-host",
    265: "supported-vendor-id",
    266: "vendor-id",
    267: "firmware-revision",
    268: "result-code",
    269: "product-name",
    273: "disconnect-cause",
    277: "auth-session-state",
    278: "origin-state-id",
    279: "failed-avp",
    280: "proxy-host",
    282: "route-record",
    283: "destination-realm",
    293: "destination-host",
    294: "error-reporting-host",
    296: "origin-realm",
    297: "experimental-result",
    298: "experimental-result-code",
}

_DIAMETER_GROUPED_AVPS = {260, 279, 297}
_DIAMETER_UNSIGNED32_AVPS = {258, 259, 265, 266, 267, 268, 273, 277, 278, 298}
_DIAMETER_UTF8_AVPS = {264, 269, 280, 282, 283, 293, 294, 296}
_DIAMETER_SENSITIVE_AVPS = {1: "user-name", 263: "session-id"}
_DIAMETER_MAX_AVPS = 1024
_DIAMETER_MAX_GROUP_DEPTH = 3


def _digest(namespace: str, value: bytes) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\x00" + value).hexdigest()


def _opaque(value: bytes, *, namespace: str) -> dict[str, Any]:
    return {
        "value_bytes": len(value),
        "value_sha256": _digest(namespace, value),
        "value_retained": False,
    }


def _dns_labels(value: bytes) -> tuple[str, bool]:
    labels: list[str] = []
    cursor = 0
    malformed = False
    while cursor < len(value) and len(labels) < 64:
        size = value[cursor]
        cursor += 1
        if size == 0 or size > 63 or cursor + size > len(value):
            malformed = True
            break
        label = value[cursor:cursor + size]
        if any(byte < 0x21 or byte > 0x7E for byte in label):
            malformed = True
            break
        labels.append(label.decode("ascii", errors="replace"))
        cursor += size
    if cursor != len(value):
        malformed = True
    return ".".join(labels), malformed


def _decode_pfcp_fteid(value: bytes) -> dict[str, Any]:
    if not value:
        raise ValueError("truncated PFCP F-TEID")
    flags = value[0]
    v4 = bool(flags & 0x01)
    v6 = bool(flags & 0x02)
    choose = bool(flags & 0x04)
    choose_id_present = bool(flags & 0x08)
    cursor = 1
    row: dict[str, Any] = {
        "ipv4_present": v4,
        "ipv6_present": v6,
        "choose": choose,
        "choose_id_present": choose_id_present,
        "spare_bits": flags & 0xF0,
    }
    if not (v4 or v6):
        row["address_family_missing"] = True
    if not choose:
        if cursor + 4 > len(value):
            raise ValueError("truncated PFCP F-TEID TEID")
        row["teid"] = struct.unpack_from("!I", value, cursor)[0]
        cursor += 4
        if v4:
            if cursor + 4 > len(value):
                raise ValueError("truncated PFCP F-TEID IPv4 address")
            row["ipv4"] = str(ipaddress.IPv4Address(value[cursor:cursor + 4]))
            cursor += 4
        if v6:
            if cursor + 16 > len(value):
                raise ValueError("truncated PFCP F-TEID IPv6 address")
            row["ipv6"] = str(ipaddress.IPv6Address(value[cursor:cursor + 16]))
            cursor += 16
    if choose_id_present:
        if not choose:
            row["choose_id_without_choose"] = True
        if cursor >= len(value):
            raise ValueError("truncated PFCP F-TEID CHOOSE ID")
        row["choose_id"] = value[cursor]
        cursor += 1
    if cursor != len(value):
        row["trailing_bytes"] = len(value) - cursor
        row["trailing_sha256"] = _digest("arenyxa-pfcp-fteid-trailing/v1", value[cursor:])
        row["trailing_retained"] = False
    return row


def _decode_pfcp_fseid(value: bytes) -> dict[str, Any]:
    if len(value) < 9:
        raise ValueError("truncated PFCP F-SEID")
    flags = value[0]
    v6 = bool(flags & 0x01)
    v4 = bool(flags & 0x02)
    row: dict[str, Any] = {
        "ipv4_present": v4,
        "ipv6_present": v6,
        "spare_bits": flags & 0xFC,
        "seid": struct.unpack_from("!Q", value, 1)[0],
    }
    cursor = 9
    if v4:
        if cursor + 4 > len(value):
            raise ValueError("truncated PFCP F-SEID IPv4 address")
        row["ipv4"] = str(ipaddress.IPv4Address(value[cursor:cursor + 4]))
        cursor += 4
    if v6:
        if cursor + 16 > len(value):
            raise ValueError("truncated PFCP F-SEID IPv6 address")
        row["ipv6"] = str(ipaddress.IPv6Address(value[cursor:cursor + 16]))
        cursor += 16
    if cursor != len(value):
        row["trailing_bytes"] = len(value) - cursor
        row["trailing_sha256"] = _digest("arenyxa-pfcp-fseid-trailing/v1", value[cursor:])
        row["trailing_retained"] = False
    return row


def _decode_pfcp_node_id(value: bytes) -> dict[str, Any]:
    if len(value) < 2:
        raise ValueError("truncated PFCP Node ID")
    node_type = value[0] & 0x0F
    spare = value[0] & 0xF0
    body = value[1:]
    row: dict[str, Any] = {"node_id_type": node_type, "spare_bits": spare}
    if node_type == 0:
        if len(body) != 4:
            raise ValueError("invalid PFCP IPv4 Node ID length")
        row.update({"node_id_kind": "ipv4", "node_id": str(ipaddress.IPv4Address(body))})
    elif node_type == 1:
        if len(body) != 16:
            raise ValueError("invalid PFCP IPv6 Node ID length")
        row.update({"node_id_kind": "ipv6", "node_id": str(ipaddress.IPv6Address(body))})
    elif node_type == 2:
        fqdn, malformed = _dns_labels(body)
        row.update({"node_id_kind": "fqdn", "node_id": fqdn, "fqdn_malformed": malformed})
    else:
        row.update({"node_id_kind": "reserved", **_opaque(body, namespace="arenyxa-pfcp-node-id/v1")})
    return row


def _decode_pfcp_ie(ie_type: int, value: bytes, *, depth: int) -> dict[str, Any]:
    if ie_type in _PFCP_GROUPED_IES and depth < _PFCP_MAX_GROUP_DEPTH:
        children, malformed = _parse_pfcp_ies(value, 0, len(value), depth=depth + 1)
        return {"grouped": True, "children": children, "child_count": len(children), "children_malformed": malformed}
    if ie_type == 19 and value:
        cause = value[0]
        return {"cause": cause, "request_accepted": 1 <= cause < 64}
    if ie_type == 20 and value:
        return {"source_interface": value[0] & 0x0F, "spare_bits": value[0] & 0xF0}
    if ie_type == 21:
        return _decode_pfcp_fteid(value)
    if ie_type == 22:
        network_instance, malformed = _dns_labels(value)
        return {"network_instance": network_instance, "network_instance_malformed": malformed}
    if ie_type == 40 and len(value) >= 2:
        return {"offending_ie_type": struct.unpack_from("!H", value, 0)[0]}
    if ie_type == 52 and len(value) >= 4:
        return {"sequence_number_ie": struct.unpack_from("!I", value, 0)[0]}
    if ie_type == 53 and value:
        return {"metric": value[0], "metric_out_of_range": value[0] > 100}
    if ie_type == 55 and value:
        return {"timer_unit": (value[0] >> 5) & 0x07, "timer_value": value[0] & 0x1F}
    if ie_type == 56 and len(value) >= 2:
        return {"pdr_id": struct.unpack_from("!H", value, 0)[0]}
    if ie_type == 57:
        return _decode_pfcp_fseid(value)
    if ie_type == 60:
        return _decode_pfcp_node_id(value)
    if ie_type in {108, 109} and len(value) >= 4:
        return {"rule_id": struct.unpack_from("!I", value, 0)[0], "predefined": bool(value[0] & 0x80)}
    if ie_type == 124 and value:
        return {"qfi": value[0] & 0x3F, "spare_bits": value[0] & 0xC0}
    return _opaque(value, namespace=f"arenyxa-pfcp-ie-{ie_type}/v1")


def _parse_pfcp_ies(data: bytes, start: int, end: int, *, depth: int = 0) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = start
    malformed = False
    while cursor < end and len(rows) < _PFCP_MAX_IES:
        if cursor + 4 > end:
            malformed = True
            break
        ie_type, length = struct.unpack_from("!HH", data, cursor)
        cursor += 4
        if cursor + length > end:
            malformed = True
            break
        value = data[cursor:cursor + length]
        row: dict[str, Any] = {"type": ie_type, "name": _PFCP_IE_NAMES.get(ie_type, f"ie-{ie_type}"), "length": length}
        if ie_type >= 32768:
            if len(value) < 2:
                row.update({"malformed": True, **_opaque(value, namespace="arenyxa-pfcp-vendor-ie-malformed/v1")})
                malformed = True
            else:
                row.update({
                    "vendor_specific": True,
                    "enterprise_id": struct.unpack_from("!H", value, 0)[0],
                    **_opaque(value[2:], namespace="arenyxa-pfcp-vendor-ie/v1"),
                })
        else:
            try:
                row.update(_decode_pfcp_ie(ie_type, value, depth=depth))
            except (ValueError, ipaddress.AddressValueError) as exc:
                row.update({"malformed": True, "parse_error": str(exc), **_opaque(value, namespace=f"arenyxa-pfcp-ie-{ie_type}-malformed/v1")})
                malformed = True
        rows.append(row)
        cursor += length
    if cursor != end:
        malformed = True
    return rows, malformed


def decode_pfcp_packet(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 8:
        raise ValueError("truncated PFCP header")
    flags = raw[0]
    version = (flags >> 5) & 0x07
    message_type = raw[1]
    message_length = struct.unpack_from("!H", raw, 2)[0]
    total = message_length + 4
    if total < 8 or total > len(raw):
        raise ValueError("invalid PFCP declared length")
    seid_present = bool(flags & 0x01)
    message_priority_present = bool(flags & 0x02)
    follow_on = bool(flags & 0x04)
    cursor = 4
    seid: int | None = None
    if seid_present:
        if cursor + 8 > total:
            raise ValueError("truncated PFCP SEID")
        seid = struct.unpack_from("!Q", raw, cursor)[0]
        cursor += 8
    if cursor + 4 > total:
        raise ValueError("truncated PFCP sequence header")
    sequence_number = int.from_bytes(raw[cursor:cursor + 3], "big")
    priority_spare = raw[cursor + 3]
    cursor += 4
    ies, malformed = _parse_pfcp_ies(raw, cursor, total)
    return {
        "version": version,
        "message_type": message_type,
        "message_name": _PFCP_MESSAGES.get(message_type, f"message-{message_type}"),
        "message_length": message_length,
        "decoded_length": total,
        "seid_present": seid_present,
        "seid": seid,
        "sequence_number": sequence_number,
        "message_priority_present": message_priority_present,
        "message_priority": ((priority_spare >> 4) & 0x0F) if message_priority_present else None,
        "sequence_spare": priority_spare & 0x0F,
        "follow_on": follow_on,
        "spare_flag_bits": flags & 0x18,
        "information_elements": ies,
        "information_element_count": len(ies),
        "information_elements_malformed": malformed,
        "subscriber_identity_values_retained": False,
    }


def _decode_diameter_address(value: bytes) -> dict[str, Any]:
    if len(value) < 2:
        raise ValueError("truncated Diameter Address")
    family = struct.unpack_from("!H", value, 0)[0]
    body = value[2:]
    if family == 1 and len(body) == 4:
        return {"address_family": "ipv4", "address": str(ipaddress.IPv4Address(body))}
    if family == 2 and len(body) == 16:
        return {"address_family": "ipv6", "address": str(ipaddress.IPv6Address(body))}
    return {"address_family_code": family, **_opaque(body, namespace="arenyxa-diameter-address/v1")}


def _decode_diameter_avp(code: int, value: bytes, *, depth: int) -> dict[str, Any]:
    sensitive = _DIAMETER_SENSITIVE_AVPS.get(code)
    if sensitive:
        return {
            f"{sensitive.replace('-', '_')}_bytes": len(value),
            f"{sensitive.replace('-', '_')}_sha256": _digest(f"arenyxa-diameter-{sensitive}/v1", value),
            f"{sensitive.replace('-', '_')}_retained": False,
        }
    if code == 257:
        return _decode_diameter_address(value)
    if code in _DIAMETER_UNSIGNED32_AVPS and len(value) == 4:
        return {"unsigned32": struct.unpack_from("!I", value, 0)[0]}
    if code in _DIAMETER_UTF8_AVPS:
        text = value.decode("utf-8", errors="replace")
        return {"text": text[:1024], "text_truncated": len(text) > 1024}
    if code in _DIAMETER_GROUPED_AVPS and depth < _DIAMETER_MAX_GROUP_DEPTH:
        children, malformed = _parse_diameter_avps(value, 0, len(value), depth=depth + 1)
        return {"grouped": True, "children": children, "child_count": len(children), "children_malformed": malformed}
    return _opaque(value, namespace=f"arenyxa-diameter-avp-{code}/v1")


def _parse_diameter_avps(data: bytes, start: int, end: int, *, depth: int = 0) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = start
    malformed = False
    while cursor < end and len(rows) < _DIAMETER_MAX_AVPS:
        if cursor + 8 > end:
            malformed = True
            break
        code = struct.unpack_from("!I", data, cursor)[0]
        flags = data[cursor + 4]
        length = int.from_bytes(data[cursor + 5:cursor + 8], "big")
        header_length = 12 if flags & 0x80 else 8
        if length < header_length or cursor + length > end:
            malformed = True
            break
        vendor_id = struct.unpack_from("!I", data, cursor + 8)[0] if flags & 0x80 else None
        value_start = cursor + header_length
        value = data[value_start:cursor + length]
        row: dict[str, Any] = {
            "code": code,
            "name": _DIAMETER_AVP_NAMES.get(code, f"avp-{code}"),
            "length": length,
            "vendor_specific": bool(flags & 0x80),
            "mandatory": bool(flags & 0x40),
            "protected": bool(flags & 0x20),
            "reserved_flag_bits": flags & 0x1F,
            "vendor_id": vendor_id,
        }
        try:
            row.update(_decode_diameter_avp(code, value, depth=depth))
        except (ValueError, ipaddress.AddressValueError) as exc:
            row.update({"malformed": True, "parse_error": str(exc), **_opaque(value, namespace=f"arenyxa-diameter-avp-{code}-malformed/v1")})
            malformed = True
        rows.append(row)
        padded = (length + 3) & ~3
        if cursor + padded > end:
            malformed = True
            break
        cursor += padded
    if cursor != end:
        malformed = True
    return rows, malformed


def decode_diameter_message(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 20:
        raise ValueError("truncated Diameter header")
    version = raw[0]
    message_length = int.from_bytes(raw[1:4], "big")
    if message_length < 20 or message_length > len(raw):
        raise ValueError("invalid Diameter message length")
    flags = raw[4]
    command_code = int.from_bytes(raw[5:8], "big")
    application_id, hop_by_hop, end_to_end = struct.unpack_from("!III", raw, 8)
    avps, malformed = _parse_diameter_avps(raw, 20, message_length)
    request = bool(flags & 0x80)
    command = _DIAMETER_COMMANDS.get(command_code, f"command-{command_code}")
    return {
        "version": version,
        "message_length": message_length,
        "decoded_length": message_length,
        "request": request,
        "proxiable": bool(flags & 0x40),
        "error": bool(flags & 0x20),
        "potential_retransmission": bool(flags & 0x10),
        "reserved_flag_bits": flags & 0x0F,
        "command_code": command_code,
        "command_name": f"{command}-{'request' if request else 'answer'}",
        "application_id": application_id,
        "hop_by_hop_id": hop_by_hop,
        "end_to_end_id": end_to_end,
        "avps": avps,
        "avp_count": len(avps),
        "avps_malformed": malformed,
        "identity_values_retained": False,
    }
