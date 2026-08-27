from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any

from arenyxa.infrastructure.capture.protocol_gtpu_extensions import decode_gtpu_extension


_GTPV1_MESSAGES = {
    1: "echo-request",
    2: "echo-response",
    3: "version-not-supported",
    16: "create-pdp-context-request",
    17: "create-pdp-context-response",
    18: "update-pdp-context-request",
    19: "update-pdp-context-response",
    20: "delete-pdp-context-request",
    21: "delete-pdp-context-response",
    26: "error-indication",
    31: "supported-extension-headers-notification",
    254: "end-marker",
    255: "g-pdu",
}

_GTPV2_MESSAGES = {
    1: "echo-request",
    2: "echo-response",
    3: "version-not-supported",
    32: "create-session-request",
    33: "create-session-response",
    34: "modify-bearer-request",
    35: "modify-bearer-response",
    36: "delete-session-request",
    37: "delete-session-response",
    38: "change-notification-request",
    39: "change-notification-response",
    40: "remote-ue-report-notification",
    41: "remote-ue-report-acknowledge",
    64: "modify-bearer-command",
    65: "modify-bearer-failure-indication",
    66: "delete-bearer-command",
    67: "delete-bearer-failure-indication",
    68: "bearer-resource-command",
    69: "bearer-resource-failure-indication",
    70: "downlink-data-notification-failure-indication",
    71: "trace-session-activation",
    72: "trace-session-deactivation",
    73: "stop-paging-indication",
    95: "create-bearer-request",
    96: "create-bearer-response",
    97: "update-bearer-request",
    98: "update-bearer-response",
    99: "delete-bearer-request",
    100: "delete-bearer-response",
    170: "release-access-bearers-request",
    171: "release-access-bearers-response",
    176: "downlink-data-notification",
    177: "downlink-data-notification-acknowledge",
}

_GTPV2_IE_NAMES = {
    1: "imsi",
    2: "cause",
    71: "apn",
    72: "ambr",
    73: "eps-bearer-id",
    74: "ip-address",
    75: "mei",
    76: "msisdn",
    77: "indication",
    78: "protocol-configuration-options",
    79: "paa",
    80: "bearer-qos",
    82: "rat-type",
    83: "serving-network",
    86: "user-location-information",
    87: "f-teid",
    93: "bearer-context",
    94: "charging-id",
    95: "charging-characteristics",
    99: "pdn-type",
    100: "procedure-transaction-id",
    126: "port-number",
    127: "apn-restriction",
    128: "selection-mode",
    136: "fqdn",
}

_RAT_TYPES = {
    1: "utran",
    2: "geran",
    3: "wlan",
    4: "gan",
    5: "hspa-evolution",
    6: "eutran",
    7: "virtual",
    8: "eutran-nb-iot",
    9: "lte-m",
    10: "nr",
}

_SENSITIVE_IDENTIFIERS = {1: "imsi", 75: "mei", 76: "msisdn"}

_GTPV2_GROUPED_IES = {93}
_GTPV2_MAX_GROUP_DEPTH = 3


def _hash(label: bytes, value: bytes) -> str:
    return hashlib.sha256(label + b"\x00" + value).hexdigest()


def _opaque(value: bytes, *, label: str) -> dict[str, Any]:
    return {
        f"{label}_bytes": len(value),
        f"{label}_sha256": _hash(f"arenyxa-gtp-{label}/v1".encode(), value),
        f"{label}_retained": False,
    }


def _decode_apn(value: bytes) -> tuple[str, bool]:
    labels: list[str] = []
    cursor = 0
    malformed = False
    while cursor < len(value) and len(labels) < 32:
        size = value[cursor]
        cursor += 1
        if not size or cursor + size > len(value):
            malformed = True
            break
        labels.append(value[cursor:cursor + size].decode("ascii", errors="replace"))
        cursor += size
    if cursor != len(value):
        malformed = True
    return ".".join(labels), malformed


def _decode_fteid(value: bytes) -> dict[str, Any]:
    if len(value) < 5:
        raise ValueError("truncated GTPv2 F-TEID")
    flags_interface = value[0]
    ipv4_present = bool(flags_interface & 0x80)
    ipv6_present = bool(flags_interface & 0x40)
    cursor = 5
    row: dict[str, Any] = {
        "ipv4_present": ipv4_present,
        "ipv6_present": ipv6_present,
        "interface_type": flags_interface & 0x3F,
        "teid": struct.unpack_from("!I", value, 1)[0],
    }
    if ipv4_present:
        if cursor + 4 > len(value):
            raise ValueError("truncated GTPv2 F-TEID IPv4 address")
        row["ipv4"] = str(ipaddress.IPv4Address(value[cursor:cursor + 4]))
        cursor += 4
    if ipv6_present:
        if cursor + 16 > len(value):
            raise ValueError("truncated GTPv2 F-TEID IPv6 address")
        row["ipv6"] = str(ipaddress.IPv6Address(value[cursor:cursor + 16]))
        cursor += 16
    if cursor != len(value):
        row.update(_opaque(value[cursor:], label="fteid-trailing"))
    return row


def _decode_gtpv2_ie(ie_type: int, value: bytes, *, depth: int) -> dict[str, Any]:
    if ie_type in _GTPV2_GROUPED_IES and depth < _GTPV2_MAX_GROUP_DEPTH:
        children, malformed = _gtpv2_ies(value, 0, len(value), depth=depth + 1)
        return {"grouped": True, "children": children, "child_count": len(children), "children_malformed": malformed}
    if ie_type in _SENSITIVE_IDENTIFIERS:
        label = _SENSITIVE_IDENTIFIERS[ie_type]
        return _opaque(value, label=label)
    if ie_type == 2 and value:
        cause = value[0]
        return {
            "cause": cause,
            "response_accepted": cause in {16, 17, 18, 19},
            "cause_flags": value[1] if len(value) > 1 else 0,
        }
    if ie_type == 3 and value:
        return {"restart_counter": value[0]}
    if ie_type == 71:
        apn, malformed = _decode_apn(value)
        return {"apn": apn, "apn_malformed": malformed}
    if ie_type == 72 and len(value) >= 8:
        uplink, downlink = struct.unpack_from("!II", value, 0)
        return {"ambr_uplink_kbps": uplink, "ambr_downlink_kbps": downlink}
    if ie_type == 73 and value:
        return {"eps_bearer_id": value[0] & 0x0F, "spare_bits": value[0] & 0xF0}
    if ie_type == 74 and len(value) in {4, 16}:
        return {"address": str(ipaddress.ip_address(value))}
    if ie_type == 82 and value:
        rat = value[0]
        return {"rat_type": rat, "rat_name": _RAT_TYPES.get(rat, f"rat-{rat}")}
    if ie_type == 87:
        return _decode_fteid(value)
    if ie_type == 94 and len(value) >= 4:
        return {"charging_id": struct.unpack_from("!I", value, 0)[0]}
    if ie_type == 99 and value:
        pdn = value[0] & 0x07
        return {"pdn_type": pdn, "pdn_type_name": {1: "ipv4", 2: "ipv6", 3: "ipv4v6", 4: "non-ip", 5: "ethernet"}.get(pdn, f"pdn-{pdn}")}
    if ie_type == 126 and len(value) >= 2:
        return {"port_number": struct.unpack_from("!H", value, 0)[0]}
    if ie_type == 136:
        fqdn, malformed = _decode_apn(value)
        return {"fqdn": fqdn, "fqdn_malformed": malformed}
    if ie_type == 254:
        if len(value) < 2:
            raise ValueError("truncated GTPv2 extended IE")
        extension_type = struct.unpack_from("!H", value, 0)[0]
        return {"ie_type_extension": extension_type, **_opaque(value[2:], label=f"extended-ie-{extension_type}-value")}
    return _opaque(value, label=f"ie-{ie_type}-value")


def _gtpv2_ies(data: bytes, start: int, end: int, *, depth: int = 0) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = start
    malformed = False
    while cursor < end and len(rows) < 512:
        if cursor + 4 > end:
            malformed = True
            break
        ie_type, length = struct.unpack_from("!BH", data, cursor)
        instance_octet = data[cursor + 3]
        cursor += 4
        if cursor + length > end:
            malformed = True
            break
        value = data[cursor:cursor + length]
        row: dict[str, Any] = {
            "type": ie_type,
            "name": _GTPV2_IE_NAMES.get(ie_type, f"ie-{ie_type}"),
            "length": length,
            "instance": instance_octet & 0x0F,
            "spare_bits": instance_octet & 0xF0,
        }
        try:
            row.update(_decode_gtpv2_ie(ie_type, value, depth=depth))
        except (ValueError, ipaddress.AddressValueError) as exc:
            row.update({"malformed": True, "parse_error": str(exc), **_opaque(value, label=f"ie-{ie_type}-malformed")})
            malformed = True
        rows.append(row)
        cursor += length
    if cursor != end:
        malformed = True
    return rows, malformed


def _gtpv1_extensions(data: bytes, cursor: int, end: int, next_type: int) -> tuple[list[dict[str, Any]], int, bool]:
    rows: list[dict[str, Any]] = []
    malformed = False
    current = next_type
    while current and cursor < end and len(rows) < 64:
        if cursor + 2 > end:
            malformed = True
            break
        units = data[cursor]
        total = units * 4
        if units == 0 or cursor + total > end or total < 2:
            malformed = True
            break
        value = data[cursor + 1:cursor + total - 1]
        following = data[cursor + total - 1]
        row: dict[str, Any] = {
            "type": current,
            "length_units": units,
            "length_bytes": total,
            "next_extension_type": following,
        }
        try:
            row.update(decode_gtpu_extension(current, value))
        except (ValueError, struct.error) as exc:
            row.update({
                "malformed": True,
                "parse_error": str(exc),
                "content_bytes": len(value),
                "content_sha256": _hash(b"arenyxa-gtpv1-extension/v1", bytes((current,)) + value),
                "content_retained": False,
            })
            malformed = True
        rows.append(row)
        cursor += total
        current = following
    if current and cursor >= end:
        malformed = True
    return rows, cursor, malformed


def decode_gtp_packet(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 8:
        raise ValueError("truncated GTP header")
    flags, message_type, length = struct.unpack_from("!BBH", raw, 0)
    version = (flags >> 5) & 0x07
    if version == 2:
        total = length + 4
        if total < 8 or total > len(raw):
            raise ValueError("invalid GTPv2 declared length")
        teid_present = bool(flags & 0x08)
        cursor = 4
        teid: int | None = None
        if teid_present:
            if cursor + 4 > total:
                raise ValueError("truncated GTPv2 TEID")
            teid = struct.unpack_from("!I", raw, cursor)[0]
            cursor += 4
        if cursor + 4 > total:
            raise ValueError("truncated GTPv2 sequence header")
        sequence_number = int.from_bytes(raw[cursor:cursor + 3], "big")
        spare = raw[cursor + 3]
        cursor += 4
        ies, malformed = _gtpv2_ies(raw, cursor, total)
        return {
            "version": 2,
            "protocol_family": "gtpv2-c",
            "message_type": message_type,
            "message_name": _GTPV2_MESSAGES.get(message_type, f"message-{message_type}"),
            "piggybacking": bool(flags & 0x10),
            "teid_present": teid_present,
            "spare_flag_bits": flags & 0x07,
            "length": length,
            "decoded_length": total,
            "teid": teid,
            "sequence_number": sequence_number,
            "sequence_spare": spare,
            "information_elements": ies,
            "information_element_count": len(ies),
            "information_elements_malformed": malformed,
            "subscriber_identifier_values_retained": False,
        }
    if version != 1:
        raise ValueError("unsupported GTP version")
    total = length + 8
    if total < 8 or total > len(raw):
        raise ValueError("invalid GTPv1 declared length")
    teid = struct.unpack_from("!I", raw, 4)[0]
    extension = bool(flags & 0x04)
    sequence_flag = bool(flags & 0x02)
    npdu_flag = bool(flags & 0x01)
    cursor = 8
    sequence_number: int | None = None
    npdu_number: int | None = None
    next_extension_type = 0
    extensions: list[dict[str, Any]] = []
    extension_malformed = False
    if extension or sequence_flag or npdu_flag:
        if cursor + 4 > total:
            raise ValueError("truncated GTPv1 optional fields")
        sequence_number = struct.unpack_from("!H", raw, cursor)[0]
        npdu_number = raw[cursor + 2]
        next_extension_type = raw[cursor + 3]
        cursor += 4
        if extension:
            extensions, cursor, extension_malformed = _gtpv1_extensions(raw, cursor, total, next_extension_type)
    payload = raw[cursor:total]
    return {
        "version": 1,
        "protocol_family": "gtpv1",
        "protocol_type": bool(flags & 0x10),
        "reserved_flag_bit": bool(flags & 0x08),
        "extension_header_flag": extension,
        "sequence_number_flag": sequence_flag,
        "npdu_number_flag": npdu_flag,
        "message_type": message_type,
        "message_name": _GTPV1_MESSAGES.get(message_type, f"message-{message_type}"),
        "length": length,
        "decoded_length": total,
        "teid": teid,
        "sequence_number": sequence_number,
        "npdu_number": npdu_number,
        "next_extension_type": next_extension_type,
        "extension_headers": extensions,
        "extension_header_count": len(extensions),
        "extension_headers_malformed": extension_malformed,
        "user_payload_offset": cursor if message_type == 255 else None,
        "user_payload_bytes": len(payload),
        "user_payload_sha256": _hash(b"arenyxa-gtpv1-payload/v1", payload),
        "user_payload_retained": False,
    }
