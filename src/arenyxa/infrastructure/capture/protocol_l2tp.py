from __future__ import annotations

import hashlib
import struct
from typing import Any


_MESSAGE_TYPES = {
    1: "SCCRQ",
    2: "SCCRP",
    3: "SCCCN",
    4: "StopCCN",
    6: "HELLO",
    7: "OCRQ",
    8: "OCRP",
    9: "OCCN",
    10: "ICRQ",
    11: "ICRP",
    12: "ICCN",
    14: "CDN",
    15: "WEN",
    16: "SLI",
}

_AVP_NAMES = {
    0: "message-type",
    1: "result-code",
    2: "protocol-version",
    3: "framing-capabilities",
    4: "bearer-capabilities",
    5: "tie-breaker",
    6: "firmware-revision",
    7: "host-name",
    8: "vendor-name",
    9: "assigned-tunnel-id",
    10: "receive-window-size",
    11: "challenge",
    12: "q931-cause-code",
    13: "challenge-response",
    14: "assigned-session-id",
    15: "call-serial-number",
    16: "minimum-bps",
    17: "maximum-bps",
    18: "bearer-type",
    19: "framing-type",
    21: "called-number",
    22: "calling-number",
    23: "sub-address",
    24: "tx-connect-speed",
    25: "physical-channel-id",
    26: "initial-received-lcp-confreq",
    27: "last-sent-lcp-confreq",
    28: "last-received-lcp-confreq",
    29: "proxy-auth-type",
    30: "proxy-auth-name",
    31: "proxy-auth-challenge",
    32: "proxy-auth-id",
    33: "proxy-auth-response",
    34: "call-errors",
    35: "accm",
    36: "random-vector",
    37: "private-group-id",
    38: "rx-connect-speed",
    39: "sequencing-required",
}

_SENSITIVE_AVPS = {11, 13, 21, 22, 23, 26, 27, 28, 30, 31, 33, 36, 37}


def _sha256(label: bytes, value: bytes) -> str:
    return hashlib.sha256(label + b"\x00" + value).hexdigest()


def _bounded_text(value: bytes, limit: int = 256) -> str:
    return value[:limit].decode("utf-8", errors="replace")


def _opaque_evidence(value: bytes, *, attr_type: int, label: str = "value") -> dict[str, Any]:
    return {
        f"{label}_bytes": len(value),
        f"{label}_sha256": _sha256(f"arenyxa-l2tp-avp-{attr_type}/v1".encode(), value),
        f"{label}_retained": False,
    }


def _decode_standard_avp(attr_type: int, value: bytes) -> dict[str, Any]:
    if attr_type == 0 and len(value) == 2:
        message_type = struct.unpack("!H", value)[0]
        return {"message_type": message_type, "message_name": _MESSAGE_TYPES.get(message_type, f"message-{message_type}")}
    if attr_type == 1 and len(value) >= 2:
        row: dict[str, Any] = {"result_code": struct.unpack_from("!H", value, 0)[0]}
        if len(value) >= 4:
            row["error_code"] = struct.unpack_from("!H", value, 2)[0]
        if len(value) > 4:
            row.update(_opaque_evidence(value[4:], attr_type=attr_type, label="error_message"))
        return row
    if attr_type == 2 and len(value) == 2:
        return {"protocol_version": value[0], "protocol_revision": value[1]}
    if attr_type in {3, 4, 18, 19} and len(value) == 4:
        bitmask = struct.unpack("!I", value)[0]
        row = {"bitmask": f"0x{bitmask:08x}"}
        if attr_type in {3, 19}:
            row.update({"asynchronous": bool(bitmask & 0x2), "synchronous": bool(bitmask & 0x1)})
        if attr_type in {4, 18}:
            row.update({"digital": bool(bitmask & 0x2), "analog": bool(bitmask & 0x1)})
        return row
    if attr_type == 5 and len(value) == 8:
        return {"tie_breaker": f"0x{int.from_bytes(value, 'big'):016x}"}
    if attr_type in {6, 9, 10, 14, 29, 32} and len(value) == 2:
        return {"value": struct.unpack("!H", value)[0]}
    if attr_type in {15, 16, 17, 24, 25, 38} and len(value) == 4:
        return {"value": struct.unpack("!I", value)[0]}
    if attr_type == 39 and not value:
        return {"sequencing_required": True}
    if attr_type in {7, 8}:
        return {"text": _bounded_text(value), "text_truncated": len(value) > 256}
    if attr_type in _SENSITIVE_AVPS:
        return _opaque_evidence(value, attr_type=attr_type)
    return _opaque_evidence(value, attr_type=attr_type)


def _decode_control_avps(raw: bytes, cursor: int, packet_end: int) -> tuple[list[dict[str, Any]], int, bool, int]:
    avps: list[dict[str, Any]] = []
    malformed = False
    hidden_count = 0
    while cursor < packet_end and len(avps) < 256:
        if cursor + 6 > packet_end:
            malformed = True
            break
        flags_length, vendor_id, attr_type = struct.unpack_from("!HHH", raw, cursor)
        avp_length = flags_length & 0x03FF
        if avp_length < 6 or cursor + avp_length > packet_end:
            malformed = True
            break
        value = raw[cursor + 6:cursor + avp_length]
        hidden = bool(flags_length & 0x4000)
        row: dict[str, Any] = {
            "vendor_id": vendor_id, "attribute_type": attr_type,
            "attribute_name": _AVP_NAMES.get(attr_type, f"attribute-{attr_type}") if vendor_id == 0 else "vendor-specific",
            "mandatory": bool(flags_length & 0x8000), "hidden": hidden,
            "reserved_bits": f"0x{flags_length & 0x3C00:04x}", "length": avp_length,
        }
        if hidden:
            hidden_count += 1
            row.update(_opaque_evidence(value, attr_type=attr_type, label="hidden_value"))
        elif vendor_id == 0:
            row.update(_decode_standard_avp(attr_type, value))
        else:
            row.update(_opaque_evidence(value, attr_type=attr_type))
        avps.append(row)
        cursor += avp_length
    return avps, cursor, malformed or cursor != packet_end, hidden_count


def decode_l2tp_packet(data: bytes) -> dict[str, Any]:
    """Decode an RFC 2661 L2TPv2 header and visible control AVPs safely."""
    raw = bytes(data)
    if len(raw) < 6:
        raise ValueError("truncated L2TPv2 header")
    flags_version = struct.unpack_from("!H", raw, 0)[0]
    version = flags_version & 0x000F
    if version != 2:
        raise ValueError("unsupported L2TP header version")
    control, length_present = bool(flags_version & 0x8000), bool(flags_version & 0x4000)
    sequence_present, offset_present, priority = bool(flags_version & 0x0800), bool(flags_version & 0x0200), bool(flags_version & 0x0100)
    cursor, declared_length = 2, None
    if length_present:
        if cursor + 2 > len(raw):
            raise ValueError("truncated L2TP length field")
        declared_length = struct.unpack_from("!H", raw, cursor)[0]
        cursor += 2
        if declared_length < 6 or declared_length > len(raw):
            raise ValueError("invalid L2TP declared length")
    packet_end = declared_length or len(raw)
    if cursor + 4 > packet_end:
        raise ValueError("truncated L2TP tunnel/session identifiers")
    tunnel_id, session_id = struct.unpack_from("!HH", raw, cursor)
    cursor += 4
    ns = nr = None
    if sequence_present:
        if cursor + 4 > packet_end:
            raise ValueError("truncated L2TP sequence fields")
        ns, nr = struct.unpack_from("!HH", raw, cursor)
        cursor += 4
    offset_size = 0
    if offset_present:
        if cursor + 2 > packet_end:
            raise ValueError("truncated L2TP offset size")
        offset_size = struct.unpack_from("!H", raw, cursor)[0]
        cursor += 2
        if cursor + offset_size > packet_end:
            raise ValueError("truncated L2TP offset padding")
        cursor += offset_size
    fields: dict[str, Any] = {
        "version": version, "control": control, "length_present": length_present, "sequence_present": sequence_present,
        "offset_present": offset_present, "priority": priority, "reserved_flag_bits": f"0x{flags_version & 0x34F0:04x}",
        "declared_length": declared_length, "decoded_length": packet_end, "header_length": cursor,
        "tunnel_id": tunnel_id, "session_id": session_id, "ns": ns, "nr": nr, "offset_size": offset_size,
        "control_required_header_fields_present": (not control) or (length_present and sequence_present and not offset_present),
        "sensitive_avp_values_retained": False,
    }
    if not control:
        payload = raw[cursor:packet_end]
        fields.update({"data_payload_bytes": len(payload), "data_payload_sha256": _sha256(b"arenyxa-l2tp-data/v1", payload), "data_payload_retained": False})
        return fields
    avps, cursor, malformed, hidden_count = _decode_control_avps(raw, cursor, packet_end)
    message = next((row for row in avps if row.get("vendor_id") == 0 and row.get("attribute_type") == 0), None)
    fields.update({
        "message_type": message.get("message_type") if isinstance(message, dict) else None,
        "message_name": message.get("message_name") if isinstance(message, dict) else "unknown",
        "avps": avps, "avp_count": len(avps), "hidden_avp_count": hidden_count, "avp_chain_malformed": malformed,
        "message_type_first_avp": bool(avps and avps[0].get("vendor_id") == 0 and avps[0].get("attribute_type") == 0),
    })
    return fields
