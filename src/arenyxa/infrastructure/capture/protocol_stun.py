from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_MAGIC_COOKIE = 0x2112A442
_MAGIC_COOKIE_BYTES = _MAGIC_COOKIE.to_bytes(4, "big")
_MAX_ATTRIBUTES = 512

_METHOD_NAMES = {
    0x001: "binding",
    0x003: "allocate",
    0x004: "refresh",
    0x006: "send",
    0x007: "data",
    0x008: "create-permission",
    0x009: "channel-bind",
}
_CLASS_NAMES = {0: "request", 1: "indication", 2: "success-response", 3: "error-response"}
_ATTRIBUTE_NAMES = {
    0x0001: "mapped-address",
    0x0006: "username",
    0x0008: "message-integrity",
    0x0009: "error-code",
    0x000A: "unknown-attributes",
    0x000C: "channel-number",
    0x000D: "lifetime",
    0x0012: "xor-peer-address",
    0x0013: "data",
    0x0014: "realm",
    0x0015: "nonce",
    0x0016: "xor-relayed-address",
    0x0017: "requested-address-family",
    0x0018: "even-port",
    0x0019: "requested-transport",
    0x001A: "dont-fragment",
    0x0020: "xor-mapped-address",
    0x0022: "reservation-token",
    0x0024: "priority",
    0x0025: "use-candidate",
    0x001C: "message-integrity-sha256",
    0x8022: "software",
    0x8023: "alternate-server",
    0x8028: "fingerprint",
    0x8029: "ice-controlled",
    0x802A: "ice-controlling",
}
_HASH_ONLY = {0x0006, 0x0008, 0x0013, 0x0014, 0x0015, 0x001C, 0x0022}
_ADDRESS = {0x0001, 0x8023}
_XOR_ADDRESS = {0x0012, 0x0016, 0x0020}


def _sha256(namespace: str, value: bytes) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\x00" + value).hexdigest()


def _method_and_class(message_type: int) -> tuple[int, int]:
    method = (message_type & 0x000F) | ((message_type & 0x00E0) >> 1) | ((message_type & 0x3E00) >> 2)
    message_class = ((message_type & 0x0010) >> 4) | ((message_type & 0x0100) >> 7)
    return method, message_class


def _decode_address(value: bytes, *, xor: bool, transaction_id: bytes) -> dict[str, Any]:
    if len(value) < 4:
        raise ValueError("truncated STUN address attribute")
    reserved, family, encoded_port = struct.unpack_from("!BBH", value, 0)
    if family == 1:
        expected = 8
        address_bytes = value[4:8]
        mask = _MAGIC_COOKIE_BYTES
    elif family == 2:
        expected = 20
        address_bytes = value[4:20]
        mask = _MAGIC_COOKIE_BYTES + transaction_id
    else:
        return {
            "reserved": reserved,
            "family": family,
            "address_bytes": max(0, len(value) - 4),
            "address_sha256": _sha256("arenyxa-stun-address/v1", value[4:]),
            "address_retained": False,
        }
    if len(value) != expected:
        raise ValueError("invalid STUN address attribute length")
    port = encoded_port ^ (_MAGIC_COOKIE >> 16) if xor else encoded_port
    if xor:
        address_bytes = bytes(byte ^ mask[index] for index, byte in enumerate(address_bytes))
    address = str(ipaddress.ip_address(address_bytes))
    return {"reserved": reserved, "family": family, "address": address, "port": port, "xor_encoded": xor}


def _decode_error(value: bytes) -> dict[str, Any]:
    if len(value) < 4:
        raise ValueError("truncated STUN ERROR-CODE")
    error_class = value[2] & 0x07
    number = value[3]
    reason = value[4:].decode("utf-8", errors="replace")
    return {
        "error_code": error_class * 100 + number,
        "reason": reason[:512],
        "reason_truncated": len(reason) > 512,
        "reserved_bits_nonzero": bool(value[0] or value[1] or (value[2] & 0xF8)),
    }


def _decode_attribute(attr_type: int, value: bytes, *, transaction_id: bytes) -> dict[str, Any]:
    row: dict[str, Any] = {
        "type": attr_type,
        "name": _ATTRIBUTE_NAMES.get(attr_type, f"attribute-0x{attr_type:04x}"),
        "length": len(value),
        "comprehension_required": attr_type < 0x8000,
    }
    if attr_type in _ADDRESS:
        row.update(_decode_address(value, xor=False, transaction_id=transaction_id))
    elif attr_type in _XOR_ADDRESS:
        row.update(_decode_address(value, xor=True, transaction_id=transaction_id))
    elif attr_type in _HASH_ONLY:
        row.update({
            "value_sha256": _sha256(f"arenyxa-stun-attr-{attr_type}/v1", value),
            "value_retained": False,
        })
    elif attr_type == 0x0009:
        row.update(_decode_error(value))
    elif attr_type == 0x000A:
        if len(value) % 2:
            raise ValueError("invalid STUN UNKNOWN-ATTRIBUTES length")
        row["unknown_attribute_types"] = [struct.unpack_from("!H", value, cursor)[0] for cursor in range(0, len(value), 2)][:128]
    elif attr_type == 0x000C and len(value) == 4:
        row.update({"channel_number": struct.unpack_from("!H", value, 0)[0], "rffu": struct.unpack_from("!H", value, 2)[0]})
    elif attr_type in {0x000D, 0x0024, 0x8028} and len(value) == 4:
        key = {0x000D: "lifetime_seconds", 0x0024: "priority", 0x8028: "fingerprint"}[attr_type]
        row[key] = struct.unpack_from("!I", value, 0)[0]
    elif attr_type in {0x8029, 0x802A} and len(value) == 8:
        row["tiebreaker"] = struct.unpack_from("!Q", value, 0)[0]
    elif attr_type == 0x0017 and len(value) >= 1:
        row.update({"address_family": value[0], "rffu_nonzero": any(value[1:])})
    elif attr_type == 0x0018 and len(value) >= 1:
        row.update({"reserve_next_port": bool(value[0] & 0x80), "rffu_nonzero": bool(value[0] & 0x7F) or any(value[1:])})
    elif attr_type == 0x0019 and len(value) == 4:
        row.update({"protocol": value[0], "rffu_nonzero": any(value[1:])})
    elif attr_type in {0x0025, 0x001A}:
        row["flag_present"] = True
        row["unexpected_value_bytes"] = len(value)
    elif attr_type == 0x8022:
        text = value.decode("utf-8", errors="replace")
        row.update({"software": text[:512], "software_truncated": len(text) > 512})
    else:
        row.update({
            "value_sha256": _sha256(f"arenyxa-stun-attr-{attr_type}/v1", value),
            "value_retained": False,
        })
    return row


def decode_stun_message(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 20:
        raise ValueError("truncated STUN header")
    message_type, message_length, magic_cookie = struct.unpack_from("!HHI", raw, 0)
    if message_type & 0xC000:
        raise ValueError("invalid STUN message-type top bits")
    if magic_cookie != _MAGIC_COOKIE:
        raise ValueError("invalid STUN magic cookie")
    if message_length % 4:
        raise ValueError("STUN message length is not 32-bit aligned")
    total = 20 + message_length
    if total > len(raw):
        raise ValueError("truncated STUN message body")
    transaction_id = raw[8:20]
    method, message_class = _method_and_class(message_type)
    cursor = 20
    attributes: list[dict[str, Any]] = []
    malformed = False
    while cursor < total and len(attributes) < _MAX_ATTRIBUTES:
        if cursor + 4 > total:
            malformed = True
            break
        attr_type, attr_length = struct.unpack_from("!HH", raw, cursor)
        value_start = cursor + 4
        value_end = value_start + attr_length
        if value_end > total:
            malformed = True
            break
        value = raw[value_start:value_end]
        try:
            attributes.append(_decode_attribute(attr_type, value, transaction_id=transaction_id))
        except (ValueError, ipaddress.AddressValueError) as exc:
            attributes.append({
                "type": attr_type,
                "name": _ATTRIBUTE_NAMES.get(attr_type, f"attribute-0x{attr_type:04x}"),
                "length": attr_length,
                "malformed": True,
                "parse_error": str(exc),
                "value_sha256": _sha256(f"arenyxa-stun-malformed-{attr_type}/v1", value),
                "value_retained": False,
            })
            malformed = True
        cursor = value_start + ((attr_length + 3) & ~3)
    if cursor != total:
        malformed = True
    unknown_required = sorted({
        int(row["type"]) for row in attributes
        if int(row.get("type") or 0) < 0x8000 and int(row.get("type") or 0) not in _ATTRIBUTE_NAMES
    })
    return {
        "message_type": message_type,
        "message_type_hex": f"0x{message_type:04x}",
        "message_length": message_length,
        "decoded_length": total,
        "magic_cookie": f"0x{magic_cookie:08x}",
        "transaction_id_sha256": _sha256("arenyxa-stun-transaction-id/v1", transaction_id),
        "transaction_id_retained": False,
        "method": method,
        "method_name": _METHOD_NAMES.get(method, f"method-0x{method:03x}"),
        "class": message_class,
        "class_name": _CLASS_NAMES.get(message_class, "unknown"),
        "attributes": attributes,
        "attribute_count": len(attributes),
        "attributes_malformed": malformed,
        "unknown_comprehension_required": unknown_required[:128],
        "credential_values_retained": False,
        "integrity_values_retained": False,
        "turn_data_values_retained": False,
    }


def looks_like_turn_channel_data(data: bytes) -> bool:
    if len(data) < 4:
        return False
    channel = struct.unpack_from("!H", data, 0)[0]
    length = struct.unpack_from("!H", data, 2)[0]
    return 0x4000 <= channel <= 0x7FFF and 4 + length <= len(data)


def decode_turn_channel_data(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 4:
        raise ValueError("truncated TURN ChannelData header")
    channel, length = struct.unpack_from("!HH", raw, 0)
    if not 0x4000 <= channel <= 0x7FFF:
        raise ValueError("invalid TURN channel number")
    if 4 + length > len(raw):
        raise ValueError("truncated TURN ChannelData payload")
    payload = raw[4:4 + length]
    return {
        "channel_number": channel,
        "data_bytes": length,
        "data_sha256": _sha256("arenyxa-turn-channel-data/v1", payload),
        "data_retained": False,
        "decoded_length": 4 + length,
        "padding_bytes": max(0, len(raw) - (4 + length)),
    }
