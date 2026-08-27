from __future__ import annotations

import hashlib
from typing import Any


_OPTION_NAMES = {
    1: "if-match",
    3: "uri-host",
    4: "etag",
    5: "if-none-match",
    6: "observe",
    7: "uri-port",
    8: "location-path",
    11: "uri-path",
    12: "content-format",
    14: "max-age",
    15: "uri-query",
    17: "accept",
    20: "location-query",
    23: "block2",
    27: "block1",
    28: "size2",
    35: "proxy-uri",
    39: "proxy-scheme",
    60: "size1",
    252: "echo",
    258: "no-response",
    292: "request-tag",
}
_TEXT_OPTIONS = {3, 8, 11, 39}
_UINT_OPTIONS = {6, 7, 12, 14, 17, 28, 60, 258}
_HASH_ONLY_OPTIONS = {1, 4, 15, 20, 35, 252, 292}
_BLOCK_OPTIONS = {23, 27}
_MAX_OPTIONS = 256
_MAX_TEXT = 1024


def _sha256(namespace: str, value: bytes) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\x00" + value).hexdigest()


def _uint(value: bytes) -> int:
    if len(value) > 4:
        raise ValueError("CoAP uint option exceeds supported width")
    return int.from_bytes(value, "big") if value else 0


def _extended(nibble: int, data: bytes, cursor: int, *, field: str) -> tuple[int, int]:
    if nibble <= 12:
        return nibble, cursor
    if nibble == 13:
        if cursor >= len(data):
            raise ValueError(f"truncated CoAP extended {field}")
        return 13 + data[cursor], cursor + 1
    if nibble == 14:
        if cursor + 2 > len(data):
            raise ValueError(f"truncated CoAP extended {field}")
        return 269 + int.from_bytes(data[cursor:cursor + 2], "big"), cursor + 2
    raise ValueError(f"reserved CoAP option {field} nibble")


def _decode_block(value: bytes) -> dict[str, Any]:
    if len(value) > 3:
        raise ValueError("CoAP Block option exceeds 3 bytes")
    raw = _uint(value)
    szx = raw & 0x07
    return {
        "block_number": raw >> 4,
        "more": bool(raw & 0x08),
        "size_exponent": szx,
        "block_size": (1 << (szx + 4)) if szx <= 6 else None,
        "transport_specific_size": szx == 7,
    }


def _decode_option(number: int, value: bytes) -> dict[str, Any]:
    row: dict[str, Any] = {
        "number": number,
        "name": _OPTION_NAMES.get(number, f"option-{number}"),
        "length": len(value),
        "critical": bool(number & 0x01),
        "unsafe_to_forward": bool(number & 0x02),
    }
    if number in _TEXT_OPTIONS:
        text = value.decode("utf-8", errors="replace")
        row.update({"text": text[:_MAX_TEXT], "text_truncated": len(text) > _MAX_TEXT})
    elif number in _UINT_OPTIONS:
        row["uint"] = _uint(value)
    elif number in _BLOCK_OPTIONS:
        row.update(_decode_block(value))
    elif number in _HASH_ONLY_OPTIONS:
        row.update({
            "value_sha256": _sha256(f"arenyxa-coap-option-{number}/v1", value),
            "value_retained": False,
        })
    else:
        row.update({
            "value_sha256": _sha256(f"arenyxa-coap-option-{number}/v1", value),
            "value_retained": False,
        })
    return row


def _code_name(code: int) -> str:
    code_class = (code >> 5) & 0x07
    detail = code & 0x1F
    if code_class == 0:
        return {0: "empty", 1: "get", 2: "post", 3: "put", 4: "delete"}.get(detail, f"0.{detail:02d}")
    return f"{code_class}.{detail:02d}"


def decode_coap_message(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 4:
        raise ValueError("truncated CoAP header")
    first = raw[0]
    version = first >> 6
    message_type = (first >> 4) & 0x03
    token_length = first & 0x0F
    if token_length > 8:
        raise ValueError("invalid CoAP token length")
    if 4 + token_length > len(raw):
        raise ValueError("truncated CoAP token")

    code = raw[1]
    token = raw[4:4 + token_length]
    cursor = 4 + token_length
    option_number = 0
    options: list[dict[str, Any]] = []
    payload = b""
    payload_marker = False

    while cursor < len(raw):
        first_option = raw[cursor]
        if first_option == 0xFF:
            payload_marker = True
            cursor += 1
            if cursor >= len(raw):
                raise ValueError("CoAP payload marker has no payload")
            payload = raw[cursor:]
            cursor = len(raw)
            break
        if len(options) >= _MAX_OPTIONS:
            raise ValueError("CoAP option count exceeds safety budget")
        cursor += 1
        delta, cursor = _extended(first_option >> 4, raw, cursor, field="delta")
        length, cursor = _extended(first_option & 0x0F, raw, cursor, field="length")
        option_number += delta
        if cursor + length > len(raw):
            raise ValueError("truncated CoAP option value")
        value = raw[cursor:cursor + length]
        cursor += length
        options.append(_decode_option(option_number, value))

    paths = [str(row.get("text") or "") for row in options if row.get("number") == 11]
    hosts = [str(row.get("text") or "") for row in options if row.get("number") == 3]
    content_formats = [int(row["uint"]) for row in options if row.get("number") == 12 and row.get("uint") is not None]
    observe = [int(row["uint"]) for row in options if row.get("number") == 6 and row.get("uint") is not None]
    blocks = [row for row in options if row.get("number") in _BLOCK_OPTIONS]
    return {
        "version": version,
        "type": message_type,
        "type_name": {0: "confirmable", 1: "non-confirmable", 2: "acknowledgement", 3: "reset"}.get(message_type, "unknown"),
        "token_length": token_length,
        "token_sha256": _sha256("arenyxa-coap-token/v1", token) if token else "",
        "token_retained": False,
        "code": code,
        "code_class": code >> 5,
        "code_detail": code & 0x1F,
        "code_name": _code_name(code),
        "message_id": int.from_bytes(raw[2:4], "big"),
        "options": options,
        "option_count": len(options),
        "uri_host": hosts[0] if hosts else "",
        "uri_path": "/" + "/".join(paths) if paths else "",
        "content_formats": content_formats,
        "observe_values": observe,
        "block_options": blocks,
        "payload_marker": payload_marker,
        "payload_bytes": len(payload),
        "payload_sha256": _sha256("arenyxa-coap-payload/v1", payload) if payload else "",
        "payload_retained": False,
        "decoded_length": len(raw),
        "query_and_proxy_values_retained": False,
    }
