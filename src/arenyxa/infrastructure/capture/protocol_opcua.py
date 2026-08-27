from __future__ import annotations

import hashlib
import struct
from typing import Any


_CONNECTION_TYPES = {"HEL", "ACK", "ERR", "RHE"}
_SECURE_TYPES = {"OPN", "MSG", "CLO"}
_VALID_CHUNKS = {"F", "C", "A"}


def _hash(namespace: str, value: bytes) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\x00" + value).hexdigest()


def _read_i32(data: bytes, cursor: int) -> tuple[int, int]:
    if cursor + 4 > len(data):
        raise ValueError("truncated OPC UA Int32")
    return struct.unpack_from("<i", data, cursor)[0], cursor + 4


def _read_string(data: bytes, cursor: int, *, maximum: int = 16_384) -> tuple[str, int]:
    length, cursor = _read_i32(data, cursor)
    if length == -1:
        return "", cursor
    if length < 0 or length > maximum or cursor + length > len(data):
        raise ValueError("invalid OPC UA String length")
    return data[cursor:cursor + length].decode("utf-8", errors="replace"), cursor + length


def _read_bytestring(data: bytes, cursor: int, *, maximum: int = 1_048_576) -> tuple[bytes, int]:
    length, cursor = _read_i32(data, cursor)
    if length == -1:
        return b"", cursor
    if length < 0 or length > maximum or cursor + length > len(data):
        raise ValueError("invalid OPC UA ByteString length")
    return data[cursor:cursor + length], cursor + length


def _opaque(namespace: str, value: bytes) -> dict[str, Any]:
    return {
        "payload_bytes": len(value),
        "payload_sha256": _hash(namespace, value) if value else "",
        "payload_retained": False,
    }


def _decode_hello(data: bytes) -> dict[str, Any]:
    if len(data) < 28:
        raise ValueError("truncated OPC UA Hello message")
    protocol, receive, send, maximum, chunks = struct.unpack_from("<IIIII", data, 8)
    endpoint, cursor = _read_string(data, 28, maximum=65_536)
    return {
        "protocol_version": protocol,
        "receive_buffer_size": receive,
        "send_buffer_size": send,
        "max_message_size": maximum,
        "max_chunk_count": chunks,
        "endpoint_url": endpoint,
        "endpoint_url_retained": True,
        "trailing_bytes": len(data) - cursor,
    }


def _decode_ack(data: bytes) -> dict[str, Any]:
    if len(data) < 28:
        raise ValueError("truncated OPC UA Acknowledge message")
    protocol, receive, send, maximum, chunks = struct.unpack_from("<IIIII", data, 8)
    return {
        "protocol_version": protocol,
        "receive_buffer_size": receive,
        "send_buffer_size": send,
        "max_message_size": maximum,
        "max_chunk_count": chunks,
        "trailing_bytes": len(data) - 28,
    }


def _decode_error(data: bytes) -> dict[str, Any]:
    if len(data) < 12:
        raise ValueError("truncated OPC UA Error message")
    status = struct.unpack_from("<I", data, 8)[0]
    reason, cursor = _read_string(data, 12, maximum=4096)
    # Error strings can carry environment details; retain a bounded preview and a digest.
    raw_reason = reason.encode("utf-8", errors="replace")
    return {
        "status_code": status,
        "reason_preview": reason[:256],
        "reason_sha256": _hash("arenyxa-opcua-error-reason/v1", raw_reason) if raw_reason else "",
        "reason_truncated": len(reason) > 256,
        "trailing_bytes": len(data) - cursor,
    }


def _decode_reverse_hello(data: bytes) -> dict[str, Any]:
    server_uri, cursor = _read_string(data, 8, maximum=65_536)
    endpoint_url, cursor = _read_string(data, cursor, maximum=65_536)
    return {
        "server_uri": server_uri,
        "endpoint_url": endpoint_url,
        "trailing_bytes": len(data) - cursor,
    }


def _decode_asymmetric_security_header(data: bytes, cursor: int) -> tuple[dict[str, Any], int]:
    policy, cursor = _read_string(data, cursor, maximum=4096)
    certificate, cursor = _read_bytestring(data, cursor)
    thumbprint, cursor = _read_bytestring(data, cursor, maximum=1024)
    return {
        "security_policy_uri": policy,
        "sender_certificate_bytes": len(certificate),
        "sender_certificate_sha256": _hash("arenyxa-opcua-sender-certificate/v1", certificate) if certificate else "",
        "receiver_thumbprint_bytes": len(thumbprint),
        "receiver_thumbprint_sha256": _hash("arenyxa-opcua-receiver-thumbprint/v1", thumbprint) if thumbprint else "",
        "certificate_material_retained": False,
    }, cursor


def _decode_secure_message(message_type: str, data: bytes) -> dict[str, Any]:
    if len(data) < 12:
        raise ValueError("truncated OPC UA SecureConversation header")
    secure_channel_id = struct.unpack_from("<I", data, 8)[0]
    row: dict[str, Any] = {"secure_channel_id": secure_channel_id}
    cursor = 12
    if message_type == "OPN":
        security, cursor = _decode_asymmetric_security_header(data, cursor)
        row["asymmetric_security_header"] = security
        policy = str(security.get("security_policy_uri") or "")
        security_none = policy.endswith("#None") or policy.casefold().endswith("/none")
        row["security_policy_none"] = security_none
        if security_none and cursor + 8 <= len(data):
            sequence, request_id = struct.unpack_from("<II", data, cursor)
            row.update({"sequence_number": sequence, "request_id": request_id, "sequence_header_visible": True})
            cursor += 8
        else:
            row["sequence_header_visible"] = False
    else:
        if cursor + 4 > len(data):
            raise ValueError("truncated OPC UA symmetric security header")
        row["security_token_id"] = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        # For MSG/CLO the sequence header may be protected. Do not interpret ciphertext as IDs.
        row["sequence_header_visible"] = False
    row.update(_opaque("arenyxa-opcua-secure-payload/v1", data[cursor:]))
    return row


def decode_opcua_tcp(data: bytes) -> dict[str, Any]:
    raw = bytes(data)
    if len(raw) < 8:
        raise ValueError("truncated OPC UA TCP message header")
    message_type = raw[:3].decode("ascii", errors="strict")
    if message_type not in _CONNECTION_TYPES | _SECURE_TYPES:
        raise ValueError("invalid OPC UA TCP message type")
    chunk_type = chr(raw[3]) if 32 <= raw[3] <= 126 else "?"
    if chunk_type not in _VALID_CHUNKS:
        raise ValueError("invalid OPC UA TCP chunk type")
    message_size = struct.unpack_from("<I", raw, 4)[0]
    if message_size < 8 or message_size > len(raw):
        raise ValueError("invalid OPC UA TCP message size")
    message = raw[:message_size]
    row: dict[str, Any] = {
        "message_type": message_type,
        "chunk_type": chunk_type,
        "message_size": message_size,
        "decoded_length": message_size,
        "trailing_bytes": len(raw) - message_size,
        "secure_conversation": message_type in _SECURE_TYPES,
    }
    if message_type in _CONNECTION_TYPES and chunk_type != "F":
        row["connection_chunk_nonfinal"] = True
    try:
        if message_type == "HEL":
            row["connection"] = _decode_hello(message)
        elif message_type == "ACK":
            row["connection"] = _decode_ack(message)
        elif message_type == "ERR":
            row["connection"] = _decode_error(message)
        elif message_type == "RHE":
            row["connection"] = _decode_reverse_hello(message)
        else:
            row["secure"] = _decode_secure_message(message_type, message)
    except ValueError as exc:
        row.update({"body_malformed": True, "body_error": str(exc)[:256]})
    return row
