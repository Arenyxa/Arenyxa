from __future__ import annotations

import hashlib
import struct
from typing import Any


_MESSAGE_NAMES = {
    1: "handshake-initiation",
    2: "handshake-response",
    3: "cookie-reply",
    4: "transport-data",
}


def _sha256(domain: bytes, value: bytes) -> str:
    return hashlib.sha256(domain + b"\x00" + value).hexdigest()


def _evidence(value: bytes, *, domain: bytes, label: str) -> dict[str, Any]:
    return {
        f"{label}_bytes": len(value),
        f"{label}_sha256": _sha256(domain, value),
        f"{label}_retained": False,
    }


def decode_wireguard_message(data: bytes) -> dict[str, Any]:
    """Decode bounded WireGuard message structure without retaining crypto material."""
    raw = bytes(data)
    if len(raw) < 4:
        raise ValueError("truncated WireGuard message type")
    message_type = struct.unpack_from("<I", raw, 0)[0]
    name = _MESSAGE_NAMES.get(message_type)
    if name is None:
        raise ValueError("invalid WireGuard message type")
    fields: dict[str, Any] = {
        "message_type": message_type,
        "message_name": name,
        "message_bytes": len(raw),
        "key_material_retained": False,
        "ciphertext_retained": False,
    }
    if message_type == 1:
        if len(raw) != 148:
            raise ValueError("WireGuard handshake initiation must be exactly 148 bytes")
        fields["sender_index"] = struct.unpack_from("<I", raw, 4)[0]
        fields.update(_evidence(raw[8:40], domain=b"arenyxa-wireguard-ephemeral/v1", label="ephemeral_public"))
        fields.update(_evidence(raw[40:88], domain=b"arenyxa-wireguard-static/v1", label="encrypted_static"))
        fields.update(_evidence(raw[88:116], domain=b"arenyxa-wireguard-timestamp/v1", label="encrypted_timestamp"))
        fields.update(_evidence(raw[116:132], domain=b"arenyxa-wireguard-mac1/v1", label="mac1"))
        fields.update(_evidence(raw[132:148], domain=b"arenyxa-wireguard-mac2/v1", label="mac2"))
        fields["expected_message_bytes"] = 148
    elif message_type == 2:
        if len(raw) != 92:
            raise ValueError("WireGuard handshake response must be exactly 92 bytes")
        fields["sender_index"], fields["receiver_index"] = struct.unpack_from("<II", raw, 4)
        fields.update(_evidence(raw[12:44], domain=b"arenyxa-wireguard-ephemeral/v1", label="ephemeral_public"))
        fields.update(_evidence(raw[44:60], domain=b"arenyxa-wireguard-empty/v1", label="encrypted_empty"))
        fields.update(_evidence(raw[60:76], domain=b"arenyxa-wireguard-mac1/v1", label="mac1"))
        fields.update(_evidence(raw[76:92], domain=b"arenyxa-wireguard-mac2/v1", label="mac2"))
        fields["expected_message_bytes"] = 92
    elif message_type == 3:
        if len(raw) != 64:
            raise ValueError("WireGuard cookie reply must be exactly 64 bytes")
        fields["receiver_index"] = struct.unpack_from("<I", raw, 4)[0]
        fields.update(_evidence(raw[8:32], domain=b"arenyxa-wireguard-cookie-nonce/v1", label="nonce"))
        fields.update(_evidence(raw[32:64], domain=b"arenyxa-wireguard-cookie/v1", label="encrypted_cookie"))
        fields["expected_message_bytes"] = 64
    else:
        if len(raw) < 32:
            raise ValueError("WireGuard transport data is shorter than header plus authentication tag")
        fields["receiver_index"] = struct.unpack_from("<I", raw, 4)[0]
        fields["counter"] = struct.unpack_from("<Q", raw, 8)[0]
        ciphertext = raw[16:]
        fields.update(_evidence(ciphertext, domain=b"arenyxa-wireguard-transport/v1", label="encrypted_payload"))
        fields["minimum_message_bytes"] = 32
    return fields
