from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_MAX_LLDP_TLVS = 128
_MAX_TEXT_BYTES = 1024

_LLDP_CAPABILITIES = {
    0x0001: "other",
    0x0002: "repeater",
    0x0004: "bridge",
    0x0008: "wlan-ap",
    0x0010: "router",
    0x0020: "telephone",
    0x0040: "docsis",
    0x0080: "station-only",
    0x0100: "c-vlan",
    0x0200: "s-vlan",
    0x0400: "two-port-mac-relay",
}
_EAPOL_PACKET_NAMES = {
    0: "eap-packet",
    1: "start",
    2: "logoff",
    3: "key",
    4: "asf-alert",
}
_EAP_CODE_NAMES = {1: "request", 2: "response", 3: "success", 4: "failure"}
_EAP_TYPE_NAMES = {
    1: "identity",
    2: "notification",
    3: "legacy-nak",
    4: "md5-challenge",
    5: "one-time-password",
    6: "generic-token-card",
    13: "eap-tls",
    17: "leap",
    18: "eap-sim",
    21: "eap-ttls",
    23: "eap-aka",
    25: "peap",
    26: "mschapv2",
    43: "eap-fast",
    52: "eap-pwd",
    55: "teap",
}


def _text(value: bytes) -> str:
    return value[:_MAX_TEXT_BYTES].decode("utf-8", errors="replace")


def _identifier(subtype: int, value: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        "subtype": subtype,
        "value_length": len(value),
        "value_sha256": hashlib.sha256(value).hexdigest(),
    }
    if subtype == 4 and len(value) == 6:
        result["mac_address"] = ":".join(f"{item:02x}" for item in value)
    elif subtype in {5, 7}:
        result["text"] = _text(value)
    return result


def _capability_names(bits: int) -> list[str]:
    return [name for mask, name in _LLDP_CAPABILITIES.items() if bits & mask]


def _management_address(value: bytes) -> dict[str, Any]:
    if len(value) < 1:
        return {"malformed": True}
    address_len = value[0]
    if address_len < 1 or 1 + address_len > len(value):
        return {"malformed": True, "address_length": address_len}
    subtype = value[1]
    address = value[2:1 + address_len]
    cursor = 1 + address_len
    row: dict[str, Any] = {"address_subtype": subtype, "address_length": max(0, address_len - 1)}
    if subtype == 1 and len(address) == 4:
        row["address"] = str(ipaddress.IPv4Address(address))
    elif subtype == 2 and len(address) == 16:
        row["address"] = str(ipaddress.IPv6Address(address))
    elif address:
        row["address_sha256"] = hashlib.sha256(address).hexdigest()
    if cursor + 5 <= len(value):
        interface_subtype = value[cursor]
        interface_number = struct.unpack_from("!I", value, cursor + 1)[0]
        cursor += 5
        row["interface_numbering_subtype"] = interface_subtype
        row["interface_number"] = interface_number
    if cursor < len(value):
        oid_len = value[cursor]
        cursor += 1
        oid = value[cursor:cursor + min(oid_len, max(0, len(value) - cursor))]
        row["object_identifier_length"] = len(oid)
        if oid:
            row["object_identifier_sha256"] = hashlib.sha256(oid).hexdigest()
    return row


def decode_lldp(payload: bytes) -> dict[str, Any]:
    """Decode bounded LLDP TLVs while retaining only non-secret topology metadata."""
    cursor = 0
    tlvs: list[dict[str, Any]] = []
    fields: dict[str, Any] = {"tlvs": tlvs, "end_seen": False}
    while cursor + 2 <= len(payload) and len(tlvs) < _MAX_LLDP_TLVS:
        header = struct.unpack_from("!H", payload, cursor)[0]
        cursor += 2
        kind = (header >> 9) & 0x7F
        length = header & 0x1FF
        if cursor + length > len(payload):
            fields["malformed_tlv"] = True
            fields["truncated_tlv_type"] = kind
            fields["truncated_tlv_declared_length"] = length
            break
        value = payload[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"type": kind, "length": length}
        if kind == 0:
            fields["end_seen"] = True
            row["name"] = "end"
            tlvs.append(row)
            break
        if kind == 1 and value:
            row.update({"name": "chassis-id", **_identifier(value[0], value[1:])})
            fields["chassis_id"] = dict(row)
        elif kind == 2 and value:
            row.update({"name": "port-id", **_identifier(value[0], value[1:])})
            fields["port_id"] = dict(row)
        elif kind == 3 and len(value) == 2:
            ttl = struct.unpack("!H", value)[0]
            row.update({"name": "ttl", "seconds": ttl})
            fields["ttl_seconds"] = ttl
        elif kind == 4:
            row.update({"name": "port-description", "text": _text(value)})
            fields["port_description"] = row["text"]
        elif kind == 5:
            row.update({"name": "system-name", "text": _text(value)})
            fields["system_name"] = row["text"]
        elif kind == 6:
            row.update({"name": "system-description", "text": _text(value)})
            fields["system_description"] = row["text"]
        elif kind == 7 and len(value) >= 4:
            supported, enabled = struct.unpack_from("!HH", value, 0)
            row.update({
                "name": "system-capabilities",
                "supported_bits": f"0x{supported:04x}",
                "enabled_bits": f"0x{enabled:04x}",
                "supported": _capability_names(supported),
                "enabled": _capability_names(enabled),
            })
            fields["system_capabilities"] = dict(row)
        elif kind == 8:
            row.update({"name": "management-address", **_management_address(value)})
            fields.setdefault("management_addresses", []).append(dict(row))
        elif kind == 127 and len(value) >= 4:
            row.update({
                "name": "organizationally-specific",
                "oui": value[:3].hex(":"),
                "subtype": value[3],
                "value_bytes": len(value) - 4,
                "value_sha256": hashlib.sha256(value[4:]).hexdigest(),
            })
        else:
            row.update({"name": "unknown", "value_sha256": hashlib.sha256(value).hexdigest()})
        tlvs.append(row)
    fields["tlv_count"] = len(tlvs)
    fields["tlv_limit_reached"] = len(tlvs) >= _MAX_LLDP_TLVS and not fields["end_seen"]
    fields["trailing_bytes"] = max(0, len(payload) - cursor)
    return fields


def _decode_eap(payload: bytes) -> dict[str, Any]:
    if len(payload) < 4:
        return {"body_malformed": True, "body_error": "truncated EAP header"}
    code, identifier, length = struct.unpack_from("!BBH", payload, 0)
    row: dict[str, Any] = {
        "eap_code": code,
        "eap_code_name": _EAP_CODE_NAMES.get(code, "unknown"),
        "eap_identifier": identifier,
        "eap_length": length,
        "eap_truncated": length > len(payload),
    }
    if length >= 5 and len(payload) >= 5 and code in {1, 2}:
        eap_type = payload[4]
        row["eap_type"] = eap_type
        row["eap_type_name"] = _EAP_TYPE_NAMES.get(eap_type, "unknown")
        data = payload[5:min(length, len(payload))]
        row["eap_data_length"] = len(data)
        # Identity strings can contain usernames/realm identifiers. Preserve
        # only length+digest for passive correlation, not the raw identity.
        if eap_type == 1 and data:
            row["identity_sha256"] = hashlib.sha256(data).hexdigest()
    return row


def _decode_eapol_key(payload: bytes) -> dict[str, Any]:
    if len(payload) < 95:
        return {"body_malformed": True, "body_error": "truncated EAPOL-Key descriptor", "descriptor_bytes": len(payload)}
    descriptor_type = payload[0]
    key_information, key_length = struct.unpack_from("!HH", payload, 1)
    replay_counter = struct.unpack_from("!Q", payload, 5)[0]
    nonce = payload[13:45]
    key_data_length = struct.unpack_from("!H", payload, 93)[0]
    available_key_data = max(0, len(payload) - 95)
    return {
        "key_descriptor_type": descriptor_type,
        "key_information": f"0x{key_information:04x}",
        "descriptor_version": key_information & 0x0007,
        "pairwise_key": bool(key_information & 0x0008),
        "install": bool(key_information & 0x0040),
        "key_ack": bool(key_information & 0x0080),
        "key_mic": bool(key_information & 0x0100),
        "secure": bool(key_information & 0x0200),
        "error": bool(key_information & 0x0400),
        "request": bool(key_information & 0x0800),
        "encrypted_key_data": bool(key_information & 0x1000),
        "smk_message": bool(key_information & 0x2000),
        "key_length": key_length,
        "replay_counter": replay_counter,
        "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
        "key_data_length": key_data_length,
        "key_data_available_bytes": available_key_data,
        "key_data_truncated": key_data_length > available_key_data,
        "sensitive_key_material_retained": False,
    }


def decode_eapol(packet: bytes) -> dict[str, Any]:
    """Decode 802.1X/EAPOL metadata without retaining identities, nonces or key data."""
    if len(packet) < 4:
        raise ValueError("truncated EAPOL header")
    version, packet_type, declared_length = struct.unpack_from("!BBH", packet, 0)
    available = max(0, len(packet) - 4)
    payload = packet[4:4 + min(declared_length, available)]
    result: dict[str, Any] = {
        "version": version,
        "packet_type": packet_type,
        "packet_type_name": _EAPOL_PACKET_NAMES.get(packet_type, "unknown"),
        "payload_length": declared_length,
        "captured_payload_bytes": len(payload),
        "truncated": declared_length > available,
    }
    if packet_type == 0:
        result.update(_decode_eap(payload))
    elif packet_type == 3:
        result.update(_decode_eapol_key(payload))
    return result
