from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any


_IKE_EXCHANGES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
    39: "GSA_AUTH",
    40: "GSA_REGISTRATION",
    41: "GSA_REKEY",
    42: "GSA_INBAND_REKEY",
    43: "IKE_INTERMEDIATE",
    44: "IKE_FOLLOWUP_KE",
}
_IKE_PAYLOADS = {
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "NONCE",
    41: "NOTIFY",
    42: "DELETE",
    43: "VENDOR",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
    48: "EAP",
    53: "SKF",
}
_PROTOCOL_IDS = {1: "ike", 2: "ah", 3: "esp"}
_TRANSFORM_TYPES = {
    1: "encryption",
    2: "prf",
    3: "integrity",
    4: "key-exchange",
    5: "sequence-numbers",
    6: "additional-key-exchange-1",
    7: "additional-key-exchange-2",
    8: "additional-key-exchange-3",
    9: "additional-key-exchange-4",
    10: "additional-key-exchange-5",
    11: "additional-key-exchange-6",
    12: "additional-key-exchange-7",
    13: "key-wrap-algorithm",
    14: "group-controller-authentication",
}
_ENCR_IDS = {
    1: "ENCR_DES_IV64",
    2: "ENCR_DES",
    3: "ENCR_3DES",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16",
    28: "ENCR_CHACHA20_POLY1305",
}
_PRF_IDS = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_CMAC",
}
_INTEG_IDS = {
    0: "NONE",
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    5: "AUTH_AES_XCBC_96",
    8: "AUTH_AES_CMAC_96",
    9: "AUTH_AES_128_GMAC",
    10: "AUTH_AES_192_GMAC",
    11: "AUTH_AES_256_GMAC",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}
_AUTH_METHODS = {
    1: "rsa-digital-signature",
    2: "shared-key-message-integrity-code",
    3: "dss-digital-signature",
    9: "ecdsa-p256-sha256",
    10: "ecdsa-p384-sha384",
    11: "ecdsa-p521-sha512",
    12: "generic-secure-password",
    13: "null-authentication",
    14: "digital-signature",
}
_ID_TYPES = {
    1: "ipv4-address",
    2: "fqdn",
    3: "rfc822-address",
    5: "ipv6-address",
    9: "der-asn1-dn",
    10: "der-asn1-gn",
    11: "key-id",
}
_NOTIFY_TYPES = {
    1: "UNSUPPORTED_CRITICAL_PAYLOAD",
    4: "INVALID_IKE_SPI",
    5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX",
    9: "INVALID_MESSAGE_ID",
    14: "NO_PROPOSAL_CHOSEN",
    17: "INVALID_KE_PAYLOAD",
    24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED",
    35: "NO_ADDITIONAL_SAS",
    36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED",
    38: "TS_UNACCEPTABLE",
    39: "INVALID_SELECTORS",
    16384: "INITIAL_CONTACT",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE",
    16391: "USE_TRANSPORT_MODE",
    16393: "REKEY_SA",
    16400: "MOBIKE_SUPPORTED",
    16401: "ADDITIONAL_IP4_ADDRESS",
    16402: "ADDITIONAL_IP6_ADDRESS",
    16403: "NO_ADDITIONAL_ADDRESSES",
    16404: "UPDATE_SA_ADDRESSES",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED",
}


def _hash(label: bytes, value: bytes) -> str:
    return hashlib.sha256(label + b"\x00" + value).hexdigest()


def _need(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError(f"truncated {label}")


def _transform_name(kind: int, transform_id: int) -> str:
    if kind == 1:
        return _ENCR_IDS.get(transform_id, f"encr-{transform_id}")
    if kind == 2:
        return _PRF_IDS.get(transform_id, f"prf-{transform_id}")
    if kind == 3:
        return _INTEG_IDS.get(transform_id, f"integ-{transform_id}")
    if kind == 4:
        return f"ke-method-{transform_id}"
    if kind == 5:
        return {0: "32-bit-sequential", 1: "partial-64-bit-sequential", 2: "32-bit-unspecified"}.get(
            transform_id, f"sequence-{transform_id}"
        )
    return f"transform-{transform_id}"


def _transform_attributes(data: bytes) -> tuple[list[dict[str, Any]], bool]:
    rows: list[dict[str, Any]] = []
    cursor = 0
    malformed = False
    while cursor + 4 <= len(data) and len(rows) < 64:
        type_format, second = struct.unpack_from("!HH", data, cursor)
        cursor += 4
        attr_type = type_format & 0x7FFF
        tv = bool(type_format & 0x8000)
        row: dict[str, Any] = {
            "type": attr_type,
            "name": "key-length" if attr_type == 14 else f"attribute-{attr_type}",
            "format": "tv" if tv else "tlv",
        }
        if tv:
            row["value"] = second
        else:
            length = second
            if cursor + length > len(data):
                row["malformed"] = True
                malformed = True
                rows.append(row)
                cursor = len(data)
                break
            value = data[cursor:cursor + length]
            cursor += length
            if attr_type == 14 and length in {1, 2, 4}:
                row["value"] = int.from_bytes(value, "big")
            else:
                row.update({
                    "value_bytes": length,
                    "value_sha256": _hash(b"arenyxa-ike-transform-attribute/v1", value),
                    "value_retained": False,
                })
        rows.append(row)
    if cursor != len(data):
        malformed = True
    return rows, malformed


def _sa_payload(body: bytes) -> dict[str, Any]:
    proposals: list[dict[str, Any]] = []
    cursor = 0
    malformed = False
    while cursor + 8 <= len(body) and len(proposals) < 64:
        start = cursor
        last_more, reserved, proposal_length = struct.unpack_from("!BBH", body, cursor)
        if proposal_length < 8 or cursor + proposal_length > len(body):
            malformed = True
            break
        proposal_number, protocol_id, spi_size, transform_count = struct.unpack_from("!BBBB", body, cursor + 4)
        cursor += 8
        spi = body[cursor:cursor + spi_size]
        cursor += spi_size
        proposal_end = start + proposal_length
        if cursor > proposal_end:
            malformed = True
            break
        transforms: list[dict[str, Any]] = []
        while cursor + 8 <= proposal_end and len(transforms) < 128:
            transform_start = cursor
            transform_more, transform_reserved, transform_length = struct.unpack_from("!BBH", body, cursor)
            if transform_length < 8 or cursor + transform_length > proposal_end:
                malformed = True
                break
            transform_type = body[cursor + 4]
            reserved2 = body[cursor + 5]
            transform_id = struct.unpack_from("!H", body, cursor + 6)[0]
            attributes, attr_malformed = _transform_attributes(body[cursor + 8:cursor + transform_length])
            transforms.append({
                "more": transform_more != 0,
                "reserved": transform_reserved,
                "type": transform_type,
                "type_name": _TRANSFORM_TYPES.get(transform_type, f"transform-type-{transform_type}"),
                "reserved2": reserved2,
                "id": transform_id,
                "id_name": _transform_name(transform_type, transform_id),
                "attributes": attributes,
                "attributes_malformed": attr_malformed,
            })
            malformed = malformed or attr_malformed
            cursor = transform_start + transform_length
            if transform_more == 0:
                break
        proposals.append({
            "more": last_more != 0,
            "reserved": reserved,
            "proposal_number": proposal_number,
            "protocol_id": protocol_id,
            "protocol_name": _PROTOCOL_IDS.get(protocol_id, f"protocol-{protocol_id}"),
            "spi": spi.hex(),
            "spi_bytes": len(spi),
            "declared_transform_count": transform_count,
            "decoded_transform_count": len(transforms),
            "transforms": transforms,
            "transform_count_mismatch": transform_count != len(transforms),
        })
        cursor = proposal_end
        if last_more == 0:
            break
    if cursor != len(body):
        malformed = True
    return {"proposals": proposals, "proposal_count": len(proposals), "malformed": malformed}


def _ke_payload(body: bytes) -> dict[str, Any]:
    _need(body, 0, 4, "IKEv2 KE payload")
    group, reserved = struct.unpack_from("!HH", body, 0)
    value = body[4:]
    return {
        "key_exchange_method": group,
        "reserved": reserved,
        "key_exchange_bytes": len(value),
        "key_exchange_sha256": _hash(b"arenyxa-ike-ke/v1", value),
        "key_exchange_retained": False,
    }


def _id_payload(body: bytes) -> dict[str, Any]:
    _need(body, 0, 4, "IKEv2 identification payload")
    identity_type, protocol_id, port = struct.unpack_from("!BBH", body, 0)
    value = body[4:]
    return {
        "identity_type": identity_type,
        "identity_type_name": _ID_TYPES.get(identity_type, f"id-type-{identity_type}"),
        "protocol_id": protocol_id,
        "port": port,
        "identity_bytes": len(value),
        "identity_sha256": _hash(b"arenyxa-ike-identity/v1", value),
        "identity_retained": False,
    }


def _certificate_payload(body: bytes) -> dict[str, Any]:
    _need(body, 0, 1, "IKEv2 certificate payload")
    value = body[1:]
    return {
        "certificate_encoding": body[0],
        "certificate_bytes": len(value),
        "certificate_sha256": _hash(b"arenyxa-ike-certificate/v1", value),
        "certificate_retained": False,
    }


def _auth_payload(body: bytes) -> dict[str, Any]:
    _need(body, 0, 4, "IKEv2 AUTH payload")
    value = body[4:]
    method = body[0]
    return {
        "authentication_method": method,
        "authentication_method_name": _AUTH_METHODS.get(method, f"auth-method-{method}"),
        "reserved_nonzero": any(body[1:4]),
        "auth_bytes": len(value),
        "auth_sha256": _hash(b"arenyxa-ike-auth/v1", value),
        "auth_retained": False,
    }


def _notify_payload(body: bytes) -> dict[str, Any]:
    _need(body, 0, 4, "IKEv2 Notify payload")
    protocol_id, spi_size, notify_type = struct.unpack_from("!BBH", body, 0)
    _need(body, 4, spi_size, "IKEv2 Notify SPI")
    spi = body[4:4 + spi_size]
    data = body[4 + spi_size:]
    row: dict[str, Any] = {
        "protocol_id": protocol_id,
        "protocol_name": _PROTOCOL_IDS.get(protocol_id, f"protocol-{protocol_id}"),
        "spi": spi.hex(),
        "spi_bytes": len(spi),
        "notify_type": notify_type,
        "notify_name": _NOTIFY_TYPES.get(notify_type, f"notify-{notify_type}"),
        "error_notification": 0 < notify_type < 16384,
        "notification_data_bytes": len(data),
    }
    if notify_type == 17 and len(data) == 2:
        row["suggested_key_exchange_method"] = struct.unpack("!H", data)[0]
    elif notify_type == 16393 and len(data) in {4, 8}:
        row["rekey_spi"] = data.hex()
    elif data:
        row.update({
            "notification_data_sha256": _hash(b"arenyxa-ike-notify/v1", data),
            "notification_data_retained": False,
        })
    return row


def _delete_payload(body: bytes) -> dict[str, Any]:
    _need(body, 0, 4, "IKEv2 Delete payload")
    protocol_id, spi_size, spi_count = struct.unpack_from("!BBH", body, 0)
    expected = 4 + spi_size * spi_count
    if expected != len(body):
        raise ValueError("invalid IKEv2 Delete SPI vector length")
    spis = [body[4 + index * spi_size:4 + (index + 1) * spi_size].hex() for index in range(spi_count)]
    return {
        "protocol_id": protocol_id,
        "protocol_name": _PROTOCOL_IDS.get(protocol_id, f"protocol-{protocol_id}"),
        "spi_size": spi_size,
        "spi_count": spi_count,
        "spis": spis[:256],
    }


def _traffic_selectors(body: bytes) -> dict[str, Any]:
    _need(body, 0, 4, "IKEv2 Traffic Selector payload")
    declared = body[0]
    cursor = 4
    rows: list[dict[str, Any]] = []
    malformed = False
    while cursor + 8 <= len(body) and len(rows) < 256:
        selector_type, protocol_id, selector_length, start_port, end_port = struct.unpack_from("!BBHHH", body, cursor)
        if selector_length < 8 or cursor + selector_length > len(body):
            malformed = True
            break
        value = body[cursor + 8:cursor + selector_length]
        row: dict[str, Any] = {
            "selector_type": selector_type,
            "protocol_id": protocol_id,
            "start_port": start_port,
            "end_port": end_port,
        }
        if selector_type == 7 and len(value) == 8:
            row.update({
                "address_family": "ipv4",
                "start_address": str(ipaddress.IPv4Address(value[:4])),
                "end_address": str(ipaddress.IPv4Address(value[4:])),
            })
        elif selector_type == 8 and len(value) == 32:
            row.update({
                "address_family": "ipv6",
                "start_address": str(ipaddress.IPv6Address(value[:16])),
                "end_address": str(ipaddress.IPv6Address(value[16:])),
            })
        else:
            row.update({
                "selector_data_bytes": len(value),
                "selector_data_sha256": _hash(b"arenyxa-ike-ts/v1", value),
                "selector_data_retained": False,
            })
        rows.append(row)
        cursor += selector_length
    if cursor != len(body):
        malformed = True
    return {
        "declared_selector_count": declared,
        "decoded_selector_count": len(rows),
        "selector_count_mismatch": declared != len(rows),
        "selectors": rows,
        "malformed": malformed,
    }


def _payload_body(payload_type: int, body: bytes) -> dict[str, Any]:
    if payload_type == 33:
        return _sa_payload(body)
    if payload_type == 34:
        return _ke_payload(body)
    if payload_type in {35, 36}:
        return _id_payload(body)
    if payload_type in {37, 38}:
        return _certificate_payload(body)
    if payload_type == 39:
        return _auth_payload(body)
    if payload_type == 40:
        return {
            "nonce_bytes": len(body),
            "nonce_sha256": _hash(b"arenyxa-ike-nonce/v1", body),
            "nonce_retained": False,
        }
    if payload_type == 41:
        return _notify_payload(body)
    if payload_type == 42:
        return _delete_payload(body)
    if payload_type == 43:
        return {
            "vendor_id_bytes": len(body),
            "vendor_id_sha256": _hash(b"arenyxa-ike-vendor/v1", body),
            "vendor_id_retained": False,
        }
    if payload_type in {44, 45}:
        return _traffic_selectors(body)
    if payload_type in {46, 53}:
        return {
            "encrypted_payload_bytes": len(body),
            "encrypted_payload_sha256": _hash(b"arenyxa-ike-encrypted/v1", body),
            "encrypted_payload_retained": False,
        }
    return {
        "payload_bytes": len(body),
        "payload_sha256": _hash(b"arenyxa-ike-opaque/v1", body),
        "payload_retained": False,
    }


def decode_ike_message(data: bytes) -> dict[str, Any]:
    nat_t = len(data) >= 4 and data[:4] == b"\x00\x00\x00\x00"
    cursor = 4 if nat_t else 0
    _need(data, cursor, 28, "IKE header")
    initiator_spi = data[cursor:cursor + 8].hex()
    responder_spi = data[cursor + 8:cursor + 16].hex()
    next_payload, version, exchange, flags, message_id, length = struct.unpack_from("!BBBBII", data, cursor + 16)
    if length < 28 or cursor + length > len(data):
        raise ValueError("invalid IKE message length")
    major = version >> 4
    minor = version & 0x0F
    row: dict[str, Any] = {
        "initiator_spi": initiator_spi,
        "responder_spi": responder_spi,
        "next_payload": next_payload,
        "next_payload_name": _IKE_PAYLOADS.get(next_payload, f"payload-{next_payload}"),
        "version_major": major,
        "version_minor": minor,
        "exchange_type": exchange,
        "exchange_name": _IKE_EXCHANGES.get(exchange, f"exchange-{exchange}"),
        "flags": flags,
        "initiator_flag": bool(flags & 0x08),
        "higher_version_flag": bool(flags & 0x10),
        "response_flag": bool(flags & 0x20),
        "reserved_flag_bits": flags & 0xC7,
        "message_id": message_id,
        "length": length,
        "nat_traversal_marker": nat_t,
        "payloads": [],
        "payload_chain_malformed": False,
        "encrypted_payload_present": False,
    }
    if major != 2:
        row.update({
            "deep_payload_decode": False,
            "message_sha256": _hash(b"arenyxa-ike-non-v2/v1", data[cursor:cursor + length]),
        })
        return row
    payload_type = next_payload
    payload_cursor = cursor + 28
    message_end = cursor + length
    payloads: list[dict[str, Any]] = []
    while payload_type and payload_cursor < message_end and len(payloads) < 256:
        if payload_cursor + 4 > message_end:
            row["payload_chain_malformed"] = True
            break
        following, critical_reserved, payload_length = struct.unpack_from("!BBH", data, payload_cursor)
        if payload_length < 4 or payload_cursor + payload_length > message_end:
            row["payload_chain_malformed"] = True
            break
        body = data[payload_cursor + 4:payload_cursor + payload_length]
        payload_row: dict[str, Any] = {
            "type": payload_type,
            "name": _IKE_PAYLOADS.get(payload_type, f"payload-{payload_type}"),
            "critical": bool(critical_reserved & 0x80),
            "reserved_bits": critical_reserved & 0x7F,
            "length": payload_length,
            "next_payload": following,
            "next_payload_name": _IKE_PAYLOADS.get(following, f"payload-{following}") if following else "none",
        }
        try:
            payload_row.update(_payload_body(payload_type, body))
        except (ValueError, struct.error, ipaddress.AddressValueError) as exc:
            payload_row.update({
                "malformed": True,
                "parse_error": str(exc),
                "body_bytes": len(body),
                "body_sha256": _hash(b"arenyxa-ike-malformed/v1", body),
                "body_retained": False,
            })
            row["payload_chain_malformed"] = True
        payloads.append(payload_row)
        payload_cursor += payload_length
        if payload_type in {46, 53}:
            row["encrypted_payload_present"] = True
            break
        payload_type = following
    if payload_cursor != message_end and not row["encrypted_payload_present"]:
        row["payload_chain_malformed"] = True
    row["payloads"] = payloads
    row["payload_count"] = len(payloads)
    row["deep_payload_decode"] = True
    return row


def decode_esp_packet(data: bytes, *, nat_traversal: bool = False) -> dict[str, Any]:
    cursor = 0
    if nat_traversal and len(data) >= 4 and data[:4] == b"\x00\x00\x00\x00":
        cursor = 4
    _need(data, cursor, 8, "ESP header")
    spi, sequence = struct.unpack_from("!II", data, cursor)
    encrypted = data[cursor + 8:]
    return {
        "spi": spi,
        "spi_hex": f"0x{spi:08x}",
        "sequence": sequence,
        "nat_traversal": nat_traversal,
        "encrypted_payload_bytes": len(encrypted),
        "encrypted_payload_sha256": _hash(b"arenyxa-esp-ciphertext/v1", encrypted),
        "encrypted_payload_retained": False,
    }


def decode_ah_packet(data: bytes) -> dict[str, Any]:
    _need(data, 0, 12, "AH header")
    next_header, payload_len, reserved = struct.unpack_from("!BBH", data, 0)
    length = (payload_len + 2) * 4
    if length < 12:
        raise ValueError("invalid AH header length")
    _need(data, 0, length, "AH header")
    spi, sequence = struct.unpack_from("!II", data, 4)
    icv = data[12:length]
    return {
        "next_header": next_header,
        "payload_length_field": payload_len,
        "header_length": length,
        "reserved": reserved,
        "spi": spi,
        "spi_hex": f"0x{spi:08x}",
        "sequence": sequence,
        "icv_bytes": len(icv),
        "icv_sha256": _hash(b"arenyxa-ah-icv/v1", icv),
        "icv_retained": False,
    }
