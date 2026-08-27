from __future__ import annotations

import hashlib
import struct
from typing import Any


_GTPU_EXTENSION_NAMES = {
    0x03: "long-pdcp-pdu-number",
    0x04: "pdu-set-information",
    0x20: "service-class-indicator",
    0x40: "udp-port",
    0x81: "ran-container",
    0x82: "long-pdcp-pdu-number-legacy",
    0x83: "xw-ran-container",
    0x84: "nr-ran-container",
    0x85: "pdu-session-container",
    0x86: "pdu-set-information-container",
    0xC0: "pdcp-pdu-number",
}


def _digest(namespace: str, value: bytes) -> str:
    return hashlib.sha256(namespace.encode("ascii") + b"\x00" + value).hexdigest()


def _opaque(value: bytes, *, namespace: str = "arenyxa-gtpu-extension/v1") -> dict[str, Any]:
    return {
        "content_bytes": len(value),
        "content_sha256": _digest(namespace, value),
        "content_retained": False,
    }


def _decode_pdu_session_container(value: bytes) -> dict[str, Any]:
    """Decode the stable two-octet PDU Session Information prefix from TS 38.415.

    Optional fields after the fixed prefix remain hash-only unless their presence and
    length can be established unambiguously from the fixed flags. This keeps packet
    evidence useful without inventing structure for future-extension octets.
    """
    if len(value) < 2:
        raise ValueError("truncated GTP-U PDU Session Container")
    first = value[0]
    second = value[1]
    pdu_type = (first >> 4) & 0x0F
    row: dict[str, Any] = {
        "pdu_type": pdu_type,
        "qfi": second & 0x3F,
        "fixed_prefix_bytes": 2,
    }
    if pdu_type == 0:
        row.update({
            "pdu_type_name": "dl-pdu-session-information",
            "direction": "downlink",
            "qos_monitoring_packet": bool(first & 0x08),
            "sequence_number_present": bool(first & 0x04),
            "mbs_sequence_number_present": bool(first & 0x02),
            "spare_bit": first & 0x01,
            "paging_policy_present": bool(second & 0x80),
            "reflective_qos_indicator": bool(second & 0x40),
        })
        if bool(second & 0x80) and len(value) >= 3:
            # PPI is the high three bits of the optional third octet. The remaining
            # flags in that octet are intentionally not decoded here because their
            # interpretation depends on the negotiated/release feature set.
            row["paging_policy_indicator"] = (value[2] >> 5) & 0x07
    elif pdu_type == 1:
        row.update({
            "pdu_type_name": "ul-pdu-session-information",
            "direction": "uplink",
            "qos_monitoring_packet": bool(first & 0x08),
            "dl_delay_indicator": bool(first & 0x04),
            "ul_delay_indicator": bool(first & 0x02),
            "sequence_number_present": bool(first & 0x01),
            "n3_n9_delay_indicator": bool(second & 0x80),
            "new_ie_flag": bool(second & 0x40),
        })
    else:
        row.update({
            "pdu_type_name": f"reserved-{pdu_type}",
            "reserved_pdu_type": True,
        })
    if len(value) > 2:
        row.update(_opaque(value[2:], namespace="arenyxa-gtpu-pdu-session-optional/v1"))
    else:
        row.update({"content_bytes": 0, "content_sha256": None, "content_retained": False})
    return row


def decode_gtpu_extension(extension_type: int, value: bytes) -> dict[str, Any]:
    """Return bounded, privacy-preserving structure for a GTP-U extension header."""
    current = int(extension_type) & 0xFF
    body = bytes(value)
    row: dict[str, Any] = {
        "type_name": _GTPU_EXTENSION_NAMES.get(current, f"extension-0x{current:02x}"),
    }
    if current == 0x40:
        if len(body) < 2:
            raise ValueError("truncated GTP-U UDP Port extension")
        row["udp_port"] = struct.unpack_from("!H", body, 0)[0]
        if len(body) > 2:
            row.update(_opaque(body[2:], namespace="arenyxa-gtpu-udp-port-trailing/v1"))
        else:
            row.update({"content_bytes": 0, "content_sha256": None, "content_retained": False})
        return row
    if current == 0x85:
        row.update(_decode_pdu_session_container(body))
        return row
    row.update(_opaque(body))
    return row
