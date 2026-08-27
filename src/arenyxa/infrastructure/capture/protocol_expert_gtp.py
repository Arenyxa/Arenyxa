from __future__ import annotations

from typing import Any, Mapping


def _row(severity: str, code: str, title: str, detail: str, **evidence: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "title": title, "detail": detail, "evidence": evidence}


def analyze_gtp_fields(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    version = int(fields.get("version") or 0)
    if version == 1:
        if bool(fields.get("reserved_flag_bit")):
            rows.append(_row(
                "note", "GTPV1_RESERVED_FLAG_NONZERO", "GTPv1 reserved flag bit is non-zero",
                "The base GTPv1 header reserves this flag bit. Correlate peer implementation and capture integrity before drawing a security conclusion.",
            ))
        if bool(fields.get("extension_headers_malformed")):
            rows.append(_row(
                "warning", "GTPV1_EXTENSION_CHAIN_MALFORMED", "GTPv1 extension-header chain is malformed",
                "At least one extension header length or next-extension boundary exceeded the declared GTP packet length.",
                extension_header_count=int(fields.get("extension_header_count") or 0),
            ))
        if int(fields.get("message_type") or 0) == 255 and int(fields.get("teid") or 0) == 0:
            rows.append(_row(
                "warning", "GTPU_GPDU_ZERO_TEID", "GTP-U G-PDU carries a zero TEID",
                "A user-plane G-PDU normally identifies a tunnel endpoint with a non-zero TEID. This is a protocol consistency signal, not proof of malicious traffic.",
            ))
        extensions = fields.get("extension_headers") if isinstance(fields.get("extension_headers"), list) else []
        for extension in extensions[:64]:
            if not isinstance(extension, Mapping) or int(extension.get("type") or 0) != 0x85:
                continue
            if bool(extension.get("malformed")):
                rows.append(_row(
                    "warning", "GTPU_PDU_SESSION_CONTAINER_MALFORMED", "GTP-U PDU Session Container is malformed",
                    "The observed PDU Session Container could not be decoded within the extension-header boundary. This is a capture/protocol consistency signal.",
                    parse_error=str(extension.get("parse_error") or ""),
                ))
            elif bool(extension.get("reserved_pdu_type")):
                rows.append(_row(
                    "note", "GTPU_PDU_SESSION_RESERVED_TYPE", "GTP-U PDU Session Container uses a reserved PDU type",
                    "The fixed PDU Session Container prefix advertises a PDU type reserved by the decoded specification revision. Treat later octets as opaque unless a newer negotiated specification is established.",
                    pdu_type=int(extension.get("pdu_type") or 0),
                ))
            if int(extension.get("spare_bit") or 0):
                rows.append(_row(
                    "note", "GTPU_PDU_SESSION_SPARE_NONZERO", "GTP-U PDU Session Container spare bit is non-zero",
                    "A spare bit in the decoded downlink fixed prefix is non-zero. Correlate peer release and capture integrity before drawing a service or security conclusion.",
                    qfi=int(extension.get("qfi") or 0),
                ))
    elif version == 2:
        if int(fields.get("spare_flag_bits") or 0):
            rows.append(_row(
                "note", "GTPV2_SPARE_FLAGS_NONZERO", "GTPv2 spare flag bits are non-zero",
                "Spare flag bits in the base GTPv2-C header are expected to be zero.",
                spare_flag_bits=int(fields.get("spare_flag_bits") or 0),
            ))
        if int(fields.get("sequence_spare") or 0):
            rows.append(_row(
                "note", "GTPV2_SEQUENCE_SPARE_NONZERO", "GTPv2 sequence-header spare octet is non-zero",
                "The spare octet following the 24-bit sequence number is expected to be zero in the base header.",
                sequence_spare=int(fields.get("sequence_spare") or 0),
            ))
        if bool(fields.get("information_elements_malformed")):
            rows.append(_row(
                "warning", "GTPV2_IE_VECTOR_MALFORMED", "GTPv2 Information Element vector is malformed",
                "An IE length or final boundary did not fit the declared GTPv2-C message length.",
                information_element_count=int(fields.get("information_element_count") or 0),
            ))
        for ie in fields.get("information_elements", ()) if isinstance(fields.get("information_elements"), list) else ():
            if not isinstance(ie, Mapping) or int(ie.get("type") or 0) != 2 or "cause" not in ie:
                continue
            if not bool(ie.get("response_accepted")):
                rows.append(_row(
                    "warning", "GTPV2_NON_ACCEPTED_CAUSE", "GTPv2 response carries a non-accepted Cause",
                    "The control-plane peer reported a non-accepted procedure outcome. This is a protocol/service state signal, not by itself evidence of attack.",
                    cause=int(ie.get("cause") or 0), message_name=str(fields.get("message_name") or ""),
                ))
    return rows
