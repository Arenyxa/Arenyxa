from __future__ import annotations

from typing import Any, Mapping


def _row(severity: str, code: str, title: str, detail: str, **evidence: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "title": title, "detail": detail, "evidence": evidence}


def analyze_l2tp_fields(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if int(fields.get("version") or 0) != 2:
        rows.append(_row(
            "warning", "L2TP_VERSION_UNSUPPORTED", "L2TP header version is not version 2",
            "The native L2TP decoder implements the RFC 2661 version-2 header and does not infer semantics for another version.",
            version=int(fields.get("version") or 0),
        ))
        return rows
    reserved = str(fields.get("reserved_flag_bits") or "0x0000")
    if reserved != "0x0000":
        rows.append(_row(
            "note", "L2TP_RESERVED_FLAGS_NONZERO", "L2TP reserved header flag bits are non-zero",
            "Reserved flag bits are expected to be zero in the RFC 2661 base header. Correlate capture integrity before inferring a peer defect.",
            reserved_flag_bits=reserved,
        ))
    if bool(fields.get("control")):
        if not bool(fields.get("control_required_header_fields_present")):
            rows.append(_row(
                "warning", "L2TP_CONTROL_HEADER_INCOMPLETE", "L2TP control header lacks required framing fields",
                "RFC 2661 control messages require Length and sequence fields and do not use the data-message offset field.",
                length_present=bool(fields.get("length_present")),
                sequence_present=bool(fields.get("sequence_present")),
                offset_present=bool(fields.get("offset_present")),
            ))
        if bool(fields.get("avp_chain_malformed")):
            rows.append(_row(
                "warning", "L2TP_AVP_CHAIN_MALFORMED", "L2TP control AVP vector is structurally inconsistent",
                "At least one AVP length or the final AVP boundary did not fit the declared L2TP message length.",
                avp_count=int(fields.get("avp_count") or 0),
            ))
        if fields.get("message_type") is not None and not bool(fields.get("message_type_first_avp")):
            rows.append(_row(
                "warning", "L2TP_MESSAGE_TYPE_NOT_FIRST", "L2TP Message Type AVP is not first",
                "The base L2TP control-message format requires Message Type to be the first AVP.",
                message_type=fields.get("message_type"), message_name=str(fields.get("message_name") or ""),
            ))
    return rows
