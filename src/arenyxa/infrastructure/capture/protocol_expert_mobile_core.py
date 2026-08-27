from __future__ import annotations

from typing import Any, Mapping


def _row(severity: str, code: str, title: str, detail: str, **evidence: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "title": title, "detail": detail, "evidence": evidence}


def analyze_pfcp_fields(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if int(fields.get("version") or 0) != 1:
        rows.append(_row(
            "warning", "PFCP_VERSION_UNEXPECTED", "Unexpected PFCP version",
            "The PFCP header does not advertise version 1. Correlate peer implementation and capture integrity before drawing a security conclusion.",
            version=int(fields.get("version") or 0),
        ))
    if int(fields.get("spare_flag_bits") or 0):
        rows.append(_row(
            "note", "PFCP_SPARE_FLAGS_NONZERO", "PFCP spare header bits are non-zero",
            "Reserved/spare header bits were observed with non-zero values.",
            spare_flag_bits=int(fields.get("spare_flag_bits") or 0),
        ))
    if int(fields.get("sequence_spare") or 0):
        rows.append(_row(
            "note", "PFCP_SEQUENCE_SPARE_NONZERO", "PFCP sequence-header spare bits are non-zero",
            "The low-order spare bits following the PFCP sequence number are non-zero.",
            sequence_spare=int(fields.get("sequence_spare") or 0),
        ))
    if bool(fields.get("information_elements_malformed")):
        rows.append(_row(
            "warning", "PFCP_IE_VECTOR_MALFORMED", "PFCP Information Element vector is malformed",
            "An IE length or nested IE boundary did not fit within the declared PFCP message length.",
            information_element_count=int(fields.get("information_element_count") or 0),
        ))
    ies = fields.get("information_elements") if isinstance(fields.get("information_elements"), list) else []
    for ie in ies[:1024]:
        if not isinstance(ie, Mapping):
            continue
        ie_type = int(ie.get("type") or 0)
        if ie_type == 19 and ie.get("cause") is not None and not bool(ie.get("request_accepted")):
            rows.append(_row(
                "warning", "PFCP_NON_ACCEPTED_CAUSE", "PFCP response carries a rejection Cause",
                "The peer reported a non-accepted PFCP procedure outcome. This is service/control-plane outcome evidence and does not establish malicious activity.",
                cause=int(ie.get("cause") or 0), message_name=str(fields.get("message_name") or ""),
            ))
        elif ie_type == 21 and bool(ie.get("choose_id_without_choose")):
            rows.append(_row(
                "warning", "PFCP_FTEID_CHID_WITHOUT_CH", "PFCP F-TEID CHOOSE ID appears without CHOOSE",
                "The F-TEID CHID flag is meaningful only together with the CH flag.",
            ))
        elif ie_type == 21 and bool(ie.get("address_family_missing")):
            rows.append(_row(
                "warning", "PFCP_FTEID_ADDRESS_FAMILY_MISSING", "PFCP F-TEID has no V4/V6 family flag",
                "At least one F-TEID address-family flag is expected to identify or request the tunnel endpoint address family.",
            ))
        elif ie_type == 53 and bool(ie.get("metric_out_of_range")):
            rows.append(_row(
                "note", "PFCP_METRIC_OUT_OF_RANGE", "PFCP Metric exceeds the defined percentage range",
                "The observed Metric value is above 100 and should be interpreted cautiously.",
                metric=int(ie.get("metric") or 0),
            ))
    return rows


def analyze_diameter_fields(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if int(fields.get("version") or 0) != 1:
        rows.append(_row(
            "warning", "DIAMETER_VERSION_UNEXPECTED", "Unexpected Diameter version",
            "The Diameter base header does not advertise version 1.",
            version=int(fields.get("version") or 0),
        ))
    if int(fields.get("reserved_flag_bits") or 0):
        rows.append(_row(
            "note", "DIAMETER_RESERVED_FLAGS_NONZERO", "Diameter reserved command flags are non-zero",
            "Reserved Diameter command flag bits were observed with non-zero values.",
            reserved_flag_bits=int(fields.get("reserved_flag_bits") or 0),
        ))
    if bool(fields.get("avps_malformed")):
        rows.append(_row(
            "warning", "DIAMETER_AVP_VECTOR_MALFORMED", "Diameter AVP vector is malformed",
            "An AVP length, vendor header, padding boundary, or grouped AVP boundary did not fit the declared Diameter message length.",
            avp_count=int(fields.get("avp_count") or 0),
        ))
    if bool(fields.get("error")):
        rows.append(_row(
            "warning", "DIAMETER_PROTOCOL_ERROR_ANSWER", "Diameter answer carries the protocol-error flag",
            "The Diameter E bit indicates a protocol-error answer. Inspect Result-Code or Experimental-Result evidence for the reported outcome.",
            command_name=str(fields.get("command_name") or ""),
        ))
    avps = fields.get("avps") if isinstance(fields.get("avps"), list) else []
    for avp in avps[:1024]:
        if not isinstance(avp, Mapping):
            continue
        if int(avp.get("reserved_flag_bits") or 0):
            rows.append(_row(
                "note", "DIAMETER_AVP_RESERVED_FLAGS_NONZERO", "Diameter AVP reserved flags are non-zero",
                "Reserved AVP flag bits were observed with non-zero values.",
                avp_code=int(avp.get("code") or 0), reserved_flag_bits=int(avp.get("reserved_flag_bits") or 0),
            ))
        if int(avp.get("code") or 0) == 268 and avp.get("unsigned32") is not None:
            result = int(avp.get("unsigned32") or 0)
            if result >= 3000:
                rows.append(_row(
                    "warning", "DIAMETER_NON_SUCCESS_RESULT", "Diameter answer carries a non-success Result-Code",
                    "The Result-Code is outside the 2xxx success class. This is AAA/control-plane outcome evidence and does not establish malicious activity.",
                    result_code=result, command_name=str(fields.get("command_name") or ""),
                ))
    return rows
