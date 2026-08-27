from __future__ import annotations

from typing import Any, Mapping


_KNOWN_OPTIONS = {
    1, 3, 4, 5, 6, 7, 8, 11, 12, 14, 15, 17, 20, 23, 27, 28, 35, 39, 60, 252, 258, 292,
}


def _row(severity: str, code: str, title: str, detail: str, **evidence: Any) -> dict[str, Any]:
    return {"severity": severity, "code": code, "title": title, "detail": detail, "evidence": evidence}


def analyze_coap_fields(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if int(fields.get("version") or 0) != 1:
        rows.append(_row(
            "warning", "COAP_VERSION_UNEXPECTED", "Unexpected CoAP version",
            "The fixed header does not advertise CoAP version 1. Treat this as protocol/capture evidence rather than an attack conclusion.",
            version=fields.get("version"),
        ))
    code = int(fields.get("code") or 0)
    token_length = int(fields.get("token_length") or 0)
    option_count = int(fields.get("option_count") or 0)
    payload_bytes = int(fields.get("payload_bytes") or 0)
    if code == 0 and (token_length or option_count or payload_bytes):
        rows.append(_row(
            "warning", "COAP_EMPTY_MESSAGE_HAS_CONTENT", "CoAP Empty message carries content",
            "A 0.00 Empty message was observed with token, option, or payload content. This is a message-format diagnostic.",
            token_length=token_length, option_count=option_count, payload_bytes=payload_bytes,
        ))
    unknown_critical: list[int] = []
    block_transport_specific: list[int] = []
    options = fields.get("options") if isinstance(fields.get("options"), list) else []
    for option in options[:256]:
        if not isinstance(option, Mapping):
            continue
        number = int(option.get("number") or 0)
        if number not in _KNOWN_OPTIONS and bool(option.get("critical")):
            unknown_critical.append(number)
        if number in {23, 27} and bool(option.get("transport_specific_size")):
            block_transport_specific.append(number)
    if unknown_critical:
        rows.append(_row(
            "note", "COAP_UNKNOWN_CRITICAL_OPTION", "Unknown critical CoAP option observed",
            "An odd-numbered option not recognized by the native decoder was observed. Endpoint behavior depends on option support; this is interoperability evidence.",
            option_numbers=sorted(set(unknown_critical))[:32],
        ))
    if block_transport_specific:
        rows.append(_row(
            "note", "COAP_BLOCK_SZX_TRANSPORT_SPECIFIC", "Transport-specific Block size exponent observed",
            "A Block1/Block2 option used SZX=7. Interpret it with the actual CoAP transport profile rather than assuming the classic UDP block size semantics.",
            option_numbers=sorted(set(block_transport_specific)),
        ))
    return rows
