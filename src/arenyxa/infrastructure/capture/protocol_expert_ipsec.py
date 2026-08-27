from __future__ import annotations

from typing import Any, Mapping


_DEPRECATED_IKE_OFFERS = {
    "ENCR_DES_IV64",
    "ENCR_DES",
    "PRF_HMAC_MD5",
    "AUTH_HMAC_MD5_96",
}


def _row(severity: str, code: str, title: str, detail: str, **evidence: Any) -> dict[str, Any]:
    return {
        "severity": severity,
        "code": code,
        "title": title,
        "detail": detail,
        "evidence": evidence,
    }


def analyze_ipsec_fields(protocol: str, fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    if protocol == "ike":
        return _ike(fields)
    if protocol == "esp":
        return _esp(fields)
    if protocol == "ah":
        return _ah(fields)
    return []


def _ike(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    major = int(fields.get("version_major") or 0)
    if major != 2:
        rows.append(_row(
            "info", "IKE_NON_V2_HEADER_ONLY", "IKE message is not IKEv2",
            "Only bounded header metadata is retained for non-IKEv2 messages; no IKEv1 negotiation semantics are inferred.",
            version_major=major,
        ))
        return rows
    reserved_flags = int(fields.get("reserved_flag_bits") or 0)
    if reserved_flags:
        rows.append(_row(
            "warning", "IKEV2_RESERVED_FLAGS_NONZERO", "IKEv2 reserved header flag bits are non-zero",
            "Reserved flag bits are unexpected. Correlate both directions and capture integrity before treating the message as malformed.",
            reserved_flag_bits=reserved_flags,
        ))
    if bool(fields.get("payload_chain_malformed")):
        rows.append(_row(
            "warning", "IKEV2_PAYLOAD_CHAIN_MALFORMED", "IKEv2 payload chain is structurally inconsistent",
            "At least one generic payload length, nested structure, or payload-chain boundary was invalid or truncated.",
            exchange_name=str(fields.get("exchange_name") or ""), message_id=int(fields.get("message_id") or 0),
        ))
    weak_offers: set[str] = set()
    for payload in fields.get("payloads", ()) if isinstance(fields.get("payloads"), list) else ():
        if not isinstance(payload, Mapping):
            continue
        name = str(payload.get("name") or "")
        if bool(payload.get("critical")) and name.startswith("payload-"):
            rows.append(_row(
                "warning", "IKEV2_UNKNOWN_CRITICAL_PAYLOAD", "Unknown critical IKEv2 payload observed",
                "The sender marked an unrecognized payload as critical. A compliant peer may reject the message if it does not understand that payload.",
                payload_type=int(payload.get("type") or 0),
            ))
        if name == "SA":
            if bool(payload.get("malformed")) or bool(payload.get("malformed")):
                rows.append(_row(
                    "warning", "IKEV2_SA_MALFORMED", "IKEv2 Security Association proposal is malformed",
                    "Proposal/Transform nesting or declared lengths did not form a consistent bounded SA payload.",
                ))
            proposals = payload.get("proposals") if isinstance(payload.get("proposals"), list) else []
            for proposal in proposals[:64]:
                if not isinstance(proposal, Mapping):
                    continue
                if bool(proposal.get("transform_count_mismatch")):
                    rows.append(_row(
                        "warning", "IKEV2_TRANSFORM_COUNT_MISMATCH", "IKEv2 proposal transform count does not match decoded transforms",
                        "The proposal's declared transform count differs from the structurally decoded transform vector.",
                        proposal_number=int(proposal.get("proposal_number") or 0),
                    ))
                transforms = proposal.get("transforms") if isinstance(proposal.get("transforms"), list) else []
                for transform in transforms[:128]:
                    if isinstance(transform, Mapping) and str(transform.get("id_name") or "") in _DEPRECATED_IKE_OFFERS:
                        weak_offers.add(str(transform["id_name"]))
        elif name == "NOTIFY" and bool(payload.get("error_notification")):
            rows.append(_row(
                "warning", "IKEV2_ERROR_NOTIFY", "IKEv2 error notification observed",
                "The peer emitted an IKEv2 error Notify. This is a negotiation/state signal, not by itself evidence of attack.",
                notify_type=int(payload.get("notify_type") or 0), notify_name=str(payload.get("notify_name") or ""),
            ))
        elif name == "AUTH" and int(payload.get("authentication_method") or 0) == 13:
            rows.append(_row(
                "note", "IKEV2_NULL_AUTHENTICATION", "IKEv2 NULL Authentication method observed",
                "NULL Authentication is an explicit IKEv2 authentication mode. Validate that it is expected for the deployed profile before drawing a security conclusion.",
            ))
    if weak_offers:
        rows.append(_row(
            "note", "IKEV2_DEPRECATED_TRANSFORM_OFFERED", "Deprecated IKEv2 transform offered",
            "The SA proposal advertised one or more deprecated transform identifiers. This records an offer only; it does not claim that the peer selected the transform.",
            transforms=sorted(weak_offers),
        ))
    return rows[:128]


def _esp(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if int(fields.get("spi") or 0) == 0:
        rows.append(_row(
            "warning", "ESP_ZERO_SPI", "ESP packet carries SPI zero",
            "SPI zero is reserved and should not be transmitted as a normal ESP Security Association identifier.",
        ))
    if int(fields.get("sequence") or 0) == 0:
        rows.append(_row(
            "note", "ESP_ZERO_SEQUENCE", "ESP packet carries sequence number zero",
            "ESP sequence counters normally begin with the first transmitted packet at one. Correlate SA establishment and capture completeness before treating this as invalid traffic.",
        ))
    return rows


def _ah(fields: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if int(fields.get("reserved") or 0):
        rows.append(_row(
            "warning", "AH_RESERVED_NONZERO", "AH reserved field is non-zero",
            "The AH reserved field is defined to be zero on transmission.", reserved=int(fields.get("reserved") or 0),
        ))
    if int(fields.get("spi") or 0) == 0:
        rows.append(_row(
            "warning", "AH_ZERO_SPI", "AH packet carries SPI zero",
            "SPI zero is reserved and should not be sent on the wire as a normal AH Security Association identifier.",
        ))
    if int(fields.get("sequence") or 0) == 0:
        rows.append(_row(
            "note", "AH_ZERO_SEQUENCE", "AH packet carries sequence number zero",
            "AH sequence counters normally begin at one for the first transmitted packet on a Security Association.",
        ))
    return rows
