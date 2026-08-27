from __future__ import annotations

from collections import Counter
from typing import Any, Iterable, Mapping


_MAX_CORRELATIONS = 4096


def _ints(value: Any) -> list[int]:
    if not isinstance(value, list):
        return []
    result: list[int] = []
    for item in value[:256]:
        try:
            result.append(int(item))
        except (TypeError, ValueError, OverflowError):
            continue
    return result


def build_pfcp_gtpu_qos_correlations(
    confirmed_rule_events: Iterable[Mapping[str, Any]],
    gtpu_teids: Counter[int],
    gtpu_qfis: Mapping[int, Counter[int]],
) -> list[dict[str, Any]]:
    """Join confirmed PFCP PDR/QER evidence to observed GTP-U TEID/QFI evidence.

    Equality is reported only as passive correlation. Absence of a user-plane QFI in
    a capture is not treated as configuration failure because capture position,
    direction, handover, and sampling can make the observation incomplete.
    """
    qer_qfis: dict[int, set[int]] = {}
    result: list[dict[str, Any]] = []
    for event in confirmed_rule_events:
        kind = str(event.get("rule_kind") or "")
        operation = str(event.get("operation") or "")
        qer_ids = _ints(event.get("qer_ids"))
        event_qfis = set(_ints(event.get("qfis")))
        if kind == "qer":
            for qer_id in qer_ids:
                if operation == "remove":
                    qer_qfis.pop(qer_id, None)
                elif event_qfis:
                    qer_qfis.setdefault(qer_id, set()).update(event_qfis)
            continue
        if kind != "pdr" or operation == "remove":
            continue
        resolved_qfis = set(_ints(event.get("resolved_qfis")))
        for qer_id in qer_ids:
            resolved_qfis.update(qer_qfis.get(qer_id, ()))
        raw_fteids = event.get("fteids")
        if not resolved_qfis or not isinstance(raw_fteids, list):
            continue
        for fteid in raw_fteids[:256]:
            if not isinstance(fteid, Mapping):
                continue
            try:
                teid = int(fteid.get("teid") or 0)
            except (TypeError, ValueError, OverflowError):
                continue
            if not teid:
                continue
            observed_qfi_counts = gtpu_qfis.get(teid, Counter())
            for qfi in sorted(resolved_qfis):
                if len(result) >= _MAX_CORRELATIONS:
                    return result
                qfi_packets = int(observed_qfi_counts.get(qfi, 0))
                teid_packets = int(gtpu_teids.get(teid, 0))
                if qfi_packets:
                    status = "teid-and-qfi-observed"
                elif teid_packets:
                    status = "teid-observed-qfi-not-observed"
                else:
                    status = "control-plane-only"
                result.append({
                    "teid": teid,
                    "teid_hex": f"0x{teid:08x}",
                    "qfi": qfi,
                    "pdr_ids": _ints(event.get("pdr_ids")),
                    "qer_ids": qer_ids,
                    "network_instances": list(event.get("network_instances") or ())[:64],
                    "request_seid": event.get("request_seid"),
                    "gtpu_packets": teid_packets,
                    "gtpu_qfi_packets": qfi_packets,
                    "correlation_status": status,
                })
    return result
