from __future__ import annotations

from typing import Any


def _segment_class(kinds: list[str | None]) -> str:
    if kinds == ["query"]:
        return "UNPREPARED_QUERY"
    if kinds == ["prepared_query"]:
        return "PREPARED_QUERY"
    if kinds == ["prepare", "prepared_query"]:
        return "PREPARE_PLUS_PREPARED_QUERY"
    return "OTHER"


def summarize_call(call: dict[str, Any]) -> dict[str, Any]:
    t0 = float(call["t0"])
    t6 = float(call["t6"])
    sends = list(call.get("send_marks") or [])
    ready = list(call.get("result_ready_marks") or [])
    kinds = [m.get("kind") for m in sends]

    event_order_valid = t6 >= t0 and len(ready) == 1 and bool(sends)
    t5 = float(ready[0]) if len(ready) == 1 else None
    if t5 is not None and not (t0 <= t5 <= t6):
        event_order_valid = False

    last = t0
    if event_order_valid:
        for mark in sends:
            try:
                begin = float(mark["begin"])
                end = float(mark["end"])
            except (KeyError, TypeError, ValueError):
                event_order_valid = False
                break
            if not (last <= begin <= end <= t5):
                event_order_valid = False
                break
            last = end

    out: dict[str, Any] = {
        "execute_ms": (t6 - t0) * 1000.0,
        "send_count": len(sends),
        "send_kinds": kinds,
        "segment_class": _segment_class(kinds),
        "result_ready_count": len(ready),
        "full_result_ready_at": t5,
        "event_order_valid": event_order_valid,
        "decomposition_valid": event_order_valid,
        "pre_result_ms": None,
        "post_result_ms": None,
        "pre_result_share": None,
        "post_result_share": None,
        "conservation_error_ms": None,
    }
    if not event_order_valid or t5 is None:
        return out

    pre = (t5 - t0) * 1000.0
    post = (t6 - t5) * 1000.0
    total = out["execute_ms"]
    out.update(
        pre_result_ms=pre,
        post_result_ms=post,
        pre_result_share=(pre / total if total > 0 else None),
        post_result_share=(post / total if total > 0 else None),
        conservation_error_ms=total - pre - post,
    )
    return out
