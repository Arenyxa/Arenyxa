"""Phase 7 offline analyzer v2 for strict post-flush T3_driver."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import phase7_analyze as base

_original_attr_record = base.attr_record


def corrected_attr_record(row, run_no: int, run_p99: float):
    rec = _original_attr_record(row, run_no, run_p99)
    if rec is None:
        return None

    contexts = row.get("phase7_executes") or []
    if len(contexts) != 1:
        return None
    ctx = contexts[0]
    exchanges = ctx.get("exchanges") or []
    business = [
        e for e in exchanges
        if e.get("kind") in ("query_unprepared", "query_prepared")
    ]
    if len(business) != 1:
        return None
    ex = business[0]
    t2 = ex.get("flush_end")
    t3 = ex.get("first_postflush_driver_read_ready")
    t5 = ex.get("end")
    if t2 is None or t5 is None:
        return None

    old_t3 = ex.get("first_driver_read_ready")
    rec["first_driver_read_ready_observed"] = t3 is not None
    rec["driver_first_read_wait_ms"] = (
        (t3 - t2) * 1000.0 if t3 is not None else None
    )
    rec["first_read_to_full_result_ms"] = (
        (t5 - t3) * 1000.0 if t3 is not None else None
    )
    rec["postflush_read_ready_events"] = int(
        ex.get("postflush_read_ready_events", 0)
    )
    rec["any_driver_read_ready_observed"] = old_t3 is not None
    rec["preflush_driver_read_observed"] = bool(
        old_t3 is not None and old_t3 < t2
    )
    rec["preflush_first_read_offset_ms"] = (
        (old_t3 - t2) * 1000.0
        if old_t3 is not None and old_t3 < t2
        else None
    )
    return rec


base.attr_record = corrected_attr_record


def _arg_value(name: str) -> str | None:
    try:
        i = sys.argv.index(name)
        return sys.argv[i + 1]
    except (ValueError, IndexError):
        return None


if __name__ == "__main__":
    base.main()
    out = _arg_value("--out")
    if out:
        summary_path = Path(out) / "PHASE7_SUMMARY.json"
        if summary_path.exists():
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            data["semantic_limits"].update({
                "T3_kernel_first_readable": "NOT DIRECTLY OBSERVABLE",
                "T3_driver_observed_read_ready": (
                    "MEASURED only for the first psycopg driver read-ready "
                    "event observed after libpq flush completed"
                ),
                "T3_preflush_read_ready": (
                    "CONTROL ONLY; not used as request-send -> response-ready boundary"
                ),
                "T4_PQconsumeInput": "NOT DIRECTLY OBSERVABLE",
            })
            data["analysis_version"] = "phase7_analyze_v2_postflush_t3"
            summary_path.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
