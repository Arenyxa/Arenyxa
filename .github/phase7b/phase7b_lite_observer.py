from __future__ import annotations

from collections.abc import Callable
from typing import Any

import phase6_minimal
import phase6_trace as p6
from phase7b_lite_core import summarize_call

LEASE_TOKEN = b"WITH eligible_worker AS"


def _observe_safely(callback: Callable[[], Any] | None) -> None:
    if callback is None:
        return
    try:
        callback()
    except Exception:
        return


def invoke_business_preserving(
    original: Callable[..., Any],
    cur: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    before: Callable[[], Any] | None = None,
    after: Callable[[], Any] | None = None,
) -> Any:
    """Run diagnostics fail-open while preserving business args/result/exception."""
    _observe_safely(before)
    try:
        return original(cur, *args, **kwargs)
    finally:
        _observe_safely(after)


def _query_bytes(pgq: Any) -> bytes:
    q = getattr(pgq, "query", b"")
    if isinstance(q, bytes):
        return q
    if isinstance(q, bytearray):
        return bytes(q)
    try:
        return bytes(q)
    except Exception:
        return str(q).encode("utf-8", "replace")


def install_boundary_hooks(
    recorder: Any,
    cursor_cls: type,
    clock: Callable[[], float],
    *,
    lease_token: bytes = LEASE_TOKEN,
) -> None:
    """Install only send-entry/exit and full-PGresult boundary instrumentation."""

    def patch_send(method_name: str, kind: str, pgq_pos: int) -> None:
        original = getattr(cursor_cls, method_name)

        def wrapped(cur: Any, *args: Any, **kwargs: Any) -> Any:
            state: dict[str, Any] = {}

            def before() -> None:
                row = recorder.lease_row()
                if row is None:
                    return
                pgq = args[pgq_pos] if len(args) > pgq_pos else kwargs.get("query") or kwargs.get("pgq")
                if pgq is None or lease_token not in _query_bytes(pgq):
                    return
                call = recorder.begin_or_get_boundary_call(row)
                mark = {"kind": kind, "begin": clock(), "end": None}
                call["send_marks"].append(mark)
                state["mark"] = mark

            def after() -> None:
                mark = state.get("mark")
                if mark is not None and mark.get("end") is None:
                    mark["end"] = clock()

            return invoke_business_preserving(original, cur, args, kwargs, before=before, after=after)

        recorder.patch(cursor_cls, method_name, wrapped)

    patch_send("_execute_send", "query", 0)
    patch_send("_send_prepare", "prepare", 1)
    patch_send("_send_query_prepared", "prepared_query", 1)

    original_check = getattr(cursor_cls, "_check_results")

    def check_results(cur: Any, results: Any) -> Any:
        def before() -> None:
            call = getattr(recorder.tls, "phase7b_call", None)
            row = recorder.lease_row()
            if call is None or row is None or call.get("row_identity") != id(row):
                return
            call["result_ready_marks"].append(clock())
            recorder.tls.phase7b_call = None

        return invoke_business_preserving(original_check, cur, (results,), {}, before=before)

    recorder.patch(cursor_cls, "_check_results", check_results)


class BoundaryLiteRecorder(phase6_minimal.MinimalRecorder):
    """Phase6-minimal plus only T1 and conservative T5 boundary timestamps."""

    def begin_or_get_boundary_call(self, row: dict) -> dict:
        call = getattr(self.tls, "phase7b_call", None)
        if call is None or call.get("row_identity") != id(row) or call.get("result_ready_marks"):
            call = {
                "row_identity": id(row),
                "send_marks": [],
                "result_ready_marks": [],
                "anomalies": [],
            }
            row.setdefault("phase7b_calls", []).append(call)
            self.tls.phase7b_call = call
        return call

    def install(self) -> None:
        super().install()
        if not self.full:
            return
        import psycopg._cursor_base as cb
        install_boundary_hooks(self, cb.BaseCursor, p6.PC)

    def result(self) -> dict:
        result = super().result()
        call_count = 0
        valid_count = 0
        for row in result["cycles"]:
            calls = row.get("phase7b_calls") or []
            lease_sql = [x for x in (row.get("sql") or []) if x[0] == "lease_fast"]
            if len(calls) == 1 and len(lease_sql) == 1:
                call = calls[0]
                _, t0, t6, backend_pid = lease_sql[0]
                call["t0"] = t0
                call["t6"] = t6
                call["backend_pid"] = backend_pid
                call.pop("row_identity", None)
                call["summary"] = summarize_call(call)
                call_count += 1
                if call["summary"]["decomposition_valid"]:
                    valid_count += 1
            elif calls:
                for call in calls:
                    call.pop("row_identity", None)
                    call.setdefault("anomalies", []).append(
                        f"identity_mismatch:calls={len(calls)}:lease_fast={len(lease_sql)}"
                    )
        result["phase7b"] = {
            "call_count": call_count,
            "valid_decomposition_count": valid_count,
            "t0": "Phase6-minimal existing lease_fast Connection.execute begin",
            "t1": "target cursor send method entry; not PQflush complete",
            "t2": "NOT DIRECTLY OBSERVABLE",
            "t3": "NOT DIRECTLY OBSERVABLE",
            "t4": "NOT DIRECTLY OBSERVABLE",
            "t5": "BaseCursor._check_results entry after main execute(pgconn) returned PGresult list; optional prepared-cache validate can precede T5",
            "t6": "Phase6-minimal existing lease_fast Connection.execute end",
            "extra_sql": False,
            "socket_read_by_observer": False,
            "wait_generator_wrapped": False,
            "schedstat": False,
            "extra_execute_rusage": False,
            "diagnostic_fail_open": True,
        }
        return result
