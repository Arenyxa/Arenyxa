from __future__ import annotations

from collections.abc import Callable
from typing import Any

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
    """Install only send-entry/exit and full-PGresult boundary instrumentation.

    The recorder supplies patch(), lease_row(), begin_or_get_boundary_call(), and
    thread-local state. No socket, libpq consume, wait machinery, or SQL is added.
    """

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

            return invoke_business_preserving(
                original, cur, args, kwargs, before=before, after=after
            )

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

        return invoke_business_preserving(
            original_check, cur, (results,), {}, before=before
        )

    recorder.patch(cursor_cls, "_check_results", check_results)
