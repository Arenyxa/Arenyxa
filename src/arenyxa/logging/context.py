from __future__ import annotations

import contextvars

trace_id = contextvars.ContextVar("trace_id", default=None)
request_id = contextvars.ContextVar("request_id", default=None)


def set_trace_context(trace: str | None = None, request: str | None = None) -> None:
    if trace:
        trace_id.set(trace)
    if request:
        request_id.set(request)
