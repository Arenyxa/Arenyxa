from __future__ import annotations

import hashlib
import secrets
from typing import Mapping

from arenyxa.compat import dataclass

TRACEPARENT_HEADER = "traceparent"
TRACESTATE_HEADER = "tracestate"
MAX_TRACESTATE_BYTES = 512


def _nonzero_hex(byte_count: int) -> str:
    while True:
        value = secrets.token_hex(byte_count)
        if any(ch != "0" for ch in value):
            return value


def _valid_hex(value: str, length: int) -> bool:
    return len(value) == length and any(ch != "0" for ch in value) and all(ch in "0123456789abcdef" for ch in value)


@dataclass(frozen=True, slots=True)
class TraceContext:
    trace_id: str
    span_id: str
    parent_span_id: str = ""
    sampled: bool = True
    tracestate: str = ""

    @property
    def trace_flags(self) -> str:
        return "01" if self.sampled else "00"

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags}"

    def headers(self) -> dict[str, str]:
        result = {TRACEPARENT_HEADER: self.traceparent}
        if self.tracestate:
            result[TRACESTATE_HEADER] = self.tracestate
        return result

    @classmethod
    def new(cls, *, sampled: bool = True, tracestate: str = "") -> "TraceContext":
        return cls(_nonzero_hex(16), _nonzero_hex(8), sampled=bool(sampled), tracestate=_sanitize_tracestate(tracestate))

    @classmethod
    def from_correlation(cls, correlation_id: str, *, sampled: bool = True) -> "TraceContext":
        raw = str(correlation_id).encode("utf-8", errors="replace")
        trace_id = hashlib.sha256(b"arenyxa-trace-v1\x00" + raw).hexdigest()[:32]
        if not any(ch != "0" for ch in trace_id):
            trace_id = "1" + trace_id[1:]
        return cls(trace_id, _nonzero_hex(8), sampled=bool(sampled))

    @classmethod
    def parse(cls, value: str | None, *, tracestate: str = "") -> "TraceContext | None":
        text = str(value or "").strip().casefold()
        parts = text.split("-")
        if len(parts) != 4 or parts[0] != "00":
            return None
        trace_id, span_id, flags = parts[1], parts[2], parts[3]
        if not _valid_hex(trace_id, 32) or not _valid_hex(span_id, 16):
            return None
        if len(flags) != 2 or any(ch not in "0123456789abcdef" for ch in flags):
            return None
        return cls(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id="",
            sampled=bool(int(flags, 16) & 0x01),
            tracestate=_sanitize_tracestate(tracestate),
        )


def _sanitize_tracestate(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    encoded = text.encode("ascii", errors="ignore")[:MAX_TRACESTATE_BYTES]
    sanitized = encoded.decode("ascii", errors="ignore")
    return sanitized if "\r" not in sanitized and "\n" not in sanitized else ""


def child_trace_context(parent: TraceContext | None, *, correlation_id: str = "") -> TraceContext:
    if parent is None:
        return TraceContext.from_correlation(correlation_id) if correlation_id else TraceContext.new()
    return TraceContext(
        trace_id=parent.trace_id,
        span_id=_nonzero_hex(8),
        parent_span_id=parent.span_id,
        sampled=parent.sampled,
        tracestate=parent.tracestate,
    )


def trace_context_from_headers(headers: Mapping[str, str], *, correlation_id: str = "") -> TraceContext:
    parent = TraceContext.parse(headers.get(TRACEPARENT_HEADER), tracestate=headers.get(TRACESTATE_HEADER, ""))
    return child_trace_context(parent, correlation_id=correlation_id)


def persisted_trace_fields(traceparent: str = "", tracestate: str = "") -> tuple[str, str]:
    """Normalize a durable job trace context or create a fresh W3C root."""
    state = _sanitize_tracestate(tracestate)
    parsed = TraceContext.parse(str(traceparent or ""), tracestate=state)
    if parsed is None:
        parsed = TraceContext.new(tracestate=state)
    return parsed.traceparent, parsed.tracestate
