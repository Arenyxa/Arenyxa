from __future__ import annotations

import os
from contextlib import nullcontext
from typing import Any, ContextManager, Mapping

from arenyxa.observability.trace_context import TraceContext

_CONFIGURED = False


def configure_otel_from_env(service_name: str = "arenyxa-enterprise-server") -> bool:
    """Configure an optional OTLP/HTTP exporter when the telemetry extra is installed.

    No network exporter is enabled implicitly. Operators must set
    ARENYXA_OTEL_EXPORTER_OTLP_ENDPOINT. Missing optional packages keep tracing local
    and W3C-compatible without weakening request handling.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return True
    endpoint = os.environ.get("ARENYXA_OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    if not endpoint:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return False
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _CONFIGURED = True
    return True


def server_span(
    name: str,
    context: TraceContext,
    attributes: Mapping[str, Any] | None = None,
) -> ContextManager[Any]:
    """Create an OpenTelemetry server span anchored to the validated W3C parent."""
    try:
        from opentelemetry import trace
        from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, TraceState
    except ImportError:
        return nullcontext()
    if not _CONFIGURED:
        return nullcontext()
    parent_span = context.parent_span_id or context.span_id
    parent = SpanContext(
        trace_id=int(context.trace_id, 16),
        span_id=int(parent_span, 16),
        is_remote=True,
        trace_flags=TraceFlags.SAMPLED if context.sampled else TraceFlags.DEFAULT,
        trace_state=TraceState(),
    )
    parent_context = trace.set_span_in_context(NonRecordingSpan(parent))
    tracer = trace.get_tracer("arenyxa.enterprise")
    return tracer.start_as_current_span(
        str(name),
        context=parent_context,
        kind=trace.SpanKind.SERVER,
        attributes=dict(attributes or {}),
    )


def internal_span(
    name: str,
    parent: TraceContext | None,
    attributes: Mapping[str, Any] | None = None,
) -> ContextManager[Any]:
    """Create an optional INTERNAL span rooted in a persisted W3C job context."""
    if parent is None or not _CONFIGURED:
        return nullcontext()
    try:
        from opentelemetry import trace
        from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags, TraceState
    except ImportError:
        return nullcontext()
    parent_context = trace.set_span_in_context(NonRecordingSpan(SpanContext(
        trace_id=int(parent.trace_id, 16),
        span_id=int(parent.span_id, 16),
        is_remote=True,
        trace_flags=TraceFlags.SAMPLED if parent.sampled else TraceFlags.DEFAULT,
        trace_state=TraceState(),
    )))
    tracer = trace.get_tracer("arenyxa.enterprise")
    return tracer.start_as_current_span(
        str(name),
        context=parent_context,
        kind=trace.SpanKind.INTERNAL,
        attributes=dict(attributes or {}),
    )
