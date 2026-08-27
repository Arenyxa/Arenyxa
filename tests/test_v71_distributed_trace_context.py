from __future__ import annotations

from arenyxa.observability.trace_context import TraceContext, child_trace_context, trace_context_from_headers


def test_trace_context_from_correlation_is_stable_at_trace_level_and_rotates_span() -> None:
    first = TraceContext.from_correlation("job:abc")
    second = TraceContext.from_correlation("job:abc")
    assert first.trace_id == second.trace_id
    assert first.span_id != second.span_id
    assert len(first.trace_id) == 32
    assert len(first.span_id) == 16


def test_incoming_w3c_traceparent_creates_child_span_and_preserves_sampling() -> None:
    incoming = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
    child = trace_context_from_headers({"traceparent": incoming, "tracestate": "vendor=value"}, correlation_id="fallback")
    assert child.trace_id == "0123456789abcdef0123456789abcdef"
    assert child.parent_span_id == "0123456789abcdef"
    assert child.span_id != child.parent_span_id
    assert child.sampled is True
    assert child.tracestate == "vendor=value"


def test_malformed_or_zero_traceparent_fails_closed_to_new_valid_context() -> None:
    child = trace_context_from_headers({"traceparent": "00-00000000000000000000000000000000-0000000000000000-01"}, correlation_id="safe")
    expected = TraceContext.from_correlation("safe")
    assert child.trace_id == expected.trace_id
    assert child.parent_span_id == ""


def test_child_context_preserves_trace_and_records_parent() -> None:
    parent = TraceContext.new(sampled=False)
    child = child_trace_context(parent)
    assert child.trace_id == parent.trace_id
    assert child.parent_span_id == parent.span_id
    assert child.sampled is False


def test_distributed_job_persists_w3c_trace_into_worker_lease(tmp_path) -> None:
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from arenyxa.enterprise.distributed import DurableDistributedQueue

    queue = DurableDistributedQueue(tmp_path / "trace.sqlite")
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public = base64.urlsafe_b64encode(public_raw).decode("ascii").rstrip("=")
    queue.register_worker("worker-trace", public, {"slots": 1})
    parent = TraceContext.new(tracestate="vendor=stable")
    job_id = queue.enqueue(
        "task.run", {"task": {"name": "trace"}}, resource_id="resource-trace",
        permission="workflow.execute", idempotency_key="trace-job",
        traceparent=parent.traceparent, tracestate=parent.tracestate,
    )
    job = queue.job(job_id)
    assert job is not None
    assert job["traceparent"] == parent.traceparent
    assert job["tracestate"] == "vendor=stable"
    lease = queue.lease_next("worker-trace")
    assert lease is not None
    assert lease.traceparent == parent.traceparent
    assert lease.tracestate == "vendor=stable"


def test_distributed_job_generates_valid_trace_when_caller_has_none(tmp_path) -> None:
    from arenyxa.enterprise.distributed import DurableDistributedQueue

    queue = DurableDistributedQueue(tmp_path / "trace-default.sqlite")
    job_id = queue.enqueue(
        "task.run", {"task": {"name": "trace"}}, resource_id="resource-trace",
        permission="workflow.execute", idempotency_key="trace-default",
    )
    job = queue.job(job_id)
    assert job is not None
    parsed = TraceContext.parse(job["traceparent"], tracestate=job["tracestate"])
    assert parsed is not None
    assert len(parsed.trace_id) == 32
