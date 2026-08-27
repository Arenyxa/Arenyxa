from __future__ import annotations

import gzip

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, RequestSpec, RetryPolicy
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher


def _response(status: int) -> FetchResponse:
    return FetchResponse(
        url="https://example.test",
        final_url="https://example.test",
        status=status,
        headers={},
        body=b"ok",
        elapsed_ms=1.0,
        encoding="utf-8",
        content_type="text/plain",
    )


def test_retryable_http_status_is_retried(monkeypatch) -> None:
    fetcher = HttpFetcher()
    statuses = iter([503, 200])
    calls: list[int] = []

    def fake_once(_spec, _token):
        calls.append(1)
        return _response(next(statuses))

    monkeypatch.setattr(fetcher, "_fetch_once", fake_once)
    spec = RequestSpec(
        "https://example.test",
        retry=RetryPolicy(attempts=2, initial_backoff_seconds=0, max_backoff_seconds=0),
    )
    assert fetcher.fetch(spec).status == 200
    assert len(calls) == 2


def test_retryable_http_status_exhaustion_is_explicit(monkeypatch) -> None:
    fetcher = HttpFetcher()
    monkeypatch.setattr(fetcher, "_fetch_once", lambda _spec, _token: _response(503))
    spec = RequestSpec(
        "https://example.test",
        retry=RetryPolicy(attempts=1, initial_backoff_seconds=0, max_backoff_seconds=0),
    )
    with pytest.raises(ArenyxaError) as caught:
        fetcher.fetch(spec)
    assert caught.value.code == "FETCH_HTTP_RETRY_EXHAUSTED"


def test_gzip_expansion_is_bounded() -> None:
    fetcher = HttpFetcher(max_response_bytes=1024)
    compressed = gzip.compress(b"A" * 16_000)
    with pytest.raises(ArenyxaError) as caught:
        fetcher._decompress_gzip_limited(compressed, CancellationToken())
    assert caught.value.code == "FETCH_TOO_LARGE"


def test_header_lookup_is_case_insensitive() -> None:
    assert HttpFetcher._header_value({"content-encoding": "gzip"}, "Content-Encoding") == "gzip"


def test_cancellation_token_pause_resume_is_thread_safe() -> None:
    import threading
    import time

    token = CancellationToken()
    token.pause()
    passed = threading.Event()

    def worker() -> None:
        token.checkpoint()
        passed.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    time.sleep(0.05)
    assert not passed.is_set()
    token.resume()
    assert passed.wait(1.0)
    thread.join(timeout=1.0)


def test_cancellation_token_wakes_paused_workers_on_cancel() -> None:
    import threading
    import time

    token = CancellationToken()
    token.pause()
    observed = threading.Event()

    def worker() -> None:
        try:
            token.checkpoint()
        except ArenyxaError as exc:
            if exc.code == "RUN_CANCELLED":
                observed.set()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    time.sleep(0.05)
    token.cancel()
    assert observed.wait(1.0)
    thread.join(timeout=1.0)
