"""Crawler-oriented transport governance layered over Arenyxa HttpFetcher."""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from arenyxa.domain.models import FetchResponse, RequestSpec
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher
from arenyxa.infrastructure.crawler_cache import CachePolicy, CrawlerResponseCache
from arenyxa.infrastructure.http3_client import Http3Fetcher


@dataclass(slots=True)
class ProxyEndpoint:
    url: str
    failures: int = 0
    successes: int = 0
    latency_ema_ms: float = 0.0
    cooldown_until: float = 0.0
    last_error: str = ""

    @property
    def healthy(self) -> bool:
        return time.monotonic() >= self.cooldown_until


class ProxyPool:
    """Health-aware round-robin proxy pool. It never invents or discovers proxies."""

    def __init__(self, proxies: list[str] | None = None, *, failure_threshold: int = 3, cooldown_seconds: float = 30.0) -> None:
        self.failure_threshold = max(1, int(failure_threshold))
        self.cooldown_seconds = max(1.0, float(cooldown_seconds))
        self._items = [ProxyEndpoint(str(value).strip()) for value in (proxies or []) if str(value).strip()]
        self._cursor = 0
        self._lock = threading.RLock()

    def select(self) -> ProxyEndpoint | None:
        with self._lock:
            if not self._items:
                return None
            now = time.monotonic()
            for _ in range(len(self._items)):
                item = self._items[self._cursor % len(self._items)]
                self._cursor += 1
                if item.cooldown_until <= now:
                    return item
            return None

    def report_success(self, item: ProxyEndpoint, elapsed_ms: float) -> None:
        with self._lock:
            item.successes += 1
            item.failures = max(0, item.failures - 1)
            item.last_error = ""
            item.latency_ema_ms = elapsed_ms if item.latency_ema_ms <= 0 else item.latency_ema_ms * 0.8 + elapsed_ms * 0.2

    def report_failure(self, item: ProxyEndpoint, error: BaseException) -> None:
        with self._lock:
            item.failures += 1
            item.last_error = f"{type(error).__name__}: {error}"[:512]
            if item.failures >= self.failure_threshold:
                item.cooldown_until = time.monotonic() + self.cooldown_seconds

    def snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            now = time.monotonic()
            return [{
                "url": item.url, "successes": item.successes, "failures": item.failures,
                "latency_ema_ms": round(item.latency_ema_ms, 3),
                "cooldown_remaining": max(0.0, item.cooldown_until - now), "last_error": item.last_error,
            } for item in self._items]


@dataclass(slots=True)
class SessionPolicy:
    default_headers: dict[str, str] = field(default_factory=dict)
    proxies: list[str] = field(default_factory=list)
    http3_mode: str = "off"  # off | prefer | require
    cache: CachePolicy = field(default_factory=CachePolicy)

    def normalized(self) -> "SessionPolicy":
        mode = str(self.http3_mode or "off").strip().casefold()
        if mode not in {"off", "prefer", "require"}:
            raise ValueError(f"Unsupported HTTP/3 mode: {self.http3_mode}")
        return SessionPolicy(
            default_headers={str(k): str(v) for k, v in list(self.default_headers.items())[:128]},
            proxies=[str(v).strip() for v in self.proxies if str(v).strip()][:256],
            http3_mode=mode,
            cache=self.cache.normalized(),
        )


class CrawlerTransport:
    """Persistent crawler transport with shared HTTP connection pools and proxy health."""

    def __init__(self, fetcher: HttpFetcher | Any | None = None, *, policy: SessionPolicy | None = None) -> None:
        self.fetcher = fetcher or HttpFetcher(transport="auto")
        self.policy = (policy or SessionPolicy()).normalized()
        self.proxy_pool = ProxyPool(self.policy.proxies)
        self.cache = CrawlerResponseCache(self.policy.cache)
        self.http3 = Http3Fetcher(network_policy=getattr(getattr(self.fetcher, "network_guard", None), "policy", None))
        self._domain_proxy: dict[str, ProxyEndpoint] = {}
        self._lock = threading.RLock()

    def _proxy_for(self, url: str) -> ProxyEndpoint | None:
        host = (urlsplit(url).hostname or "").casefold()
        with self._lock:
            current = self._domain_proxy.get(host)
            if current is not None and current.healthy:
                return current
            selected = self.proxy_pool.select()
            if selected is not None:
                self._domain_proxy[host] = selected
            return selected

    def fetch(self, spec: RequestSpec, token: CancellationToken | None = None, on_attempt=None) -> FetchResponse:
        proxy = self._proxy_for(spec.url) if spec.proxy is None else None
        headers = {**self.policy.default_headers, **spec.headers}
        effective = RequestSpec(
            url=spec.url, method=spec.method, query=dict(spec.query), headers=headers,
            cookies=dict(spec.cookies), body=spec.body, content_type=spec.content_type,
            connect_timeout=spec.connect_timeout, read_timeout=spec.read_timeout,
            verify_tls=spec.verify_tls, proxy=spec.proxy or (proxy.url if proxy else None),
            user_agent=spec.user_agent, retry=spec.retry,
        )
        cached = self.cache.get(effective)
        if cached is not None:
            return cached
        started = time.perf_counter()
        try:
            use_http3 = (
                self.policy.http3_mode != "off"
                and urlsplit(effective.url).scheme.casefold() == "https"
                and not effective.proxy
            )
            if use_http3:
                try:
                    response = self.http3.fetch(effective, token=token)
                except (ArenyxaError, OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
                    if self.policy.http3_mode == "require":
                        raise
                    response = self.fetcher.fetch(effective, token=token, on_attempt=on_attempt)
            else:
                response = self.fetcher.fetch(effective, token=token, on_attempt=on_attempt)
        except (ArenyxaError, OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
            if proxy is not None:
                self.proxy_pool.report_failure(proxy, exc)
            raise
        if proxy is not None:
            self.proxy_pool.report_success(proxy, (time.perf_counter() - started) * 1000.0)
        self.cache.put(effective, response)
        return response

    def close(self) -> None:
        close = getattr(self.fetcher, "close", None)
        if callable(close):
            close()
