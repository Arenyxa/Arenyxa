from __future__ import annotations
from arenyxa.recoverable import record_current_exception

"""Async HTTP transport for the modern Arenyxa runtime.

The synchronous :mod:`arenyxa.infrastructure.http_client` path remains the compatibility
boundary for blocking libraries and the frozen legacy lane.  This module owns modern
high-I/O request execution: one event loop can multiplex many sockets while reusing
bounded HTTPX connection pools.
"""

import asyncio
import time
from collections.abc import Callable

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, RequestSpec
from arenyxa.infrastructure.http_client import CancellationToken, HttpFetcher
from arenyxa.security.network_guard import NetworkUseGuard
from arenyxa.security.dlp import GLOBAL_DLP_ENGINE


async def async_checkpoint(token: CancellationToken) -> None:
    """Cancellation/pause checkpoint that never blocks the event-loop thread."""
    if token.cancelled:
        raise ArenyxaError("RUN_CANCELLED", "操作已取消。", domain="RUN")
    while token.paused:
        await asyncio.sleep(0.05)
        if token.cancelled:
            raise ArenyxaError("RUN_CANCELLED", "操作已取消。", domain="RUN")


class AsyncHttpFetcher(HttpFetcher):
    """HTTPX AsyncClient based fetcher with bounded connection reuse.

    Instances are intentionally event-loop scoped.  Create one per async run/runtime,
    reuse it for the run, then call :meth:`aclose` before the loop is closed.
    """

    def __init__(
        self,
        max_response_bytes: int = 32 * 1024 * 1024,
        *,
        network_guard: NetworkUseGuard | None = None,
    ) -> None:
        super().__init__(max_response_bytes, transport="httpx", network_guard=network_guard)
        self._async_clients: dict[tuple[bool, str], object] = {}
        self._async_closed = False

    async def _async_client(self, verify_tls: bool, proxy: str | None) -> object:
        try:
            import httpx
        except ImportError as exc:
            raise ArenyxaError(
                "FETCH_TRANSPORT_UNAVAILABLE",
                "HTTPX async transport is unavailable.",
                domain="FETCH",
            ) from exc
        if self._async_closed:
            raise ArenyxaError("FETCHER_CLOSED", "HTTP fetcher is closed.", domain="FETCH")
        key = (bool(verify_tls), str(proxy or ""))
        client = self._async_clients.get(key)
        if client is not None:
            return client

        async def guard_request(request: object) -> None:
            await asyncio.to_thread(self._guard_url, str(request.url))  # type: ignore[attr-defined]

        kwargs: dict[str, object] = {
            "verify": self._tls_context(bool(verify_tls)),
            "follow_redirects": True,
            "max_redirects": 10,
            "trust_env": False,
            "limits": httpx.Limits(
                max_connections=128,
                max_keepalive_connections=32,
                keepalive_expiry=30.0,
            ),
            "event_hooks": {"request": [guard_request]},
        }
        if proxy:
            kwargs["proxy"] = str(proxy)
        try:
            client = httpx.AsyncClient(**kwargs)
        except TypeError:
            if "proxy" not in kwargs:
                raise
            proxy_value = kwargs.pop("proxy")
            kwargs["proxies"] = proxy_value
            client = httpx.AsyncClient(**kwargs)
        self._async_clients[key] = client
        return client

    async def aclose(self) -> None:
        if self._async_closed:
            return
        self._async_closed = True
        clients = list(self._async_clients.values())
        self._async_clients.clear()
        for client in clients:
            try:
                await client.aclose()  # type: ignore[attr-defined]
            except (OSError, RuntimeError):
                record_current_exception(__name__, 'AsyncHttpFetcher.aclose:102')
        # No synchronous HTTPX client is normally allocated by this class, but close the
        # inherited cache as a defensive ownership boundary.
        super().close()

    async def fetch_async(
        self,
        spec: RequestSpec,
        token: CancellationToken | None = None,
        on_attempt: Callable[[int], None] | None = None,
    ) -> FetchResponse:
        errors = spec.validate()
        if errors:
            raise ArenyxaError("TASK_INVALID", "；".join(errors), domain="TASK")
        token = token or CancellationToken()
        last_error: Exception | None = None
        last_retry_after: float | None = None
        method = spec.method.upper()
        idempotent = method in {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
        retry_attempts = spec.retry.attempts if (idempotent or spec.retry.allow_non_idempotent) else 0

        for attempt in range(retry_attempts + 1):
            await async_checkpoint(token)
            if on_attempt:
                on_attempt(attempt)
            try:
                response = await self._fetch_once_httpx_async(spec, token)
                if response.status not in spec.retry.retry_statuses:
                    return response
                last_retry_after = self._parse_retry_after(response.headers)
                last_error = ArenyxaError(
                    "FETCH_RETRYABLE_STATUS",
                    f"服务器返回可重试 HTTP 状态 {response.status}。",
                    domain="FETCH",
                    retryable=True,
                    context={"url": spec.url, "status": response.status},
                )
                if attempt >= retry_attempts:
                    raise ArenyxaError(
                        "FETCH_HTTP_RETRY_EXHAUSTED",
                        f"HTTP {response.status} 在 {attempt + 1} 次请求后仍未恢复。",
                        domain="FETCH",
                        retryable=True,
                        context={
                            "url": spec.url,
                            "status": response.status,
                            "attempts": attempt + 1,
                            "retry_after": last_retry_after,
                        },
                    )
            except ArenyxaError as exc:
                last_error = exc
                if not exc.retryable or attempt >= retry_attempts:
                    raise

            delay = self._retry_delay(spec, attempt, last_retry_after)
            last_retry_after = None
            stop_at = time.monotonic() + delay
            while time.monotonic() < stop_at:
                await async_checkpoint(token)
                await asyncio.sleep(min(0.05, max(0.0, stop_at - time.monotonic())))

        if self._is_timeout_error(last_error):
            code, message = "FETCH_TIMEOUT", f"请求超时：{last_error}"
        else:
            code, message = "FETCH_NETWORK_ERROR", f"网络请求失败：{last_error}"
        raise ArenyxaError(code, message, domain="FETCH", retryable=True, context={"url": spec.url})

    async def _prepare_async_request(
        self, spec: RequestSpec, token: CancellationToken, httpx: object
    ) -> tuple[str, dict[str, str], bytes | None, object]:
        """Apply egress policy and build bounded HTTPX request parameters."""
        await async_checkpoint(token)
        url = self._build_url(spec)
        dlp = GLOBAL_DLP_ENGINE.inspect_http(
            url=url, headers=spec.headers, cookies=spec.cookies, body=spec.body
        )
        if not dlp.allowed:
            raise ArenyxaError(
                "DLP_EGRESS_BLOCKED",
                "Outbound request was blocked by the Data Loss Prevention policy.",
                domain="SECURITY",
                context={
                    "host": dlp.destination_host,
                    "finding_kinds": sorted({item.kind for item in dlp.findings}),
                },
            )
        await asyncio.to_thread(self._guard_url, url)
        headers = {"User-Agent": spec.user_agent, "Accept-Encoding": "gzip", **spec.headers}
        if spec.cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in spec.cookies.items())
        if spec.content_type:
            headers["Content-Type"] = spec.content_type
        body = spec.body.encode("utf-8") if spec.body is not None else None
        timeout = httpx.Timeout(  # type: ignore[attr-defined]
            connect=min(float(spec.connect_timeout), self.MAX_EFFECTIVE_CONNECT_TIMEOUT),
            read=float(spec.read_timeout),
            write=float(spec.read_timeout),
            pool=min(float(spec.connect_timeout), self.MAX_EFFECTIVE_CONNECT_TIMEOUT),
        )
        return url, headers, body, timeout

    async def _fetch_once_httpx_async(
        self, spec: RequestSpec, token: CancellationToken
    ) -> FetchResponse:
        try:
            import httpx
        except ImportError as exc:
            raise ArenyxaError(
                "FETCH_TRANSPORT_UNAVAILABLE",
                "HTTPX async transport is unavailable.",
                domain="FETCH",
            ) from exc

        url, headers, body, timeout = await self._prepare_async_request(spec, token, httpx)
        client = await self._async_client(bool(spec.verify_tls), spec.proxy)
        started = time.perf_counter()
        try:
            async with client.stream(  # type: ignore[attr-defined]
                spec.method.upper(), url, headers=headers, content=body, timeout=timeout
            ) as response:
                status = int(response.status_code)
                raw_headers = {str(key): str(value) for key, value in response.headers.items()}
                self._guard_content_length(raw_headers)
                body_buffer = bytearray()
                total = 0
                async for chunk in response.aiter_raw():
                    await async_checkpoint(token)
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise ArenyxaError(
                            "FETCH_TOO_LARGE",
                            f"响应超过 {self.max_response_bytes} 字节上限。",
                            domain="FETCH",
                        )
                    body_buffer.extend(chunk)
                body_bytes = bytes(body_buffer)
                final_url = str(response.url)
                redirect_chain = [str(item.url) for item in response.history]
                if response.history:
                    redirect_chain.append(final_url)
        except httpx.TimeoutException as exc:
            raise ArenyxaError("FETCH_TIMEOUT", "网络请求超时。", domain="FETCH", retryable=True) from exc
        except httpx.TooManyRedirects as exc:
            raise ArenyxaError(
                "FETCH_REDIRECT_LIMIT", "HTTP 重定向次数超过安全上限。", domain="FETCH"
            ) from exc
        except httpx.TransportError as exc:
            raise ArenyxaError(
                "FETCH_NETWORK_ERROR",
                f"网络请求失败：{type(exc).__name__}",
                domain="FETCH",
                retryable=True,
                context={"url": spec.url},
            ) from exc

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        content_encoding = self._header_value(raw_headers, "Content-Encoding").casefold().strip()
        if content_encoding == "gzip":
            # gzip decompression is CPU-bound and bounded; offload it so other sockets keep moving.
            body_bytes = await asyncio.to_thread(self._decompress_gzip_limited, body_bytes, token)
        elif content_encoding not in {"", "identity"}:
            raise ArenyxaError(
                "FETCH_CONTENT_ENCODING_UNSUPPORTED",
                f"服务器返回了未支持的 Content-Encoding：{content_encoding}。",
                domain="FETCH",
                context={"url": spec.url, "content_encoding": content_encoding},
            )
        content_type, charset = self._content_type(raw_headers)
        return FetchResponse(
            url=spec.url,
            final_url=final_url,
            status=status,
            headers=raw_headers,
            body=body_bytes,
            elapsed_ms=elapsed_ms,
            encoding=charset,
            content_type=content_type,
            redirect_chain=redirect_chain,
        )
