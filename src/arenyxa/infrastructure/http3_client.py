"""Optional real HTTP/3 transport backed by aioquic.

This transport is deliberately explicit: it is never claimed as available unless
`aioquic` is importable, it only supports HTTPS, it does not emulate browser TLS
fingerprints, and proxy tunnelling is not silently downgraded.
"""
from __future__ import annotations

import asyncio
import ssl
import time
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, RequestSpec
from arenyxa.infrastructure.http_client import CancellationToken
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


class Http3Fetcher:
    def __init__(self, *, network_policy: NetworkGuardPolicy | None = None, max_response_bytes: int = 64 * 1024 * 1024, max_redirects: int = 10) -> None:
        self.guard = NetworkUseGuard(network_policy or NetworkGuardPolicy())
        self.max_response_bytes = max(1024, min(int(max_response_bytes), 512 * 1024 * 1024))
        self.max_redirects = max(0, min(int(max_redirects), 32))

    @staticmethod
    def dependency_available() -> bool:
        try:
            import aioquic  # noqa: F401
            return True
        except ImportError:
            return False

    def fetch(self, spec: RequestSpec, token: CancellationToken | None = None) -> FetchResponse:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.fetch_async(spec, token=token))
        raise ArenyxaError(
            "HTTP3_ASYNC_CONTEXT",
            "Http3Fetcher.fetch() cannot run inside an active event loop; use fetch_async()",
            domain="FETCH",
        )

    async def fetch_async(self, spec: RequestSpec, token: CancellationToken | None = None) -> FetchResponse:
        errors = spec.validate()
        if errors:
            raise ValueError("; ".join(errors))
        if spec.proxy:
            raise ArenyxaError("HTTP3_PROXY_UNSUPPORTED", "HTTP/3 proxy tunnelling is not configured", domain="FETCH")
        if not self.dependency_available():
            raise ArenyxaError("HTTP3_RUNTIME_UNAVAILABLE", "HTTP/3 requires the optional aioquic dependency", domain="FETCH")
        current = _build_url(spec)
        redirects: list[str] = []
        for _ in range(self.max_redirects + 1):
            response = await self._fetch_once(current, spec, token or CancellationToken())
            if response.status not in {301, 302, 303, 307, 308}:
                response.redirect_chain = redirects + ([response.final_url] if redirects else [])
                return response
            location = _header(response.headers, "location")
            if not location:
                return response
            next_url = urljoin(current, location)
            redirects.append(next_url)
            if len(set(redirects)) != len(redirects):
                raise ArenyxaError("FETCH_REDIRECT_LIMIT", "HTTP/3 redirect loop detected", domain="FETCH")
            current = next_url
        raise ArenyxaError("FETCH_REDIRECT_LIMIT", "HTTP/3 redirect count exceeded safety limit", domain="FETCH")

    async def _fetch_once(self, url: str, spec: RequestSpec, token: CancellationToken) -> FetchResponse:
        from aioquic.asyncio.client import connect
        from aioquic.asyncio.protocol import QuicConnectionProtocol
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import DataReceived, HeadersReceived
        from aioquic.quic.configuration import QuicConfiguration

        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ArenyxaError("HTTP3_HTTPS_REQUIRED", "HTTP/3 transport requires an HTTPS URL", domain="FETCH")
        self.guard.check_target(parsed.hostname, resolve_dns=True)
        token.checkpoint()
        port = parsed.port or 443
        authority = parsed.hostname if port == 443 else f"{parsed.hostname}:{port}"
        path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        method = spec.method.upper()
        body = (spec.body or "").encode("utf-8")
        headers: list[tuple[bytes, bytes]] = [
            (b":method", method.encode("ascii")),
            (b":scheme", b"https"),
            (b":authority", authority.encode("ascii")),
            (b":path", path.encode("utf-8")),
            (b"user-agent", spec.user_agent.encode("utf-8")),
            (b"accept-encoding", b"identity"),
        ]
        if spec.cookies:
            headers.append((b"cookie", "; ".join(f"{k}={v}" for k, v in spec.cookies.items()).encode("utf-8")))
        if spec.content_type:
            headers.append((b"content-type", spec.content_type.encode("utf-8")))
        for key, value in spec.headers.items():
            lower = key.casefold()
            if lower in {"host", "content-length", "connection", "transfer-encoding"}:
                continue
            headers.append((lower.encode("ascii"), value.encode("utf-8")))

        class _Protocol(QuicConnectionProtocol):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                self.http = H3Connection(self._quic)
                self.waiters: dict[int, asyncio.Future[tuple[list[tuple[bytes, bytes]], bytes]]] = {}
                self.parts: dict[int, bytearray] = {}
                self.response_headers: dict[int, list[tuple[bytes, bytes]]] = {}

            async def request(self) -> tuple[list[tuple[bytes, bytes]], bytes]:
                stream_id = self._quic.get_next_available_stream_id()
                loop = asyncio.get_running_loop()
                waiter: asyncio.Future[tuple[list[tuple[bytes, bytes]], bytes]] = loop.create_future()
                self.waiters[stream_id] = waiter
                self.parts[stream_id] = bytearray()
                self.response_headers[stream_id] = []
                self.http.send_headers(stream_id=stream_id, headers=headers, end_stream=not body)
                if body:
                    self.http.send_data(stream_id=stream_id, data=body, end_stream=True)
                self.transmit()
                return await waiter

            def quic_event_received(self, event: Any) -> None:
                for http_event in self.http.handle_event(event):
                    stream_id = getattr(http_event, "stream_id", None)
                    if stream_id is None:
                        continue
                    if isinstance(http_event, HeadersReceived):
                        self.response_headers[stream_id].extend(http_event.headers)
                    elif isinstance(http_event, DataReceived):
                        target = self.parts[stream_id]
                        target.extend(http_event.data)
                        if len(target) > self_outer.max_response_bytes:
                            waiter = self.waiters.pop(stream_id, None)
                            if waiter is not None and not waiter.done():
                                waiter.set_exception(ArenyxaError("FETCH_TOO_LARGE", "HTTP/3 response exceeds configured size limit", domain="FETCH"))
                            return
                    if bool(getattr(http_event, "stream_ended", False)):
                        waiter = self.waiters.pop(stream_id, None)
                        if waiter is not None and not waiter.done():
                            waiter.set_result((self.response_headers.pop(stream_id, []), bytes(self.parts.pop(stream_id, b""))))

        self_outer = self
        configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        configuration.server_name = parsed.hostname
        if not spec.verify_tls:
            configuration.verify_mode = ssl.CERT_NONE
        started = time.perf_counter()
        try:
            async with connect(
                parsed.hostname,
                port,
                configuration=configuration,
                create_protocol=_Protocol,
                wait_connected=True,
            ) as protocol:
                raw_headers, response_body = await asyncio.wait_for(
                    protocol.request(),  # type: ignore[attr-defined]
                    timeout=max(float(spec.connect_timeout), float(spec.read_timeout)),
                )
        except asyncio.TimeoutError as exc:
            raise ArenyxaError("FETCH_TIMEOUT", "HTTP/3 request timed out", domain="FETCH", retryable=True) from exc
        except ArenyxaError:
            raise
        except (OSError, RuntimeError, TimeoutError, ValueError, ConnectionError) as exc:
            raise ArenyxaError("HTTP3_NETWORK_ERROR", f"HTTP/3 request failed: {type(exc).__name__}", domain="FETCH", retryable=True) from exc
        token.checkpoint()
        decoded_headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in raw_headers if not k.startswith(b":")}
        status = next((int(v.decode("ascii")) for k, v in raw_headers if k == b":status"), 0)
        content_type = _header(decoded_headers, "content-type")
        media, _, suffix = content_type.partition(";")
        charset = "utf-8"
        if "charset=" in suffix.casefold():
            charset = suffix.split("charset=", 1)[1].strip().strip('"')[:64] or "utf-8"
        return FetchResponse(
            url=spec.url,
            final_url=url,
            status=status,
            headers=decoded_headers,
            body=response_body,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            encoding=charset,
            content_type=media.strip(),
        )


def _build_url(spec: RequestSpec) -> str:
    parsed = urlsplit(spec.url)
    query = parsed.query
    extra = urlencode(spec.query)
    if extra:
        query = f"{query}&{extra}" if query else extra
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))


def _header(headers: dict[str, str], name: str) -> str:
    target = name.casefold()
    return next((str(v) for k, v in headers.items() if str(k).casefold() == target), "")
