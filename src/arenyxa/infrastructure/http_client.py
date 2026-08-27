from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import codecs
import gzip
import io
import importlib.util
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import field as dataclass_field
from datetime import datetime
from email.message import Message
from email.utils import parsedate_to_datetime

from arenyxa.compat import UTC, dataclass
from arenyxa.domain.errors import ArenyxaError, domain_error
from arenyxa.domain.models import FetchResponse, RequestSpec
from arenyxa.security.dlp import GLOBAL_DLP_ENGINE
from arenyxa.security.network_guard import NetworkUseGuard


@dataclass(slots=True)
class CancellationToken:
    

    _cancel_event: threading.Event = dataclass_field(default_factory=threading.Event)
    _resume_gate: threading.Event = dataclass_field(default_factory=threading.Event)

    def __post_init__(self) -> None:
        self._resume_gate.set()

    def cancel(self) -> None:
        self._cancel_event.set()
                                                                           
        self._resume_gate.set()

    def pause(self) -> None:
        if not self._cancel_event.is_set():
            self._resume_gate.clear()

    def resume(self) -> None:
        self._resume_gate.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel_event.is_set()

    @property
    def paused(self) -> bool:
        return not self._resume_gate.is_set() and not self._cancel_event.is_set()

    def checkpoint(self) -> None:
        if self._cancel_event.is_set():
            raise ArenyxaError("RUN_CANCELLED", "操作已取消。", domain="RUN")
        while not self._resume_gate.wait(timeout=0.05):
            if self._cancel_event.is_set():
                raise ArenyxaError("RUN_CANCELLED", "操作已取消。", domain="RUN")
        if self._cancel_event.is_set():
            raise ArenyxaError("RUN_CANCELLED", "操作已取消。", domain="RUN")


class LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 10
    max_repeats = 4

    def __init__(self, url_validator: Callable[[str], None] | None = None) -> None:
        super().__init__()
        self._url_validator = url_validator

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: Message,
        newurl: str,
    ) -> urllib.request.Request | None:
        if self._url_validator is not None:
            self._url_validator(str(newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class HttpFetcher:
                                                                                          
                                                                                            
                                                                                           
                                                                                   
    MAX_EFFECTIVE_CONNECT_TIMEOUT = 30.0

    def __init__(
        self,
        max_response_bytes: int = 32 * 1024 * 1024,
        *,
        transport: str = "auto",
        network_guard: NetworkUseGuard | None = None,
    ) -> None:
        self.max_response_bytes = max_response_bytes
        selected = str(transport).strip().casefold()
        if selected not in {"auto", "httpx", "urllib"}:
            raise ValueError("transport must be auto, httpx or urllib")
        if selected == "auto":
            selected = "httpx" if importlib.util.find_spec("httpx") is not None else "urllib"
        if selected == "httpx" and importlib.util.find_spec("httpx") is None:
            raise RuntimeError("HTTPX transport requested but httpx is not installed")
        self.transport = selected
        self.network_guard = network_guard or NetworkUseGuard()
                                                                                              
                                                                                               
                                                                                                
                                                                                    
        self._tls_contexts: dict[bool, ssl.SSLContext] = {}
        self._tls_context_lock = threading.Lock()
        # Keep HTTPX transports alive across requests. RunOrchestrator may issue
        # requests from multiple worker threads; httpx.Client is thread-safe and its
        # connection pool avoids rebuilding TCP/TLS state for every request.
        self._httpx_clients: dict[tuple[bool, str], object] = {}
        self._httpx_clients_lock = threading.RLock()
        self._closed = False

    def fetch(
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
            token.checkpoint()
            if on_attempt:
                on_attempt(attempt)
            try:
                response = self._fetch_once(spec, token)
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
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                last_error = exc
                if attempt >= retry_attempts:
                    break

            delay = self._retry_delay(spec, attempt, last_retry_after)
            last_retry_after = None
            stop_at = time.monotonic() + delay
            while time.monotonic() < stop_at:
                token.checkpoint()
                time.sleep(min(0.05, max(0.0, stop_at - time.monotonic())))

        if self._is_timeout_error(last_error):
            code, message = "FETCH_TIMEOUT", f"请求超时：{last_error}"
        else:
            code, message = "FETCH_NETWORK_ERROR", f"网络请求失败：{last_error}"
        raise ArenyxaError(
            code, message, domain="FETCH", retryable=True, context={"url": spec.url}
        )

    def _retry_delay(
        self, spec: RequestSpec, attempt: int, retry_after: float | None = None
    ) -> float:
        base = min(
            spec.retry.max_backoff_seconds,
            spec.retry.initial_backoff_seconds * (2**attempt),
        )
                                                                                        
                                                                                  
        if base > 0:
            base = min(spec.retry.max_backoff_seconds, base * random.uniform(0.85, 1.15))
        if retry_after is not None:
            base = max(base, min(float(retry_after), spec.retry.max_backoff_seconds))
        return max(0.0, float(base))

    @staticmethod
    def _parse_retry_after(headers: dict[str, str]) -> float | None:
        raw = HttpFetcher._header_value(headers, "Retry-After").strip()
        if not raw:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            try:
                moment = parsedate_to_datetime(raw)
                if moment.tzinfo is None:
                    moment = moment.replace(tzinfo=UTC)
                return max(0.0, (moment - datetime.now(UTC)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return None

    @staticmethod
    def _is_timeout_error(error: Exception | None) -> bool:
        if isinstance(error, (TimeoutError, socket.timeout)):
            return True
        if isinstance(error, urllib.error.URLError):
            return isinstance(error.reason, (TimeoutError, socket.timeout))
        if isinstance(error, ArenyxaError):
            return error.code == "FETCH_TIMEOUT"
        return False

    @staticmethod
    def _build_url(spec: RequestSpec) -> str:
        if not spec.query:
            return spec.url
        parts = urllib.parse.urlsplit(spec.url)
        encoded = urllib.parse.urlencode(spec.query)
        query = "&".join(part for part in (parts.query, encoded) if part)
        return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))

    @staticmethod
    def _accept_encoding() -> str:
        encodings = ["gzip"]
        if importlib.util.find_spec("brotli") is not None or importlib.util.find_spec("brotlicffi") is not None:
            encodings.append("br")
        if importlib.util.find_spec("zstandard") is not None:
            encodings.append("zstd")
        return ", ".join(encodings)

    def _decode_content(self, payload: bytes, encoding: str, token: CancellationToken) -> bytes:
        normalized = encoding.casefold().strip()
        if normalized in {"", "identity"}:
            return payload
        if normalized == "gzip":
            return self._decompress_gzip_limited(payload, token)
        if normalized == "br":
            try:
                try:
                    import brotli
                except ImportError:
                    import brotlicffi as brotli  # type: ignore[no-redef]
                decoded = brotli.decompress(payload)
            except ImportError as exc:
                raise ArenyxaError("FETCH_CONTENT_ENCODING_UNSUPPORTED", "Brotli support is not installed.", domain="FETCH") from exc
            except Exception as exc:
                raise ArenyxaError("FETCH_DECOMPRESSION_FAILED", "Invalid Brotli response.", domain="FETCH") from exc
        elif normalized == "zstd":
            try:
                import zstandard
                decoded = zstandard.ZstdDecompressor().decompress(payload, max_output_size=self.max_response_bytes + 1)
            except ImportError as exc:
                raise ArenyxaError("FETCH_CONTENT_ENCODING_UNSUPPORTED", "Zstandard support is not installed.", domain="FETCH") from exc
            except Exception as exc:
                raise ArenyxaError("FETCH_DECOMPRESSION_FAILED", "Invalid Zstandard response.", domain="FETCH") from exc
        else:
            raise ArenyxaError("FETCH_CONTENT_ENCODING_UNSUPPORTED", f"Unsupported Content-Encoding: {normalized}.", domain="FETCH")
        token.checkpoint()
        if len(decoded) > self.max_response_bytes:
            raise ArenyxaError("FETCH_TOO_LARGE", f"Decompressed response exceeds {self.max_response_bytes} bytes.", domain="FETCH")
        return bytes(decoded)

    def _fetch_once(self, spec: RequestSpec, token: CancellationToken) -> FetchResponse:
        url = self._build_url(spec)
        # DLP is a local preflight and must run before DNS resolution or any other
        # network-side effect so sensitive material is rejected at the earliest boundary.
        dlp = GLOBAL_DLP_ENGINE.inspect_http(
            url=url,
            headers=spec.headers,
            cookies=spec.cookies,
            body=spec.body,
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
        self._guard_url(url)
        if self.transport == "httpx":
            return self._fetch_once_httpx(spec, token)
        return self._fetch_once_urllib(spec, token)

    def _fetch_once_urllib(self, spec: RequestSpec, token: CancellationToken) -> FetchResponse:
        url = self._build_url(spec)
        headers = {"User-Agent": spec.user_agent, "Accept-Encoding": self._accept_encoding(), **spec.headers}
        if spec.cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in spec.cookies.items())
        if spec.content_type:
            headers["Content-Type"] = spec.content_type
        body = spec.body.encode("utf-8") if spec.body is not None else None
        request = urllib.request.Request(url, data=body, headers=headers, method=spec.method.upper())
        context = self._tls_context(bool(spec.verify_tls))
        handlers: list[urllib.request.BaseHandler] = [
            LimitedRedirectHandler(self._guard_url),
            urllib.request.HTTPSHandler(context=context),
        ]
        if spec.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": spec.proxy, "https": spec.proxy}))
        opener = urllib.request.build_opener(*handlers)
        started = time.perf_counter()
        try:
            with opener.open(
                request,
                timeout=min(float(spec.connect_timeout), self.MAX_EFFECTIVE_CONNECT_TIMEOUT),
            ) as response:
                self._apply_read_timeout(response, min(float(spec.read_timeout), 0.5))
                status = int(response.status)
                raw_headers = {str(key): str(value) for key, value in response.headers.items()}
                self._guard_content_length(raw_headers)
                body_bytes = self._read_limited(response, token, read_timeout=float(spec.read_timeout))
                final_url = response.geturl()
        except urllib.error.HTTPError as exc:
            with exc:
                self._apply_read_timeout(exc, min(float(spec.read_timeout), 0.5))
                status = int(exc.code)
                raw_headers = {str(key): str(value) for key, value in exc.headers.items()}
                self._guard_content_length(raw_headers)
                body_bytes = self._read_limited(exc, token, read_timeout=float(spec.read_timeout))
                final_url = exc.geturl()
        except ssl.SSLError as exc:
            raise domain_error("FETCH_TLS_ERROR", url=spec.url, details=str(exc)) from exc
        except (TimeoutError, socket.timeout) as exc:
            raise ArenyxaError("FETCH_TIMEOUT", "读取响应超时。", domain="FETCH", retryable=True) from exc
        elapsed_ms = (time.perf_counter() - started) * 1000
        content_encoding = self._header_value(raw_headers, "Content-Encoding")
        body_bytes = self._decode_content(body_bytes, content_encoding, token)
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
            redirect_chain=[] if final_url == spec.url else [spec.url, final_url],
        )

    def _httpx_client(self, verify_tls: bool, proxy: str | None) -> object:
        """Return a bounded, reusable HTTPX client for one TLS/proxy transport profile."""
        try:
            import httpx
        except ImportError as exc:
            raise ArenyxaError(
                "FETCH_TRANSPORT_UNAVAILABLE",
                "HTTPX transport is unavailable.",
                domain="FETCH",
            ) from exc

        key = (bool(verify_tls), str(proxy or ""))
        with self._httpx_clients_lock:
            if self._closed:
                raise ArenyxaError("FETCHER_CLOSED", "HTTP fetcher is closed.", domain="FETCH")
            cached = self._httpx_clients.get(key)
            if cached is not None:
                return cached
            limits = httpx.Limits(
                max_connections=128,
                max_keepalive_connections=32,
                keepalive_expiry=30.0,
            )
            client_kwargs: dict[str, object] = {
                "verify": self._tls_context(bool(verify_tls)),
                "follow_redirects": True,
                "max_redirects": 10,
                "trust_env": False,
                "limits": limits,
                "event_hooks": {"request": [lambda request: self._guard_url(str(request.url))]},
            }
            if proxy:
                client_kwargs["proxy"] = str(proxy)
            try:
                client = httpx.Client(**client_kwargs)
            except TypeError:
                # Compatibility with HTTPX releases that still use ``proxies``.
                if "proxy" not in client_kwargs:
                    raise
                proxy_value = client_kwargs.pop("proxy")
                client_kwargs["proxies"] = proxy_value
                client = httpx.Client(**client_kwargs)
            self._httpx_clients[key] = client
            return client

    def close(self) -> None:
        """Close reusable transports.  Safe to call repeatedly during coordinated shutdown."""
        with self._httpx_clients_lock:
            if self._closed:
                return
            self._closed = True
            clients = list(self._httpx_clients.values())
            self._httpx_clients.clear()
        for client in clients:
            try:
                client.close()  # type: ignore[attr-defined]
            except (OSError, RuntimeError):
                # Shutdown is best-effort; request-level failures are handled before this boundary.
                record_current_exception(__name__, 'HttpFetcher.close:395')

    def _fetch_once_httpx(self, spec: RequestSpec, token: CancellationToken) -> FetchResponse:
        try:
            import httpx
        except ImportError as exc:
            raise ArenyxaError("FETCH_TRANSPORT_UNAVAILABLE", "HTTPX transport is unavailable.", domain="FETCH") from exc

        token.checkpoint()
        url = self._build_url(spec)
        headers = {"User-Agent": spec.user_agent, "Accept-Encoding": self._accept_encoding(), **spec.headers}
        if spec.cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in spec.cookies.items())
        if spec.content_type:
            headers["Content-Type"] = spec.content_type
        body = spec.body.encode("utf-8") if spec.body is not None else None
        timeout = httpx.Timeout(
            connect=min(float(spec.connect_timeout), self.MAX_EFFECTIVE_CONNECT_TIMEOUT),
            read=float(spec.read_timeout),
            write=float(spec.read_timeout),
            pool=min(float(spec.connect_timeout), self.MAX_EFFECTIVE_CONNECT_TIMEOUT),
        )
        client = self._httpx_client(bool(spec.verify_tls), spec.proxy)
        started = time.perf_counter()
        try:
            with client.stream(  # type: ignore[attr-defined]
                spec.method.upper(), url, headers=headers, content=body, timeout=timeout
            ) as response:
                status = int(response.status_code)
                raw_headers = {str(key): str(value) for key, value in response.headers.items()}
                self._guard_content_length(raw_headers)
                body_buffer = bytearray()
                total = 0
                for chunk in response.iter_raw():
                    token.checkpoint()
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
                "FETCH_NETWORK_ERROR", f"网络请求失败：{type(exc).__name__}",
                domain="FETCH", retryable=True, context={"url": spec.url},
            ) from exc
        elapsed_ms = (time.perf_counter() - started) * 1000
        content_encoding = self._header_value(raw_headers, "Content-Encoding")
        body_bytes = self._decode_content(body_bytes, content_encoding, token)
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

    def _guard_url(self, url: str) -> None:
        try:
            parsed = urllib.parse.urlsplit(str(url))
        except ValueError as exc:
            raise ArenyxaError("NETWORK_TARGET_INVALID", "Network target URL is malformed.", domain="NETWORK_GOVERNANCE") from exc
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            raise ArenyxaError(
                "NETWORK_TARGET_INVALID",
                "Only HTTP and HTTPS network targets are accepted.",
                domain="NETWORK_GOVERNANCE",
            )
        self.network_guard.check_target(parsed.hostname, resolve_dns=True)

    def _tls_context(self, verify_tls: bool) -> ssl.SSLContext:
        key = bool(verify_tls)
        cached = self._tls_contexts.get(key)
        if cached is not None:
            return cached
        with self._tls_context_lock:
            cached = self._tls_contexts.get(key)
            if cached is None:
                cached = ssl.create_default_context()
                if not key:
                    cached.check_hostname = False
                    cached.verify_mode = ssl.CERT_NONE
                self._tls_contexts[key] = cached
            return cached

    @staticmethod
    def _apply_read_timeout(response: object, timeout: float) -> None:
        
        candidates = [
            getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None),
            getattr(
                getattr(getattr(getattr(response, "fp", None), "fp", None), "raw", None),
                "_sock",
                None,
            ),
        ]
        for sock in candidates:
            if sock is not None and hasattr(sock, "settimeout"):
                try:
                    sock.settimeout(float(timeout))
                    return
                except (OSError, TypeError, ValueError):
                    continue

    def _guard_content_length(self, headers: dict[str, str]) -> None:
        raw = self._header_value(headers, "Content-Length").strip()
        if not raw:
            return
        try:
            size = int(raw)
        except ValueError:
            return
        if size > self.max_response_bytes:
            raise ArenyxaError(
                "FETCH_TOO_LARGE",
                f"响应声明大小 {size} 字节，超过 {self.max_response_bytes} 字节上限。",
                domain="FETCH",
            )

    def _read_limited(
        self, response: object, token: CancellationToken, *, read_timeout: float
    ) -> bytes:
        






        body_buffer = bytearray()
        total = 0
        last_progress = time.monotonic()
        timeout = max(0.05, float(read_timeout))
        while True:
            token.checkpoint()
            try:
                chunk = response.read(64 * 1024)                              
            except socket.timeout as exc:
                token.checkpoint()
                if time.monotonic() - last_progress >= timeout:
                    raise ArenyxaError(
                        "FETCH_TIMEOUT",
                        "读取响应超时。",
                        domain="FETCH",
                        retryable=True,
                    ) from exc
                continue
            if not chunk:
                break
            last_progress = time.monotonic()
            total += len(chunk)
            if total > self.max_response_bytes:
                raise ArenyxaError(
                    "FETCH_TOO_LARGE",
                    f"响应超过 {self.max_response_bytes} 字节上限。",
                    domain="FETCH",
                )
            body_buffer.extend(chunk)
        return bytes(body_buffer)

    def _decompress_gzip_limited(self, payload: bytes, token: CancellationToken) -> bytes:
        body_buffer = bytearray()
        total = 0
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as stream:
                while True:
                    token.checkpoint()
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_response_bytes:
                        raise ArenyxaError(
                            "FETCH_TOO_LARGE",
                            f"解压后的响应超过 {self.max_response_bytes} 字节上限。",
                            domain="FETCH",
                        )
                    body_buffer.extend(chunk)
        except (gzip.BadGzipFile, EOFError, OSError) as exc:
            raise ArenyxaError(
                "FETCH_DECOMPRESSION_FAILED",
                "服务器返回了无效的 gzip 响应。",
                domain="FETCH",
                context={"details": str(exc)},
            ) from exc
        return bytes(body_buffer)

    @staticmethod
    def _header_value(headers: dict[str, str], name: str, default: str = "") -> str:
        wanted = name.casefold()
        for key, value in headers.items():
            if key.casefold() == wanted:
                return value
        return default

    @classmethod
    def _content_type(cls, headers: dict[str, str]) -> tuple[str, str]:
        message = Message()
        message["content-type"] = cls._header_value(headers, "Content-Type", "application/octet-stream")
        charset = message.get_content_charset() or "utf-8"
        try:
            codecs.lookup(charset)
        except LookupError:
                                                                                         
                                                                                              
                                                                   
            charset = "utf-8"
        return message.get_content_type(), charset
