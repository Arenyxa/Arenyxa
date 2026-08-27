"""Pooled Playwright browser runtime for Arenyxa Web Intelligence.

The pool owns dedicated worker threads because Playwright's synchronous runtime is
thread-affine.  Each worker lazily starts one Chromium process and keeps bounded,
session-keyed browser contexts alive across requests.  This gives crawler jobs
real browser/session reuse without sharing Playwright objects across threads.

All top-level and subresource http/https targets are checked through Arenyxa's
NetworkUseGuard before navigation is allowed.  Network observations are bounded
and sensitive request/response headers are redacted before they leave the engine.
"""
from __future__ import annotations

import fnmatch
import hashlib
import importlib.util
import logging
import queue
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import atomic_write_text
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard

LOGGER = logging.getLogger(__name__)

_SENSITIVE_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token",
}
_ALLOWED_WAIT_UNTIL = {"commit", "domcontentloaded", "load", "networkidle"}


@dataclass(slots=True)
class BrowserEngineConfig:
    workers: int = 2
    headless: bool = True
    max_sessions_per_worker: int = 8
    navigation_timeout_ms: int = 30_000
    max_network_events: int = 5_000
    max_websocket_frames: int = 1_000
    max_html_bytes: int = 16 * 1024 * 1024
    enable_cdp: bool = True
    capture_text_previews: bool = False
    text_preview_bytes: int = 512
    snapshot_root: str = ""
    remote_cdp_url: str = ""
    remote_cdp_headers: dict[str, str] = field(default_factory=dict)
    blocked_domains: list[str] = field(default_factory=list)

    def normalized(self) -> "BrowserEngineConfig":
        return BrowserEngineConfig(
            workers=max(1, min(8, int(self.workers))),
            headless=bool(self.headless),
            max_sessions_per_worker=max(1, min(64, int(self.max_sessions_per_worker))),
            navigation_timeout_ms=max(1_000, min(300_000, int(self.navigation_timeout_ms))),
            max_network_events=max(100, min(50_000, int(self.max_network_events))),
            max_websocket_frames=max(0, min(20_000, int(self.max_websocket_frames))),
            max_html_bytes=max(64 * 1024, min(128 * 1024 * 1024, int(self.max_html_bytes))),
            enable_cdp=bool(self.enable_cdp),
            capture_text_previews=bool(self.capture_text_previews),
            text_preview_bytes=max(32, min(4096, int(self.text_preview_bytes))),
            snapshot_root=str(self.snapshot_root or "").strip(),
            remote_cdp_url=_validated_cdp_url(self.remote_cdp_url),
            remote_cdp_headers=_validated_headers(self.remote_cdp_headers, limit=64),
            blocked_domains=[str(v).strip().casefold().rstrip(".") for v in self.blocked_domains if str(v).strip()][:4096],
        )


@dataclass(slots=True)
class BrowserRequest:
    url: str
    session_id: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    user_agent: str = ""
    locale: str = "en-US"
    viewport_width: int = 1440
    viewport_height: int = 900
    wait_until: str = "domcontentloaded"
    timeout_ms: int = 0
    snapshot: bool = False

    def normalized(self, defaults: BrowserEngineConfig) -> "BrowserRequest":
        value = str(self.url).strip()
        parsed = urlsplit(value)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Browser request requires a valid http/https URL")
        wait = str(self.wait_until or "domcontentloaded").casefold()
        if wait not in _ALLOWED_WAIT_UNTIL:
            raise ValueError(f"Unsupported browser wait_until mode: {wait}")
        headers: dict[str, str] = {}
        for key, raw in list(dict(self.headers).items())[:128]:
            name, content = str(key), str(raw)
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in name + content):
                raise ValueError("Browser headers cannot contain HTTP control characters")
            headers[name] = content
        cookies: dict[str, str] = {}
        for key, raw in list(dict(self.cookies).items())[:128]:
            name, content = str(key), str(raw)
            if not name or any(ord(ch) < 32 or ord(ch) == 127 for ch in name + content):
                raise ValueError("Browser cookies contain invalid control characters")
            cookies[name] = content
        timeout = int(self.timeout_ms or defaults.navigation_timeout_ms)
        return BrowserRequest(
            url=value,
            session_id=str(self.session_id or "")[:512],
            headers=headers,
            cookies=cookies,
            user_agent=str(self.user_agent or "")[:1024],
            locale=str(self.locale or "en-US")[:64],
            viewport_width=max(320, min(7680, int(self.viewport_width))),
            viewport_height=max(240, min(4320, int(self.viewport_height))),
            wait_until=wait,
            timeout_ms=max(1_000, min(300_000, timeout)),
            snapshot=bool(self.snapshot),
        )


@dataclass(slots=True)
class BrowserNetworkObservation:
    kind: str
    url: str = ""
    method: str = ""
    status: int | None = None
    resource_type: str = ""
    elapsed_ms: float | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    direction: str = ""
    size: int = 0
    sha256: str = ""
    text_preview: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BrowserFetchResult:
    requested_url: str
    final_url: str
    status: int
    title: str
    html: str
    elapsed_ms: float
    response_headers: dict[str, str] = field(default_factory=dict)
    network_events: list[BrowserNetworkObservation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    snapshot_path: str = ""
    cdp_enabled: bool = False
    cdp_metrics: dict[str, float] = field(default_factory=dict)
    session_id: str = ""

    def snapshot(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["network_events"] = [item.snapshot() for item in self.network_events]
        return payload


class BrowserWorker(Protocol):
    def fetch(self, request: BrowserRequest) -> BrowserFetchResult: ...
    def close(self) -> None: ...


@dataclass(slots=True)
class _PoolTask:
    request: BrowserRequest
    future: Future[BrowserFetchResult]


@dataclass(slots=True)
class _SessionContext:
    context: Any
    profile_signature: str
    last_used: float = field(default_factory=time.monotonic)


class PlaywrightBrowserWorker:
    """One thread-affine Chromium runtime with bounded reusable contexts."""

    def __init__(self, config: BrowserEngineConfig, guard: NetworkUseGuard) -> None:
        self.config = config.normalized()
        self.guard = guard
        self._playwright: Any | None = None
        self._browser: Any | None = None
        self._contexts: OrderedDict[str, _SessionContext] = OrderedDict()

    @staticmethod
    def dependency_available() -> bool:
        try:
            return importlib.util.find_spec("playwright.sync_api") is not None
        except (ImportError, ModuleNotFoundError, ValueError):
            return False

    def _ensure_runtime(self) -> None:
        if self._browser is not None:
            return
        if not self.dependency_available():
            raise ArenyxaError(
                "BROWSER_RUNTIME_UNAVAILABLE",
                "Browser Engine requires Playwright and a Chromium runtime",
                domain="CRAWLER",
                suggested_action="Install the browser extra and run: playwright install chromium",
            )
        try:
            from playwright.sync_api import sync_playwright
            self._playwright = sync_playwright().start()
            if self.config.remote_cdp_url:
                parsed = urlsplit(self.config.remote_cdp_url)
                assert parsed.hostname is not None
                self.guard.check_target(parsed.hostname, resolve_dns=True)
                self._browser = self._playwright.chromium.connect_over_cdp(
                    self.config.remote_cdp_url,
                    headers=dict(self.config.remote_cdp_headers) or None,
                    timeout=self.config.navigation_timeout_ms,
                )
            else:
                self._browser = self._playwright.chromium.launch(headless=self.config.headless)
        except (OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
            self.close()
            raise ArenyxaError(
                "BROWSER_RUNTIME_START_FAILED",
                f"Browser Engine could not start Chromium: {type(exc).__name__}: {exc}",
                domain="CRAWLER",
            ) from exc

    @staticmethod
    def _profile_signature(request: BrowserRequest) -> str:
        payload = "\x1f".join([
            request.user_agent, request.locale,
            str(request.viewport_width), str(request.viewport_height),
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _new_context(self, request: BrowserRequest) -> Any:
        assert self._browser is not None
        kwargs: dict[str, Any] = {
            "locale": request.locale,
            "viewport": {"width": request.viewport_width, "height": request.viewport_height},
            "accept_downloads": False,
            "ignore_https_errors": False,
        }
        if request.user_agent:
            kwargs["user_agent"] = request.user_agent
        return self._browser.new_context(**kwargs)

    def _context_for(self, request: BrowserRequest) -> tuple[Any, bool]:
        """Return context and whether it is ephemeral and must be closed by caller."""
        signature = self._profile_signature(request)
        if not request.session_id:
            return self._new_context(request), True
        current = self._contexts.get(request.session_id)
        if current is not None and current.profile_signature != signature:
            try:
                current.context.close()
            finally:
                self._contexts.pop(request.session_id, None)
            current = None
        if current is None:
            current = _SessionContext(self._new_context(request), signature)
            self._contexts[request.session_id] = current
        current.last_used = time.monotonic()
        self._contexts.move_to_end(request.session_id)
        while len(self._contexts) > self.config.max_sessions_per_worker:
            _old_key, old = self._contexts.popitem(last=False)
            try:
                old.context.close()
            except Exception:
                LOGGER.warning("Browser Engine context eviction cleanup failed", exc_info=True)
        return current.context, False

    def fetch(self, raw_request: BrowserRequest) -> BrowserFetchResult:
        request = raw_request.normalized(self.config)
        self._ensure_runtime()
        parsed = urlsplit(request.url)
        assert parsed.hostname is not None
        self.guard.check_target(parsed.hostname, resolve_dns=True)
        context, ephemeral = self._context_for(request)
        page: Any | None = None
        cdp: Any | None = None
        warnings: list[str] = []
        events: list[BrowserNetworkObservation] = []
        websocket_frames = 0
        started_requests: dict[int, float] = {}
        main_headers: dict[str, str] = {}
        main_status = 0
        cdp_enabled = False
        cdp_metrics: dict[str, float] = {}

        def append_event(event: BrowserNetworkObservation) -> None:
            if len(events) < self.config.max_network_events:
                events.append(event)
            elif not any(item == "browser-network-event-limit-reached" for item in warnings):
                warnings.append("browser-network-event-limit-reached")

        def route_request(route: Any, pw_request: Any) -> None:
            target = str(getattr(pw_request, "url", "") or "")
            target_parts = urlsplit(target)
            if target_parts.scheme.casefold() in {"http", "https"} and target_parts.hostname:
                host = target_parts.hostname.casefold().rstrip(".")
                if _domain_blocked(host, self.config.blocked_domains):
                    append_event(BrowserNetworkObservation(
                        kind="blocked-domain", url=target,
                        method=str(getattr(pw_request, "method", "") or ""),
                        resource_type=str(getattr(pw_request, "resource_type", "") or ""),
                        metadata={"reason": "configured-domain-block"},
                    ))
                    route.abort("blockedbyclient")
                    return
                try:
                    self.guard.check_target(target_parts.hostname, resolve_dns=True)
                except (OSError, RuntimeError, TimeoutError, TypeError, ValueError, ArenyxaError) as exc:
                    append_event(BrowserNetworkObservation(
                        kind="blocked-subresource", url=target,
                        method=str(getattr(pw_request, "method", "") or ""),
                        resource_type=str(getattr(pw_request, "resource_type", "") or ""),
                        metadata={"reason": type(exc).__name__},
                    ))
                    route.abort("blockedbyclient")
                    return
            route.continue_()

        def on_request(pw_request: Any) -> None:
            started_requests[id(pw_request)] = time.perf_counter()

        def on_response(response: Any) -> None:
            nonlocal main_headers, main_status
            pw_request = response.request
            resource_type = str(getattr(pw_request, "resource_type", "") or "")
            request_started = started_requests.pop(id(pw_request), None)
            elapsed = None if request_started is None else round((time.perf_counter() - request_started) * 1000.0, 3)
            try:
                request_headers = _redact_headers(dict(getattr(pw_request, "headers", {}) or {}))
            except Exception:
                request_headers = {}
            try:
                response_headers = _redact_headers(dict(getattr(response, "headers", {}) or {}))
            except Exception:
                response_headers = {}
            if pw_request.is_navigation_request() and pw_request.frame == page.main_frame:
                main_status = int(response.status)
                main_headers = response_headers
            append_event(BrowserNetworkObservation(
                kind="xhr" if resource_type in {"xhr", "fetch"} else "http",
                url=str(response.url), method=str(pw_request.method), status=int(response.status),
                resource_type=resource_type, elapsed_ms=elapsed,
                request_headers=request_headers, response_headers=response_headers,
            ))

        def on_request_failed(pw_request: Any) -> None:
            started_requests.pop(id(pw_request), None)
            failure = getattr(pw_request, "failure", None)
            append_event(BrowserNetworkObservation(
                kind="request-failed", url=str(getattr(pw_request, "url", "") or ""),
                method=str(getattr(pw_request, "method", "") or ""),
                resource_type=str(getattr(pw_request, "resource_type", "") or ""),
                metadata={"failure": str(failure or "request_failed")[:500]},
            ))

        def on_websocket(socket: Any) -> None:
            ws_url = str(getattr(socket, "url", "") or "")
            append_event(BrowserNetworkObservation(kind="websocket-open", url=ws_url, resource_type="websocket"))

            def frame(direction: str, payload: Any) -> None:
                nonlocal websocket_frames
                if websocket_frames >= self.config.max_websocket_frames:
                    return
                websocket_frames += 1
                raw = _frame_bytes(payload)
                preview = ""
                if self.config.capture_text_previews and isinstance(payload, str):
                    preview = payload[: self.config.text_preview_bytes]
                append_event(BrowserNetworkObservation(
                    kind="websocket-frame", url=ws_url, resource_type="websocket",
                    direction=direction, size=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                    text_preview=preview,
                ))

            socket.on("framesent", lambda payload: frame("outbound", payload))
            socket.on("framereceived", lambda payload: frame("inbound", payload))
            socket.on("close", lambda *_args: append_event(
                BrowserNetworkObservation(kind="websocket-close", url=ws_url, resource_type="websocket")
            ))

        started = time.monotonic()
        try:
            page = context.new_page()
            if request.headers:
                page.set_extra_http_headers(dict(request.headers))
            if request.cookies:
                context.add_cookies([
                    {"name": key, "value": value, "url": request.url}
                    for key, value in request.cookies.items()
                ])
            page.route("**/*", route_request)
            page.on("request", on_request)
            page.on("response", on_response)
            page.on("requestfailed", on_request_failed)
            page.on("websocket", on_websocket)

            if self.config.enable_cdp:
                try:
                    cdp = context.new_cdp_session(page)
                    cdp.send("Network.enable")
                    cdp.send("Performance.enable")
                    cdp_enabled = True
                except Exception as exc:
                    warnings.append(f"cdp-unavailable:{type(exc).__name__}")
                    cdp = None

            navigation_response = page.goto(request.url, timeout=request.timeout_ms, wait_until=request.wait_until)
            if navigation_response is not None and not main_status:
                main_status = int(navigation_response.status)
                try:
                    main_headers = _redact_headers(dict(navigation_response.headers or {}))
                except Exception:
                    main_headers = {}
            final_url = str(page.url)
            final_parts = urlsplit(final_url)
            if final_parts.scheme.casefold() in {"http", "https"} and final_parts.hostname:
                self.guard.check_target(final_parts.hostname, resolve_dns=True)

            markup = str(page.content())
            markup_size = len(markup.encode("utf-8"))
            if markup_size > self.config.max_html_bytes:
                raise ArenyxaError(
                    "BROWSER_DOM_LIMIT",
                    f"Rendered DOM exceeds the configured {self.config.max_html_bytes} byte safety limit",
                    domain="CRAWLER",
                )
            title = str(page.title())[:1024]
            if cdp is not None:
                try:
                    metrics = cdp.send("Performance.getMetrics")
                    for item in list(metrics.get("metrics", []))[:256]:
                        name = str(item.get("name", ""))
                        value = item.get("value")
                        if name and isinstance(value, (int, float)):
                            cdp_metrics[name] = float(value)
                except Exception as exc:
                    warnings.append(f"cdp-metrics-unavailable:{type(exc).__name__}")

            snapshot_path = ""
            if request.snapshot and self.config.snapshot_root:
                root = Path(self.config.snapshot_root).expanduser().resolve()
                root.mkdir(parents=True, exist_ok=True)
                identity = hashlib.sha256(
                    f"{request.url}\x1f{time.time_ns()}".encode("utf-8")
                ).hexdigest()[:24]
                target = root / f"dom-{identity}.html"
                atomic_write_text(target, markup, encoding="utf-8")
                snapshot_path = str(target)

            return BrowserFetchResult(
                requested_url=request.url,
                final_url=final_url,
                status=int(main_status),
                title=title,
                html=markup,
                elapsed_ms=round((time.monotonic() - started) * 1000.0, 3),
                response_headers=main_headers,
                network_events=events,
                warnings=warnings,
                snapshot_path=snapshot_path,
                cdp_enabled=cdp_enabled,
                cdp_metrics=cdp_metrics,
                session_id=request.session_id,
            )
        except ArenyxaError:
            raise
        except Exception as exc:
            raise ArenyxaError(
                "BROWSER_FETCH_FAILED",
                f"Browser navigation failed: {type(exc).__name__}: {exc}",
                domain="CRAWLER",
            ) from exc
        finally:
            if cdp is not None:
                try:
                    cdp.detach()
                except Exception:
                    LOGGER.debug("CDP detach failed", exc_info=True)
            if page is not None:
                try:
                    page.close()
                except Exception:
                    LOGGER.warning("Browser page cleanup failed", exc_info=True)
            if ephemeral:
                try:
                    context.close()
                except Exception:
                    LOGGER.warning("Ephemeral browser context cleanup failed", exc_info=True)

    def close(self) -> None:
        for _key, item in list(self._contexts.items()):
            try:
                item.context.close()
            except Exception:
                LOGGER.warning("Browser session cleanup failed", exc_info=True)
        self._contexts.clear()
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                LOGGER.warning("Chromium shutdown failed", exc_info=True)
            self._browser = None
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:
                LOGGER.warning("Playwright shutdown failed", exc_info=True)
            self._playwright = None


class BrowserPool:
    """Bounded dedicated-worker browser pool with sticky session routing."""

    def __init__(
        self,
        config: BrowserEngineConfig | None = None,
        *,
        network_policy: NetworkGuardPolicy | None = None,
        network_guard: NetworkUseGuard | None = None,
        worker_factory: Callable[[int], BrowserWorker] | None = None,
        max_contexts: int | None = None,
    ) -> None:
        if max_contexts is not None:
            if int(max_contexts) <= 0:
                raise ValueError("max_contexts must be greater than zero")
            if config is None:
                config = BrowserEngineConfig(workers=1, max_sessions_per_worker=int(max_contexts))
        self.config = (config or BrowserEngineConfig()).normalized()
        self.max_contexts = int(max_contexts) if max_contexts is not None else self.config.workers * self.config.max_sessions_per_worker
        self.guard = network_guard or NetworkUseGuard(network_policy or NetworkGuardPolicy())
        self._closed = False
        self._close_lock = threading.RLock()
        self._queues: list[queue.Queue[_PoolTask | None]] = [
            queue.Queue(maxsize=128) for _ in range(self.config.workers)
        ]
        self._threads: list[threading.Thread] = []
        self._round_robin = 0
        self._round_robin_lock = threading.Lock()
        self._factory = worker_factory or (lambda _index: PlaywrightBrowserWorker(self.config, self.guard))
        for index in range(self.config.workers):
            thread = threading.Thread(
                target=self._worker_main,
                args=(index,),
                name=f"arenyxa-browser-{index + 1}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    @staticmethod
    def dependency_available() -> bool:
        return PlaywrightBrowserWorker.dependency_available()

    def _worker_main(self, index: int) -> None:
        worker: BrowserWorker | None = None
        try:
            worker = self._factory(index)
            inbox = self._queues[index]
            while True:
                task = inbox.get()
                try:
                    if task is None:
                        return
                    if task.future.set_running_or_notify_cancel():
                        try:
                            task.future.set_result(worker.fetch(task.request))
                        except (ArenyxaError, OSError, RuntimeError, TimeoutError, TypeError, ValueError) as exc:
                            task.future.set_exception(exc)
                finally:
                    inbox.task_done()
        finally:
            if worker is not None:
                try:
                    worker.close()
                except Exception:
                    LOGGER.warning("Browser worker cleanup failed", exc_info=True)

    def _worker_index(self, session_id: str) -> int:
        if session_id:
            digest = hashlib.blake2b(session_id.encode("utf-8"), digest_size=8).digest()
            return int.from_bytes(digest, "big") % len(self._queues)
        with self._round_robin_lock:
            index = self._round_robin % len(self._queues)
            self._round_robin += 1
            return index

    def fetch(self, request: BrowserRequest) -> BrowserFetchResult:
        normalized = request.normalized(self.config)
        with self._close_lock:
            if self._closed:
                raise RuntimeError("BrowserPool is closed")
            index = self._worker_index(normalized.session_id)
            future: Future[BrowserFetchResult] = Future()
            task = _PoolTask(normalized, future)
            try:
                self._queues[index].put(task, timeout=max(1.0, normalized.timeout_ms / 1000.0))
            except queue.Full as exc:
                raise ArenyxaError(
                    "BROWSER_POOL_SATURATED",
                    "Browser Engine worker queue is saturated",
                    domain="CRAWLER",
                ) from exc
        try:
            return future.result(timeout=max(5.0, normalized.timeout_ms / 1000.0 + 15.0))
        except TimeoutError as exc:
            future.cancel()
            raise ArenyxaError(
                "BROWSER_POOL_TIMEOUT",
                "Browser Engine task exceeded its bounded execution window",
                domain="CRAWLER",
            ) from exc

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
            for inbox in self._queues:
                while True:
                    try:
                        inbox.put(None, timeout=0.5)
                        break
                    except queue.Full:
                        continue
        for thread in self._threads:
            thread.join(timeout=10.0)
            if thread.is_alive():
                LOGGER.error("Browser worker did not terminate cleanly: %s", thread.name)

    def __enter__(self) -> "BrowserPool":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


def _validated_cdp_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw)
    if parsed.scheme.casefold() not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        raise ValueError("remote_cdp_url must be an http/https/ws/wss endpoint")
    return raw


def _validated_headers(values: Mapping[str, Any], *, limit: int) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in list(dict(values).items())[:limit]:
        name, content = str(key), str(value)
        if any((ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in name + content):
            raise ValueError("Browser transport headers cannot contain HTTP control characters")
        output[name] = content
    return output


def _domain_blocked(host: str, patterns: list[str]) -> bool:
    normalized = str(host or "").casefold().rstrip(".")
    for pattern in patterns:
        value = str(pattern or "").casefold().strip().rstrip(".")
        if not value:
            continue
        if "*" in value or "?" in value or "[" in value:
            if fnmatch.fnmatchcase(normalized, value):
                return True
        elif normalized == value or normalized.endswith("." + value):
            return True
    return False


def _redact_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in list(headers.items())[:256]:
        name = str(key)[:256]
        output[name] = "<redacted>" if name.casefold() in _SENSITIVE_HEADERS else str(value)[:8192]
    return output


def _frame_bytes(payload: Any) -> bytes:
    if isinstance(payload, bytes):
        return payload
    if isinstance(payload, bytearray):
        return bytes(payload)
    if isinstance(payload, memoryview):
        return payload.tobytes()
    return str(payload).encode("utf-8", errors="replace")
