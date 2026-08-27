from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from arenyxa.application.reliability import ResourceLease, ResourceLeasePool
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent, utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_text
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.platform_compat import select_runtime

class BrowserCaptureAdapter:
    """Capture browser HTTP, TLS metadata, and WebSocket traffic safely."""

    def __init__(
        self,
        url: str,
        profile_dir: Path,
        headless: bool = False,
        *,
        body_store: NetworkBodyStore | None = None,
        browser_pool: ResourceLeasePool | None = None,
    ) -> None:
        self.url = url
        self.profile_dir = profile_dir
        self.headless = headless
        self.body_store = body_store
        self.browser_pool = browser_pool
        self._browser_lease: ResourceLease | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._browser_context: Any = None
        self.snapshot_ref: str | None = None
        self._error: Exception | None = None

    def start(self, session: CaptureSession, emit: Callable[[NetworkEvent], None]) -> None:
        """Start browser capture in a bounded background thread."""
        if not select_runtime().browser_automation:
            raise ArenyxaError(
                "CAPTURE_BROWSER_UNSUPPORTED_LEGACY",
                "Windows 7 Legacy Enterprise 不支持内置 Chromium 浏览器捕获；请使用 HTTP/代理/导入式捕获。",
                domain="CAPTURE",
            )
        self._stop.clear()
        self._pause.clear()
        self._error = None
        try:
            import playwright.sync_api  # noqa: F401
        except ImportError as exc:
            raise ArenyxaError(
                "CAPTURE_BROWSER_DEPENDENCY_MISSING",
                "浏览器捕获需要安装 playwright extra，并执行 playwright install chromium。",
                domain="CAPTURE",
                suggested_action="运行 pip install -e .[browser]，然后运行 playwright install chromium。",
            ) from exc
        if self.browser_pool is not None:
            self._browser_lease = self.browser_pool.acquire(
                code="BROWSER_RESOURCE_LIMIT",
                message="浏览器实例已达到 Resource Governor 当前上限，请等待现有实例结束。",
            )
        self._thread = threading.Thread(
            target=self._run,
            args=(session, emit),
            name="arenyxa-browser-capture",
            daemon=True,
        )
        try:
            self._thread.start()
        except Exception:
            if self._browser_lease is not None:
                self._browser_lease.release()
                self._browser_lease = None
            raise

    @staticmethod
    def _playwright_value(obj: Any, name: str, default: Any = None) -> Any:
        """Read a Playwright property or method without leaking adapter-specific failures."""
        try:
            value = getattr(obj, name)
            return value() if callable(value) else value
        except Exception:
            # Playwright exposes backend-specific exception classes; metadata probes are best-effort.
            return default

    def _store_payload(
        self,
        session: CaptureSession,
        payload: Any,
        *,
        content_type: str = "",
        encoding: str = "",
        sensitive: bool = False,
    ) -> tuple[str | None, dict[str, Any] | None]:
        """Persist a bounded captured body and return its durable reference."""
        if self.body_store is None or payload is None:
            return None, None
        if not isinstance(payload, (bytes, bytearray, memoryview, str)):
            return None, None
        if len(payload) == 0:
            return None, None
        artifact = self.body_store.put(
            session.id,
            payload,
            content_type=content_type,
            encoding=encoding,
            sensitive=sensitive,
        )
        return artifact.id, self.body_store.metadata(artifact)

    def _capture_enabled(self) -> bool:
        return not self._pause.is_set() and not self._stop.is_set()

    def _capture_response_body(
        self,
        session: CaptureSession,
        response: Any | None,
        *,
        content_length: int,
        content_type: str,
        resource_type: str,
    ) -> tuple[str | None, bytes | None, str, list[dict[str, Any]]]:
        body_ref: str | None = None
        payload: bytes | None = None
        artifacts: list[dict[str, Any]] = []
        if response is None:
            return body_ref, payload, "not_attempted", artifacts
        if self.body_store is None:
            return body_ref, payload, "disabled", artifacts

        may_read_unknown = resource_type in {"xhr", "fetch", "document"}
        within_budget = 0 < content_length <= self.body_store.max_body_bytes
        if not within_budget and not (content_length <= 0 and may_read_unknown):
            state = "skipped_size_budget" if content_length > 0 else "skipped_unknown_size_resource"
            return body_ref, payload, state, artifacts

        payload_value = self._playwright_value(response, "body")
        if not isinstance(payload_value, (bytes, bytearray, memoryview)):
            return body_ref, payload, "attempted", artifacts
        payload = bytes(payload_value)
        if not payload:
            return body_ref, payload, "empty", artifacts
        body_ref, artifact = self._store_payload(session, payload, content_type=content_type)
        if artifact:
            artifacts.append(artifact)
            return body_ref, payload, "stored_truncated" if artifact.get("truncated") else "stored", artifacts
        return body_ref, payload, "attempted", artifacts

    def _http_connection_metadata(
        self,
        request: Any,
        response: Any | None,
        *,
        parsed: Any,
        elapsed_ms: float,
        response_body_capture: str,
        resource_type: str,
    ) -> tuple[dict[str, Any], dict[str, Any], str | None, dict[str, Any]]:
        server = self._playwright_value(response, "server_addr", {}) if response else {}
        security = self._playwright_value(response, "security_details", {}) if response else {}
        if not isinstance(server, dict):
            server = {}
        if not isinstance(security, dict):
            security = {}
        remote_ip = str(server.get("ipAddress") or server.get("ip_address") or "")
        remote_port = server.get("port")
        if remote_ip:
            flow_ref = f"browser:{remote_ip}:{remote_port or 0}"
        elif parsed.hostname:
            default_port = 443 if parsed.scheme == "https" else 80
            flow_ref = f"browser-host:{parsed.hostname}:{parsed.port or default_port}"
        else:
            flow_ref = None

        timing: dict[str, Any] = {"total_ms": elapsed_ms}
        timing_value = self._playwright_value(request, "timing", {})
        if isinstance(timing_value, dict):
            for key, value in timing_value.items():
                try:
                    numeric = float(value)
                except (TypeError, ValueError, OverflowError):
                    continue
                if numeric >= 0:
                    timing[str(key)] = numeric

        metadata: dict[str, Any] = {
            "resource_type": resource_type,
            "frame_url": str(self._playwright_value(self._playwright_value(request, "frame"), "url", "") or ""),
            "service_worker": bool(self._playwright_value(response, "from_service_worker", False)) if response else False,
            "dom_snapshot_ref": self.snapshot_ref,
            "connection_confidence": "endpoint" if flow_ref else "host",
            "transport": "tcp",
            "encrypted_payload": parsed.scheme.casefold() in {"https", "wss"},
            "response_body_capture": response_body_capture,
        }
        if remote_ip:
            metadata["remote_address"] = remote_ip
            if remote_port is not None:
                metadata["remote_port"] = remote_port
                metadata["remote_endpoint"] = f"[{remote_ip}]:{remote_port}" if ":" in remote_ip else f"{remote_ip}:{remote_port}"
            else:
                metadata["remote_endpoint"] = remote_ip
        return metadata, security, flow_ref, timing

    def _emit_http_event(
        self,
        session: CaptureSession,
        emit: Callable[[NetworkEvent], None],
        started: dict[int, float],
        seen_tls_flows: set[str],
        request: Any,
        response: Any | None,
        *,
        failed: bool = False,
    ) -> None:
        if not self._capture_enabled():
            return
        elapsed = (time.perf_counter() - started.pop(id(request), time.perf_counter())) * 1000
        parsed = urlparse(str(request.url))
        request_headers = dict(self._playwright_value(request, "headers", {}) or {})
        response_headers = dict(self._playwright_value(response, "headers", {}) or {}) if response else {}
        status = int(self._playwright_value(response, "status", 0) or 0) if response else None
        content_type = str(response_headers.get("content-type", ""))
        try:
            content_length = int(response_headers.get("content-length", "0") or 0)
        except (TypeError, ValueError, OverflowError):
            content_length = 0

        flags = [name for name in ("authorization", "cookie") if name in {str(key).casefold() for key in request_headers}]
        artifacts: list[dict[str, Any]] = []
        request_payload = self._playwright_value(request, "post_data_buffer")
        if request_payload is None:
            request_payload = self._playwright_value(request, "post_data")
        request_body_ref: str | None = None
        if request_payload is not None:
            flags.append("request_body")
            request_body_ref, artifact = self._store_payload(
                session, request_payload,
                content_type=str(request_headers.get("content-type", "")),
                encoding="utf-8" if isinstance(request_payload, str) else "",
                sensitive=bool(flags),
            )
            if artifact:
                artifacts.append(artifact)

        resource_type = str(self._playwright_value(request, "resource_type", "") or "")
        response_body_ref, response_payload, response_state, response_artifacts = self._capture_response_body(
            session, response, content_length=content_length, content_type=content_type, resource_type=resource_type
        )
        artifacts.extend(response_artifacts)
        metadata, security, flow_ref, timing = self._http_connection_metadata(
            request, response, parsed=parsed, elapsed_ms=elapsed,
            response_body_capture=response_state, resource_type=resource_type,
        )
        if content_length > 0:
            metadata["declared_content_length"] = content_length
        if artifacts:
            metadata["body_artifacts"] = artifacts
        if failed:
            failure = self._playwright_value(request, "failure", "")
            error_text = getattr(failure, "error_text", failure) if failure else "request_failed"
            metadata["error"] = str(error_text)

        tls_version = str(security.get("protocol") or "")
        tls_flow_key = flow_ref or str(parsed.hostname or "")
        if tls_version and tls_flow_key and tls_flow_key not in seen_tls_flows:
            seen_tls_flows.add(tls_flow_key)
            metadata.update({
                "tls_version": tls_version,
                "server_name": str(parsed.hostname or ""),
                "tls_issuer": str(security.get("issuer") or ""),
                "cert_subject": str(security.get("subjectName") or ""),
                "cert_valid_from": security.get("validFrom"),
                "cert_valid_to": security.get("validTo"),
            })
        size = len(response_payload) if response_payload is not None else max(0, content_length)
        emit(NetworkEvent(
            session_id=session.id, source_type=CaptureSource.BROWSER, protocol=parsed.scheme or "http",
            direction="bidirectional", size=size, process_ref=None, flow_ref=flow_ref,
            method=str(request.method), url=str(request.url), status=status, host=parsed.hostname,
            timing=timing,
            request_headers=request_headers, response_headers=response_headers, request_body_ref=request_body_ref,
            response_body_ref=response_body_ref, sensitivity_flags=sorted(set(flags)), initiator=resource_type, metadata=metadata,
        ))

    def _emit_websocket_frame(
        self,
        session: CaptureSession,
        emit: Callable[[NetworkEvent], None],
        *,
        direction: str,
        payload: Any,
        ws_url: str,
        host: str | None,
        flow_ref: str,
        common: dict[str, Any],
    ) -> None:
        if not self._capture_enabled():
            return
        binary = isinstance(payload, (bytes, bytearray, memoryview))
        opcode = "binary" if binary else "text"
        normalized = payload if isinstance(payload, (bytes, bytearray, memoryview, str)) else str(payload)
        raw_size = len(normalized) if binary else len(str(normalized).encode("utf-8"))
        body_ref, artifact = self._store_payload(
            session, normalized,
            content_type="application/octet-stream" if binary else "text/plain",
            encoding="" if binary else "utf-8",
        )
        metadata = {**common, "opcode": opcode}
        if artifact:
            metadata["body_artifacts"] = [artifact]
        emit(NetworkEvent(
            session_id=session.id, source_type=CaptureSource.BROWSER, protocol="websocket",
            direction=direction, size=raw_size, flow_ref=flow_ref, url=ws_url, host=host,
            request_body_ref=body_ref if direction == "outbound" else None,
            response_body_ref=body_ref if direction == "inbound" else None, metadata=metadata,
        ))

    def _bind_websocket(
        self, session: CaptureSession, emit: Callable[[NetworkEvent], None], socket: Any
    ) -> None:
        ws_url = str(self._playwright_value(socket, "url", "") or "")
        parsed = urlparse(ws_url)
        flow_ref = f"browser-ws:{id(socket)}"
        common = {
            "resource_type": "websocket", "websocket_id": flow_ref, "transport": "tcp",
            "encrypted_payload": parsed.scheme.casefold() == "wss", "connection_confidence": "websocket",
        }
        if self._capture_enabled():
            emit(NetworkEvent(
                session_id=session.id, source_type=CaptureSource.BROWSER, protocol="websocket",
                direction="bidirectional", size=0, flow_ref=flow_ref, url=ws_url, host=parsed.hostname,
                metadata={**common, "opened_at": utc_now()},
            ))

        socket.on("framesent", lambda payload: self._emit_websocket_frame(
            session, emit, direction="outbound", payload=payload, ws_url=ws_url, host=parsed.hostname, flow_ref=flow_ref, common=common
        ))
        socket.on("framereceived", lambda payload: self._emit_websocket_frame(
            session, emit, direction="inbound", payload=payload, ws_url=ws_url, host=parsed.hostname, flow_ref=flow_ref, common=common
        ))

        def on_close(*_args: Any) -> None:
            if self._capture_enabled():
                emit(NetworkEvent(
                    session_id=session.id, source_type=CaptureSource.BROWSER, protocol="websocket",
                    direction="bidirectional", size=0, flow_ref=flow_ref, url=ws_url, host=parsed.hostname,
                    metadata={**common, "closed_at": utc_now()},
                ))

        socket.on("close", on_close)

    def _bind_page_events(
        self, page: Any, session: CaptureSession, emit: Callable[[NetworkEvent], None]
    ) -> None:
        started: dict[int, float] = {}
        responses: dict[int, Any] = {}
        seen_tls_flows: set[str] = set()

        page.on("request", lambda request: started.__setitem__(id(request), time.perf_counter()))
        page.on("response", lambda response: responses.__setitem__(id(response.request), response))

        def on_finished(request: Any) -> None:
            response = responses.pop(id(request), None) or self._playwright_value(request, "response")
            self._emit_http_event(session, emit, started, seen_tls_flows, request, response)

        def on_failed(request: Any) -> None:
            responses.pop(id(request), None)
            self._emit_http_event(session, emit, started, seen_tls_flows, request, None, failed=True)

        page.on("requestfinished", on_finished)
        page.on("requestfailed", on_failed)
        page.on("websocket", lambda socket: self._bind_websocket(session, emit, socket))

    def _run(self, session: CaptureSession, emit: Callable[[NetworkEvent], None]) -> None:
        from playwright.sync_api import sync_playwright

        context: Any = None
        try:
            with sync_playwright() as playwright:
                context = playwright.chromium.launch_persistent_context(
                    str(self.profile_dir), headless=self.headless, ignore_https_errors=False,
                    record_har_path=str(self.profile_dir / "session.har"),
                )
                self._browser_context = context
                page = context.pages[0] if context.pages else context.new_page()
                self._bind_page_events(page, session, emit)
                page.goto(self.url, wait_until="domcontentloaded")
                snapshot_path = self.profile_dir / "dom-snapshot.html"
                atomic_write_text(snapshot_path, page.content(), encoding="utf-8")
                self.snapshot_ref = str(snapshot_path)
                self._stop.wait()
        except Exception as exc:
            if not self._stop.is_set():
                self._error = exc
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception as exc:
                    if not self._stop.is_set() and self._error is None:
                        self._error = exc
            self._browser_context = None
            if self._browser_lease is not None:
                self._browser_lease.release()
                self._browser_lease = None

    def stop(self) -> None:
        """Stop capture and wait for the background thread to terminate."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                raise ArenyxaError(
                    "CAPTURE_SOURCE_LOST", "浏览器捕获线程未能在超时内停止。", domain="CAPTURE"
                )

    def failure(self) -> Exception | None:
        """Return the terminal adapter failure, if one exists."""
        if self._error is not None:
            return self._error
        if self._thread and not self._thread.is_alive() and not self._stop.is_set():
            return ArenyxaError("CAPTURE_SOURCE_LOST", "浏览器捕获线程意外退出。", domain="CAPTURE")
        return None

    def pause(self) -> None:
        """Pause event emission while leaving the browser context alive."""
        self._pause.set()

    def resume(self) -> None:
        """Resume browser event emission after a pause."""
        self._pause.clear()
