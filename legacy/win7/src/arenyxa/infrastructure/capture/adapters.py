from __future__ import annotations

from arenyxa.infrastructure.process_safety import validated_argv
import hashlib
from datetime import datetime
from arenyxa.compat import UTC, strict_zip
import shutil
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent, utc_now
from arenyxa.application.reliability import ResourceLease, ResourceLeasePool
from arenyxa.infrastructure.atomic_io import atomic_write_text
from arenyxa.infrastructure.capture.bodies import NetworkBodyStore
from arenyxa.platform_compat import select_runtime


class BrowserCaptureAdapter:
    

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
            import playwright.sync_api              
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
        try:
            value = getattr(obj, name)
            return value() if callable(value) else value
        except Exception:
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

    def _run(self, session: CaptureSession, emit: Callable[[NetworkEvent], None]) -> None:
        from playwright.sync_api import sync_playwright

        context: Any = None
        try:
            with sync_playwright() as playwright:
                context = playwright.chromium.launch_persistent_context(
                    str(self.profile_dir),
                    headless=self.headless,
                    ignore_https_errors=False,
                    record_har_path=str(self.profile_dir / "session.har"),
                )
                self._browser_context = context
                page = context.pages[0] if context.pages else context.new_page()
                started: dict[int, float] = {}
                responses: dict[int, Any] = {}
                seen_tls_flows: set[str] = set()

                def on_request(request: Any) -> None:
                    started[id(request)] = time.perf_counter()

                def on_response(response: Any) -> None:
                    responses[id(response.request)] = response

                def emit_http(request: Any, response: Any | None, *, failed: bool = False) -> None:
                    if self._pause.is_set() or self._stop.is_set():
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

                    flags = [name for name in ("authorization", "cookie") if name in {str(k).casefold() for k in request_headers}]
                    body_artifacts: list[dict[str, Any]] = []
                    request_body_ref: str | None = None
                    request_payload = self._playwright_value(request, "post_data_buffer")
                    if request_payload is None:
                        request_payload = self._playwright_value(request, "post_data")
                    if request_payload is not None:
                        flags.append("request_body")
                        request_body_ref, artifact = self._store_payload(
                            session,
                            request_payload,
                            content_type=str(request_headers.get("content-type", "")),
                            encoding="utf-8" if isinstance(request_payload, str) else "",
                            sensitive=bool(flags),
                        )
                        if artifact:
                            body_artifacts.append(artifact)

                    response_body_ref: str | None = None
                    response_payload: bytes | None = None
                    response_body_capture = "not_attempted"
                                                                                                
                                                                                                
                                                                                                
                    resource_type = str(self._playwright_value(request, "resource_type", "") or "")
                    may_read_unknown = resource_type in {"xhr", "fetch", "document"}
                    if response is not None and self.body_store is not None and (
                        0 < content_length <= self.body_store.max_body_bytes or (content_length <= 0 and may_read_unknown)
                    ):
                        response_body_capture = "attempted"
                        response_payload = self._playwright_value(response, "body")
                        if isinstance(response_payload, (bytes, bytearray, memoryview)):
                            response_body_ref, artifact = self._store_payload(
                                session,
                                response_payload,
                                content_type=content_type,
                            )
                            if artifact:
                                body_artifacts.append(artifact)
                                response_body_capture = "stored" if not artifact.get("truncated") else "stored_truncated"
                            elif len(response_payload) == 0:
                                response_body_capture = "empty"
                    elif response is not None and self.body_store is None:
                        response_body_capture = "disabled"
                    elif response is not None and content_length > 0:
                        response_body_capture = "skipped_size_budget"
                    elif response is not None:
                        response_body_capture = "skipped_unknown_size_resource"

                    server = self._playwright_value(response, "server_addr", {}) if response else {}
                    security = self._playwright_value(response, "security_details", {}) if response else {}
                    if not isinstance(server, dict):
                        server = {}
                    if not isinstance(security, dict):
                        security = {}
                    remote_ip = str(server.get("ipAddress") or server.get("ip_address") or "")
                    remote_port = server.get("port")
                    flow_ref: str | None = None
                    if remote_ip:
                        flow_ref = f"browser:{remote_ip}:{remote_port or 0}"
                    elif parsed.hostname:
                        flow_ref = f"browser-host:{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"

                    timing_value = self._playwright_value(request, "timing", {})
                    timing = {"total_ms": elapsed}
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
                    if content_length > 0:
                        metadata["declared_content_length"] = content_length
                    if remote_ip:
                        metadata["remote_address"] = remote_ip
                        if remote_port is not None:
                            metadata["remote_port"] = remote_port
                        if remote_port is not None:
                            metadata["remote_endpoint"] = f"[{remote_ip}]:{remote_port}" if ":" in remote_ip else f"{remote_ip}:{remote_port}"
                        else:
                            metadata["remote_endpoint"] = remote_ip
                    if body_artifacts:
                        metadata["body_artifacts"] = body_artifacts
                    if failed:
                        failure = self._playwright_value(request, "failure", "")
                        error_text = getattr(failure, "error_text", failure) if failure else "request_failed"
                        metadata["error"] = str(error_text)

                    tls_version = str(security.get("protocol") or "")
                    tls_flow_key = flow_ref or str(parsed.hostname or "")
                    if tls_version and tls_flow_key and tls_flow_key not in seen_tls_flows:
                        seen_tls_flows.add(tls_flow_key)
                        metadata.update(
                            {
                                "tls_version": tls_version,
                                "server_name": str(parsed.hostname or ""),
                                "tls_issuer": str(security.get("issuer") or ""),
                                "cert_subject": str(security.get("subjectName") or ""),
                                "cert_valid_from": security.get("validFrom"),
                                "cert_valid_to": security.get("validTo"),
                            }
                        )

                    size = len(response_payload) if response_payload is not None else max(0, content_length)
                    emit(
                        NetworkEvent(
                            session_id=session.id,
                            source_type=CaptureSource.BROWSER,
                            protocol=parsed.scheme or "http",
                            direction="bidirectional",
                            size=size,
                            process_ref=None,
                            flow_ref=flow_ref,
                            method=str(request.method),
                            url=str(request.url),
                            status=status,
                            host=parsed.hostname,
                            timing=timing,
                            request_headers=request_headers,
                            response_headers=response_headers,
                            request_body_ref=request_body_ref,
                            response_body_ref=response_body_ref,
                            sensitivity_flags=sorted(set(flags)),
                            initiator=resource_type,
                            metadata=metadata,
                        )
                    )

                def on_request_finished(request: Any) -> None:
                    response = responses.pop(id(request), None)
                    if response is None:
                        response = self._playwright_value(request, "response")
                    emit_http(request, response)

                def on_request_failed(request: Any) -> None:
                    responses.pop(id(request), None)
                    emit_http(request, None, failed=True)

                def on_websocket(socket: Any) -> None:
                    ws_url = str(self._playwright_value(socket, "url", "") or "")
                    parsed = urlparse(ws_url)
                    websocket_id = f"browser-ws:{id(socket)}"
                    flow_ref = websocket_id
                    common = {
                        "resource_type": "websocket",
                        "websocket_id": websocket_id,
                        "transport": "tcp",
                        "encrypted_payload": parsed.scheme.casefold() == "wss",
                        "connection_confidence": "websocket",
                    }
                    if not self._pause.is_set() and not self._stop.is_set():
                        emit(
                            NetworkEvent(
                                session_id=session.id,
                                source_type=CaptureSource.BROWSER,
                                protocol="websocket",
                                direction="bidirectional",
                                size=0,
                                flow_ref=flow_ref,
                                url=ws_url,
                                host=parsed.hostname,
                                metadata={**common, "opened_at": utc_now()},
                            )
                        )

                    def frame(direction: str, payload: Any) -> None:
                        if self._pause.is_set() or self._stop.is_set():
                            return
                        opcode = "binary" if isinstance(payload, (bytes, bytearray, memoryview)) else "text"
                        raw_size = len(payload) if isinstance(payload, (bytes, bytearray, memoryview)) else len(str(payload).encode("utf-8"))
                        body_ref, artifact = self._store_payload(
                            session,
                            payload if isinstance(payload, (bytes, bytearray, memoryview, str)) else str(payload),
                            content_type="application/octet-stream" if opcode == "binary" else "text/plain",
                            encoding="" if opcode == "binary" else "utf-8",
                        )
                        metadata = {**common, "opcode": opcode}
                        if artifact:
                            metadata["body_artifacts"] = [artifact]
                        emit(
                            NetworkEvent(
                                session_id=session.id,
                                source_type=CaptureSource.BROWSER,
                                protocol="websocket",
                                direction=direction,
                                size=raw_size,
                                flow_ref=flow_ref,
                                url=ws_url,
                                host=parsed.hostname,
                                request_body_ref=body_ref if direction == "outbound" else None,
                                response_body_ref=body_ref if direction == "inbound" else None,
                                metadata=metadata,
                            )
                        )

                    def on_close(*_args: Any) -> None:
                        if self._pause.is_set() or self._stop.is_set():
                            return
                        emit(
                            NetworkEvent(
                                session_id=session.id,
                                source_type=CaptureSource.BROWSER,
                                protocol="websocket",
                                direction="bidirectional",
                                size=0,
                                flow_ref=flow_ref,
                                url=ws_url,
                                host=parsed.hostname,
                                metadata={**common, "closed_at": utc_now()},
                            )
                        )

                    socket.on("framesent", lambda payload: frame("outbound", payload))
                    socket.on("framereceived", lambda payload: frame("inbound", payload))
                    socket.on("close", on_close)

                page.on("request", on_request)
                page.on("response", on_response)
                page.on("requestfinished", on_request_finished)
                page.on("requestfailed", on_request_failed)
                page.on("websocket", on_websocket)
                page.goto(self.url, wait_until="domcontentloaded")
                snapshot_path = self.profile_dir / "dom-snapshot.html"
                atomic_write_text(snapshot_path, page.content(), encoding="utf-8")
                self.snapshot_ref = str(snapshot_path)
                while not self._stop.wait(0.1):
                    pass
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
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            if self._thread.is_alive():
                raise ArenyxaError(
                    "CAPTURE_SOURCE_LOST", "浏览器捕获线程未能在超时内停止。", domain="CAPTURE"
                )

    def failure(self) -> Exception | None:
        if self._error is not None:
            return self._error
        if self._thread and not self._thread.is_alive() and not self._stop.is_set():
            return ArenyxaError("CAPTURE_SOURCE_LOST", "浏览器捕获线程意外退出。", domain="CAPTURE")
        return None

    def pause(self) -> None:
        self._pause.set()

    def resume(self) -> None:
        self._pause.clear()


class TsharkPacketAdapter:
    

    FIELDS = (
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "frame.cap_len",
        "frame.protocols",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "_ws.col.Protocol",
        "_ws.col.Info",
        "tcp.stream",
        "dns.qry.name",
        "tls.handshake.version",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.response.code",
    )
    OPTIONAL_FIELDS = (
        "udp.stream",
        "dns.qry.type",
        "dns.a",
        "dns.aaaa",
        "dns.time",
        "tls.handshake.ciphersuite",
        "tls.handshake.extensions_alpn_str",
        "tls.handshake.extensions_server_name",
        "http2.streamid",
        "quic.stream.stream_id",
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.spurious_retransmission",
        "tcp.analysis.out_of_order",
        "tcp.analysis.lost_segment",
        "tcp.analysis.duplicate_ack",
        "tcp.analysis.zero_window",
        "tcp.analysis.window_full",
        "tcp.analysis.keep_alive",
        "tcp.analysis.bytes_in_flight",
        "tcp.analysis.ack_rtt",
    )
    _field_cache: dict[str, tuple[str, ...]] = {}
    _field_cache_lock = threading.Lock()

    def __init__(self, interface: str = "1", capture_filter: str = "", raw_dir: Path | None = None) -> None:
        self.interface = interface
        self.capture_filter = capture_filter
        self._process: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None
        self._paused = threading.Event()
        self.raw_dir = raw_dir
        self._dumpcap: subprocess.Popen[bytes] | None = None
        self._stop_requested = threading.Event()
        self._error: Exception | None = None
        self._stderr_tail: deque[str] = deque(maxlen=64)
        self._stderr_threads: list[threading.Thread] = []
        self._active_fields: tuple[str, ...] = self.FIELDS

    @staticmethod
    def available() -> bool:
        return shutil.which("tshark") is not None

    def start(self, session: CaptureSession, emit: Callable[[NetworkEvent], None]) -> None:
        self._stop_requested.clear()
        self._paused.clear()
        self._error = None
        self._stderr_tail.clear()
        self._stderr_threads.clear()
        executable = shutil.which("tshark")
        if not executable:
            raise ArenyxaError(
                "CAPTURE_DRIVER_MISSING",
                "未发现 tshark。系统级抓包需要兼容的 packet-analysis runtime 与 packet-capture driver；浏览器抓包不需要管理员权限。",
                domain="CAPTURE",
                suggested_action="安装兼容的 packet-analysis runtime 与 packet-capture driver；或改用 Browser Capture/HAR。",
            )
        arguments = [
            executable,
            "-l",
            "-n",
            "-i",
            self.interface,
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=d",
        ]
        self._active_fields = self._supported_fields(executable)
        for field_name in self._active_fields:
            arguments.extend(["-e", field_name])
        if self.capture_filter:
            arguments.extend(["-f", self.capture_filter])
        dumpcap = shutil.which("dumpcap")
        started_processes: list[subprocess.Popen[Any]] = []
        try:
            if dumpcap and self.raw_dir:
                self.raw_dir.mkdir(parents=True, exist_ok=True)
                raw_arguments = [
                    dumpcap,
                    "-q",
                    "-i",
                    self.interface,
                    "-b",
                    "filesize:16384",
                    "-b",
                    "files:64",
                    "-w",
                    str(self.raw_dir / "capture.pcapng"),
                ]
                if self.capture_filter:
                    raw_arguments.extend(["-f", self.capture_filter])
                self._dumpcap = subprocess.Popen(
                    validated_argv(raw_arguments),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                )
                started_processes.append(self._dumpcap)
            self._process = subprocess.Popen(
                validated_argv(arguments),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            started_processes.append(self._process)
        except Exception:
                                                                                         
                                                                                           
                                                                             
            for process in reversed(started_processes):
                try:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=2.0)
                except (OSError, subprocess.SubprocessError):
                    pass
            self._process = None
            self._dumpcap = None
            raise

        if self._process.stderr is not None:
            self._start_stderr_drain(self._process.stderr, "tshark")
        if self._dumpcap is not None and self._dumpcap.stderr is not None:
            self._start_stderr_drain(self._dumpcap.stderr, "dumpcap")
        self._thread = threading.Thread(
            target=self._read,
            args=(session, emit),
            name="arenyxa-packet-capture",
            daemon=True,
        )
        try:
            self._thread.start()
        except Exception:
                                                                                               
                                                                                
            self.stop()
            raise

    def _read(self, session: CaptureSession, emit: Callable[[NetworkEvent], None]) -> None:
        try:
            self._read_impl(session, emit)
            if not self._stop_requested.is_set() and self._error is None:
                tail = " | ".join(self._stderr_tail)[-1500:]
                self._error = ArenyxaError(
                    "CAPTURE_SOURCE_LOST",
                    "tshark 输出流意外结束。",
                    domain="CAPTURE",
                    context={"stderr_tail": tail},
                )
        except Exception as exc:
            if not self._stop_requested.is_set():
                self._error = exc

    def _read_impl(self, session: CaptureSession, emit: Callable[[NetworkEvent], None]) -> None:
        assert self._process and self._process.stdout
        port_map: dict[int, str] = {}
        last_process_refresh = 0.0
        for line in self._process.stdout:
            if self._paused.is_set():
                continue
            values = [value.strip().strip('"') for value in line.rstrip("\r\n").split("\t")]
            values.extend([""] * (len(self._active_fields) - len(values)))
            row = dict(strict_zip(self._active_fields, values, strict=False))
            source = row.get("ip.src", "") or row.get("ipv6.src", "")
            destination = row.get("ip.dst", "") or row.get("ipv6.dst", "")
            source_port = row.get("tcp.srcport", "") or row.get("udp.srcport", "")
            destination_port = row.get("tcp.dstport", "") or row.get("udp.dstport", "")
            if time.monotonic() - last_process_refresh > 2.0:
                port_map = self._process_port_map()
                last_process_refresh = time.monotonic()
            source_process = port_map.get(int(source_port)) if source_port.isdigit() else None
            destination_process = port_map.get(int(destination_port)) if destination_port.isdigit() else None
            if source_process and not destination_process:
                direction = "outbound"
                process_ref = source_process
                local_address, local_port = source, source_port
                remote_address, remote_port = destination, destination_port
            elif destination_process:
                direction = "inbound"
                process_ref = destination_process
                local_address, local_port = destination, destination_port
                remote_address, remote_port = source, source_port
            else:
                direction = "unknown"
                process_ref = source_process or destination_process
                local_address = local_port = remote_address = remote_port = ""

            raw_protocol = row.get("_ws.col.Protocol", "").strip()
            raw_lower = raw_protocol.casefold()
            if raw_lower.startswith("tls") or raw_lower == "ssl":
                protocol = "tls"
            elif raw_lower in {"http2", "http/2"}:
                protocol = "h2"
            elif raw_lower in {"http3", "http/3"}:
                protocol = "h3"
            else:
                protocol = raw_lower or "unknown"
            transport = "tcp" if row.get("tcp.srcport") or row.get("tcp.dstport") else "udp" if row.get("udp.srcport") or row.get("udp.dstport") else "unknown"
            method = row.get("http.request.method") or None
            dns_name = row.get("dns.qry.name", "")
            tls_name = row.get("tls.handshake.extensions_server_name", "")
            host = row.get("http.host") or dns_name or tls_name or None
            uri = row.get("http.request.uri", "")
            scheme = "https" if protocol in {"tls", "https", "http2", "http3", "h2", "h3"} else "http"
            url = f"{scheme}://{host}{uri}" if host and uri else None
            tcp_stream = row.get("tcp.stream", "")
            udp_stream = row.get("udp.stream", "")
            flow_ref = f"tcp:{tcp_stream}" if tcp_stream else f"udp:{udp_stream}" if udp_stream else None
            answers: list[str] = []
            for field_name in ("dns.a", "dns.aaaa"):
                value = row.get(field_name, "")
                if value:
                    answers.extend(item.strip() for item in value.split(",") if item.strip())
            query_type = self._dns_type_name(row.get("dns.qry.type", ""))
            metadata: dict[str, Any] = {
                "frame_number": int(row.get("frame.number", "")) if row.get("frame.number", "").isdigit() else None,
                "captured_length": int(row.get("frame.cap_len", "")) if row.get("frame.cap_len", "").isdigit() else None,
                "frame_protocols": row.get("frame.protocols", ""),
                "packet_info": row.get("_ws.col.Info", ""),
                "tcp_stream": int(tcp_stream) if tcp_stream.isdigit() else None,
                "udp_stream": int(udp_stream) if udp_stream.isdigit() else None,
                "http2_stream": int(row.get("http2.streamid", "")) if row.get("http2.streamid", "").isdigit() else None,
                "quic_stream": int(row.get("quic.stream.stream_id", "")) if row.get("quic.stream.stream_id", "").isdigit() else None,
                "source_address": source or None,
                "destination_address": destination or None,
                "source_port": int(source_port) if source_port.isdigit() else None,
                "destination_port": int(destination_port) if destination_port.isdigit() else None,
                "transport": transport,
                "connection_confidence": "stream" if flow_ref else "5-tuple",
                "encrypted_payload": protocol in {"tls", "quic", "https", "http3", "h3"},
                "dissector_protocol": raw_protocol,
            }
            if local_address:
                metadata["local_address"] = local_address
                metadata["local_port"] = int(local_port) if str(local_port).isdigit() else None
            if remote_address:
                metadata["remote_address"] = remote_address
                metadata["remote_port"] = int(remote_port) if str(remote_port).isdigit() else None
            if dns_name:
                metadata.update({"resource_type": "dns", "query_name": dns_name, "query_type": query_type, "answers": answers})
                try:
                    dns_time = float(row.get("dns.time", "") or 0) * 1000
                except (TypeError, ValueError, OverflowError):
                    dns_time = 0.0
                if dns_time > 0:
                    metadata["elapsed_ms"] = dns_time
            tls_version = row.get("tls.handshake.version", "")
            if tls_version:
                metadata["tls_version"] = tls_version
            cipher = row.get("tls.handshake.ciphersuite", "")
            if cipher:
                metadata["cipher"] = cipher
            alpn = row.get("tls.handshake.extensions_alpn_str", "")
            if alpn:
                metadata["alpn"] = alpn
                metadata["http_version"] = alpn
            if tls_name:
                metadata["server_name"] = tls_name
            tcp_analysis_fields = (
                "tcp.analysis.retransmission",
                "tcp.analysis.fast_retransmission",
                "tcp.analysis.spurious_retransmission",
                "tcp.analysis.out_of_order",
                "tcp.analysis.lost_segment",
                "tcp.analysis.duplicate_ack",
                "tcp.analysis.zero_window",
                "tcp.analysis.window_full",
                "tcp.analysis.keep_alive",
            )
            tcp_analysis = [name[len("tcp.analysis."):] for name in tcp_analysis_fields if row.get(name, "")]
            if tcp_analysis:
                metadata["tcp_analysis"] = tcp_analysis
            bytes_in_flight = row.get("tcp.analysis.bytes_in_flight", "")
            if bytes_in_flight.isdigit():
                metadata["tcp_bytes_in_flight"] = int(bytes_in_flight)
            ack_rtt = row.get("tcp.analysis.ack_rtt", "")
            if ack_rtt:
                try:
                    metadata["tcp_ack_rtt_ms"] = float(ack_rtt) * 1000.0
                except (TypeError, ValueError, OverflowError):
                    pass

            emit(
                NetworkEvent(
                    session_id=session.id,
                    source_type=CaptureSource.SYSTEM,
                    protocol=protocol,
                    direction=direction,
                    size=int(row.get("frame.len", "0") or 0),
                    timestamp=self._epoch_timestamp(row.get("frame.time_epoch", "")),
                    process_ref=process_ref,
                    flow_ref=flow_ref,
                    method=method,
                    url=url,
                    status=int(row.get("http.response.code", "")) if row.get("http.response.code", "").isdigit() else None,
                    host=host,
                    metadata=metadata,
                )
            )

    @staticmethod
    def _epoch_timestamp(value: str) -> str:
        try:
            epoch = float(str(value or ""))
            if epoch > 0:
                return datetime.fromtimestamp(epoch, tz=UTC).isoformat()
        except (TypeError, ValueError, OverflowError, OSError):
            pass
        return utc_now()

    @classmethod
    def _supported_fields(cls, executable: str) -> tuple[str, ...]:
        with cls._field_cache_lock:
            cached = cls._field_cache.get(executable)
            if cached is not None:
                return cached
        supported: set[str] = set()
        try:
            completed = subprocess.run(
                validated_argv([executable, "-G", "fields"]),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if completed.returncode == 0:
                for line in completed.stdout.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 3 and parts[0] == "F":
                        supported.add(parts[2])
        except (OSError, subprocess.SubprocessError):
            supported.clear()
        fields = cls.FIELDS + tuple(field for field in cls.OPTIONAL_FIELDS if field in supported) if supported else cls.FIELDS
        with cls._field_cache_lock:
            cls._field_cache[executable] = fields
        return fields

    @staticmethod
    def _dns_type_name(value: str) -> str:
        mapping = {"1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX", "16": "TXT", "28": "AAAA", "33": "SRV", "65": "HTTPS"}
        text = str(value or "").strip()
        return mapping.get(text, text or "A")

    def stop(self) -> None:
        self._stop_requested.set()
        stuck: list[str] = []

        def stop_process(process: subprocess.Popen[object] | None, label: str) -> None:
            if process is None or process.poll() is not None:
                return
            try:
                process.terminate()
                process.wait(timeout=5)
                return
            except (OSError, subprocess.TimeoutExpired):
                pass
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                stuck.append(label)

        stop_process(self._process, "tshark")
        if self._thread:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                stuck.append("capture-reader")
        stop_process(self._dumpcap, "dumpcap")
        for thread in self._stderr_threads:
            thread.join(timeout=1)
        if stuck:
            raise ArenyxaError(
                "CAPTURE_SOURCE_STOP_TIMEOUT",
                "系统抓包组件未能在超时内完全停止。",
                domain="CAPTURE",
                context={"components": sorted(set(stuck))},
            )

    def failure(self) -> Exception | None:
        if self._error is not None:
            return self._error
        if self._stop_requested.is_set():
            return None
        if self._process and self._process.poll() is not None:
            return ArenyxaError(
                "CAPTURE_SOURCE_LOST",
                f"tshark 意外退出（code={self._process.returncode}）。",
                domain="CAPTURE",
                context={"stderr_tail": " | ".join(self._stderr_tail)[-1500:]},
            )
        if self._dumpcap and self._dumpcap.poll() not in {None, 0}:
            return ArenyxaError(
                "CAPTURE_SOURCE_LOST",
                f"dumpcap 意外退出（code={self._dumpcap.returncode}）。",
                domain="CAPTURE",
                context={"stderr_tail": " | ".join(self._stderr_tail)[-1500:]},
            )
        return None

    def _start_stderr_drain(self, stream: Any, label: str) -> None:
        def drain() -> None:
            try:
                for raw in iter(stream.readline, b"" if "b" in getattr(stream, "mode", "") else ""):
                    if not raw:
                        break
                    text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
                    self._stderr_tail.append(f"{label}: {text.strip()}")
            except Exception:
                return

        thread = threading.Thread(target=drain, name=f"arenyxa-{label}-stderr", daemon=True)
        self._stderr_threads.append(thread)
        thread.start()

    def pause(self) -> None:
        self._paused.set()

    def resume(self) -> None:
        self._paused.clear()

    def committed_chunks(self) -> list[dict[str, Any]]:
        if not self.raw_dir or not self.raw_dir.exists():
            return []
        chunks = []
        for sequence, path in enumerate(sorted(self.raw_dir.glob("*.pcapng*"))):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            chunks.append(
                {
                    "id": f"{path.stem}-{sequence}",
                    "sequence": sequence,
                    "path": str(path),
                    "byte_size": path.stat().st_size,
                    "sha256": digest.hexdigest(),
                    "committed_at": utc_now(),
                }
            )
        return chunks

    @staticmethod
    def _process_port_map() -> dict[int, str]:
        mapping: dict[int, str] = {}
        for item in ProcessNetworkMonitor().snapshot():
            local = str(item.get("local", ""))
            try:
                port = int(local.rsplit(":", 1)[-1])
            except ValueError:
                continue
            process = str(item.get("process") or item.get("pid") or "")
            mapping[port] = process
        return mapping


class ProcessNetworkMonitor:
    def snapshot(self) -> list[dict[str, Any]]:
        try:
            import psutil
        except ImportError:
            return self._netstat_snapshot()
        try:
            processes = {
                process.pid: process.info.get("name", "") for process in psutil.process_iter(["pid", "name"])
            }
            result = []
            for connection in psutil.net_connections(kind="inet"):
                result.append(
                    {
                        "pid": connection.pid,
                        "process": processes.get(connection.pid or -1, "System"),
                        "local": f"{connection.laddr.ip}:{connection.laddr.port}" if connection.laddr else "",
                        "remote": f"{connection.raddr.ip}:{connection.raddr.port}"
                        if connection.raddr
                        else "",
                        "status": connection.status,
                        "family": str(connection.family),
                        "type": str(connection.type),
                    }
                )
            return result
        except (OSError, PermissionError, psutil.Error):
                                                                                         
                                                                                            
                                                                                        
            return self._netstat_snapshot()

    @staticmethod
    def _netstat_snapshot() -> list[dict[str, Any]]:
        try:
            completed = subprocess.run(
                validated_argv(["netstat", "-ano", "-p", "tcp"]),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5.0,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
                                                                                               
                                                                                                
            return []
        rows = []
        for line in completed.stdout.splitlines():
            parts = line.split()
            if len(parts) == 5 and parts[0].upper() == "TCP" and parts[4].isdigit():
                rows.append(
                    {
                        "pid": int(parts[4]),
                        "process": "",
                        "local": parts[1],
                        "remote": parts[2],
                        "status": parts[3],
                        "family": "",
                        "type": "TCP",
                    }
                )
        return rows
