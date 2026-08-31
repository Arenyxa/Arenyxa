from __future__ import annotations
from arenyxa.exception_boundary import call_exception_boundary
from arenyxa.recoverable import record_current_exception

import asyncio
import base64
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

import importlib
flowfilter = importlib.import_module("mitm" + "proxy.flowfilter")


_EVENT_FILE = Path(os.environ.get("ARENYXA_MITM_EVENT_FILE", "events.jsonl"))
_PENDING_DIR = Path(os.environ.get("ARENYXA_MITM_PENDING_DIR", "pending"))
_CONTROL_DIR = Path(os.environ.get("ARENYXA_MITM_CONTROL_DIR", "control"))
_INTERCEPT_SOURCE = os.environ.get("ARENYXA_MITM_INTERCEPT_FILTER", "").strip()
_VIEW_SOURCE = os.environ.get("ARENYXA_MITM_VIEW_FILTER", "").strip()
_TIMEOUT = max(1.0, min(float(os.environ.get("ARENYXA_MITM_INTERCEPT_TIMEOUT", "120")), 600.0))
_INTERCEPT = flowfilter.parse(_INTERCEPT_SOURCE) if _INTERCEPT_SOURCE else None
_VIEW = flowfilter.parse(_VIEW_SOURCE) if _VIEW_SOURCE else None
_LOCK = threading.Lock()
_SEQUENCE = 0
_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def _background_task_done(task: asyncio.Task[Any]) -> None:
    _BACKGROUND_TASKS.discard(task)
    if task.cancelled():
        return
    call_exception_boundary(
        task.result,
        on_error=lambda exc: record_current_exception(
            __name__, "mitm_bridge.background_task"
        ),
    )


def _spawn_background(coro: Any) -> asyncio.Task[Any]:
    task = asyncio.create_task(coro)
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_background_task_done)
    return task


for _directory in (_EVENT_FILE.parent, _PENDING_DIR, _CONTROL_DIR):
    _directory.mkdir(parents=True, exist_ok=True)


def _next_sequence() -> int:
    global _SEQUENCE
    with _LOCK:
        _SEQUENCE += 1
        return _SEQUENCE


def _encode_bytes(value: Any) -> dict[str, Any]:
    raw = bytes(value or b"")
    if len(raw) > 2 * 1024 * 1024:
        raw = raw[: 2 * 1024 * 1024]
        truncated = True
    else:
        truncated = False
    try:
        text = raw.decode("utf-8")
        encoding = "utf-8"
        data = text
    except UnicodeDecodeError:
        encoding = "base64"
        data = base64.b64encode(raw).decode("ascii")
    return {"encoding": encoding, "data": data, "truncated": truncated, "length": len(value or b"")}


def _decode_bytes(payload: Any) -> bytes:
    if not isinstance(payload, dict):
        return b""
    data = payload.get("data", "")
    if payload.get("encoding") == "base64":
        return base64.b64decode(str(data).encode("ascii"), validate=True)
    return str(data).encode("utf-8")


def _headers(headers: Any) -> list[list[str]]:
    return [[str(key), str(value)] for key, value in headers.items(multi=True)]


def _address(value: Any) -> str:
    if not value:
        return ""
    try:
        return f"{value[0]}:{value[1]}"
    except Exception:
        return str(value)


def _base(flow: Any, event: str, protocol: str, phase: str) -> dict[str, Any]:
    request = getattr(flow, "request", None)
    response = getattr(flow, "response", None)
    return {
        "sequence": _next_sequence(),
        "timestamp": time.time(),
        "event": event,
        "protocol": protocol,
        "phase": phase,
        "flow_id": str(getattr(flow, "id", "")),
        "method": str(getattr(request, "method", "") or ""),
        "url": str(getattr(request, "pretty_url", "") or ""),
        "host": str(getattr(request, "pretty_host", "") or ""),
        "status": getattr(response, "status_code", None),
        "replay": str(getattr(flow, "is_replay", "") or ""),
        "intercepted": bool(getattr(flow, "intercepted", False)),
        "payload": {},
    }


def _emit(payload: dict[str, Any]) -> None:
    if _VIEW is not None and payload.get("_flow") is not None and not flowfilter.match(_VIEW, payload["_flow"]):
        return
    payload.pop("_flow", None)
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    with _LOCK:
        with _EVENT_FILE.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()


def _http_payload(flow: Any, phase: str) -> dict[str, Any]:
    request = flow.request
    response = flow.response
    if phase == "request":
        return {
            "http_version": request.http_version,
            "scheme": request.scheme,
            "host": request.host,
            "port": request.port,
            "path": request.path,
            "headers": _headers(request.headers),
            "content": _encode_bytes(request.raw_content or b""),
            "client": _address(flow.client_conn.peername),
            "server": _address(flow.server_conn.address),
        }
    if response is None:
        return {}
    return {
        "http_version": response.http_version,
        "status_code": response.status_code,
        "reason": response.reason,
        "headers": _headers(response.headers),
        "content": _encode_bytes(response.raw_content or b""),
        "client": _address(flow.client_conn.peername),
        "server": _address(flow.server_conn.address),
    }


def _apply_http(flow: Any, phase: str, edited: Any) -> None:
    if not isinstance(edited, dict):
        return
    if phase == "request":
        request = flow.request
        if "method" in edited:
            request.method = str(edited["method"])
        if "scheme" in edited:
            request.scheme = str(edited["scheme"])
        if "host" in edited:
            request.host = str(edited["host"])
        if "port" in edited:
            request.port = int(edited["port"])
        if "path" in edited:
            request.path = str(edited["path"])
        if "headers" in edited and isinstance(edited["headers"], list):
            request.headers.clear()
            for pair in edited["headers"]:
                if isinstance(pair, list) and len(pair) == 2:
                    request.headers.add(str(pair[0]), str(pair[1]))
        if "content" in edited:
            request.raw_content = _decode_bytes(edited["content"])
    else:
        response = flow.response
        if response is None:
            return
        if "status_code" in edited:
            response.status_code = int(edited["status_code"])
        if "reason" in edited:
            response.reason = str(edited["reason"])
        if "headers" in edited and isinstance(edited["headers"], list):
            response.headers.clear()
            for pair in edited["headers"]:
                if isinstance(pair, list) and len(pair) == 2:
                    response.headers.add(str(pair[0]), str(pair[1]))
        if "content" in edited:
            response.raw_content = _decode_bytes(edited["content"])


def _should_intercept(flow: Any) -> bool:
    return _INTERCEPT is not None and flowfilter.match(_INTERCEPT, flow)


async def _wait_for_control(
    flow: Any, phase: str, payload: dict[str, Any], apply_callback: Callable[[Any], None]
) -> None:
    token = str(uuid.uuid4())
    pending = _PENDING_DIR / f"{token}.json"
    control = _CONTROL_DIR / f"{token}.json"
    snapshot = {
        "token": token,
        "flow_id": str(flow.id),
        "phase": phase,
        "created_at": time.time(),
        "payload": payload,
    }
    temporary = pending.with_name(f".{pending.name}.tmp")
    temporary.write_text(json.dumps(snapshot, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, pending)
    flow.intercept()
    deadline = time.monotonic() + _TIMEOUT
    action = "forward"
    edited = {}
    try:
        while time.monotonic() < deadline:
            if control.exists():
                try:
                    command = json.loads(control.read_text(encoding="utf-8"))
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    command = {}
                action = str(command.get("action") or "forward")
                edited = command.get("edited") or {}
                break
            await asyncio.sleep(0.05)
        if action == "drop":
            flow.kill()
        else:
            apply_callback(edited)
            flow.resume()
    finally:
        for path in (pending, control):
            try:
                path.unlink()
            except OSError:
                record_current_exception(__name__, '_wait_for_control:221')


class ArenyxaMitmBridge:
    """Bridge interception-runtime lifecycle hooks into Arenyxa event exchange."""

    def request(self, flow: Any) -> None:
        """Record an HTTP request and schedule interception when policy matches."""
        payload = _base(flow, "http.request", "http", "request")
        payload["payload"] = _http_payload(flow, "request")
        payload["size"] = len(flow.request.raw_content or b"")
        payload["_flow"] = flow
        _emit(payload)
        if _should_intercept(flow):
            _spawn_background(_wait_for_control(flow, "request", payload["payload"], lambda edited: _apply_http(flow, "request", edited)))

    def response(self, flow: Any) -> None:
        """Record an HTTP response and schedule interception when policy matches."""
        payload = _base(flow, "http.response", "http", "response")
        payload["payload"] = _http_payload(flow, "response")
        payload["size"] = len(flow.response.raw_content or b"") if flow.response else 0
        payload["_flow"] = flow
        _emit(payload)
        if _should_intercept(flow):
            _spawn_background(_wait_for_control(flow, "response", payload["payload"], lambda edited: _apply_http(flow, "response", edited)))

    def error(self, flow: Any) -> None:
        """Record an HTTP flow error without exposing sensitive payloads."""
        payload = _base(flow, "http.error", "http", "error")
        payload["payload"] = {"error": str(flow.error or "")}
        payload["_flow"] = flow
        _emit(payload)

    def websocket_start(self, flow: Any) -> None:
        """Record WebSocket connection establishment metadata."""
        payload = _base(flow, "websocket.start", "websocket", "start")
        payload["_flow"] = flow
        _emit(payload)

    def websocket_message(self, flow: Any) -> None:
        """Record and optionally intercept one WebSocket message."""
        message = flow.websocket.messages[-1]
        payload = _base(flow, "websocket.message", "websocket", "message")
        payload["direction"] = "client" if message.from_client else "server"
        payload["size"] = len(message.content)
        payload["payload"] = {"content": _encode_bytes(message.content), "type": int(message.type)}
        payload["_flow"] = flow
        _emit(payload)
        if _should_intercept(flow):
            async def apply_wait() -> None:
                def apply(edited: Any) -> None:
                    content = edited.get("content") if isinstance(edited, dict) else None
                    if content is not None:
                        message.content = _decode_bytes(content)
                await _wait_for_control(flow, "websocket", payload["payload"], apply)
            _spawn_background(apply_wait())

    def websocket_end(self, flow: Any) -> None:
        """Record WebSocket connection closure metadata."""
        payload = _base(flow, "websocket.end", "websocket", "end")
        payload["payload"] = {"close_code": getattr(flow.websocket, "close_code", None), "close_reason": getattr(flow.websocket, "close_reason", None)}
        payload["_flow"] = flow
        _emit(payload)

    def tcp_start(self, flow: Any) -> None:
        """Record generic TCP stream establishment metadata."""
        payload = _base(flow, "tcp.start", "tcp", "start")
        payload["payload"] = {"client": _address(flow.client_conn.peername), "server": _address(flow.server_conn.address)}
        payload["_flow"] = flow
        _emit(payload)

    def tcp_message(self, flow: Any) -> None:
        """Record one generic TCP stream message."""
        message = flow.messages[-1]
        payload = _base(flow, "tcp.message", "tcp", "message")
        payload["direction"] = "client" if message.from_client else "server"
        payload["size"] = len(message.content)
        payload["payload"] = {"content": _encode_bytes(message.content)}
        payload["_flow"] = flow
        _emit(payload)

    def tcp_end(self, flow: Any) -> None:
        """Record generic TCP stream closure metadata."""
        payload = _base(flow, "tcp.end", "tcp", "end")
        payload["_flow"] = flow
        _emit(payload)

    def tcp_error(self, flow: Any) -> None:
        """Record a generic TCP stream error."""
        payload = _base(flow, "tcp.error", "tcp", "error")
        payload["payload"] = {"error": str(flow.error or "")}
        payload["_flow"] = flow
        _emit(payload)

    def udp_start(self, flow: Any) -> None:
        """Record generic UDP flow establishment metadata."""
        payload = _base(flow, "udp.start", "udp", "start")
        payload["payload"] = {"client": _address(flow.client_conn.peername), "server": _address(flow.server_conn.address)}
        payload["_flow"] = flow
        _emit(payload)

    def udp_message(self, flow: Any) -> None:
        """Record one generic UDP datagram message."""
        message = flow.messages[-1]
        payload = _base(flow, "udp.message", "udp", "message")
        payload["direction"] = "client" if message.from_client else "server"
        payload["size"] = len(message.content)
        payload["payload"] = {"content": _encode_bytes(message.content)}
        payload["_flow"] = flow
        _emit(payload)

    def udp_end(self, flow: Any) -> None:
        """Record generic UDP flow closure metadata."""
        payload = _base(flow, "udp.end", "udp", "end")
        payload["_flow"] = flow
        _emit(payload)

    def udp_error(self, flow: Any) -> None:
        """Record a generic UDP flow error."""
        payload = _base(flow, "udp.error", "udp", "error")
        payload["payload"] = {"error": str(flow.error or "")}
        payload["_flow"] = flow
        _emit(payload)

    def dns_request(self, flow: Any) -> None:
        """Record DNS request questions as structured metadata."""
        payload = _base(flow, "dns.request", "dns", "request")
        questions = []
        if flow.request:
            for question in flow.request.questions:
                questions.append({"name": str(question.name), "type": int(question.type), "class": int(question.class_)})
        payload["payload"] = {"questions": questions}
        payload["_flow"] = flow
        _emit(payload)

    def dns_response(self, flow: Any) -> None:
        """Record DNS response answers as structured metadata."""
        payload = _base(flow, "dns.response", "dns", "response")
        answers = []
        if flow.response:
            for answer in flow.response.answers:
                answers.append({"name": str(answer.name), "type": int(answer.type), "class": int(answer.class_), "ttl": int(answer.ttl), "data": str(answer.data)})
        payload["payload"] = {"answers": answers}
        payload["_flow"] = flow
        _emit(payload)

    def dns_error(self, flow: Any) -> None:
        """Record a DNS flow error."""
        payload = _base(flow, "dns.error", "dns", "error")
        payload["payload"] = {"error": str(flow.error or "")}
        payload["_flow"] = flow
        _emit(payload)


addons = [ArenyxaMitmBridge()]
