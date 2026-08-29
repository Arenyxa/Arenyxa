from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit

from arenyxa.infrastructure.capture.proxy_models import ProxyFlow
from arenyxa.infrastructure.capture.proxy_transport import _parse_raw_message, _secure_write


def _headers_for_har(
    headers: list[tuple[str, str]], *, redact_sensitive: bool
) -> list[dict[str, str]]:
    sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
    return [
        {
            "name": name,
            "value": "[REDACTED]"
            if redact_sensitive and name.casefold() in sensitive
            else value,
        }
        for name, value in headers
    ]


def _har_entry(flow: ProxyFlow, *, redact_sensitive: bool) -> dict[str, Any] | None:
    if not flow.request_raw or flow.tunnel:
        return None
    try:
        request_line, request_headers, request_body = _parse_raw_message(flow.request_raw)
    except ValueError:
        return None
    request_parts = request_line.split(" ", 2)
    if len(request_parts) != 3:
        return None
    method, _, http_version = request_parts
    response_headers: list[tuple[str, str]] = []
    response_body = b""
    status_text = flow.reason
    response_version = http_version
    if flow.response_raw:
        try:
            response_line, response_headers, response_body = _parse_raw_message(flow.response_raw)
            response_parts = response_line.split(" ", 2)
            if response_parts:
                response_version = response_parts[0]
            if len(response_parts) >= 3:
                status_text = response_parts[2]
        except ValueError:
            response_headers = []
            response_body = b""
    content_type = next(
        (value for name, value in response_headers if name.casefold() == "content-type"),
        "",
    )
    textual = any(
        token in content_type.casefold()
        for token in ("text/", "json", "xml", "javascript", "graphql")
    )
    content: dict[str, Any] = {"size": len(response_body), "mimeType": content_type}
    if response_body:
        content["text"] = (
            response_body.decode("utf-8", "replace")
            if textual
            else base64.b64encode(response_body).decode("ascii")
        )
        if not textual:
            content["encoding"] = "base64"
    parsed_url = urlsplit(flow.url)
    request_content_type = next(
        (value for name, value in request_headers if name.casefold() == "content-type"),
        "",
    )
    request: dict[str, Any] = {
        "method": method,
        "url": flow.url,
        "httpVersion": http_version,
        "headers": _headers_for_har(request_headers, redact_sensitive=redact_sensitive),
        "queryString": [
            {"name": name, "value": value}
            for name, value in parse_qsl(parsed_url.query, keep_blank_values=True)
        ],
        "cookies": [],
        "headersSize": max(0, len(flow.request_raw) - len(request_body)),
        "bodySize": len(request_body),
    }
    if request_body:
        request["postData"] = {
            "mimeType": request_content_type,
            "text": request_body.decode("utf-8", "replace"),
        }
    return {
        "startedDateTime": flow.started_at,
        "time": float(flow.duration_ms),
        "request": request,
        "response": {
            "status": int(flow.status or 0),
            "statusText": status_text,
            "httpVersion": response_version,
            "headers": _headers_for_har(response_headers, redact_sensitive=redact_sensitive),
            "cookies": [],
            "content": content,
            "redirectURL": next(
                (value for name, value in response_headers if name.casefold() == "location"),
                "",
            ),
            "headersSize": max(0, len(flow.response_raw) - len(response_body)),
            "bodySize": len(response_body),
        },
        "cache": {},
        "timings": {
            "blocked": -1,
            "dns": -1,
            "connect": -1,
            "ssl": -1,
            "send": 0,
            "wait": float(flow.duration_ms),
            "receive": 0,
        },
        "comment": "Exported by Arenyxa Proxy; sensitive headers redacted"
        if redact_sensitive
        else "Exported by Arenyxa Proxy",
    }


def export_proxy_har(
    destination: Path,
    flows: Iterable[ProxyFlow],
    *,
    redact_sensitive: bool = True,
) -> Path:
    """Write a bounded flow collection as a HAR 1.2 document."""
    entries = [
        entry
        for flow in flows
        if (entry := _har_entry(flow, redact_sensitive=redact_sensitive)) is not None
    ]
    payload = {
        "log": {
            "version": "1.2",
            "creator": {"name": "Arenyxa Proxy", "version": "8.1.1"},
            "entries": entries,
        }
    }
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _secure_write(
        destination,
        json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
        public=False,
    )
    return destination
