from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import base64
import json
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlsplit

from arenyxa.infrastructure.capture.proxy import ProxyFlow


_SECRET_NAMES = re.compile(r"(?i)(token|secret|password|passwd|authorization|cookie|api[-_]?key|session)")
_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)


@dataclass(slots=True)
class ProxyParameterFinding:
    location: str
    name: str
    value_preview: str
    repeated: bool = False
    sensitive: bool = False


@dataclass(slots=True)
class ProxyDeepInspection:
    flow_id: str
    url: str
    request_headers: dict[str, str]
    response_headers: dict[str, str]
    request_content_type: str
    response_content_type: str
    parameters: list[ProxyParameterFinding]
    cookies: list[dict[str, Any]]
    security_headers: dict[str, bool]
    encodings: list[str]
    body_previews: dict[str, str]
    warnings: list[str]

    def snapshot(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["parameters"] = [asdict(item) for item in self.parameters]
        return payload


class ProxyDeepInspector:
    MAX_HEADERS = 256
    MAX_PARAMETERS = 512
    MAX_PREVIEW = 4096

    def inspect(self, flow: ProxyFlow) -> ProxyDeepInspection:
        request_line, request_headers, request_body = self._parse(flow.request_raw)
        _response_line, response_headers, response_body = self._parse(flow.response_raw)
        request_lower = {key.casefold(): value for key, value in request_headers.items()}
        response_lower = {key.casefold(): value for key, value in response_headers.items()}
        parameters: list[ProxyParameterFinding] = []
        parsed = urlsplit(flow.url)
        parameters.extend(self._parameter_rows("query", parse_qsl(parsed.query, keep_blank_values=True)))
        request_type = request_lower.get("content-type", "").split(";", 1)[0].strip().casefold()
        if request_body and request_type == "application/x-www-form-urlencoded":
            parameters.extend(self._parameter_rows("body", parse_qsl(request_body.decode("utf-8", "replace"), keep_blank_values=True)))
        elif request_body and request_type in {"application/json", "text/json"}:
            parameters.extend(self._json_parameters(request_body))
        cookies = self._cookies(request_lower.get("cookie", ""), response_headers)
        encodings = self._encoding_hints(request_headers, response_headers, request_body, response_body)
        warnings: list[str] = []
        missing = [header for header in _SECURITY_HEADERS if not response_lower.get(header)]
        if flow.scheme == "https" and missing:
            warnings.append(f"HTTPS response is missing {len(missing)} common browser security headers")
        if flow.error:
            warnings.append(f"Flow completed with error: {flow.error[:500]}")
        if flow.duration_ms >= 2000:
            warnings.append("Flow latency exceeds 2 seconds")
        if len(parameters) >= self.MAX_PARAMETERS:
            warnings.append("Parameter analysis was truncated at the configured budget")
        return ProxyDeepInspection(
            flow_id=flow.id,
            url=flow.url,
            request_headers=self._redacted_headers(request_headers),
            response_headers=self._redacted_headers(response_headers),
            request_content_type=request_type,
            response_content_type=response_lower.get("content-type", "").split(";", 1)[0].strip().casefold(),
            parameters=parameters[: self.MAX_PARAMETERS],
            cookies=cookies,
            security_headers={header: bool(response_lower.get(header)) for header in _SECURITY_HEADERS},
            encodings=encodings,
            body_previews={
                "request": self._preview_body(request_body, request_type),
                "response": self._preview_body(response_body, response_lower.get("content-type", "")),
            },
            warnings=warnings,
        )

    def compare(self, left: ProxyFlow, right: ProxyFlow) -> dict[str, Any]:
        left_item = self.inspect(left)
        right_item = self.inspect(right)
        left_params = {(item.location, item.name): item.value_preview for item in left_item.parameters}
        right_params = {(item.location, item.name): item.value_preview for item in right_item.parameters}
        keys = sorted(set(left_params) | set(right_params))[: self.MAX_PARAMETERS]
        parameter_diff = [
            {"location": location, "name": name, "left": left_params.get((location, name)), "right": right_params.get((location, name))}
            for location, name in keys
            if left_params.get((location, name)) != right_params.get((location, name))
        ]
        return {
            "left": {"id": left.id, "url": left.url, "status": left.status, "duration_ms": left.duration_ms},
            "right": {"id": right.id, "url": right.url, "status": right.status, "duration_ms": right.duration_ms},
            "status_changed": left.status != right.status,
            "latency_delta_ms": round(float(right.duration_ms) - float(left.duration_ms), 3),
            "parameter_diff": parameter_diff,
            "request_content_type_changed": left_item.request_content_type != right_item.request_content_type,
            "response_content_type_changed": left_item.response_content_type != right_item.response_content_type,
        }

    def timeline(self, flows: Iterable[ProxyFlow], *, limit: int = 1000) -> list[dict[str, Any]]:
        rows = list(flows)[: max(1, min(int(limit), 5000))]
        if not rows:
            return []
        origin = min(float(item.sequence) for item in rows)
        return [
            {
                "id": item.id,
                "sequence": item.sequence,
                "offset": int(item.sequence - origin),
                "method": item.method,
                "host": item.host,
                "target": item.target,
                "status": item.status,
                "duration_ms": round(float(item.duration_ms), 3),
                "request_bytes": int(item.request_bytes),
                "response_bytes": int(item.response_bytes),
                "rewritten": bool(item.rewrite_rule_ids),
                "error": bool(item.error),
            }
            for item in rows
        ]

    @staticmethod
    def _parse(raw: bytes) -> tuple[str, dict[str, str], bytes]:
        if not raw:
            return "", {}, b""
        head, sep, body = raw.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = raw.partition(b"\n\n")
        lines = head.decode("iso-8859-1", "replace").splitlines()
        first = lines[0] if lines else ""
        headers: dict[str, str] = {}
        for line in lines[1:257]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[str(key).strip()] = str(value).strip()
        return first, headers, body

    def _parameter_rows(self, location: str, pairs: Iterable[tuple[str, str]]) -> list[ProxyParameterFinding]:
        rows = list(pairs)[: self.MAX_PARAMETERS]
        counts: dict[str, int] = {}
        for name, _value in rows:
            counts[name] = counts.get(name, 0) + 1
        return [
            ProxyParameterFinding(location, name[:256], self._redact_value(name, value), counts.get(name, 0) > 1, bool(_SECRET_NAMES.search(name)))
            for name, value in rows
        ]

    def _json_parameters(self, body: bytes) -> list[ProxyParameterFinding]:
        try:
            payload = json.loads(body[: 2 * 1024 * 1024].decode("utf-8", "replace"))
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
            return []
        rows: list[ProxyParameterFinding] = []

        def walk(value: Any, path: str, depth: int) -> None:
            if len(rows) >= self.MAX_PARAMETERS or depth > 8:
                return
            if isinstance(value, dict):
                for key, child in list(value.items())[:128]:
                    child_path = f"{path}.{key}" if path else str(key)
                    walk(child, child_path, depth + 1)
            elif isinstance(value, list):
                for index, child in enumerate(value[:32]):
                    walk(child, f"{path}[{index}]", depth + 1)
            else:
                name = path or "$"
                text = "" if value is None else str(value)
                rows.append(ProxyParameterFinding("json", name[:256], self._redact_value(name, text), False, bool(_SECRET_NAMES.search(name))))

        walk(payload, "", 0)
        return rows

    def _cookies(self, request_cookie: str, response_headers: dict[str, str]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for pair in str(request_cookie).split(";")[:128]:
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            rows.append({"direction": "request", "name": name.strip()[:256], "value": self._redact_value(name, value.strip())})
        for key, value in list(response_headers.items())[: self.MAX_HEADERS]:
            if key.casefold() != "set-cookie":
                continue
            first = value.split(";", 1)[0]
            name, _sep, cookie_value = first.partition("=")
            rows.append({
                "direction": "response",
                "name": name.strip()[:256],
                "value": self._redact_value(name, cookie_value.strip()),
                "secure": "; secure" in value.casefold(),
                "httponly": "; httponly" in value.casefold(),
                "samesite": "samesite=" in value.casefold(),
            })
        return rows[:256]

    @staticmethod
    def _encoding_hints(request_headers: dict[str, str], response_headers: dict[str, str], request_body: bytes, response_body: bytes) -> list[str]:
        hints: set[str] = set()
        for headers in (request_headers, response_headers):
            for key, value in headers.items():
                if key.casefold() in {"content-encoding", "transfer-encoding"}:
                    for part in value.split(","):
                        if part.strip():
                            hints.add(part.strip().casefold())
        for body in (request_body, response_body):
            prefix = body[:128].strip()
            if prefix and len(prefix) % 4 == 0 and re.fullmatch(br"[A-Za-z0-9+/=\r\n]+", prefix):
                try:
                    base64.b64decode(prefix, validate=True)
                    hints.add("possible-base64")
                except (ValueError, TypeError):
                    record_current_exception(__name__, 'ProxyDeepInspector._encoding_hints:237')
        return sorted(hints)

    @staticmethod
    def _redact_value(name: str, value: str) -> str:
        if _SECRET_NAMES.search(str(name)):
            return "<redacted>"
        text = str(value)
        return text[:256] + ("…" if len(text) > 256 else "")

    def _redacted_headers(self, headers: dict[str, str]) -> dict[str, str]:
        output: dict[str, str] = {}
        for key, value in list(headers.items())[: self.MAX_HEADERS]:
            output[key] = self._redact_value(key, value)
        return output

    def _preview_body(self, body: bytes, content_type: str) -> str:
        if not body:
            return ""
        lower = str(content_type).casefold()
        if any(token in lower for token in ("json", "text", "xml", "html", "javascript", "form-urlencoded")):
            text = body[: self.MAX_PREVIEW].decode("utf-8", "replace")
            return re.sub(r"(?i)(token|secret|password|api[-_]?key)(\s*[=:]\s*)[^\s,}&]+", r"\1\2<redacted>", text)
        return f"<binary {len(body):,} bytes>"
