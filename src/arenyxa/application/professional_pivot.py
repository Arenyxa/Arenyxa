"""Local cross-workspace pivot artifacts for captured HTTP exchanges.

The pivot service is intentionally side-effect free: it summarizes already captured
state and suggests bounded Arenyxa workspace transitions without issuing network
requests or executing workflows.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


_SENSITIVE_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "apikey",
        "password",
        "passwd",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "client_secret",
    }
)


def _sensitive_name(name: str) -> bool:
    normalized = str(name or "").strip().casefold().replace("-", "_")
    if normalized in {item.replace("-", "_") for item in _SENSITIVE_NAMES}:
        return True
    return any(marker in normalized for marker in ("password", "passwd", "secret", "token", "api_key", "apikey"))


def _bounded_text(value: Any, limit: int = 512) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _redact_mapping(values: Mapping[str, Any] | None, *, max_items: int = 64) -> dict[str, str]:
    result: dict[str, str] = {}
    for index, (raw_key, raw_value) in enumerate((values or {}).items()):
        if index >= max_items:
            result["<truncated>"] = f"{max(0, len(values or {}) - max_items)} additional entries"
            break
        key = _bounded_text(raw_key, 128)
        result[key] = "<redacted>" if _sensitive_name(key) else _bounded_text(raw_value)
    return result


def _redact_url(raw_url: str) -> str:
    text = _bounded_text(raw_url, 4096)
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.query:
        return text
    safe_query = [
        (key, "<redacted>" if _sensitive_name(key) else _bounded_text(value, 256))
        for key, value in parse_qsl(parts.query, keep_blank_values=True, strict_parsing=False)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(safe_query, doseq=True), parts.fragment))


@dataclass(frozen=True, slots=True)
class PivotAction:
    """A side-effect-free suggestion for the next Arenyxa workspace."""

    workspace: str
    action: str
    context: dict[str, Any]
    reason: str


@dataclass(frozen=True, slots=True)
class PivotArtifact:
    """Bounded, redacted context shared across professional workspaces."""

    source_kind: str
    source_id: str
    request: dict[str, Any]
    response: dict[str, Any]
    analysis: dict[str, Any]
    actions: tuple[PivotAction, ...]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class ProfessionalPivotService:
    """Create local professional pivots from normalized captured HTTP data."""

    def __init__(self, store: Any) -> None:
        self._store = store

    def from_request(self, request_id: str) -> PivotArtifact | None:
        exchange = self._store.get_http_exchange(str(request_id))
        return None if exchange is None else self._build("request", str(request_id), exchange)

    def from_event(self, event_id: str) -> PivotArtifact | None:
        exchange = self._store.get_http_exchange_by_event(str(event_id))
        return None if exchange is None else self._build("event", str(event_id), exchange)

    @staticmethod
    def _build(source_kind: str, source_id: str, exchange: Mapping[str, Any]) -> PivotArtifact:
        request_id = _bounded_text(exchange.get("request_id"), 160)
        event_id = _bounded_text(exchange.get("event_id"), 160)
        session_id = _bounded_text(exchange.get("session_id"), 160)
        flow_id = _bounded_text(exchange.get("flow_id"), 160)
        method = _bounded_text(exchange.get("method") or "GET", 32).upper()
        url = _redact_url(str(exchange.get("url") or ""))
        host = _bounded_text(exchange.get("host"), 255)
        status_raw = exchange.get("status")
        status = int(status_raw) if isinstance(status_raw, int) and not isinstance(status_raw, bool) else None
        request_headers = _redact_mapping(exchange.get("request_headers") if isinstance(exchange.get("request_headers"), Mapping) else {})
        response_headers = _redact_mapping(exchange.get("response_headers") if isinstance(exchange.get("response_headers"), Mapping) else {})
        query = _redact_mapping(exchange.get("query") if isinstance(exchange.get("query"), Mapping) else {})
        content_type = _bounded_text(exchange.get("content_type") or response_headers.get("Content-Type") or response_headers.get("content-type"), 256)
        size = max(0, int(exchange.get("size") or 0))
        timing = exchange.get("timing") if isinstance(exchange.get("timing"), Mapping) else {}
        total_ms_raw = timing.get("total_ms")
        total_ms = float(total_ms_raw) if isinstance(total_ms_raw, (int, float)) and not isinstance(total_ms_raw, bool) else None

        actions: list[PivotAction] = [
            PivotAction(
                "Packet Intelligence",
                "analyze-session",
                {"session_id": session_id, "focus_event_id": event_id},
                "Correlate this exchange with protocol, endpoint, latency, and conversation statistics.",
            ),
            PivotAction(
                "Proxy",
                "open-request-context",
                {"request_id": request_id, "flow_id": flow_id, "method": method, "url": url},
                "Inspect or deliberately replay the request from a controlled proxy workflow.",
            ),
            PivotAction(
                "Extraction Lab",
                "analyze-source",
                {"session_id": session_id, "source_url": url, "content_type": content_type},
                "Discover structured fields and build a bounded local extraction recipe from captured data.",
            ),
            PivotAction(
                "Flow Designer",
                "draft-from-request",
                {"request_id": request_id, "session_id": session_id, "method": method, "url": url},
                "Turn the captured request context into an explicit workflow draft without automatic execution.",
            ),
        ]
        if status is not None and status >= 400:
            actions.insert(
                1,
                PivotAction(
                    "Proxy",
                    "compare-error-response",
                    {"request_id": request_id, "status": status},
                    "The captured response is an error; compare it with a known-good request before replay.",
                ),
            )

        analysis = {
            "has_request_body": bool(exchange.get("request_body_ref")),
            "has_response_body": bool(exchange.get("response_body_ref")),
            "structured_response": any(marker in content_type.casefold() for marker in ("json", "xml", "html")),
            "error_response": bool(status is not None and status >= 400),
            "slow_response": bool(total_ms is not None and total_ms >= 1000.0),
            "response_bytes": size,
            "total_ms": total_ms,
        }
        return PivotArtifact(
            source_kind=source_kind,
            source_id=_bounded_text(source_id, 160),
            request={
                "request_id": request_id,
                "event_id": event_id,
                "session_id": session_id,
                "flow_id": flow_id,
                "method": method,
                "url": url,
                "host": host,
                "query": query,
                "headers": request_headers,
                "body_ref": _bounded_text(exchange.get("request_body_ref"), 160),
            },
            response={
                "response_id": _bounded_text(exchange.get("response_id"), 160),
                "status": status,
                "headers": response_headers,
                "body_ref": _bounded_text(exchange.get("response_body_ref"), 160),
                "content_type": content_type,
                "size": size,
            },
            analysis=analysis,
            actions=tuple(actions[:8]),
        )
