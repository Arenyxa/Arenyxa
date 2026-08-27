"""Crawler-facing Web/Network Intelligence integration for Phase 6.

This module is the bridge between Browser/Crawler observations and Arenyxa's
existing WebIntelligenceCenter + ApiMapService.  It does not replay captured
requests automatically; WebIntelligenceCenter keeps sensitive and non-idempotent
requests review-gated.
"""
from __future__ import annotations

from collections import Counter
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from arenyxa.application.api_map import ApiMapService, ApiMapSnapshot
from arenyxa.application.browser_engine import BrowserFetchResult, BrowserNetworkObservation
from arenyxa.application.web_intelligence import WebIntelligenceCenter, WebIntelligenceReport
from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import FetchResponse, NetworkEvent, new_id


_SENSITIVE_NAME = re.compile(
    r"(?:^|[_\-.])(?:pass(?:word|wd)?|secret|token|api[_-]?key|auth(?:orization)?|cookie|credential|session|sid|csrf|xsrf)(?:$|[_\-.])",
    re.I,
)
_SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key",
    "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token",
}


def _redact_url(url: str) -> tuple[str, list[str]]:
    flags: list[str] = []
    try:
        parts = urlsplit(str(url))
    except ValueError:
        return str(url)[:4096], flags
    query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if _SENSITIVE_NAME.search(str(key)):
            flags.append("query:" + str(key)[:160])
            query.append((key, "<redacted>"))
        else:
            query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))[:4096], flags


def _redact_headers(headers: Mapping[str, Any]) -> tuple[dict[str, str], list[str]]:
    output: dict[str, str] = {}
    flags: list[str] = []
    for key, value in list(headers.items())[:256]:
        name = str(key)[:256]
        if name.casefold().strip() in _SENSITIVE_HEADERS or _SENSITIVE_NAME.search(name):
            output[name] = "<redacted>"
            flags.append("header:" + name)
        else:
            output[name] = str(value)[:8192]
    return output, flags


def _sanitize_event(event: NetworkEvent) -> NetworkEvent:
    safe_url, query_flags = _redact_url(event.url or "")
    request_headers, request_flags = _redact_headers(event.request_headers)
    response_headers, response_flags = _redact_headers(event.response_headers)
    flags = sorted(set([*event.sensitivity_flags, *query_flags, *request_flags, *response_flags]))
    return NetworkEvent(
        session_id=event.session_id, source_type=event.source_type, protocol=event.protocol,
        direction=event.direction, size=event.size, id=event.id, timestamp=event.timestamp,
        process_ref=event.process_ref, flow_ref=event.flow_ref, request_ref=event.request_ref,
        method=event.method, url=safe_url or None, status=event.status, host=event.host,
        timing=dict(event.timing), request_headers=request_headers, response_headers=response_headers,
        request_body_ref=event.request_body_ref, response_body_ref=event.response_body_ref,
        sensitivity_flags=flags, initiator=event.initiator, metadata=dict(event.metadata),
    )


def _sanitize_response(response: FetchResponse | None) -> FetchResponse | None:
    if response is None:
        return None
    url, _ = _redact_url(response.url)
    final_url, _ = _redact_url(response.final_url)
    headers, _ = _redact_headers(response.headers)
    redirects = [_redact_url(item)[0] for item in response.redirect_chain]
    return FetchResponse(
        url=url, final_url=final_url, status=response.status, headers=headers, body=response.body,
        elapsed_ms=response.elapsed_ms, encoding=response.encoding, content_type=response.content_type,
        redirect_chain=redirects, error=response.error,
    )


@dataclass(slots=True)
class CrawlerIntelligenceBundle:
    session_id: str
    source_url: str
    recommended_collection_path: str
    confidence: float
    safe_api_candidates: list[dict[str, Any]]
    network_summary: dict[str, Any]
    web_report: WebIntelligenceReport
    api_map: ApiMapSnapshot
    warnings: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "source_url": self.source_url,
            "recommended_collection_path": self.recommended_collection_path,
            "confidence": self.confidence,
            "safe_api_candidates": list(self.safe_api_candidates),
            "network_summary": dict(self.network_summary),
            "web_report": asdict(self.web_report),
            "api_map": self.api_map.to_dict(),
            "warnings": list(self.warnings),
        }


def browser_observations_to_events(
    result: BrowserFetchResult,
    *,
    session_id: str = "",
) -> list[NetworkEvent]:
    """Project bounded/redacted browser observations into the capture event model."""
    sid = str(session_id).strip() or new_id("crawlcap")
    events: list[NetworkEvent] = []
    for observation in result.network_events:
        if not isinstance(observation, BrowserNetworkObservation):
            continue
        url = str(observation.url or "")
        if not url:
            continue
        kind = str(observation.kind or "http").casefold()
        resource = str(observation.resource_type or kind).casefold()
        if "websocket" in kind or resource == "websocket" or url.startswith(("ws://", "wss://")):
            protocol = "wss" if url.startswith("wss://") else "websocket"
        else:
            protocol = "https" if url.startswith("https://") else "http"
        metadata = {
            "resource_type": resource,
            "browser_event_kind": kind,
            "sha256": str(observation.sha256 or ""),
        }
        if observation.elapsed_ms is not None:
            metadata["elapsed_ms"] = float(observation.elapsed_ms)
        # Intentionally do not copy text_preview into cross-subsystem intelligence
        # metadata because it may contain page/account data. Hash + size are enough
        # for correlation and the browser result remains available to its owner.
        events.append(_sanitize_event(
            NetworkEvent(
                session_id=sid,
                source_type=CaptureSource.BROWSER,
                protocol=protocol,
                direction=str(observation.direction or "out"),
                size=max(0, int(observation.size or 0)),
                method=str(observation.method or "GET") if not kind.startswith("websocket-frame") else None,
                url=url,
                status=observation.status,
                host="",
                timing={"elapsed_ms": float(observation.elapsed_ms)} if observation.elapsed_ms is not None else {},
                request_headers=dict(observation.request_headers),
                response_headers=dict(observation.response_headers),
                metadata=metadata,
            )
        ))
    return events


def browser_result_to_fetch_response(result: BrowserFetchResult) -> FetchResponse:
    body = result.html.encode("utf-8", errors="replace")
    content_type = "text/html"
    for key, value in result.response_headers.items():
        if str(key).casefold() == "content-type":
            content_type = str(value).split(";", 1)[0].strip() or content_type
            break
    return FetchResponse(
        url=result.requested_url,
        final_url=result.final_url,
        status=int(result.status),
        headers=dict(result.response_headers),
        body=body,
        elapsed_ms=float(result.elapsed_ms),
        encoding="utf-8",
        content_type=content_type,
        redirect_chain=[],
    )


class CrawlerWebIntelligencePipeline:
    """Unifies crawler/browser observations with API and protocol intelligence."""

    def __init__(self, center: WebIntelligenceCenter, *, api_map: ApiMapService | None = None) -> None:
        self.center = center
        self.api_map = api_map or ApiMapService()

    @staticmethod
    def _exchange(event: NetworkEvent) -> dict[str, Any]:
        content_type = ""
        for key, value in event.response_headers.items():
            if str(key).casefold() == "content-type":
                content_type = str(value)
                break
        return {
            "event_id": event.id,
            "request_id": event.request_ref or event.id,
            "url": event.url or "",
            "method": event.method or "GET",
            "status": event.status,
            "request_headers": dict(event.request_headers),
            "response_headers": dict(event.response_headers),
            "request_body_ref": event.request_body_ref,
            "response_body_ref": event.response_body_ref,
            "content_type": content_type,
        }

    @staticmethod
    def _network_summary(events: Sequence[NetworkEvent]) -> dict[str, Any]:
        protocols = Counter(str(event.protocol or "unknown").casefold() for event in events)
        resources = Counter(str((event.metadata or {}).get("resource_type", "unknown")).casefold() for event in events)
        hosts = {str(event.host or "").casefold() for event in events if event.host}
        api_like = 0
        for event in events:
            url = str(event.url or "").casefold()
            ctype = " ".join(str(value) for value in event.response_headers.values()).casefold()
            resource = str((event.metadata or {}).get("resource_type", "")).casefold()
            if "/api/" in url or "graphql" in url or "json" in ctype or resource in {"xhr", "fetch", "graphql"}:
                api_like += 1
        return {
            "event_count": len(events),
            "protocols": dict(sorted(protocols.items())),
            "resource_types": dict(sorted(resources.items())),
            "host_count": len(hosts),
            "api_like_events": api_like,
            "websocket_events": sum(count for name, count in protocols.items() if name in {"ws", "wss", "websocket"}),
        }

    def analyze(
        self,
        response: FetchResponse | None,
        events: Sequence[NetworkEvent],
        *,
        session_id: str = "",
        history_success: Mapping[str, float] | None = None,
    ) -> CrawlerIntelligenceBundle:
        sid = str(session_id).strip() or (events[0].session_id if events else new_id("crawlcap"))
        safe_events = [_sanitize_event(event) for event in events]
        safe_response = _sanitize_response(response)
        report = self.center.analyze(safe_response, safe_events, history_success or {})
        api_map = self.api_map.build(sid, [self._exchange(event) for event in safe_events])
        safe = [
            {
                "event_id": candidate.event_id,
                "method": candidate.method,
                "url": candidate.url,
                "kind": candidate.kind,
                "confidence": candidate.confidence,
            }
            for candidate in report.endpoints
            if candidate.safe_to_replay and candidate.persistable
        ]
        safe.sort(key=lambda item: (-float(item["confidence"]), item["url"]))
        recommended = report.recommended_engine
        confidence = float(report.confidence)
        if safe and float(safe[0]["confidence"]) >= 0.80:
            recommended = "api"
            confidence = max(confidence, float(safe[0]["confidence"]))
        warnings = list(api_map.warnings)
        if safe and recommended == "api":
            warnings.append(
                "Structured idempotent endpoint candidate discovered; validate authorization and target policy before collection."
            )
        return CrawlerIntelligenceBundle(
            session_id=sid,
            source_url=(safe_response.final_url if safe_response is not None else report.url),
            recommended_collection_path=recommended,
            confidence=round(min(0.99, max(0.0, confidence)), 4),
            safe_api_candidates=safe[:100],
            network_summary=self._network_summary(safe_events),
            web_report=report,
            api_map=api_map,
            warnings=warnings[:100],
        )

    def analyze_browser(
        self,
        result: BrowserFetchResult,
        *,
        extra_events: Sequence[NetworkEvent] = (),
        session_id: str = "",
        history_success: Mapping[str, float] | None = None,
    ) -> CrawlerIntelligenceBundle:
        sid = str(session_id).strip() or new_id("crawlcap")
        browser_events = browser_observations_to_events(result, session_id=sid)
        # Capture/MITM events can be merged here.  This is the actual cross-subsystem
        # integration point; caller retains ownership of capture persistence.
        events = [*browser_events, *list(extra_events)]
        return self.analyze(
            browser_result_to_fetch_response(result),
            events,
            session_id=sid,
            history_success=history_success,
        )
