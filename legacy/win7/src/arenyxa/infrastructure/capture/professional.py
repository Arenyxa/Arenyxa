from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit

from dataclasses import field

from arenyxa.compat import dataclass
from arenyxa.domain.models import NetworkEvent
from arenyxa.infrastructure.capture.filtering import FilterEngine
from arenyxa.infrastructure.capture.replay import ReplayDraft, RequestReplayService


@dataclass(slots=True)
class ProtocolConversation:
    key: str
    protocol: str
    host: str
    events: int
    bytes_total: int
    statuses: dict[int, int] = field(default_factory=dict)
    methods: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class ProtocolAnalysis:
    total_events: int
    total_bytes: int
    protocols: dict[str, int]
    hosts: dict[str, int]
    fields: dict[str, int]
    conversations: list[ProtocolConversation]
    suggested_filters: list[str]


class ProtocolWorkbench:
    def __init__(self) -> None:
        self.filters = FilterEngine()

    def analyze(self, events: Sequence[NetworkEvent], expression: str = "") -> ProtocolAnalysis:
        predicate = self.filters.compile(expression)
        selected = [event for event in events if predicate(event)]
        protocols: Counter[str] = Counter()
        hosts: Counter[str] = Counter()
        fields: Counter[str] = Counter()
        grouped: dict[str, dict[str, Any]] = defaultdict(lambda: {
            "protocol": "unknown", "host": "", "events": 0, "bytes": 0,
            "statuses": Counter(), "methods": Counter(),
        })
        total_bytes = 0
        for event in selected:
            protocol = str(event.protocol or "unknown").casefold()
            host = str(event.host or self._host_from_url(event.url) or "")
            protocols[protocol] += 1
            if host:
                hosts[host] += 1
            total_bytes += max(0, int(event.size or 0))
            for name, value in self._field_snapshot(event).items():
                if value not in (None, "", [], {}, ()): fields[name] += 1
            conversation_key = str(event.flow_ref or event.request_ref or f"{protocol}:{host or 'local'}")
            state = grouped[conversation_key]
            state["protocol"] = protocol
            state["host"] = host
            state["events"] += 1
            state["bytes"] += max(0, int(event.size or 0))
            if event.status is not None:
                state["statuses"][int(event.status)] += 1
            if event.method:
                state["methods"][str(event.method).upper()] += 1
        conversations = [
            ProtocolConversation(
                key=key,
                protocol=str(value["protocol"]),
                host=str(value["host"]),
                events=int(value["events"]),
                bytes_total=int(value["bytes"]),
                statuses=dict(value["statuses"]),
                methods=dict(value["methods"]),
            )
            for key, value in grouped.items()
        ]
        conversations.sort(key=lambda item: (item.bytes_total, item.events), reverse=True)
        suggestions = self._suggest_filters(protocols, hosts, selected)
        return ProtocolAnalysis(
            total_events=len(selected),
            total_bytes=total_bytes,
            protocols=dict(protocols.most_common()),
            hosts=dict(hosts.most_common(64)),
            fields=dict(fields.most_common()),
            conversations=conversations[:256],
            suggested_filters=suggestions,
        )

    @staticmethod
    def _host_from_url(url: str | None) -> str:
        if not url:
            return ""
        try:
            return str(urlsplit(url).hostname or "")
        except ValueError:
            return ""

    @staticmethod
    def _field_snapshot(event: NetworkEvent) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "protocol": event.protocol,
            "direction": event.direction,
            "bytes": event.size,
            "http.method": event.method,
            "http.url": event.url,
            "http.host": event.host,
            "http.status": event.status,
            "process.name": event.process_ref,
            "flow.id": event.flow_ref,
            "request.id": event.request_ref,
        }
        for key, value in event.metadata.items():
            snapshot[f"meta.{key}"] = value
        return snapshot

    @staticmethod
    def _suggest_filters(protocols: Counter[str], hosts: Counter[str], events: Sequence[NetworkEvent]) -> list[str]:
        result: list[str] = []
        for protocol, _ in protocols.most_common(4):
            result.append(f'protocol == "{protocol}"')
        for host, _ in hosts.most_common(4):
            escaped = host.replace('"', '\\"')
            result.append(f'http.host == "{escaped}"')
        statuses = Counter(int(event.status) for event in events if event.status is not None)
        for status, _ in statuses.most_common(3):
            result.append(f"http.status == {status}")
        if any((event.protocol or "").casefold() in {"ws", "wss", "websocket"} for event in events):
            result.append('protocol in ["ws","wss","websocket"]')
        return result[:12]


@dataclass(slots=True)
class PassiveFinding:
    code: str
    severity: str
    title: str
    evidence: str
    remediation: str


class PassiveSecurityAuditor:
    def audit(self, events: Sequence[NetworkEvent]) -> list[PassiveFinding]:
        findings: list[PassiveFinding] = []
        seen: set[tuple[str, str]] = set()
        for event in events:
            for finding in self.audit_event(event):
                key = (finding.code, finding.evidence)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        findings.sort(key=lambda item: severity_rank.get(item.severity, 0), reverse=True)
        return findings

    def audit_event(self, event: NetworkEvent) -> list[PassiveFinding]:
        url = str(event.url or "")
        response = {str(key).casefold(): str(value) for key, value in event.response_headers.items()}
        request = {str(key).casefold(): str(value) for key, value in event.request_headers.items()}
        findings: list[PassiveFinding] = []
        host = str(event.host or ProtocolWorkbench._host_from_url(event.url) or "unknown")
        is_https = url.casefold().startswith("https://")
        if url and not is_https and not self._local_url(url):
            findings.append(PassiveFinding(
                "TRANSPORT_PLAINTEXT", "medium", "Plain HTTP transport",
                host, "Prefer HTTPS for application traffic carrying user or session data.",
            ))
        if is_https and response and "strict-transport-security" not in response:
            findings.append(PassiveFinding(
                "HSTS_MISSING", "low", "HSTS header is absent",
                host, "Consider Strict-Transport-Security after confirming HTTPS-only deployment.",
            ))
        content_type = response.get("content-type", "").casefold()
        if "text/html" in content_type:
            if "content-security-policy" not in response:
                findings.append(PassiveFinding(
                    "CSP_MISSING", "low", "Content-Security-Policy is absent",
                    host, "Define a restrictive CSP appropriate for the application.",
                ))
            if response.get("x-content-type-options", "").casefold() != "nosniff":
                findings.append(PassiveFinding(
                    "NOSNIFF_MISSING", "low", "X-Content-Type-Options nosniff is absent",
                    host, "Return X-Content-Type-Options: nosniff for browser-delivered content.",
                ))
        allow_origin = response.get("access-control-allow-origin", "").strip()
        allow_credentials = response.get("access-control-allow-credentials", "").casefold().strip()
        if allow_origin == "*" and allow_credentials == "true":
            findings.append(PassiveFinding(
                "CORS_CREDENTIAL_WILDCARD", "medium", "Credentialed CORS policy is inconsistent",
                host, "Use an explicit allowlist for credentialed cross-origin requests.",
            ))
        set_cookie = response.get("set-cookie", "")
        if set_cookie:
            lowered = set_cookie.casefold()
            if is_https and "secure" not in lowered:
                findings.append(PassiveFinding(
                    "COOKIE_SECURE_MISSING", "medium", "Cookie lacks Secure",
                    host, "Mark session-bearing cookies Secure when delivered over HTTPS.",
                ))
            if "httponly" not in lowered:
                findings.append(PassiveFinding(
                    "COOKIE_HTTPONLY_MISSING", "low", "Cookie lacks HttpOnly",
                    host, "Mark cookies HttpOnly when client-side scripts do not require access.",
                ))
            if "samesite=" not in lowered:
                findings.append(PassiveFinding(
                    "COOKIE_SAMESITE_MISSING", "low", "Cookie lacks SameSite",
                    host, "Set a SameSite policy appropriate for the application flow.",
                ))
        if "authorization" in request and not is_https and not self._local_url(url):
            findings.append(PassiveFinding(
                "AUTH_OVER_PLAINTEXT", "high", "Authorization header observed over plaintext transport",
                host, "Do not transmit authentication credentials over plaintext HTTP.",
            ))
        if response.get("server"):
            findings.append(PassiveFinding(
                "SERVER_BANNER", "info", "Server banner is exposed",
                f"{host}: {response['server'][:160]}", "Reduce unnecessary version/product disclosure where practical.",
            ))
        return findings

    @staticmethod
    def _local_url(url: str) -> bool:
        try:
            host = str(urlsplit(url).hostname or "").casefold()
        except ValueError:
            return False
        return host in {"127.0.0.1", "::1", "localhost"}


@dataclass(slots=True)
class ExtractionPlan:
    source_url: str
    recommended_mode: str
    structured_sources: list[dict[str, Any]]
    pagination: list[dict[str, str]]
    interactions: list[str]
    steps: list[dict[str, Any]]


class NoCodeExtractionPlanner:
    PAGINATION_KEYS = {"page", "p", "offset", "cursor", "start", "limit", "next", "after"}

    def build(self, events: Sequence[NetworkEvent], source_url: str = "") -> ExtractionPlan:
        structured: list[dict[str, Any]] = []
        pagination: list[dict[str, str]] = []
        interactions: list[str] = []
        seen_sources: set[str] = set()
        seen_pagination: set[tuple[str, str]] = set()
        for event in events:
            url = str(event.url or "")
            if not url:
                continue
            headers = {str(key).casefold(): str(value) for key, value in event.response_headers.items()}
            content_type = headers.get("content-type", "").casefold()
            looks_structured = "json" in content_type or "/api/" in url.casefold() or "graphql" in url.casefold()
            if looks_structured and url not in seen_sources:
                seen_sources.add(url)
                structured.append({
                    "url": url,
                    "method": str(event.method or "GET").upper(),
                    "content_type": headers.get("content-type", ""),
                    "status": event.status,
                })
            try:
                pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            except ValueError:
                pairs = []
            for key, value in pairs:
                normalized = key.casefold()
                if normalized in self.PAGINATION_KEYS:
                    marker = (urlsplit(url)._replace(query="").geturl(), normalized)
                    if marker not in seen_pagination:
                        seen_pagination.add(marker)
                        pagination.append({"url": marker[0], "parameter": key, "sample": value})
            initiator = str(event.initiator or "").casefold()
            if "scroll" in initiator and "scroll" not in interactions:
                interactions.append("scroll")
            if "click" in initiator and "click" not in interactions:
                interactions.append("click")
        recommended = "api" if structured else "browser"
        steps: list[dict[str, Any]] = [{"kind": "open", "url": source_url or (structured[0]["url"] if structured else "")}]
        if structured:
            steps.append({"kind": "capture_structured_source", "count": len(structured)})
        else:
            steps.append({"kind": "select_fields", "mode": "visual"})
        for item in pagination[:8]:
            steps.append({"kind": "paginate", **item})
        for interaction in interactions:
            steps.append({"kind": "interaction", "action": interaction})
        steps.append({"kind": "normalize_and_export"})
        return ExtractionPlan(
            source_url=source_url,
            recommended_mode=recommended,
            structured_sources=structured[:64],
            pagination=pagination[:64],
            interactions=interactions,
            steps=steps,
        )


@dataclass(slots=True)
class FlowWorkbenchSnapshot:
    draft: ReplayDraft
    request: dict[str, Any]
    unresolved_secrets: list[str]
    warnings: list[str]


class FlowWorkbench:
    def __init__(self, replay: RequestReplayService | None = None) -> None:
        self.replay = replay or RequestReplayService()

    def prepare_event(self, event: NetworkEvent) -> FlowWorkbenchSnapshot:
        draft = self.replay.draft_from_event(event)
        return self._snapshot(draft)

    def prepare_exchange(self, exchange: Mapping[str, Any], **kwargs: Any) -> FlowWorkbenchSnapshot:
        draft = self.replay.draft_from_exchange(exchange, **kwargs)
        return self._snapshot(draft)

    def _snapshot(self, draft: ReplayDraft) -> FlowWorkbenchSnapshot:
        return FlowWorkbenchSnapshot(
            draft=draft,
            request=self.replay.redacted_request_snapshot(draft),
            unresolved_secrets=self.replay.unresolved_secret_refs(draft.request),
            warnings=list(draft.warnings),
        )


@dataclass(slots=True)
class ProfessionalAnalysis:
    protocol: ProtocolAnalysis
    extraction: ExtractionPlan
    passive_findings: list[PassiveFinding]


class ProfessionalAnalysisSuite:
    def __init__(self) -> None:
        self.protocol = ProtocolWorkbench()
        self.extraction = NoCodeExtractionPlanner()
        self.security = PassiveSecurityAuditor()

    def analyze(self, events: Sequence[NetworkEvent], *, source_url: str = "", display_filter: str = "") -> ProfessionalAnalysis:
        return ProfessionalAnalysis(
            protocol=self.protocol.analyze(events, display_filter),
            extraction=self.extraction.build(events, source_url),
            passive_findings=self.security.audit(events),
        )
