from __future__ import annotations

"""Phase 2 Web Intelligence Center.

The center composes the already mature SmartPath, capture/network, protocol, selector and
recorder services behind one auditable application facade.  It does not introduce a cloud
requirement and it never persists captured credentials.
"""

import hashlib
import json
import re
from dataclasses import asdict, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from arenyxa.compat import dataclass
from arenyxa.domain.models import FetchResponse, NetworkEvent, Workflow, WorkflowNode, utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited


_SENSITIVE_NAME = re.compile(
    r"(?:^|[_\-.])(?:pass(?:word|wd)?|secret|token|api[_-]?key|auth(?:orization)?|cookie|credential|session|sid|csrf|xsrf)(?:$|[_\-.])",
    re.I,
)
_SENSITIVE_HEADERS = {
    "authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-xsrf-token",
}
_SENSITIVE_TEXT = re.compile(
    r"(?:authorization\s*[:=]|cookie\s*[:=]|(?:access[_-]?)?token\s*[:=]|api[_-]?key\s*[:=]|password\s*[:=]|bearer\s+[A-Za-z0-9._~+\-/]{6,})",
    re.I,
)
_IDEMPOTENT_METHODS = {"GET", "HEAD", "OPTIONS"}
_STRUCTURED_HINTS = {"json", "graphql", "api", "xhr", "fetch"}


@dataclass(slots=True)
class ReplayCandidate:
    event_id: str
    method: str
    url: str
    kind: str
    confidence: float
    safe_to_replay: bool
    persistable: bool
    review_required: bool
    sensitive_fields: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WebIntelligenceReport:
    url: str
    recommended_engine: str
    confidence: float
    fallback_chain: list[str]
    decision_trace: list[dict[str, Any]]
    data_sources: list[dict[str, Any]]
    endpoints: list[ReplayCandidate]
    graphql: list[dict[str, Any]]
    websocket: list[dict[str, Any]]
    sse: list[dict[str, Any]]
    risk_flags: list[dict[str, str]]
    workflow: Workflow
    generated_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class TimeMachineEntry:
    id: str
    created_at: str
    url: str
    dom_sha256: str
    response_sha256: str
    response_status: int | None
    response_content_type: str
    selector: str
    workflow_definition_sha256: str
    dataset_revision: str
    metadata: dict[str, Any] = field(default_factory=dict)


class WebTimeMachine:
    







    MAX_ENTRIES = 5000
    MAX_FILE_BYTES = 16 * 1024 * 1024

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @staticmethod
    def _hash_bytes(value: bytes) -> str:
        return hashlib.sha256(value).hexdigest() if value else ""

    @staticmethod
    def _workflow_hash(workflow: Workflow | Mapping[str, Any] | None) -> str:
        if workflow is None:
            return ""
        payload = asdict(workflow) if isinstance(workflow, Workflow) else dict(workflow)
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_url(url: str) -> str:
        try:
            parts = urlsplit(url)
        except ValueError:
            return url[:2048]
        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            query.append((key, "<redacted>" if _SENSITIVE_NAME.search(key) else value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))[:4096]

    @classmethod
    def _sanitize_metadata(cls, value: Any, *, depth: int = 0) -> Any:
        if depth >= 5:
            return "<truncated>"
        if isinstance(value, Mapping):
            output: dict[str, Any] = {}
            for raw_key, raw_value in list(value.items())[:200]:
                key = str(raw_key)[:160]
                if _SENSITIVE_NAME.search(key):
                    output[key] = "<redacted>"
                else:
                    output[key] = cls._sanitize_metadata(raw_value, depth=depth + 1)
            return output
        if isinstance(value, (list, tuple)):
            return [cls._sanitize_metadata(item, depth=depth + 1) for item in list(value)[:200]]
        if isinstance(value, bytes):
            return "<bytes sha256=" + hashlib.sha256(value).hexdigest() + ">"
        if isinstance(value, str):
            text = value[:4096]
            return "<redacted>" if _SENSITIVE_TEXT.search(text) else text
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:4096]

    def _load(self) -> list[dict[str, Any]]:
        try:
            raw = json.loads(read_text_limited(self.path, self.MAX_FILE_BYTES, encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return []
        if not isinstance(raw, list):
            return []
        return [dict(item) for item in raw if isinstance(item, dict)][-self.MAX_ENTRIES :]

    def record(
        self,
        *,
        url: str,
        dom: str | bytes | None = None,
        response: FetchResponse | bytes | None = None,
        selector: str = "",
        workflow: Workflow | Mapping[str, Any] | None = None,
        dataset_revision: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> TimeMachineEntry:
        dom_bytes = dom.encode("utf-8", errors="replace") if isinstance(dom, str) else (dom or b"")
        response_body = b""
        status: int | None = None
        content_type = ""
        if isinstance(response, FetchResponse):
            response_body = response.body
            status = response.status
            content_type = response.content_type
        elif isinstance(response, bytes):
            response_body = response
        stable_seed = "|".join(
            [self._safe_url(url), self._hash_bytes(dom_bytes), self._hash_bytes(response_body), self._workflow_hash(workflow), dataset_revision]
        )
        entry = TimeMachineEntry(
            id="wtm_" + hashlib.sha256(stable_seed.encode("utf-8")).hexdigest()[:24],
            created_at=utc_now(),
            url=self._safe_url(url),
            dom_sha256=self._hash_bytes(dom_bytes),
            response_sha256=self._hash_bytes(response_body),
            response_status=status,
            response_content_type=str(content_type or "")[:256],
            selector=str(selector or "")[:4096],
            workflow_definition_sha256=self._workflow_hash(workflow),
            dataset_revision=str(dataset_revision or "")[:256],
            metadata=self._sanitize_metadata(dict(metadata or {})),
        )
        items = self._load()
        items.append(asdict(entry))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.path, items[-self.MAX_ENTRIES :])
        return entry

    def history(self, *, url: str | None = None, limit: int = 100) -> list[TimeMachineEntry]:
        wanted = self._safe_url(url) if url else None
        output = []
        for item in self._load():
            if wanted is not None and item.get("url") != wanted:
                continue
            try:
                output.append(TimeMachineEntry(**item))
            except TypeError:
                continue
        return output[-max(1, min(1000, int(limit))) :]


class WebIntelligenceCenter:
    

    def __init__(
        self,
        *,
        intelligence: Any,
        sources: Any,
        protocols: Any,
        context_bridge: Any,
        selector: Any,
        recorder: Any,
        time_machine: WebTimeMachine,
    ) -> None:
        self.intelligence = intelligence
        self.sources = sources
        self.protocols = protocols
        self.context_bridge = context_bridge
        self.selector = selector
        self.recorder = recorder
        self.time_machine = time_machine

    @staticmethod
    def _redact_url(url: str) -> tuple[str, list[str]]:
        sensitive: list[str] = []
        try:
            parts = urlsplit(url)
        except ValueError:
            return url[:4096], sensitive
        query = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if _SENSITIVE_NAME.search(key):
                sensitive.append("query:" + key)
                query.append((key, "<redacted>"))
            else:
                query.append((key, value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), "")), sensitive

    @staticmethod
    def _event_kind(event: NetworkEvent) -> str:
        text = " ".join(
            [event.url or "", event.protocol or "", " ".join(event.response_headers.values()), str(event.metadata or {})]
        ).casefold()
        if "graphql" in text:
            return "graphql"
        if "json" in text or "/api/" in (event.url or "").casefold():
            return "api-json"
        resource = str((event.metadata or {}).get("resource_type", "")).casefold()
        if resource in {"xhr", "fetch"}:
            return resource
        return "http"

    def classify_endpoint(self, event: NetworkEvent) -> ReplayCandidate | None:
        if not event.url:
            return None
        method = (event.method or "GET").upper()
        redacted_url, sensitive = self._redact_url(event.url)
        for key in event.request_headers:
            folded = str(key).casefold().strip()
            if folded in _SENSITIVE_HEADERS or _SENSITIVE_NAME.search(folded):
                sensitive.append("header:" + str(key))
        sensitive.extend("flag:" + str(value) for value in event.sensitivity_flags)
        kind = self._event_kind(event)
        structured = kind in {"graphql", "api-json", "xhr", "fetch"}
        reasons: list[str] = []
        confidence = 0.58
        if structured:
            confidence += 0.24
            reasons.append("capture indicates a structured endpoint")
        if event.status is not None and 200 <= int(event.status) < 400:
            confidence += 0.08
            reasons.append("captured response succeeded")
        if method in _IDEMPOTENT_METHODS:
            confidence += 0.06
            reasons.append("HTTP method is idempotent for replay planning")
        else:
            reasons.append("non-idempotent method requires explicit review")
        if sensitive:
            reasons.append("credential/sensitive material detected; candidate is not persistable or auto-replayable")
        safe = method in _IDEMPOTENT_METHODS and not sensitive and structured
        return ReplayCandidate(
            event_id=event.id,
            method=method,
            url=redacted_url,
            kind=kind,
            confidence=round(min(0.99, confidence), 3),
            safe_to_replay=safe,
            persistable=not sensitive,
            review_required=not safe,
            sensitive_fields=sorted(set(sensitive)),
            reasons=reasons,
        )

    def replay_candidates(self, events: Sequence[NetworkEvent]) -> list[ReplayCandidate]:
        output = [item for item in (self.classify_endpoint(event) for event in events) if item is not None]
        return sorted(output, key=lambda item: (not item.safe_to_replay, -item.confidence, item.url, item.event_id))

    def event_to_workflow(self, event: NetworkEvent, *, require_safe: bool = True) -> Workflow:
        candidate = self.classify_endpoint(event)
        if candidate is None:
            raise ValueError("NetworkEvent 没有 URL，无法转换为 Workflow。")
        if require_safe and not candidate.safe_to_replay:
            raise ValueError("该请求不是安全自动重放候选；请先人工审查幂等性与敏感参数。")
        spec = self.context_bridge.event_to_request(event, include_sensitive=False)
                                                                                              
                                                                                             
        spec.url = candidate.url
        workflow = self.context_bridge.request_to_workflow(spec, name="Web Intelligence Captured API")
        if workflow.nodes:
            workflow.nodes[0].config["web_intelligence"] = {
                "candidate_kind": candidate.kind,
                "confidence": candidate.confidence,
                "sensitive_material_omitted": True,
                "review_required": candidate.review_required,
            }
        return workflow

    def analyze(
        self,
        response: FetchResponse | None,
        events: Sequence[NetworkEvent],
        history_success: Mapping[str, float] | None = None,
    ) -> WebIntelligenceReport:
        blueprint = self.intelligence.analyze(response, events, history_success or {})
        endpoints = self.replay_candidates(events)
        return WebIntelligenceReport(
            url=blueprint.url,
            recommended_engine=blueprint.recommended_engine,
            confidence=blueprint.confidence,
            fallback_chain=list(blueprint.fallback_chain),
            decision_trace=[asdict(item) for item in blueprint.decision_trace],
            data_sources=list(blueprint.data_sources),
            endpoints=endpoints,
            graphql=self.protocols.graphql(events),
            websocket=self.protocols.websocket(events),
            sse=self.protocols.sse(events),
            risk_flags=list(blueprint.risk_flags),
            workflow=blueprint.workflow,
        )
