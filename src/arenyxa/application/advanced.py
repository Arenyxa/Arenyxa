from __future__ import annotations

import collections
import re
from dataclasses import field
from arenyxa.compat import dataclass
from typing import Any, ClassVar
from urllib.parse import urlparse

from lxml import html

from arenyxa.domain.models import FetchResponse, NetworkEvent
from arenyxa.application.api_map import ApiMapService


@dataclass(slots=True)
class ExecutionPlan:
    engine: str
    confidence: float
    reasons: list[str]
    estimated_cost: str
    override_allowed: bool = True


class SmartExecutionPlanner:
    def plan(
        self,
        response: FetchResponse | None,
        events: list[NetworkEvent],
        history_success: dict[str, float] | None = None,
    ) -> ExecutionPlan:
        scores: dict[str, float] = {"http": 1.0, "api": 0.0, "browser": 0.0, "distributed": 0.0}
        reasons: list[str] = []
        if response:
            if "json" in response.content_type:
                scores["api"] += 5
                reasons.append("响应为 JSON，可优先使用 API 引擎。")
            if "html" in response.content_type:
                text = response.body.decode(response.encoding, errors="ignore")
                scripts = len(re.findall(r"<script\b", text, re.IGNORECASE))
                app_markers = len(
                    re.findall(r"__NEXT_DATA__|webpack|vite|react|vue|angular", text, re.IGNORECASE)
                )
                if scripts > 12 or app_markers:
                    scores["browser"] += 4
                    reasons.append("页面 JavaScript 依赖较高。")
                if len(text) > 10_000:
                    scores["http"] += 1
                    reasons.append("初始 HTML 已包含较多可解析内容。")
        api_events = [
            event
            for event in events
            if event.url
            and ("json" in event.response_headers.get("content-type", "").lower() or "/api/" in event.url)
        ]
        if api_events:
            scores["api"] += min(6, len(api_events) / 2)
            reasons.append(f"网络会话识别到 {len(api_events)} 个 API 候选。")
        if len(events) > 20_000:
            scores["distributed"] += 3
            reasons.append("历史规模较大，建议分布式执行。")
        for engine, success in (history_success or {}).items():
            scores[engine] += max(0, min(1, success)) * 2
        engine, score = max(scores.items(), key=lambda item: item[1])
        total = sum(max(0, value) for value in scores.values()) or 1
        return ExecutionPlan(
            engine=engine,
            confidence=round(score / total, 3),
            reasons=reasons or ["未发现强特征，使用轻量 HTTP 引擎。"],
            estimated_cost={"http": "low", "api": "low", "browser": "medium", "distributed": "high"}[engine],
        )


@dataclass(slots=True)
class GraphNode:
    id: str
    kind: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str


@dataclass(slots=True)
class IntelligenceMap:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)


class WebsiteIntelligenceMapper:
    def build(self, events: list[NetworkEvent]) -> IntelligenceMap:
        result = IntelligenceMap()
        node_ids: set[str] = set()

        def add_node(node: GraphNode) -> None:
            if node.id not in node_ids:
                node_ids.add(node.id)
                result.nodes.append(node)

        for event in events:
            if not event.url:
                continue
            parsed = urlparse(event.url)
            domain_id = f"domain:{parsed.hostname}"
            route_id = f"route:{parsed.hostname}{parsed.path}"
            add_node(GraphNode(domain_id, "domain", parsed.hostname or "unknown"))
            add_node(
                GraphNode(
                    route_id,
                    "api" if "/api/" in parsed.path else "page",
                    parsed.path or "/",
                    {"method": event.method, "status": event.status},
                )
            )
            result.edges.append(GraphEdge(domain_id, route_id, "hosts"))
            if event.initiator:
                initiator_id = f"initiator:{event.initiator}"
                add_node(GraphNode(initiator_id, "initiator", event.initiator))
                result.edges.append(GraphEdge(initiator_id, route_id, "initiates"))
        return result


class ApiMapper:
    





    def analyze(self, events: list[NetworkEvent]) -> list[dict[str, Any]]:
        exchanges: list[dict[str, Any]] = []
        for event in events:
            if not event.url or not event.method:
                continue
            content_type = ""
            for key, value in event.response_headers.items():
                if str(key).casefold() == "content-type":
                    content_type = str(value)
                    break
            exchanges.append(
                {
                    "request_id": event.request_ref or event.id,
                    "event_id": event.id,
                    "session_id": event.session_id,
                    "method": event.method,
                    "url": event.url,
                    "host": event.host,
                    "status": event.status,
                    "request_headers": dict(event.request_headers),
                    "response_headers": dict(event.response_headers),
                    "request_body_ref": event.request_body_ref,
                    "response_body_ref": event.response_body_ref,
                    "content_type": content_type,
                    "timing": dict(event.timing),
                    "initiator": event.initiator,
                }
            )
        session_id = events[0].session_id if events else "legacy"
        return ApiMapService().build(session_id, exchanges).to_dict()["endpoints"]


class SecurityAnalyzer:
    SECURITY_HEADERS: ClassVar[dict[str, str]] = {
        "strict-transport-security": "启用 HSTS，降低 HTTPS 降级风险。",
        "content-security-policy": "配置 CSP，限制内容来源与脚本执行。",
        "x-content-type-options": "设置 nosniff，避免 MIME 猜测。",
        "referrer-policy": "限制 Referrer 信息暴露。",
        "permissions-policy": "限制浏览器敏感能力。",
    }

    def analyze(self, response: FetchResponse) -> list[dict[str, Any]]:
        headers = {key.lower(): value for key, value in response.headers.items()}
        findings = []
        if response.final_url.startswith("http:"):
            findings.append(
                {
                    "severity": "high",
                    "code": "SEC_HTTP",
                    "evidence": response.final_url,
                    "recommendation": "使用 HTTPS。",
                }
            )
        for name, recommendation in self.SECURITY_HEADERS.items():
            if name not in headers:
                findings.append(
                    {
                        "severity": "medium",
                        "code": f"SEC_HEADER_{name.upper().replace('-', '_')}",
                        "evidence": "header missing",
                        "recommendation": recommendation,
                    }
                )
        cookies = headers.get("set-cookie", "")
        if cookies and "secure" not in cookies.lower():
            findings.append(
                {
                    "severity": "medium",
                    "code": "SEC_COOKIE_SECURE",
                    "evidence": "Set-Cookie without Secure",
                    "recommendation": "为 HTTPS Cookie 添加 Secure。",
                }
            )
        if cookies and "httponly" not in cookies.lower():
            findings.append(
                {
                    "severity": "medium",
                    "code": "SEC_COOKIE_HTTPONLY",
                    "evidence": "Set-Cookie without HttpOnly",
                    "recommendation": "对非脚本 Cookie 添加 HttpOnly。",
                }
            )
        if (
            "access-control-allow-origin" in headers
            and headers["access-control-allow-origin"].strip() == "*"
            and headers.get("access-control-allow-credentials", "").lower() == "true"
        ):
            findings.append(
                {
                    "severity": "high",
                    "code": "SEC_CORS_CREDENTIALS",
                    "evidence": "wildcard origin with credentials",
                    "recommendation": "使用明确的受信任 Origin。",
                }
            )
        return findings


class CompatibilityAnalyzer:
    def analyze_html(self, response: FetchResponse) -> list[dict[str, Any]]:
        if "html" not in response.content_type:
            return [{"severity": "info", "code": "COMPAT_NOT_HTML", "message": "响应不是 HTML。"}]
        document = html.fromstring(response.body.decode(response.encoding, errors="replace"))
        findings = []
        if not document.xpath(
            "//meta[translate(@name,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='viewport']"
        ):
            findings.append(
                {"severity": "warning", "code": "COMPAT_VIEWPORT", "message": "缺少 viewport 元数据。"}
            )
        if not document.xpath("//html/@lang"):
            findings.append({"severity": "warning", "code": "COMPAT_LANG", "message": "html 元素缺少 lang。"})
        images_without_alt = len(document.xpath("//img[not(@alt)]"))
        if images_without_alt:
            findings.append(
                {
                    "severity": "warning",
                    "code": "A11Y_IMG_ALT",
                    "message": f"{images_without_alt} 个图片缺少 alt。",
                }
            )
        duplicate_ids = [
            key for key, count in collections.Counter(document.xpath("//*[@id]/@id")).items() if count > 1
        ]
        if duplicate_ids:
            findings.append(
                {
                    "severity": "warning",
                    "code": "COMPAT_DUPLICATE_ID",
                    "message": f"重复 id：{', '.join(duplicate_ids[:10])}",
                }
            )
        return findings


class PerformanceProfiler:
    def summarize(self, events: list[NetworkEvent]) -> dict[str, Any]:
        total_bytes = sum(event.size for event in events)
        durations = sorted(float(event.timing.get("total_ms", 0)) for event in events)
        hosts = collections.Counter(event.host for event in events if event.host)
        mime_types = collections.Counter(str(event.metadata.get("mime_type", "unknown")) for event in events)
        return {
            "requests": len(events),
            "total_bytes": total_bytes,
            "p50_ms": self._percentile(durations, 0.50),
            "p95_ms": self._percentile(durations, 0.95),
            "slowest": sorted(events, key=lambda event: event.timing.get("total_ms", 0), reverse=True)[:20],
            "hosts": dict(hosts.most_common()),
            "mime_types": dict(mime_types.most_common()),
            "failed": sum(1 for event in events if event.status and event.status >= 400),
        }

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        if not values:
            return 0.0
        return values[min(len(values) - 1, round((len(values) - 1) * percentile))]
