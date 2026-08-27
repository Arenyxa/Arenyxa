from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from statistics import median
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from arenyxa.domain.enums import CaptureSource
from arenyxa.domain.models import FetchResponse, NetworkEvent, RequestSpec, Workflow, WorkflowNode


_SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token"}
_SECRET_KEY = re.compile(r"(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)", re.I)
_SECRET_PLACEHOLDER = re.compile(r"^\$\{secret\.[\w.-]+\}$")


@dataclass(slots=True)
class DecisionEvidence:
    code: str
    category: str
    observation: str
    engine: str
    weight: float
    source: str = "runtime"


@dataclass(slots=True)
class EngineEstimate:
    engine: str
    score: float
    confidence: float
    completeness: float
    stability: float
    resource_efficiency: float
    estimated_latency_ms: int
    estimated_peak_memory_mb: int
    estimated_requests: int | None
    prerequisites: list[str] = field(default_factory=list)
    tradeoffs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WebIntelligenceBlueprint:
    url: str
    recommended_engine: str
    confidence: float
    fallback_chain: list[str]
    decision_trace: list[DecisionEvidence]
    engine_estimates: list[EngineEstimate]
    data_sources: list[dict[str, Any]]
    risk_flags: list[dict[str, str]]
    workflow: Workflow
    workflow_explanation: list[str]
    optimization_summary: dict[str, Any]


class WebIntelligenceEngine:
    







    def __init__(self, smartpath: Any) -> None:
        self.smartpath = smartpath

    def analyze(
        self,
        response: FetchResponse | None,
        events: Sequence[NetworkEvent],
        history_success: Mapping[str, float] | None = None,
    ) -> WebIntelligenceBlueprint:
        plan = self.smartpath.analyze(response, events, history_success or {})
        trace: list[DecisionEvidence] = []
        risks: list[dict[str, str]] = []
        data_sources = list(plan.data_sources)
        url = (response.final_url if response is not None else "") or next((item.url for item in events if item.url), "")

        content_type = response.content_type.casefold() if response is not None else ""
        body_text = ""
        body_size = 0
        script_count = 0
        if response is not None:
            body_size = len(response.body)
            if "html" in content_type:
                body_text = response.body.decode(response.encoding, errors="ignore")
                script_count = len(re.findall(r"<script\b", body_text, re.I))
            if response.status in {401, 403}:
                risks.append({"severity": "high", "code": "AUTH_OR_BLOCK", "message": f"HTTP {response.status} 可能需要认证或存在访问限制。"})
            elif response.status == 429:
                risks.append({"severity": "high", "code": "RATE_LIMIT", "message": "检测到 HTTP 429，应启用自适应限速。"})
            elif response.status >= 500:
                risks.append({"severity": "medium", "code": "ORIGIN_UNSTABLE", "message": f"源站返回 HTTP {response.status}。"})

        api_sources = [item for item in data_sources if item.get("kind") in {"api-json", "xhr-json", "graphql", "nextjs", "nuxt", "embedded-json"}]
        network_api_events = [
            item for item in events
            if item.url and (
                "/api/" in item.url
                or "graphql" in item.url.casefold()
                or "json" in " ".join(item.response_headers.values()).casefold()
            )
        ]
        auth_events = [item for item in events if any(key.casefold() in _SENSITIVE_HEADER_NAMES for key in item.request_headers)]
        websocket_events = [item for item in events if (item.protocol or "").casefold() in {"ws", "wss", "websocket"}]

        if "json" in content_type:
            trace.append(DecisionEvidence("DIRECT_JSON", "data-source", "主响应就是结构化 JSON。", "api", 3.5, "response"))
        if api_sources:
            top = max(float(item.get("confidence", 0.0)) for item in api_sources)
            trace.append(DecisionEvidence("API_DISCOVERED", "data-source", f"发现 {len(api_sources)} 个可复用结构化数据源，最高置信度 {top:.0%}。", "api", 3.0 + top, "capture"))
        if network_api_events:
            trace.append(DecisionEvidence("API_ACTIVITY", "network", f"捕获到 {len(network_api_events)} 个 API/JSON 网络事件。", "api", min(3.0, 0.5 + len(network_api_events) / 10.0), "capture"))
        if "html" in content_type:
            trace.append(DecisionEvidence("HTML_AVAILABLE", "document", "主响应包含可直接解析的 HTML DOM。", "http", 1.2, "response"))
        if script_count >= 20:
            trace.append(DecisionEvidence("JS_HEAVY", "rendering", f"页面包含 {script_count} 个 script 标签，渲染层较重。", "browser", 2.2, "response"))
        if auth_events:
            trace.append(DecisionEvidence("SESSION_STATE", "session", f"{len(auth_events)} 个请求携带认证/Cookie 类状态；浏览器 Profile 可能更稳定。", "browser", 1.7, "capture"))
            risks.append({"severity": "medium", "code": "SESSION_DEPENDENCY", "message": "存在会话状态依赖；导出/共享工作流时应使用 Secrets Vault 引用。"})
        if websocket_events:
            trace.append(DecisionEvidence("WEBSOCKET_DATA", "protocol", f"检测到 {len(websocket_events)} 个 WebSocket 事件。", "browser", 1.0, "capture"))
        if len(events) > 20_000:
            trace.append(DecisionEvidence("HIGH_EVENT_VOLUME", "scale", f"捕获事件达到 {len(events):,}，可考虑 Distributed Worker。", "distributed", 2.8, "capture"))
            risks.append({"severity": "medium", "code": "SCALE_PRESSURE", "message": "事件规模较大；建议分片并启用有界队列/Worker。"})
        if plan.confidence < 0.45:
            risks.append({"severity": "medium", "code": "LOW_CONFIDENCE", "message": "执行策略置信度较低，建议先运行小样本验证。"})

        smart_scores = {str(item["engine"]): float(item["score"]) for item in plan.ranking}
        max_smart = max(smart_scores.values(), default=1.0) or 1.0
        record_estimate = self._record_estimate(data_sources)
        latency_base = max(20.0, float(response.elapsed_ms if response is not None else 250.0))
        memory_body = max(1.0, body_size / (1024 * 1024))

        estimates: list[EngineEstimate] = []
        for engine in ("api", "http", "browser", "distributed"):
            smart = max(0.0, smart_scores.get(engine, 0.0)) / max_smart
            completeness, stability, resource, latency, memory, requests, prerequisites, tradeoffs = self._engine_profile(
                engine,
                api_available=bool(api_sources),
                html_available="html" in content_type,
                auth_required=bool(auth_events),
                js_heavy=script_count >= 20,
                record_estimate=record_estimate,
                latency_base=latency_base,
                memory_body=memory_body,
                event_count=len(events),
            )
            evidence_boost = sum(item.weight for item in trace if item.engine == engine) / 10.0
            final_score = 0.46 * smart + 0.22 * completeness + 0.16 * stability + 0.12 * resource + 0.04 * min(1.0, evidence_boost)
            estimates.append(
                EngineEstimate(
                    engine=engine,
                    score=round(final_score, 4),
                    confidence=round(min(0.99, 0.55 * float(plan.confidence) + 0.45 * max(smart, min(1.0, evidence_boost))), 4),
                    completeness=round(completeness, 3),
                    stability=round(stability, 3),
                    resource_efficiency=round(resource, 3),
                    estimated_latency_ms=max(1, int(latency)),
                    estimated_peak_memory_mb=max(8, int(memory)),
                    estimated_requests=requests,
                    prerequisites=prerequisites,
                    tradeoffs=tradeoffs,
                )
            )

        estimates.sort(key=lambda item: (item.score, item.confidence), reverse=True)
                                                                                            
                                                                                                  
        selected = plan.recommended_engine
        current = next((item for item in estimates if item.engine == selected), None)
        if current is None or (estimates and estimates[0].score - current.score >= 0.18):
            selected = estimates[0].engine
        selected_estimate = next(item for item in estimates if item.engine == selected)
        fallbacks = [item.engine for item in estimates if item.engine != selected]
        workflow, explanation = self._workflow(url, selected, data_sources, risks)

        optimization = {
            "selected": selected,
            "estimated_latency_ms": selected_estimate.estimated_latency_ms,
            "estimated_peak_memory_mb": selected_estimate.estimated_peak_memory_mb,
            "estimated_requests": selected_estimate.estimated_requests,
            "completeness": selected_estimate.completeness,
            "stability": selected_estimate.stability,
            "resource_efficiency": selected_estimate.resource_efficiency,
            "note": "这些是基于当前响应/捕获信息的相对估算，不是实测 benchmark。",
        }
        return WebIntelligenceBlueprint(
            url=url,
            recommended_engine=selected,
            confidence=selected_estimate.confidence,
            fallback_chain=fallbacks,
            decision_trace=trace,
            engine_estimates=estimates,
            data_sources=data_sources,
            risk_flags=risks,
            workflow=workflow,
            workflow_explanation=explanation,
            optimization_summary=optimization,
        )

    @staticmethod
    def _record_estimate(sources: Sequence[Mapping[str, Any]]) -> int | None:
        values = [int(item["estimated_records"]) for item in sources if isinstance(item.get("estimated_records"), int) and int(item["estimated_records"]) >= 0]
        return max(values) if values else None

    @staticmethod
    def _engine_profile(
        engine: str,
        *,
        api_available: bool,
        html_available: bool,
        auth_required: bool,
        js_heavy: bool,
        record_estimate: int | None,
        latency_base: float,
        memory_body: float,
        event_count: int,
    ) -> tuple[float, float, float, float, float, int | None, list[str], list[str]]:
        requests = None if record_estimate is None else max(1, math.ceil(record_estimate / 100))
        if engine == "api":
            return (
                0.98 if api_available else 0.38,
                0.94 if api_available else 0.52,
                0.98,
                latency_base * (0.65 if api_available else 1.2),
                18 + memory_body * 1.5,
                requests,
                ["已发现可复用 API/JSON 数据源"] if api_available else ["需要先发现或构造 API 请求"],
                ["API Schema 变化时需要回归检测", "认证状态必须通过 Secrets/Profile 管理"] if auth_required else ["API Schema 变化时需要回归检测"],
            )
        if engine == "http":
            return (
                0.88 if html_available and not js_heavy else 0.62,
                0.90 if html_available else 0.60,
                0.93,
                latency_base,
                26 + memory_body * 3.0,
                requests,
                ["服务器响应包含可解析 HTML"] if html_available else ["需要 HTTP 可达"],
                ["客户端渲染字段可能缺失"] if js_heavy else ["选择器需要网站变更监控"],
            )
        if engine == "browser":
            return (
                0.97,
                0.84 if not auth_required else 0.91,
                0.36,
                latency_base * 4.0 + 450,
                320 + min(700.0, memory_body * 8.0),
                requests,
                ["Playwright/Chromium 可用", "Browser Profile 可选"],
                ["CPU/RAM 成本最高", "浏览器版本与站点脚本变化会影响稳定性"],
            )
        return (
            0.99,
            0.90,
            0.54,
            latency_base * 0.85 + 180,
            150 + min(450.0, event_count / 120.0),
            requests,
            ["至少一个健康 Worker", "任务可安全分片"],
            ["存在调度/网络开销", "Worker 版本和秘密配置需要一致"],
        )

    @staticmethod
    def _workflow(url: str, engine: str, sources: Sequence[Mapping[str, Any]], risks: Sequence[Mapping[str, str]]) -> tuple[Workflow, list[str]]:
        source = WorkflowNode(kind="source", config={"engine": engine, "url": url}, id="source", next_ids=["normalize"])
        constants: dict[str, Any] = {"_arenyxa_engine": engine}
        if sources:
            constants["_arenyxa_source"] = str(sources[0].get("location", ""))
        normalize = WorkflowNode(kind="map", config={"constants": constants}, id="normalize", next_ids=["validate"])
        validate = WorkflowNode(kind="validate", config={"required": []}, id="validate", next_ids=["sink"], failure_ids=["sink"])
        sink = WorkflowNode(kind="sink", config={"quality_gate": True, "risk_count": len(risks)}, id="sink")
        workflow = Workflow(name=f"Arenyxa Blueprint · {engine.upper()}", nodes=[source, normalize, validate, sink])
        explanation = [
            f"使用 {engine} 作为首选执行引擎。",
            "所有采集结果先经过 normalize 节点标注来源。",
            "validate 节点作为数据质量/Schema Gate 的挂载点。",
            "失败路径仍进入 sink，以便保留可诊断的运行上下文。",
        ]
        return workflow, explanation


class ContextBridgeService:
    

    def __init__(self, code_generator: Any) -> None:
        self.code_generator = code_generator

    def event_to_request(self, event: NetworkEvent, *, include_sensitive: bool = False) -> RequestSpec:
        if not event.url:
            raise ValueError("NetworkEvent 没有 URL，无法转换为 RequestSpec。")
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        for key, value in event.request_headers.items():
            lowered = key.casefold().strip()
            if lowered == "cookie":
                if include_sensitive:
                    for chunk in value.split(";"):
                        if "=" in chunk:
                            name, cookie_value = chunk.split("=", 1)
                            cookies[name.strip()] = cookie_value.strip()
                continue
            if not include_sensitive and lowered in _SENSITIVE_HEADER_NAMES:
                continue
            headers[str(key)] = str(value)
        return RequestSpec(url=event.url, method=(event.method or "GET").upper(), headers=headers, cookies=cookies)

    def request_to_workflow(self, spec: RequestSpec, *, name: str = "Captured Request Workflow") -> Workflow:
        config = {
            "url": spec.url,
            "method": spec.method,
            "query": dict(spec.query),
            "headers": {key: value for key, value in spec.headers.items() if key.casefold() not in _SENSITIVE_HEADER_NAMES},
            "body": spec.body,
            "content_type": spec.content_type,
            "verify_tls": spec.verify_tls,
            "proxy": "${secret.proxy_url}" if spec.proxy else None,
        }
        return Workflow(
            name=name,
            nodes=[
                WorkflowNode(kind="source", config={"request": config}, id="request", next_ids=["normalize"]),
                WorkflowNode(kind="map", config={"constants": {"_arenyxa_context": "network-request"}}, id="normalize", next_ids=["sink"]),
                WorkflowNode(kind="sink", config={}, id="sink"),
            ],
        )

    def event_bundle(self, event: NetworkEvent) -> dict[str, Any]:
        spec = self.event_to_request(event, include_sensitive=False)
        return {
            "request": asdict(spec),
            "workflow": asdict(self.request_to_workflow(spec)),
            "code": {
                target: self.code_generator.generate(spec, target)
                for target in ("curl", "python", "httpx", "fetch", "powershell")
            },
            "sensitive_material_omitted": True,
        }


class WorkflowPortabilityService:
    

    SCHEMA = "arenyxa.workflow/v1"
    MAX_NODES = 10_000
    MAX_BYTES = 8 * 1024 * 1024

    def export(self, workflow: Workflow, *, allow_inline_secrets: bool = False) -> dict[str, Any]:
        payload = {
            "schema": self.SCHEMA,
            "workflow": asdict(workflow),
            "metadata": {"portable": True, "secrets": "references-only"},
        }
        findings = self.secret_findings(payload["workflow"])
        if findings and not allow_inline_secrets:
            raise ValueError("工作流包含疑似内联秘密：" + ", ".join(findings[:8]) + "。请改用 ${secret.name}。")
        payload["sha256"] = self._digest(payload)
        return payload

    def dumps(self, workflow: Workflow, *, allow_inline_secrets: bool = False) -> str:
        return json.dumps(self.export(workflow, allow_inline_secrets=allow_inline_secrets), ensure_ascii=False, indent=2, sort_keys=True)

    def load(self, document: str | bytes | Mapping[str, Any]) -> Workflow:
        if isinstance(document, bytes):
            if len(document) > self.MAX_BYTES:
                raise ValueError("Workflow document 过大。")
            data = json.loads(document.decode("utf-8"))
        elif isinstance(document, str):
            if len(document.encode("utf-8")) > self.MAX_BYTES:
                raise ValueError("Workflow document 过大。")
            data = json.loads(document)
        else:
            data = dict(document)
        if data.get("schema") != self.SCHEMA:
            raise ValueError("不支持的 Workflow schema。")
        expected = str(data.get("sha256", ""))
        if not expected or expected != self._digest({key: value for key, value in data.items() if key != "sha256"}):
            raise ValueError("Workflow SHA-256 校验失败。")
        raw = data.get("workflow")
        if not isinstance(raw, dict):
            raise ValueError("workflow 必须是对象。")
        raw_nodes = raw.get("nodes")
        if not isinstance(raw_nodes, list) or not raw_nodes or len(raw_nodes) > self.MAX_NODES:
            raise ValueError("Workflow 节点数量无效。")
        nodes: list[WorkflowNode] = []
        ids: set[str] = set()
        for item in raw_nodes:
            if not isinstance(item, dict):
                raise ValueError("Workflow node 必须是对象。")
            node = WorkflowNode(
                kind=str(item.get("kind", "")),
                config=dict(item.get("config") or {}),
                id=str(item.get("id", "")),
                next_ids=[str(value) for value in item.get("next_ids", [])],
                failure_ids=[str(value) for value in item.get("failure_ids", [])],
            )
            if not node.kind or not node.id or node.id in ids:
                raise ValueError("Workflow 节点 kind/id 无效或重复。")
            ids.add(node.id)
            nodes.append(node)
        for node in nodes:
            missing = [target for target in node.next_ids + node.failure_ids if target not in ids]
            if missing:
                raise ValueError(f"Workflow 节点 {node.id} 引用了不存在的目标：{missing[0]}")
        findings = self.secret_findings(raw)
        if findings:
            raise ValueError("导入文档包含疑似内联秘密：" + ", ".join(findings[:8]))
        return Workflow(
            name=str(raw.get("name") or "Imported Workflow"),
            nodes=nodes,
            id=str(raw.get("id") or "workflow-imported"),
            version=str(raw.get("version") or "1.0.0"),
            created_at=str(raw.get("created_at") or ""),
            schema_version=int(raw.get("schema_version") or 1),
        )

    @classmethod
    def secret_findings(cls, value: Any, path: str = "workflow") -> list[str]:
        findings: list[str] = []
        if isinstance(value, Mapping):
            for key, nested in value.items():
                current = f"{path}.{key}"
                if _SECRET_KEY.search(str(key)) and isinstance(nested, str) and nested and not _SECRET_PLACEHOLDER.match(nested):
                    findings.append(current)
                findings.extend(cls.secret_findings(nested, current))
        elif isinstance(value, list):
            for index, nested in enumerate(value):
                findings.extend(cls.secret_findings(nested, f"{path}[{index}]"))
        return findings

    @staticmethod
    def _digest(payload: Mapping[str, Any]) -> str:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


@dataclass(slots=True)
class CompatibilityCase:
    id: str
    response: FetchResponse | None
    events: list[NetworkEvent]
    expected_engine: str
    expected_source_kinds: set[str] = field(default_factory=set)
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CompatibilityCaseResult:
    id: str
    passed: bool
    engine_ok: bool
    source_recall: float
    recommended_engine: str
    confidence: float
    tags: list[str]
    notes: list[str]


class CompatibilityLab:
    





    def __init__(self, intelligence: WebIntelligenceEngine) -> None:
        self.intelligence = intelligence

    def run(
        self,
        cases: Sequence[CompatibilityCase] | None = None,
        progress: Callable[[int, int, str], None] | None = None,
    ) -> dict[str, Any]:
        cases = list(cases or self.default_cases())
        results: list[CompatibilityCaseResult] = []
        total = len(cases)
        for index, case in enumerate(cases, 1):
            blueprint = self.intelligence.analyze(case.response, case.events)
            found = {str(item.get("kind")) for item in blueprint.data_sources}
            expected = set(case.expected_source_kinds)
            recall = 1.0 if not expected else len(found & expected) / len(expected)
            engine_ok = blueprint.recommended_engine == case.expected_engine
            passed = engine_ok and recall >= 0.999
            notes = []
            if not engine_ok:
                notes.append(f"expected engine {case.expected_engine}, got {blueprint.recommended_engine}")
            if recall < 1.0:
                notes.append(f"source recall {recall:.0%}")
            results.append(CompatibilityCaseResult(case.id, passed, engine_ok, round(recall, 3), blueprint.recommended_engine, blueprint.confidence, list(case.tags), notes))
            if progress:
                progress(index, total, case.id)
        pass_rate = sum(item.passed for item in results) / max(1, total)
        engine_accuracy = sum(item.engine_ok for item in results) / max(1, total)
        source_recall = sum(item.source_recall for item in results) / max(1, total)
        by_tag: dict[str, dict[str, Any]] = {}
        for item in results:
            for tag in item.tags:
                bucket = by_tag.setdefault(tag, {"cases": 0, "passed": 0})
                bucket["cases"] += 1
                bucket["passed"] += int(item.passed)
        for bucket in by_tag.values():
            bucket["pass_rate"] = round(bucket["passed"] / max(1, bucket["cases"]), 4)
        return {
            "scope": "offline deterministic fixtures",
            "cases": total,
            "passed": sum(item.passed for item in results),
            "pass_rate": round(pass_rate, 4),
            "engine_accuracy": round(engine_accuracy, 4),
            "source_recall": round(source_recall, 4),
            "by_tag": by_tag,
            "results": [asdict(item) for item in results],
            "disclaimer": "该报告验证 Arenyxa 的本地策略/解析回归，不代表对实时第三方网站的兼容率。",
        }

    @staticmethod
    def default_cases() -> list[CompatibilityCase]:
        def response(body: str, ctype: str = "text/html", status: int = 200) -> FetchResponse:
            return FetchResponse("https://fixture.local", "https://fixture.local", status, {"Content-Type": ctype}, body.encode(), 80.0, "utf-8", ctype)

        def event(url: str, ctype: str = "application/json", *, headers: Mapping[str, str] | None = None) -> NetworkEvent:
            return NetworkEvent(
                session_id="fixture",
                source_type=CaptureSource.BROWSER,
                protocol="https",
                direction="out",
                size=1024,
                method="GET",
                url=url,
                status=200,
                request_headers=dict(headers or {}),
                response_headers={"content-type": ctype},
            )

        return [
            CompatibilityCase("direct-json", response('[{"id":1},{"id":2}]', "application/json"), [], "api", {"api-json"}, ["api", "json"]),
            CompatibilityCase("nextjs-api", response("<html><script id='__NEXT_DATA__'>{}</script></html>"), [event("https://fixture.local/api/products")], "api", {"nextjs", "xhr-json"}, ["nextjs", "api"]),
            CompatibilityCase("static-html", response("<html><body><article><h1>Static</h1></article></body></html>"), [], "http", {"dom"}, ["html", "static"]),
            CompatibilityCase("graphql", response("<html><body>app</body></html>"), [event("https://fixture.local/graphql") for _ in range(3)], "api", {"graphql"}, ["graphql", "api"]),
            CompatibilityCase("js-heavy-no-api", response("<html>" + "<script>window.x=1</script>" * 30 + "<body></body></html>"), [], "browser", {"dom"}, ["spa", "browser"]),
            CompatibilityCase("session-browser", response("<html>" + "<script>window.x=1</script>" * 25 + "</html>"), [event("https://fixture.local/page", "text/html", headers={"Cookie": "session=secret"})], "browser", {"dom"}, ["session", "browser"]),
        ]


class ReliabilityAdvisor:
    

    def assess(
        self,
        *,
        current_quality: float,
        baseline_quality: float,
        selector_confidence: float | None = None,
        error_rate: float = 0.0,
        schema_changes: int = 0,
        rate_limited: bool = False,
    ) -> dict[str, Any]:
        quality_drop = max(0.0, float(baseline_quality) - float(current_quality))
        score = 100.0
        score -= min(35.0, quality_drop * 0.7)
        score -= min(30.0, max(0.0, error_rate) * 100.0 * 0.5)
        score -= min(20.0, max(0, int(schema_changes)) * 4.0)
        if selector_confidence is not None:
            score -= max(0.0, 0.85 - float(selector_confidence)) * 25.0
        if rate_limited:
            score -= 8.0
        actions: list[dict[str, str]] = []
        if rate_limited:
            actions.append({"priority": "P0", "action": "adaptive-rate-limit", "reason": "检测到限流信号，先降低并发并遵循 Retry-After。"})
        if selector_confidence is not None and selector_confidence < 0.75:
            actions.append({"priority": "P0", "action": "selector-self-heal", "reason": "选择器稳定度下降，先使用历史指纹生成替代候选。"})
        if schema_changes:
            actions.append({"priority": "P1", "action": "schema-diff", "reason": f"检测到 {schema_changes} 个 Schema 变化，运行 Data Quality/Regression Gate。"})
        if quality_drop >= 10:
            actions.append({"priority": "P1", "action": "quality-gate", "reason": f"数据质量比基线下降 {quality_drop:.1f} 分。"})
        if error_rate >= 0.1:
            actions.append({"priority": "P1", "action": "smartpath-replan", "reason": f"错误率达到 {error_rate:.1%}，重新评估数据源和 fallback chain。"})
        if not actions:
            actions.append({"priority": "P3", "action": "continue-monitoring", "reason": "没有发现需要立即干预的漂移。"})
        return {"reliability_score": round(max(0.0, min(100.0, score)), 1), "actions": actions}
