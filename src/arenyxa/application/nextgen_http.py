from __future__ import annotations

from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.compat import path_is_relative_to
import base64
import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import statistics
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from cryptography.fernet import Fernet, InvalidToken
from lxml import etree, html
from arenyxa import __version__
from arenyxa.application.advanced import SmartExecutionPlanner
from arenyxa.application.autopilot import AutopilotEngine, ExperienceStore
from arenyxa.application.reliability import ResourceLeasePool
from arenyxa.application.competitive import (
    CompatibilityLab, ContextBridgeService, ReliabilityAdvisor,
    WebIntelligenceEngine, WorkflowPortabilityService,
)
from arenyxa.application.runtime_ecosystem import BrowserProfileService, RegressionLab, WorkflowMarketplaceService
from arenyxa.application.web_intelligence import WebIntelligenceCenter, WebTimeMachine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, NetworkEvent, RequestSpec, RetryPolicy, Workflow, WorkflowNode, new_id, utc_now
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited, read_text_limited
from arenyxa.platform_compat import select_runtime

LOGGER = logging.getLogger(__name__)

from arenyxa.application.nextgen_core import ActivityCenter, ActivityEvent

class RequestCodeGenerator:
    @staticmethod
    def _url(spec: RequestSpec) -> str:
                                                                                         
                                                                                            
        return HttpFetcher._build_url(spec)

    def generate(self, spec: RequestSpec, target: str) -> str:
        errors = spec.validate()
        if errors:
            raise ValueError("；".join(errors))
        target = target.casefold().strip()
        url = self._url(spec)
        headers = dict(spec.headers)
        folded = {key.casefold() for key in headers}
        if spec.user_agent and "user-agent" not in folded:
            headers["User-Agent"] = spec.user_agent
            folded.add("user-agent")
        if spec.content_type and "content-type" not in folded:
            headers["Content-Type"] = spec.content_type
        body = spec.body
        if target == "curl":
            parts = ["curl", "-X", spec.method.upper(), json.dumps(url)]
            for key, value in headers.items(): parts += ["-H", json.dumps(f"{key}: {value}")]
            for key, value in spec.cookies.items(): parts += ["-b", json.dumps(f"{key}={value}")]
            if body is not None: parts += ["--data-raw", json.dumps(body)]
            if spec.proxy: parts += ["--proxy", json.dumps(spec.proxy)]
            if not spec.verify_tls: parts.append("-k")
            return " ".join(parts)
        if target in {"python", "requests"}:
            return "\n".join([
                "import requests",
                f"url = {url!r}",
                f"headers = {headers!r}",
                f"cookies = {spec.cookies!r}",
                f"response = requests.request({spec.method.upper()!r}, url, headers=headers, cookies=cookies, data={body!r}, timeout=({spec.connect_timeout!r}, {spec.read_timeout!r}), verify={spec.verify_tls!r}, proxies={ {'http': spec.proxy, 'https': spec.proxy} if spec.proxy else None!r})",
                "print(response.status_code)",
                "print(response.text)", ""
            ])
        if target == "httpx":
            return "\n".join(["import httpx", f"with httpx.Client(verify={spec.verify_tls!r}, proxy={spec.proxy!r}, timeout={spec.read_timeout!r}) as client:", f"    response = client.request({spec.method.upper()!r}, {url!r}, headers={headers!r}, cookies={spec.cookies!r}, content={body!r})", "    print(response.status_code)", "    print(response.text)", ""])
        if target in {"fetch", "javascript", "js"}:
            options = {"method": spec.method.upper(), "headers": headers}
            if body is not None: options["body"] = body
            return f"const response = await fetch({json.dumps(url)}, {json.dumps(options, ensure_ascii=False, indent=2)});\nconsole.log(response.status, await response.text());\n"
        if target == "axios":
            payload = {"method": spec.method.lower(), "url": url, "headers": headers, "data": body}
            return f"import axios from 'axios';\nconst response = await axios({json.dumps(payload, ensure_ascii=False, indent=2)});\nconsole.log(response.status, response.data);\n"
        if target in {"powershell", "pwsh"}:
            header_expr = "@{" + "; ".join(f"{json.dumps(k)}={json.dumps(v)}" for k, v in headers.items()) + "}"
            body_arg = f" -Body {json.dumps(body)}" if body is not None else ""
            return f"$headers = {header_expr}\nInvoke-WebRequest -Uri {json.dumps(url)} -Method {spec.method.upper()} -Headers $headers{body_arg}\n"
        if target in {"playwright", "playwright-python"}:
            return "\n".join(["from playwright.sync_api import sync_playwright", "with sync_playwright() as p:", "    request = p.request.new_context()", f"    response = request.fetch({url!r}, method={spec.method.upper()!r}, headers={headers!r}, data={body!r})", "    print(response.status)", "    print(response.text())", ""])
        raise ValueError(f"未知代码目标：{target}")

@dataclass(slots=True)
class RequestAssertion:
    kind: str
    expected: Any = None
    name: str = ""

class HttpRequestWorkbench:
    def __init__(self, max_response_bytes: int = 32 * 1024 * 1024) -> None:
        self.fetcher = HttpFetcher(max_response_bytes)
        self.generator = RequestCodeGenerator()

    @staticmethod
    def from_payload(payload: Mapping[str, Any]) -> RequestSpec:
        allowed = set(RequestSpec.__dataclass_fields__)
        values = {key: value for key, value in dict(payload).items() if key in allowed}
        retry = values.get("retry")
        if isinstance(retry, Mapping):
            retry_allowed = set(RetryPolicy.__dataclass_fields__)
            unknown = set(retry) - retry_allowed
            if unknown:
                raise ValueError(f"未知 RetryPolicy 字段：{', '.join(sorted(map(str, unknown)))}")
            retry_values = dict(retry)
            if isinstance(retry_values.get("retry_statuses"), list):
                retry_values["retry_statuses"] = tuple(retry_values["retry_statuses"])
            try:
                values["retry"] = RetryPolicy(**retry_values)
            except (TypeError, ValueError) as exc:
                raise ValueError("RetryPolicy 配置无效。") from exc
        return RequestSpec(**values)

    @staticmethod
    def apply_variables(spec: RequestSpec, variables: Mapping[str, Any]) -> RequestSpec:
        pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}")
        def resolve(value: Any) -> Any:
            if not isinstance(value, str):
                return value
            def replace(match: re.Match[str]) -> str:
                key = match.group(1)
                if key not in variables:
                    raise KeyError(f"未找到 HTTP 变量：{key}")
                return str(variables[key])
            return pattern.sub(replace, value)
        payload = asdict(spec)
                                                                                              
                                                                                                 
        payload["retry"] = spec.retry
        for name in ("url", "body", "content_type", "proxy", "user_agent"):
            payload[name] = resolve(payload.get(name))
        for name in ("query", "headers", "cookies"):
            payload[name] = {str(resolve(key)): str(resolve(value)) for key, value in dict(payload.get(name) or {}).items()}
        return RequestSpec(**payload)

    @staticmethod
    def apply_actions(spec: RequestSpec, actions: Sequence[Mapping[str, Any]]) -> RequestSpec:
        





        payload = asdict(spec); payload["retry"] = spec.retry
        for raw in actions:
            action = str(raw.get("action", "")).casefold()
            name = str(raw.get("name", ""))
            value = str(raw.get("value", ""))
            if action == "set_header": payload["headers"][name] = value
            elif action == "remove_header": payload["headers"].pop(name, None)
            elif action == "set_query": payload["query"][name] = value
            elif action == "set_cookie": payload["cookies"][name] = value
            elif action == "set_body": payload["body"] = value
            elif action == "set_url": payload["url"] = value
            elif action == "set_user_agent": payload["user_agent"] = value
            else: raise ValueError(f"未知 pre-request action：{action}")
        return RequestSpec(**payload)

    def send(self, spec: RequestSpec) -> FetchResponse:
        return self.fetcher.fetch(spec)

    def send_with_assertions(self, spec: RequestSpec, assertions: Sequence[RequestAssertion | Mapping[str, Any]]) -> dict[str, Any]:
        response = self.send(spec)
        results: list[dict[str, Any]] = []
        text = response.body.decode(response.encoding or "utf-8", errors="replace")
        headers = {str(key).casefold(): str(value) for key, value in response.headers.items()}
        for raw in assertions:
            item = raw if isinstance(raw, RequestAssertion) else RequestAssertion(**dict(raw))
            kind = item.kind.casefold()
            passed = False; actual: Any = None
            if kind == "status_eq": actual = response.status; passed = response.status == int(item.expected)
            elif kind == "status_between":
                low, high = item.expected; actual = response.status; passed = int(low) <= response.status <= int(high)
            elif kind == "body_contains": actual = str(item.expected) in text; passed = bool(actual)
            elif kind == "header_exists": actual = str(item.expected).casefold() in headers; passed = bool(actual)
            elif kind == "header_equals":
                key = item.name.casefold(); actual = headers.get(key); passed = actual == str(item.expected)
            elif kind == "json_path_exists":
                try: value: Any = json.loads(text)
                except json.JSONDecodeError: value = None
                if value is not None:
                    try:
                        for part in str(item.expected).strip(".").split("."):
                            value = value[int(part)] if isinstance(value, list) else value[part]
                        actual = value; passed = True
                    except (KeyError, IndexError, TypeError, ValueError): passed = False
            else: raise ValueError(f"未知 assertion：{item.kind}")
            results.append({"kind": item.kind, "name": item.name, "expected": item.expected, "actual": actual, "passed": passed})
        return {"response": response, "assertions": results, "passed": all(item["passed"] for item in results)}

@dataclass(slots=True)
class DataSourceCandidate:
    kind: str
    location: str
    confidence: float
    estimated_records: int | None = None
    notes: list[str] = field(default_factory=list)

class ProtocolInspector:
    def graphql(self, events: Iterable[NetworkEvent]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for event in events:
            url = event.url or ""
            meta = event.metadata or {}
            resource = str(meta.get("resource_type", "")).casefold()
            if "graphql" not in url.casefold() and "graphql" not in resource and "graphql" not in str(meta).casefold():
                continue
            operation = meta.get("operationName") or meta.get("operation_name") or meta.get("graphql_operation")
            operation_type = meta.get("operationType") or meta.get("operation_type")
            variables = meta.get("variables") if isinstance(meta.get("variables"), dict) else {}
            result.append({"timestamp": event.timestamp, "method": event.method, "url": url, "status": event.status, "operation": operation, "operation_type": operation_type, "variables": variables})
        return result

    def websocket(self, events: Iterable[NetworkEvent]) -> list[dict[str, Any]]:
        result = []
        for event in events:
            proto = (event.protocol or "").casefold()
            meta = event.metadata or {}
            resource = str(meta.get("resource_type", "")).casefold()
            if proto not in {"ws", "wss", "websocket"} and "websocket" not in resource and not str(event.url or "").startswith(("ws://", "wss://")):
                continue
            result.append({"timestamp": event.timestamp, "url": event.url, "direction": event.direction, "size": event.size, "opcode": meta.get("opcode"), "frame_type": meta.get("frame_type"), "preview": str(meta.get("payload_preview", ""))[:500]})
        return result

    def sse(self, events: Iterable[NetworkEvent]) -> list[dict[str, Any]]:
        result = []
        for event in events:
            content_type = " ".join(f"{k}:{v}" for k, v in event.response_headers.items()).casefold()
            meta = event.metadata or {}
            if "text/event-stream" not in content_type and str(meta.get("resource_type", "")).casefold() not in {"eventsource", "sse"}:
                continue
            result.append({"timestamp": event.timestamp, "url": event.url, "status": event.status, "size": event.size, "last_event_id": meta.get("last_event_id"), "event": meta.get("event")})
        return result

class DataSourceDiscovery:
    def discover(self, response: FetchResponse | None, events: Sequence[NetworkEvent]) -> list[DataSourceCandidate]:
        candidates: list[DataSourceCandidate] = []
        if response is not None:
            ctype = response.content_type.casefold()
            if "json" in ctype:
                records = self._record_count_json(response.body, response.encoding)
                candidates.append(DataSourceCandidate("api-json", response.final_url, 0.99, records, ["响应本身为 JSON"]))
            if "html" in ctype:
                text = response.body.decode(response.encoding, errors="replace")
                if "__NEXT_DATA__" in text:
                    candidates.append(DataSourceCandidate("nextjs", "script#__NEXT_DATA__", 0.94, None, ["发现 Next.js hydration 数据"]))
                if "__NUXT__" in text or "__NUXT_DATA__" in text:
                    candidates.append(DataSourceCandidate("nuxt", "Nuxt hydration payload", 0.92, None, ["发现 Nuxt hydration 数据"]))
                jsonld = len(re.findall(r'application/ld\+json', text, re.I))
                if jsonld:
                    candidates.append(DataSourceCandidate("json-ld", "script[type=application/ld+json]", 0.82, jsonld, ["结构化数据"] ))
                embedded = len(re.findall(r'<script[^>]+type=["\']application/json["\']', text, re.I))
                if embedded:
                    candidates.append(DataSourceCandidate("embedded-json", "script[type=application/json]", 0.84, embedded, ["发现嵌入 JSON"] ))
                candidates.append(DataSourceCandidate("dom", response.final_url, 0.66, None, ["HTML DOM 可解析"] ))
        api_count: Counter[str] = Counter()
        for event in events:
            if not event.url:
                continue
            ctype = " ".join(event.response_headers.values()).casefold()
            if "json" in ctype or "/api/" in event.url or "graphql" in event.url.casefold():
                api_count[event.url] += 1
        for url, count in api_count.most_common(20):
            kind = "graphql" if "graphql" in url.casefold() else "xhr-json"
            candidates.append(DataSourceCandidate(kind, url, min(0.98, 0.78 + min(count, 10) * 0.02), None, [f"捕获到 {count} 次 API 请求"]))
        dedup: dict[tuple[str, str], DataSourceCandidate] = {}
        for item in candidates:
            key = (item.kind, item.location)
            previous = dedup.get(key)
            if previous is None or item.confidence > previous.confidence:
                dedup[key] = item
        return sorted(dedup.values(), key=lambda item: (-item.confidence, item.kind, item.location))

    @staticmethod
    def _record_count_json(payload: bytes, encoding: str) -> int | None:
        try:
            value = json.loads(payload.decode(encoding, errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            for candidate in ("data", "items", "results", "records", "rows"):
                nested = value.get(candidate)
                if isinstance(nested, list):
                    return len(nested)
        return None

@dataclass(slots=True)
class SmartPathV2Result:
    recommended_engine: str
    confidence: float
    ranking: list[dict[str, Any]]
    reasons: list[str]
    data_sources: list[dict[str, Any]]
    optimization: dict[str, str]
    execution_path: list[dict[str, Any]] = field(default_factory=list)

class SmartPathV2:
    def __init__(self) -> None:
        self.discovery = DataSourceDiscovery()
        self.legacy = SmartExecutionPlanner()

    def analyze(self, response: FetchResponse | None, events: Sequence[NetworkEvent], history_success: Mapping[str, float] | None = None) -> SmartPathV2Result:
        base = self.legacy.plan(response, list(events), dict(history_success or {}))
        sources = self.discovery.discover(response, events)
        scores = {"http": 1.0, "api": 0.0, "browser": 0.0, "distributed": 0.0}
        reasons = list(base.reasons)
        for source in sources:
            if source.kind in {"api-json", "xhr-json", "graphql", "nextjs", "nuxt", "embedded-json"}:
                scores["api"] += source.confidence * 3.0
            if source.kind == "dom":
                scores["http"] += source.confidence
        if response and "html" in response.content_type.casefold():
            text = response.body.decode(response.encoding, errors="ignore")
            dynamic = len(re.findall(r"<script\b", text, re.I)) + 4 * len(re.findall(r"react|vue|angular|webpack|vite", text, re.I))
            if dynamic > 20 and not any(item.kind in {"xhr-json", "api-json", "graphql"} for item in sources):
                scores["browser"] += 4.0
                reasons.append("动态脚本较多且未发现可直接复用的数据 API。")
        if len(events) > 20_000:
            scores["distributed"] += 3.0
        for engine, success in (history_success or {}).items():
            if engine in scores:
                scores[engine] += max(0.0, min(1.0, float(success))) * 2.0
        engine, top = max(scores.items(), key=lambda item: item[1])
        total = sum(max(0.0, item) for item in scores.values()) or 1.0
        ranking = [{"engine": key, "score": round(value, 3)} for key, value in sorted(scores.items(), key=lambda item: item[1], reverse=True)]
        optimization = {
            "http": "最低资源占用；适合静态 HTML 与直接资源。",
            "api": "优先绕过渲染层；通常具有最高吞吐和最低 RAM。",
            "browser": "适合必须执行 JavaScript、登录或交互的页面。",
            "distributed": "适合超大任务与多 Worker 协作。",
        }
        structured = [item for item in sources if item.kind in {"api-json", "xhr-json", "graphql", "nextjs", "nuxt", "embedded-json"}]
        has_html = bool(response and "html" in response.content_type.casefold())
        execution_path = [
            {
                "stage": "static-html",
                "available": has_html,
                "decision": "inspect-first" if has_html else "skip",
                "evidence": "direct HTML response available" if has_html else "no direct HTML response",
            },
            {
                "stage": "structured-endpoint",
                "available": bool(structured),
                "decision": "prefer" if engine == "api" and structured else ("candidate" if structured else "skip"),
                "evidence": f"{len(structured)} structured source candidate(s)",
            },
            {
                "stage": "browser-discovery-fallback",
                "available": True,
                "decision": "execute" if engine == "browser" else "fallback",
                "evidence": "browser is used only when direct/structured paths are insufficient or interaction is required",
            },
        ]
        return SmartPathV2Result(
            engine,
            round(top / total, 3),
            ranking,
            reasons,
            [asdict(item) for item in sources[:30]],
            {"selected": optimization[engine], **optimization},
            execution_path,
        )

@dataclass(slots=True)
class RateDecision:
    concurrency: int
    delay_seconds: float
    mode: str
    reason: str

class AdaptiveRateLimiter:
    def __init__(self, minimum: int = 1, maximum: int = 32, initial: int = 8) -> None:
        self.minimum = max(1, int(minimum))
        self.maximum = max(self.minimum, int(maximum))
        self.concurrency = max(self.minimum, min(self.maximum, int(initial)))
        self.delay_seconds = 0.0
        self._stable = 0
        self._baseline_latency: float | None = None

    def observe(self, status: int | None, latency_ms: float | None, retry_after: float | None = None) -> RateDecision:
        latency = max(0.0, float(latency_ms or 0.0))
        if self._baseline_latency is None and latency:
            self._baseline_latency = latency
        elif latency and self._baseline_latency:
            self._baseline_latency = self._baseline_latency * 0.92 + latency * 0.08
        throttled = status in {429, 503}
        latency_pressure = bool(latency and self._baseline_latency and latency > self._baseline_latency * 2.5 and latency > 750)
        if throttled or latency_pressure:
            self.concurrency = max(self.minimum, math.ceil(self.concurrency * 0.55))
            suggested = max(0.25, min(60.0, float(retry_after or 0.0))) if throttled else 0.25
            self.delay_seconds = max(self.delay_seconds * 1.6, suggested)
            self._stable = 0
            reason = f"HTTP {status} 触发自适应退避" if throttled else "响应延迟显著上升，主动降载"
            return RateDecision(self.concurrency, round(self.delay_seconds, 3), "backoff", reason)
        if status is None or 200 <= status < 400:
            self._stable += 1
            self.delay_seconds *= 0.9
            if self._stable >= 20 and self.concurrency < self.maximum:
                self.concurrency += 1
                self._stable = 0
                return RateDecision(self.concurrency, round(self.delay_seconds, 3), "recover", "稳定窗口达标，渐进恢复并发")
        return RateDecision(self.concurrency, round(self.delay_seconds, 3), "steady", "维持当前速率")

class SchemaInference:
    @staticmethod
    def infer_value(value: Any) -> str:
        if value is None: return "null"
        if isinstance(value, bool): return "boolean"
        if isinstance(value, int) and not isinstance(value, bool): return "integer"
        if isinstance(value, float): return "number"
        if isinstance(value, list): return "array"
        if isinstance(value, dict): return "object"
        text = str(value).strip()
        if not text: return "string"
        if re.fullmatch(r"https?://\S+", text, re.I): return "url"
        if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", text): return "email"
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", text, re.I): return "uuid"
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", text): return "ip"
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ][0-9:.+-Z]+)?", text): return "date"
        if re.fullmatch(r"[$€£¥￥]\s?[-+]?\d[\d,.]*", text): return "currency"
        return "string"

    def infer(self, records: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
        fields = sorted({str(key) for record in records for key in record})
        result: dict[str, dict[str, Any]] = {}
        total = len(records)
        for field_name in fields:
            types = Counter(self.infer_value(record.get(field_name)) for record in records if field_name in record)
            non_null = sum(count for kind, count in types.items() if kind != "null")
            primary = types.most_common(1)[0][0] if types else "unknown"
            result[field_name] = {"type": primary, "observed_types": dict(types), "presence": round(sum(field_name in record for record in records) / total, 4) if total else 0.0, "non_null": non_null}
        return result

class DataQualityStudio:
    def __init__(self) -> None:
        self.schema = SchemaInference()

    def analyze(self, records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        normalized = [dict(record) for record in records]
        total = len(normalized)
        schema = self.schema.infer(normalized)
        canonical = [json.dumps(record, ensure_ascii=False, sort_keys=True, default=str) for record in normalized]
        duplicates = total - len(set(canonical))
        fields: dict[str, Any] = {}
        outlier_total = 0
        for name, info in schema.items():
            missing = sum(1 for record in normalized if name not in record or record.get(name) in {None, ""})
            values = [record.get(name) for record in normalized if isinstance(record.get(name), (int, float)) and not isinstance(record.get(name), bool)]
            outliers: list[float] = []
            if len(values) >= 4:
                sorted_values = sorted(float(value) for value in values)
                q1, _, q3 = statistics.quantiles(sorted_values, n=4, method="inclusive")
                iqr = q3 - q1
                lower, upper = q1 - 1.5 * iqr, q3 + 1.5 * iqr
                outliers = [value for value in sorted_values if value < lower or value > upper]
            outlier_total += len(outliers)
            fields[name] = {**info, "missing": missing, "missing_rate": round(missing / total, 4) if total else 0.0, "outliers": len(outliers)}
        score = 100.0
        if total:
            score -= min(35.0, duplicates / total * 35)
            score -= min(45.0, sum(item["missing_rate"] for item in fields.values()) * 8)
            score -= min(20.0, outlier_total / total * 10)
        return {"records": total, "duplicates": duplicates, "duplicate_rate": round(duplicates / total, 4) if total else 0.0, "outliers": outlier_total, "quality_score": round(max(0.0, score), 1), "schema": fields}

    def compare_schema(self, old: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
        old_keys, new_keys = set(old), set(new)
        changed = {}
        for key in old_keys & new_keys:
            old_type = old[key].get("type") if isinstance(old[key], Mapping) else old[key]
            new_type = new[key].get("type") if isinstance(new[key], Mapping) else new[key]
            if old_type != new_type:
                changed[key] = {"old": old_type, "new": new_type}
        return {"added": sorted(new_keys - old_keys), "removed": sorted(old_keys - new_keys), "changed": changed}


    def clean(
        self,
        records: Sequence[Mapping[str, Any]],
        *,
        deduplicate: bool = True,
        defaults: Mapping[str, Any] | None = None,
        type_coercions: Mapping[str, str] | None = None,
        trim_strings: bool = True,
    ) -> dict[str, Any]:
        
        defaults = dict(defaults or {})
        coercions = {str(k): str(v).casefold() for k, v in dict(type_coercions or {}).items()}
        output: list[dict[str, Any]] = []
        seen: set[str] = set()
        changes = Counter()
        for raw in records:
            row = dict(raw)
            for key, value in list(row.items()):
                if trim_strings and isinstance(value, str):
                    trimmed = value.strip()
                    if trimmed != value:
                        row[key] = trimmed; changes["trimmed"] += 1
            for key, default in defaults.items():
                if key not in row or row.get(key) in {None, ""}:
                    row[key] = default; changes["defaults"] += 1
            for key, target in coercions.items():
                if key not in row or row[key] in {None, ""}:
                    continue
                value = row[key]
                try:
                    if target in {"int", "integer"}: converted = int(value)
                    elif target in {"float", "number"}: converted = float(value)
                    elif target in {"str", "string"}: converted = str(value)
                    elif target in {"bool", "boolean"}:
                        if isinstance(value, bool): converted = value
                        elif str(value).strip().casefold() in {"1","true","yes","y","on"}: converted = True
                        elif str(value).strip().casefold() in {"0","false","no","n","off"}: converted = False
                        else: raise ValueError("invalid boolean")
                    else: raise ValueError(f"unsupported coercion: {target}")
                except (TypeError, ValueError, OverflowError):
                    changes["coercion_failures"] += 1
                else:
                    if converted != value: changes["coerced"] += 1
                    row[key] = converted
            if deduplicate:
                signature = json.dumps(row, ensure_ascii=False, sort_keys=True, default=str)
                if signature in seen:
                    changes["duplicates_removed"] += 1
                    continue
                seen.add(signature)
            output.append(row)
        return {"records": output, "input_count": len(records), "output_count": len(output), "changes": dict(changes), "quality": self.analyze(output)}

