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
from arenyxa.application.workflow_contract import validate_workflow_contract
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited, read_text_limited
from arenyxa.platform_compat import select_runtime

LOGGER = logging.getLogger(__name__)

from arenyxa.application.nextgen_core import ActivityCenter, ActivityEvent

_STABLE_ATTRS = ("data-testid", "data-test", "data-qa", "aria-label", "name", "role", "itemprop")

_UNSTABLE_CLASS = re.compile(r"(?:^|[-_])(?:css|sc|jsx|chakra|mui|ant|hash)[-_]?[0-9a-z]{5,}|[0-9a-f]{8,}$", re.I)

@dataclass(slots=True)
class SelectorFingerprint:
    tag: str
    element_id: str = ""
    text: str = ""
    attrs: dict[str, str] = field(default_factory=dict)
    classes: list[str] = field(default_factory=list)
    parent_tag: str = ""
    sibling_index: int = 0
    ancestor_tags: list[str] = field(default_factory=list)
    structure_hash: str = ""

@dataclass(slots=True)
class SelectorCandidate:
    selector_type: str
    selector: str
    score: float
    reasons: list[str]
    match_count: int

@dataclass(slots=True)
class HealCandidate:
    selector: str
    selector_type: str
    confidence: float
    evidence: list[str]
    match_count: int = 0
    uniqueness_risk: str = "unknown"
    auto_apply_eligible: bool = False

class SelectorStudio:
    @staticmethod
    def _document(markup: str) -> html.HtmlElement:
        if not isinstance(markup, str) or not markup.strip():
            raise ValueError("HTML 不能为空。")
        try:
            return html.fromstring(markup)
        except (etree.ParserError, ValueError) as exc:
            raise ValueError(f"HTML 无法解析：{exc}") from exc

    @staticmethod
    def _select(document: html.HtmlElement, selector: str, selector_type: str) -> list[html.HtmlElement]:
        if selector_type == "xpath":
            result = document.xpath(selector)
        else:
            try:
                result = document.cssselect(selector)
            except ImportError:
                                                                                            
                                                                                             
                result = SelectorStudio._simple_css_select(document, selector)
        return [item for item in result if isinstance(item, html.HtmlElement)]

    @staticmethod
    def _simple_css_select(document: html.HtmlElement, selector: str) -> list[html.HtmlElement]:
        





        selector = selector.strip()
        if " > " in selector:
            parent_sel, child_sel = selector.split(" > ", 1)
            parents = SelectorStudio._simple_css_select(document, parent_sel)
            children: list[html.HtmlElement] = []
            nth = re.search(r":nth-of-type\((\d+)\)$", child_sel)
            if nth:
                wanted = int(nth.group(1)); child_sel = child_sel[: nth.start()]
            else:
                wanted = None
            for parent in parents:
                matches = [child for child in parent if isinstance(getattr(child, "tag", None), str) and SelectorStudio._simple_css_match(child, child_sel)]
                if wanted is None:
                    children.extend(matches)
                elif 0 < wanted <= len(matches):
                    children.append(matches[wanted - 1])
            return children
        return [node for node in document.iter() if isinstance(getattr(node, "tag", None), str) and SelectorStudio._simple_css_match(node, selector)]

    @staticmethod
    def _simple_css_match(node: html.HtmlElement, selector: str) -> bool:
        selector = selector.strip()
        element_id = None
        id_match = re.search(r"#([A-Za-z0-9_.:-]+)", selector)
        if id_match:
            element_id = id_match.group(1).replace("\\", "")
            selector = selector[: id_match.start()] + selector[id_match.end():]
        attrs = re.findall(r"\[([A-Za-z_:][-A-Za-z0-9_:.]*)(?:=[\"']([^\"']*)[\"'])?\]", selector)
        selector = re.sub(r"\[[^]]+\]", "", selector)
        classes = [item.replace("\\", "") for item in re.findall(r"\.([A-Za-z0-9_-]+)", selector)]
        tag = re.split(r"[.#:]", selector, maxsplit=1)[0].strip() or "*"
        if tag != "*" and str(node.tag).casefold() != tag.casefold():
            return False
        if element_id is not None and node.get("id") != element_id:
            return False
        node_classes = set(node.get("class", "").split())
        if any(item not in node_classes for item in classes):
            return False
        for key, value in attrs:
            if key not in node.attrib:
                return False
            if value and node.get(key) != value:
                return False
        return True

    def analyze(self, markup: str, selector: str, selector_type: str = "css") -> dict[str, Any]:
        document = self._document(markup)
        matches = self._select(document, selector, selector_type)
        if not matches:
            return {"matches": 0, "fingerprint": None, "candidates": []}
        node = matches[0]
        fingerprint = self.fingerprint(node)
        candidates = self.candidates(document, node)
        return {
            "matches": len(matches),
            "fingerprint": asdict(fingerprint),
            "candidates": [asdict(item) for item in candidates],
        }

    def fingerprint(self, node: html.HtmlElement) -> SelectorFingerprint:
        parent = node.getparent()
        siblings = [child for child in parent] if parent is not None else []
        try:
            sibling_index = siblings.index(node)
        except ValueError:
            sibling_index = 0
        attrs = {key: value[:160] for key, value in node.attrib.items() if key in _STABLE_ATTRS and value}
        
        # Improvement: enforce a length limit to reduce regex ReDoS risk.
        classes = []
        for value in node.get("class", "").split():
            if not value or len(value) > 256:
                continue
            if not _UNSTABLE_CLASS.search(value):
                classes.append(value)
                
        text = " ".join(node.text_content().split())[:240]
        ancestor_tags: list[str] = []
        cursor = parent
        while cursor is not None and len(ancestor_tags) < 5:
            if isinstance(getattr(cursor, "tag", None), str):
                ancestor_tags.append(str(cursor.tag).lower())
            cursor = cursor.getparent()
        structure_payload = {
            "tag": str(node.tag).lower(),
            "parent": str(parent.tag).lower() if parent is not None and isinstance(parent.tag, str) else "",
            "ancestors": ancestor_tags,
            "attrs": attrs,
            "classes": classes[:8],
            "sibling_index": sibling_index,
        }
        structure_hash = hashlib.sha256(
            json.dumps(structure_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return SelectorFingerprint(
            tag=str(node.tag).lower(),
            element_id=node.get("id", "")[:160],
            text=text,
            attrs=attrs,
            classes=classes[:8],
            parent_tag=str(parent.tag).lower() if parent is not None and isinstance(parent.tag, str) else "",
            sibling_index=sibling_index,
            ancestor_tags=ancestor_tags,
            structure_hash=structure_hash,
        )

    def candidates(self, document: html.HtmlElement, node: html.HtmlElement) -> list[SelectorCandidate]:
        raw: list[tuple[str, str, float, list[str]]] = []
        tag = str(node.tag).lower()
        element_id = node.get("id", "")
        if element_id and not re.search(r"\d{5,}|[0-9a-f]{12,}", element_id, re.I):
            raw.append(("css", f"#{self._css_escape(element_id)}", 0.99, ["稳定 ID", "唯一性优先"]))
        for attr in _STABLE_ATTRS:
            value = node.get(attr)
            if value:
                raw.append(("css", f'{tag}[{attr}="{self._css_string(value)}"]', 0.95, [f"稳定属性 {attr}"]))
        
        # Improvement: enforce a length limit to reduce regex ReDoS risk.
        classes = []
        for value in node.get("class", "").split():
            if not value or len(value) > 256:
                continue
            if not _UNSTABLE_CLASS.search(value):
                classes.append(value)
                
        if classes:
            selector = tag + "".join(f".{self._css_escape(value)}" for value in classes[:3])
            raw.append(("css", selector, 0.78, ["语义 class", "已过滤疑似 hash class"]))
        normalized_text = " ".join(node.text_content().split())
        if normalized_text and len(normalized_text) <= 80:
            xpath_text = normalized_text.replace("'", "&apos;")
            raw.append(("xpath", f"//{tag}[normalize-space(.)='{xpath_text}']", 0.82, ["可读文本定位"]))
        raw.append(("xpath", document.getroottree().getpath(node), 0.48, ["绝对 XPath 仅作回退"]))

                                       
        parent = node.getparent()
        if parent is not None and isinstance(parent.tag, str):
            same = [child for child in parent if getattr(child, "tag", None) == node.tag]
            if len(same) > 1:
                raw.append(("css", f"{str(parent.tag).lower()} > {tag}:nth-of-type({same.index(node)+1})", 0.52, ["结构回退", "页面重排时可能失效"]))

        output: list[SelectorCandidate] = []
        seen: set[tuple[str, str]] = set()
        for selector_type, selector, base, reasons in raw:
            key = (selector_type, selector)
            if key in seen:
                continue
            seen.add(key)
            try:
                count = len(self._select(document, selector, selector_type))
            except Exception:
                continue
            score = base
            if count == 1:
                score += 0.03
                reasons = [*reasons, "当前页面唯一"]
            elif count > 1:
                score -= min(0.35, 0.05 * (count - 1))
                reasons = [*reasons, f"当前匹配 {count} 个元素"]
            output.append(SelectorCandidate(selector_type, selector, round(max(0.0, min(1.0, score)), 3), reasons, count))
        return sorted(output, key=lambda item: (-item.score, item.match_count, item.selector))

    def heal(
        self,
        markup: str,
        fingerprint: SelectorFingerprint | Mapping[str, Any],
        limit: int = 5,
        history: Sequence[Mapping[str, Any]] | None = None,
    ) -> list[HealCandidate]:
        document = self._document(markup)
        fp = fingerprint if isinstance(fingerprint, SelectorFingerprint) else SelectorFingerprint(**dict(fingerprint))
        scored: list[tuple[float, html.HtmlElement, list[str]]] = []
        for node in document.iter():
            if not isinstance(node.tag, str):
                continue
            score = 0.0
            evidence: list[str] = []
            if node.tag.lower() == fp.tag:
                score += 0.22
                evidence.append("tag 相同")
            if fp.element_id and node.get("id") == fp.element_id:
                score += 0.36
                evidence.append("ID 相同")
            for key, value in fp.attrs.items():
                if node.get(key) == value:
                    score += 0.18
                    evidence.append(f"{key} 相同")
            classes = set(node.get("class", "").split())
            overlap = len(classes.intersection(fp.classes))
            if fp.classes:
                score += min(0.16, 0.16 * overlap / len(fp.classes))
                if overlap:
                    evidence.append(f"{overlap} 个 class 相同")
            current_text = " ".join(node.text_content().split())[:240]
            if fp.text and current_text:
                if fp.text.casefold() == current_text.casefold():
                    # Exact normalized element text is a strong semantic identity
                    # signal even when site redesigns remove IDs/classes/attributes.
                    score += 0.34
                    evidence.append("文本完全相同")
                else:
                    similarity = self._text_similarity(fp.text, current_text)
                    score += 0.20 * similarity
                    if similarity >= 0.7:
                        evidence.append("文本高度相似")
            parent = node.getparent()
            if fp.parent_tag and parent is not None and str(parent.tag).lower() == fp.parent_tag:
                score += 0.06
                evidence.append("父元素类型相同")
            if fp.ancestor_tags:
                current_ancestors: list[str] = []
                cursor = parent
                while cursor is not None and len(current_ancestors) < len(fp.ancestor_tags):
                    if isinstance(getattr(cursor, "tag", None), str):
                        current_ancestors.append(str(cursor.tag).lower())
                    cursor = cursor.getparent()
                common = sum(1 for left, right in zip(fp.ancestor_tags, current_ancestors) if left == right)
                if common:
                    score += min(0.10, 0.10 * common / max(1, len(fp.ancestor_tags)))
                    evidence.append(f"祖先结构 {common}/{len(fp.ancestor_tags)} 匹配")
            if score >= 0.35:
                scored.append((score, node, evidence))
        scored.sort(key=lambda item: item[0], reverse=True)
        result: list[HealCandidate] = []
        history_rows = [dict(item) for item in (history or ()) if isinstance(item, Mapping)]
        for score, node, evidence in scored[: max(1, min(20, limit))]:
            candidates = self.candidates(document, node)
            if not candidates:
                continue
            top = candidates[0]
            history_bonus, history_evidence = self._selector_history_evidence(top.selector, history_rows)
            confidence = min(1.0, score + top.score * 0.25 + history_bonus)
            risk = "low" if top.match_count == 1 else ("medium" if top.match_count == 2 else "high")
            eligible = top.match_count == 1 and confidence >= 0.92 and risk == "low"
            result.append(HealCandidate(
                top.selector,
                top.selector_type,
                round(confidence, 3),
                evidence + top.reasons + history_evidence,
                match_count=top.match_count,
                uniqueness_risk=risk,
                auto_apply_eligible=eligible,
            ))
        return result

    @staticmethod
    def _selector_history_evidence(selector: str, history: Sequence[Mapping[str, Any]]) -> tuple[float, list[str]]:
        relevant = [item for item in history if str(item.get("selector", "")) == selector]
        if not relevant:
            return 0.0, []
        successes = sum(1 for item in relevant if bool(item.get("success")))
        ratio = successes / len(relevant)
        bonus = min(0.08, 0.08 * ratio * min(1.0, len(relevant) / 3.0))
        return bonus, [f"历史证据 {successes}/{len(relevant)} 次成功"]

    def heal_with_policy(
        self,
        markup: str,
        fingerprint: SelectorFingerprint | Mapping[str, Any],
        *,
        history: Sequence[Mapping[str, Any]] | None = None,
        auto_apply: bool = False,
        min_confidence: float = 0.92,
        limit: int = 5,
    ) -> dict[str, Any]:
        candidates = self.heal(markup, fingerprint, limit=limit, history=history)
        threshold = max(0.50, min(0.999, float(min_confidence)))
        selected = None
        if auto_apply:
            for item in candidates:
                if item.auto_apply_eligible and item.confidence >= threshold and item.match_count == 1:
                    selected = asdict(item)
                    break
        return {
            "mode": "auto-apply" if auto_apply else "review-only",
            "selected": selected,
            "candidates": [asdict(item) for item in candidates],
            "decision": (
                "auto-apply selected a unique high-confidence candidate"
                if selected is not None
                else "review required; no selector was automatically applied"
            ),
        }

    @staticmethod
    def _text_similarity(left: str, right: str) -> float:
        left_tokens = set(re.findall(r"[\w\u4e00-\u9fff]+", left.casefold()))
        right_tokens = set(re.findall(r"[\w\u4e00-\u9fff]+", right.casefold()))
        if not left_tokens or not right_tokens:
            return 0.0
        return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)

    @staticmethod
    def _css_escape(value: str) -> str:
        return re.sub(r"([^a-zA-Z0-9_-])", lambda match: "\\" + match.group(1), value)

    @staticmethod
    def _css_string(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

@dataclass(slots=True)
class BrowserAction:
    kind: str
    selector: str = ""
    value: str = ""
    url: str = ""
    timeout_ms: int = 30_000
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class SemanticStage:
    kind: str
    action_indexes: list[int]
    confidence: float
    evidence: list[str] = field(default_factory=list)

class BrowserRecorderService:
    SUPPORTED = {"goto", "click", "fill", "press", "check", "uncheck", "select", "wait", "scroll", "download", "upload", "assert_text"}

    def __init__(self, browser_pool: ResourceLeasePool | None = None) -> None:
        self.browser_pool = browser_pool

    def _acquire_browser(self) -> Any:
        if self.browser_pool is None:
            return None
        return self.browser_pool.acquire(
            code="BROWSER_RESOURCE_LIMIT",
            message="浏览器实例已达到 Resource Governor 当前上限，请等待现有实例结束。",
        )

    def normalize(self, actions: Sequence[BrowserAction | Mapping[str, Any]]) -> list[BrowserAction]:
        result: list[BrowserAction] = []
        for raw in actions:
            action = raw if isinstance(raw, BrowserAction) else BrowserAction(**dict(raw))
            if action.kind not in self.SUPPORTED:
                raise ValueError(f"不支持的录制动作：{action.kind}")
            action.timeout_ms = max(100, min(300_000, int(action.timeout_ms)))
            result.append(action)
        return result

    def to_workflow(self, actions: Sequence[BrowserAction | Mapping[str, Any]], name: str = "Recorded Browser Workflow") -> Workflow:
        normalized = self.normalize(actions)
        nodes: list[WorkflowNode] = []
        for index, action in enumerate(normalized):
            node_id = f"browser_{index+1}"
            next_ids = [f"browser_{index+2}"] if index + 1 < len(normalized) else []
            nodes.append(WorkflowNode(kind="browser_action", config=asdict(action), id=node_id, next_ids=next_ids))
        workflow = Workflow(name=name, nodes=nodes)
        validate_workflow_contract(workflow)
        return workflow

    @staticmethod
    def _semantic_kind(action: BrowserAction) -> tuple[str, float, list[str]]:
        meta_text = " ".join(f"{key}={value}" for key, value in action.metadata.items())
        text = " ".join([action.kind, action.selector, action.value, action.url, meta_text]).casefold()
        if action.kind == "download" or any(term in text for term in ("download", "export", "save-file")):
            return "download", 0.98, ["download/export action"]
        if any(term in text for term in ("pagination", "next-page", "page-next", "load-more", "load more", "rel=next", "page=")):
            return "pagination", 0.90, ["pagination marker"]
        if action.kind == "goto" and re.search(r"[?&](?:page|offset|cursor)=", action.url, re.I):
            return "pagination", 0.92, ["pagination parameter in URL"]
        if any(term in text for term in ("search", "query", "site-search", "aria-label=search")):
            return "search", 0.92, ["search/query control"]
        if any(term in text for term in ("login", "log-in", "signin", "sign-in", "username", "user-name", "email", "password", "credential")):
            return "login", 0.88, ["authentication control"]
        if action.kind == "assert_text" or any(term in text for term in ("extract", "scrape", "result-list", "data-row", "record")):
            return "extraction", 0.82, ["data/result marker"]
        return "interaction", 0.60, ["generic browser interaction"]

    def compile_semantics(self, actions: Sequence[BrowserAction | Mapping[str, Any]]) -> list[SemanticStage]:
        normalized = self.normalize(actions)
        classified: list[tuple[str, float, list[str]]] = [self._semantic_kind(action) for action in normalized]
                                                                                               
        for index in range(1, len(classified)):
            kind, confidence, evidence = classified[index]
            previous = classified[index - 1]
            action = normalized[index]
            if kind == "interaction" and action.kind in {"click", "press"} and previous[0] in {"login", "search"}:
                classified[index] = (previous[0], min(0.95, previous[1] - 0.03), [f"follows {previous[0]} input"])
        stages: list[SemanticStage] = []
        for index, (kind, confidence, evidence) in enumerate(classified):
            if stages and stages[-1].kind == kind:
                stages[-1].action_indexes.append(index)
                stages[-1].confidence = round((stages[-1].confidence + confidence) / 2.0, 3)
                stages[-1].evidence.extend(item for item in evidence if item not in stages[-1].evidence)
            else:
                stages.append(SemanticStage(kind, [index], round(confidence, 3), list(evidence)))
        return stages

    def to_semantic_workflow(
        self, actions: Sequence[BrowserAction | Mapping[str, Any]], name: str = "Recorded Semantic Browser Workflow"
    ) -> Workflow:
        normalized = self.normalize(actions)
        workflow = self.to_workflow(normalized, name=name)
        stages = self.compile_semantics(normalized)
        by_index: dict[int, SemanticStage] = {}
        for stage in stages:
            for index in stage.action_indexes:
                by_index[index] = stage
        for index, node in enumerate(workflow.nodes):
            stage = by_index.get(index)
            if stage is not None:
                node.config["semantic_stage"] = {
                    "kind": stage.kind,
                    "confidence": stage.confidence,
                    "evidence": list(stage.evidence),
                }
        return workflow

    def execute_playwright(self, actions: Sequence[BrowserAction | Mapping[str, Any]], *, headless: bool = True) -> list[dict[str, Any]]:
        if not select_runtime().browser_automation:
            raise RuntimeError("Windows 7 Legacy Enterprise 不执行内置 Playwright/Chromium；请使用 HTTP/Capture 核心或在现代运行时执行浏览器自动化。")
        normalized = self.normalize(actions)
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Browser Recorder 执行需要安装可选依赖：pip install -e .[browser] && playwright install chromium") from exc
        events: list[dict[str, Any]] = []
        lease = self._acquire_browser()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=headless)
                context = browser.new_context(accept_downloads=True)
                page = context.new_page()
                try:
                    for index, action in enumerate(normalized, start=1):
                        started = time.perf_counter()
                        if action.kind == "goto": page.goto(action.url or action.value, timeout=action.timeout_ms)
                        elif action.kind == "click": page.locator(action.selector).click(timeout=action.timeout_ms)
                        elif action.kind == "fill": page.locator(action.selector).fill(action.value, timeout=action.timeout_ms)
                        elif action.kind == "press": page.locator(action.selector).press(action.value, timeout=action.timeout_ms)
                        elif action.kind == "check": page.locator(action.selector).check(timeout=action.timeout_ms)
                        elif action.kind == "uncheck": page.locator(action.selector).uncheck(timeout=action.timeout_ms)
                        elif action.kind == "select": page.locator(action.selector).select_option(action.value)
                        elif action.kind == "wait": page.wait_for_timeout(max(0, int(action.value or 0)))
                        elif action.kind == "scroll": page.locator(action.selector or "body").evaluate("el => el.scrollIntoView()")
                        elif action.kind == "upload": page.locator(action.selector).set_input_files(action.value)
                        elif action.kind == "download":
                            with page.expect_download(timeout=action.timeout_ms) as download_info:
                                page.locator(action.selector).click(timeout=action.timeout_ms)
                            events.append({"index": index, "kind": action.kind, "suggested_filename": download_info.value.suggested_filename})
                            continue
                        elif action.kind == "assert_text":
                            if action.value not in page.locator(action.selector).inner_text(timeout=action.timeout_ms):
                                raise AssertionError(f"assert_text failed: {action.value!r}")
                        events.append({"index": index, "kind": action.kind, "elapsed_ms": round((time.perf_counter()-started)*1000, 2), "url": page.url})
                finally:
                    context.close()
                    browser.close()
        finally:
            if lease is not None:
                lease.release()
        return events

    def record_live(self, start_url: str, *, duration_seconds: int = 30, headless: bool = False) -> list[BrowserAction]:
        




        if not select_runtime().browser_automation:
            raise RuntimeError("Windows 7 Legacy Enterprise 不执行内置 Playwright/Chromium；录制功能需 Windows 10 1809+ 现代运行时。")
        parsed = urlparse(start_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("Recorder URL 必须是有效的 http/https 地址。")
        seconds = max(5, min(900, int(duration_seconds)))
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise RuntimeError("Browser Recorder 需要可选依赖：pip install -e .[browser] && playwright install chromium") from exc

        recorded: list[BrowserAction] = [BrowserAction("goto", url=start_url)]
        lock = threading.Lock()
        last_signature: tuple[str, str, str] | None = None

        def receive(_source: Any, payload: Any) -> None:
            nonlocal last_signature
            if not isinstance(payload, dict):
                return
            kind = str(payload.get("kind", ""))
            if kind not in {"click", "fill", "press", "check", "uncheck", "select", "scroll"}:
                return
            selector = str(payload.get("selector", ""))[:2000]
            value = str(payload.get("value", ""))[:20_000]
            if not selector and kind not in {"scroll"}:
                return
            signature = (kind, selector, value)
            with lock:
                if signature == last_signature:
                    return
                last_signature = signature
                recorded.append(BrowserAction(kind=kind, selector=selector, value=value, metadata={"recorded_live": True}))

        recorder_script = r"""
        (() => {
          const esc = (v) => (window.CSS && CSS.escape ? CSS.escape(String(v)) : String(v).replace(/[^a-zA-Z0-9_-]/g, '\\$&'));
          const locator = (el) => {
            if (!el || !el.tagName) return '';
            const tag = el.tagName.toLowerCase();
            const stable = ['data-testid','data-test','data-qa','aria-label','name'];
            if (el.id && !/[0-9a-f]{12,}|\d{5,}/i.test(el.id)) return '#' + esc(el.id);
            for (const key of stable) {
              const value = el.getAttribute(key);
              if (value) return `${tag}[${key}=${JSON.stringify(value)}]`;
            }
            const classes = [...el.classList].filter(v => v.length < 64 && !/[0-9a-f]{8,}|^(css|sc|jsx|chakra|mui|ant)[-_]/i.test(v)).slice(0, 2);
            if (classes.length) return tag + classes.map(v => '.' + esc(v)).join('');
            let index = 1; let sib = el;
            while ((sib = sib.previousElementSibling)) if (sib.tagName === el.tagName) index++;
            return `${tag}:nth-of-type(${index})`;
          };
          const emit = (payload) => { try { window.arenyxaRecord(payload); } catch (_) {} };
          document.addEventListener('click', e => emit({kind:'click', selector:locator(e.target)}), true);
          document.addEventListener('input', e => {
            const el = e.target;
            if (!el || !('value' in el) || String(el.type || '').toLowerCase() === 'password') return;
            emit({kind:'fill', selector:locator(el), value:String(el.value || '')});
          }, true);
          document.addEventListener('change', e => {
            const el = e.target; if (!el) return;
            if (el.tagName === 'SELECT') emit({kind:'select', selector:locator(el), value:String(el.value || '')});
            else if (String(el.type || '').toLowerCase() === 'checkbox') emit({kind:el.checked?'check':'uncheck', selector:locator(el)});
          }, true);
          document.addEventListener('keydown', e => {
            if (['Enter','Tab','Escape','ArrowUp','ArrowDown','ArrowLeft','ArrowRight'].includes(e.key)) emit({kind:'press', selector:locator(e.target), value:e.key});
          }, true);
          let scrollTimer = null;
          document.addEventListener('scroll', () => {
            clearTimeout(scrollTimer); scrollTimer=setTimeout(() => emit({kind:'scroll', selector:'body', value:String(window.scrollY)}), 180);
          }, true);
        })();
        """

        lease = self._acquire_browser()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=headless)
                context = browser.new_context(accept_downloads=True)
                page = context.new_page()
                try:
                    page.expose_binding("arenyxaRecord", receive)
                    page.add_init_script(recorder_script)
                    page.goto(start_url, wait_until="domcontentloaded", timeout=30_000)
                    page.wait_for_timeout(seconds * 1000)
                finally:
                    context.close()
                    browser.close()
        finally:
            if lease is not None:
                lease.release()
        return self.normalize(recorded)

    def to_playwright(self, actions: Sequence[BrowserAction | Mapping[str, Any]], language: str = "python") -> str:
        normalized = self.normalize(actions)
        if language.lower() in {"js", "javascript", "node"}:
            lines = ["import { chromium } from 'playwright';", "const browser = await chromium.launch();", "const page = await browser.newPage();"]
            for action in normalized:
                lines.extend(self._action_js(action))
            lines.append("await browser.close();")
            return "\n".join(lines) + "\n"
        lines = ["from playwright.sync_api import sync_playwright", "", "with sync_playwright() as p:", "    browser = p.chromium.launch()", "    page = browser.new_page()"]
        for action in normalized:
            lines.extend("    " + line for line in self._action_py(action))
        lines.append("    browser.close()")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _q(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)

    def _action_py(self, action: BrowserAction) -> list[str]:
        q = self._q
        if action.kind == "goto": return [f"page.goto({q(action.url or action.value)}, timeout={action.timeout_ms})"]
        if action.kind == "click": return [f"page.locator({q(action.selector)}).click(timeout={action.timeout_ms})"]
        if action.kind == "fill": return [f"page.locator({q(action.selector)}).fill({q(action.value)}, timeout={action.timeout_ms})"]
        if action.kind == "press": return [f"page.locator({q(action.selector)}).press({q(action.value)}, timeout={action.timeout_ms})"]
        if action.kind == "check": return [f"page.locator({q(action.selector)}).check(timeout={action.timeout_ms})"]
        if action.kind == "uncheck": return [f"page.locator({q(action.selector)}).uncheck(timeout={action.timeout_ms})"]
        if action.kind == "select": return [f"page.locator({q(action.selector)}).select_option({q(action.value)})"]
        if action.kind == "wait": return [f"page.wait_for_timeout({max(0, int(action.value or 0))})"]
        if action.kind == "scroll": return [f"page.locator({q(action.selector or 'body')}).evaluate(\"el => el.scrollIntoView()\")"]
        if action.kind == "upload": return [f"page.locator({q(action.selector)}).set_input_files({q(action.value)})"]
        if action.kind == "download": return [f"with page.expect_download() as download_info:", f"    page.locator({q(action.selector)}).click()", "download = download_info.value"]
        if action.kind == "assert_text": return [f"assert {q(action.value)} in page.locator({q(action.selector)}).inner_text()"]
        return [f"# unsupported: {action.kind}"]

    def _action_js(self, action: BrowserAction) -> list[str]:
        q = self._q
        if action.kind == "goto": return [f"await page.goto({q(action.url or action.value)}, {{ timeout: {action.timeout_ms} }});"]
        if action.kind == "click": return [f"await page.locator({q(action.selector)}).click({{ timeout: {action.timeout_ms} }});"]
        if action.kind == "fill": return [f"await page.locator({q(action.selector)}).fill({q(action.value)}, {{ timeout: {action.timeout_ms} }});"]
        if action.kind == "press": return [f"await page.locator({q(action.selector)}).press({q(action.value)});"]
        if action.kind == "check": return [f"await page.locator({q(action.selector)}).check();"]
        if action.kind == "uncheck": return [f"await page.locator({q(action.selector)}).uncheck();"]
        if action.kind == "select": return [f"await page.locator({q(action.selector)}).selectOption({q(action.value)});"]
        if action.kind == "wait": return [f"await page.waitForTimeout({max(0, int(action.value or 0))});"]
        if action.kind == "scroll": return [f"await page.locator({q(action.selector or 'body')}).evaluate(el => el.scrollIntoView());"]
        if action.kind == "upload": return [f"await page.locator({q(action.selector)}).setInputFiles({q(action.value)});"]
        if action.kind == "download": return [f"const downloadPromise = page.waitForEvent('download');", f"await page.locator({q(action.selector)}).click();", "const download = await downloadPromise;"]
        if action.kind == "assert_text": return [f"if (!(await page.locator({q(action.selector)}).innerText()).includes({q(action.value)})) throw new Error('assert_text failed');"]
        return [f"// unsupported: {action.kind}"]

