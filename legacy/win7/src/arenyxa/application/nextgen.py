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

LOGGER = logging.getLogger(__name__)

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


                                                                             
                               
                                                                             


@dataclass(slots=True)
class ActivityEvent:
    kind: str
    message: str
    level: str = "info"
    details: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: new_id("activity"))
    timestamp: str = field(default_factory=utc_now)


class ActivityCenter:
    






    def __init__(self, capacity: int = 1000) -> None:
        self.capacity = max(100, min(20_000, int(capacity)))
        self._events: deque[ActivityEvent] = deque(maxlen=self.capacity)
        self._lock = threading.RLock()
        self._subscribers: list[Callable[[ActivityEvent], None]] = []

    def publish(self, kind: str, message: str, *, level: str = "info", details: Mapping[str, Any] | None = None) -> ActivityEvent:
        event = ActivityEvent(kind=kind, message=message, level=level, details=dict(details or {}))
        with self._lock:
            self._events.append(event)
            subscribers = tuple(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:
                                                                                              
                                                                                    
                LOGGER.exception("Activity Center subscriber callback failed for event %s", event.kind)
        return event

    def snapshot(self, limit: int = 200) -> list[ActivityEvent]:
        with self._lock:
            items = list(self._events)
        return items[-max(1, min(5000, int(limit))):]

    def subscribe(self, callback: Callable[[ActivityEvent], None]) -> Callable[[], None]:
        with self._lock:
            self._subscribers.append(callback)

        def unsubscribe() -> None:
            with self._lock:
                if callback in self._subscribers:
                    self._subscribers.remove(callback)

        return unsubscribe


                                                                             
                                
                                                                             


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
        classes = [value for value in node.get("class", "").split() if value and not _UNSTABLE_CLASS.search(value)]
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
        classes = [value for value in node.get("class", "").split() if value and not _UNSTABLE_CLASS.search(value)]
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

    def _acquire_browser(self):
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
        return Workflow(name=name, nodes=nodes)

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
        except Exception:
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


                                                                             
                                      
                                                                             


_VAULT_KEY_CREATION_LOCK = threading.Lock()
_VAULT_LOCKS_GUARD = threading.Lock()
_VAULT_ROOT_LOCKS: dict[Path, threading.RLock] = {}


def _vault_root_lock(root: Path) -> threading.RLock:
    with _VAULT_LOCKS_GUARD:
        lock = _VAULT_ROOT_LOCKS.get(root)
        if lock is None:
            lock = threading.RLock()
            _VAULT_ROOT_LOCKS[root] = lock
        return lock


class SecretVault:
    






    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.vault_path = self.root / "secrets.vault"
        self.backup_path = self.root / "secrets.vault.bak"
        self.key_path = self.root / "secrets.key"
                                                                                          
                                                                                          
        self._lock = _vault_root_lock(self.root)
        key = self._load_or_create_key()
        try:
            self._fernet = Fernet(key)
        except (TypeError, ValueError) as exc:
            raise ArenyxaError("VAULT_KEY_INVALID", "Secrets Vault 密钥无效或已损坏。", domain="SECURITY") from exc

    def _load_or_create_key(self) -> bytes:
        with _VAULT_KEY_CREATION_LOCK:
            if self.key_path.exists():
                try:
                    raw = read_bytes_limited(self.key_path, 64 * 1024)
                    if raw.startswith(b"DPAPI1:") and os.name == "nt":
                        return self._dpapi_unprotect(base64.b64decode(raw.split(b":", 1)[1], validate=True))
                    return raw.strip()
                except (OSError, ValueError, TypeError) as exc:
                    raise ArenyxaError("VAULT_KEY_INVALID", "Secrets Vault 密钥无法读取或解保护。", domain="SECURITY") from exc
            key = Fernet.generate_key()
            payload = key
            if os.name == "nt":
                payload = b"DPAPI1:" + base64.b64encode(self._dpapi_protect(key))
            atomic_write_bytes(self.key_path, payload, mode=0o600)
            return key

    def _decode_vault(self, payload: bytes) -> dict[str, str]:
        clear = self._fernet.decrypt(payload)
        data = json.loads(clear)
        if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in data.items()):
            raise ValueError("vault root or entry type invalid")
        return data

    def _load(self) -> dict[str, str]:
        if not self.vault_path.exists():
            return {}
        try:
            return self._decode_vault(read_bytes_limited(self.vault_path, 8 * 1024 * 1024))
        except (InvalidToken, OSError, UnicodeError, json.JSONDecodeError, ValueError) as primary_exc:
                                                                                             
                                                                                    
            if self.backup_path.exists():
                try:
                    backup_payload = read_bytes_limited(self.backup_path, 8 * 1024 * 1024)
                    recovered = self._decode_vault(backup_payload)
                    atomic_write_bytes(self.vault_path, backup_payload, mode=0o600)
                    return recovered
                except (InvalidToken, OSError, UnicodeError, json.JSONDecodeError, ValueError):
                    pass
            raise ArenyxaError("VAULT_CORRUPT", "Secrets Vault 无法解密或已损坏。", domain="SECURITY") from primary_exc

    def _save(self, data: Mapping[str, str]) -> None:
        clear = json.dumps(dict(data), ensure_ascii=False, sort_keys=True).encode("utf-8")
        if self.vault_path.exists():
                                                                               
            try:
                current = read_bytes_limited(self.vault_path, 8 * 1024 * 1024)
                self._decode_vault(current)
            except (InvalidToken, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise ArenyxaError("VAULT_CORRUPT", "Secrets Vault 已损坏，拒绝覆盖以保留恢复证据。", domain="SECURITY") from exc
            atomic_write_bytes(self.backup_path, current, mode=0o600)
        encrypted = self._fernet.encrypt(clear)
        if len(encrypted) > 8 * 1024 * 1024:
            raise ArenyxaError("VAULT_TOO_LARGE", "Secrets Vault 超过 8 MiB 安全上限。", domain="SECURITY")
        atomic_write_bytes(self.vault_path, encrypted, mode=0o600)

    def set(self, name: str, value: str) -> None:
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", name):
            raise ValueError("秘密名称必须由字母开头，只包含字母、数字、点、下划线或连字符。")
        with self._lock:
            data = self._load()
            data[name] = str(value)
            self._save(data)

    def get(self, name: str) -> str | None:
        with self._lock:
            return self._load().get(name)

    def delete(self, name: str) -> bool:
        with self._lock:
            data = self._load()
            existed = name in data
            data.pop(name, None)
            if existed:
                self._save(data)
            return existed

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._load())

    @staticmethod
    def redact(text: str) -> str:
        text = re.sub(r"(?i)(authorization|api[_-]?key|token|password|cookie)(\s*[:=]\s*)([^\s,;]+)", r"\1\2***", text)
        text = re.sub(r"(https?://[^:/\s]+:)[^@/\s]+(@)", r"\1***\2", text)
        return text

    @staticmethod
    def _dpapi_protect(data: bytes) -> bytes:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
        buffer = ctypes.create_string_buffer(data)
        source = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
        target = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), "Arenyxa", None, None, None, 0, ctypes.byref(target)):
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(target.pbData, target.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(target.pbData)

    @staticmethod
    def _dpapi_unprotect(data: bytes) -> bytes:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
        buffer = ctypes.create_string_buffer(data)
        source = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
        target = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)):
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(target.pbData, target.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(target.pbData)


class ProjectEnvironmentService:
    def __init__(self, projects_root: Path) -> None:
        self.projects_root = projects_root.resolve()
        self.projects_root.mkdir(parents=True, exist_ok=True)

    def path(self, project_name: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", project_name.strip()).strip(".-")
        if not safe:
            raise ValueError("项目名称无效。")
        target = (self.projects_root / safe).resolve()
        if not path_is_relative_to(target, self.projects_root):
            raise ValueError("项目路径越界。")
        return target

    def ensure(self, project_name: str) -> dict[str, str]:
        root = self.path(project_name)
        directories = {name: root / name for name in ("workflows", "selectors", "schemas", "scripts", "tests", "snapshots", "downloads", "browser-profile")}
        root.mkdir(parents=True, exist_ok=True)
        for path in directories.values(): path.mkdir(parents=True, exist_ok=True)
        return {key: str(value) for key, value in {"root": root, **directories}.items()}

    def save_environment(self, project_name: str, values: Mapping[str, str]) -> Path:
        root = self.path(project_name)
        self.ensure(project_name)
        path = root / ".arenyxa-env.json"
        safe = {str(key): str(value) for key, value in values.items() if not re.search(r"secret|password|token|cookie|authorization|api[_-]?key", str(key), re.I)}
        atomic_write_json(path, safe, ensure_ascii=False, indent=2)
        return path

    def load_environment(self, project_name: str) -> dict[str, str]:
        root = self.path(project_name)
        path = root / ".arenyxa-env.json"
        legacy = root / ".arenyxa-env.json"
        if not path.exists() and legacy.exists():
            path = legacy
        if not path.exists():
            return {}
        try:
            raw = json.loads(read_text_limited(path, 4 * 1024 * 1024, encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ArenyxaError("PROJECT_ENV_CORRUPT", "项目环境配置已损坏，未加载任何环境变量。", domain="PROJECT") from exc
        if not isinstance(raw, dict):
            raise ArenyxaError("PROJECT_ENV_CORRUPT", "项目环境配置根节点必须是对象。", domain="PROJECT")
        return {str(k): str(v) for k, v in raw.items()}


                                                                             
                                                   
                                                                             


class ProjectPythonEnvironmentService:
    







    def __init__(self, projects: ProjectEnvironmentService) -> None:
        self.projects = projects

    def venv_path(self, project_name: str) -> Path:
        return self.projects.path(project_name) / ".venv"

    def python_path(self, project_name: str) -> Path:
        root = self.venv_path(project_name)
        return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def status(self, project_name: str) -> dict[str, Any]:
        root = self.venv_path(project_name)
        python = self.python_path(project_name)
        result: dict[str, Any] = {
            "project": project_name,
            "venv": str(root),
            "exists": root.exists(),
            "python": str(python),
            "ready": python.exists(),
        }
        if python.exists():
            try:
                completed = subprocess.run(
                    validated_argv([str(python), "-c", "import platform,sys;print(sys.version.split()[0]);print(platform.architecture()[0])"]),
                    cwd=self.projects.path(project_name),
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=15,
                    check=False,
                )
                lines = completed.stdout.strip().splitlines()
                result.update({"version": lines[0] if lines else "", "architecture": lines[1] if len(lines) > 1 else "", "returncode": completed.returncode})
            except (OSError, subprocess.SubprocessError) as exc:
                result["error"] = str(exc)
        return result

    @staticmethod
    def _discover_python() -> list[str]:
        runtime = select_runtime()
        candidates: list[list[str]] = []
        if not getattr(sys, "frozen", False):
            candidates.append([sys.executable])
        if os.name == "nt":
            if runtime.legacy:
                candidates.extend([["py", "-3.8"], ["python"]])
            else:
                candidates.extend([["py", "-3.13"], ["py", "-3.12"], ["py", "-3.11"], ["python"]])
        else:
            candidates.extend([["python3.13"], ["python3.12"], ["python3.11"], ["python3"], ["python"]])
        seen: set[tuple[str, ...]] = set()
        for command in candidates:
            key = tuple(command)
            if key in seen:
                continue
            seen.add(key)
            try:
                completed = subprocess.run(
                    validated_argv([*command, "-c", "import platform,sys;print(sys.version_info[:2]);print(platform.architecture()[0])"]),
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            text = completed.stdout
            required_minor = "8" if runtime.legacy else "1[123]"
            match = re.search(rf"\((3),\s*({required_minor})\)", text)
            if completed.returncode == 0 and match and "64bit" in text:
                return command
        requirement = "Python 3.8.x" if runtime.legacy else "Python 3.11–3.13"
        raise RuntimeError(f"未找到受支持的 64-bit {requirement}。请先安装对应 Python，然后重试。")

    def create(self, project_name: str, *, clear: bool = False) -> dict[str, Any]:
        self.projects.ensure(project_name)
        root = self.venv_path(project_name)
        backup: Path | None = None
        if clear and root.exists():
            backup = root.with_name(f".venv.backup-{time.time_ns()}")
            root.replace(backup)
        try:
            command = self._discover_python()
            completed = subprocess.run(
                validated_argv([*command, "-m", "venv", str(root)]),
                cwd=self.projects.path(project_name),
                capture_output=True,
                text=True,
                errors="replace",
                timeout=300,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "python -m venv failed")[-20_000:])
            status = self.status(project_name)
            if not status.get("ready"):
                raise RuntimeError("新建 Python 环境缺少可执行解释器。")
        except Exception:
                                                                                           
            if backup is not None and backup.exists():
                if root.exists():
                    shutil.rmtree(root, ignore_errors=True)
                backup.replace(root)
            raise
        if backup is not None and backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        return status

    def run(self, project_name: str, arguments: Sequence[str], *, timeout: int = 300) -> dict[str, Any]:
        python = self.python_path(project_name)
        if not python.exists():
            raise RuntimeError("项目 Python 环境尚未创建。")
        args = [str(value) for value in arguments]
        completed = subprocess.run(
            validated_argv([str(python), *args]),
            cwd=self.projects.path(project_name),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, min(3600, int(timeout))),
            check=False,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout[-200_000:],
            "stderr": completed.stderr[-200_000:],
        }

    def install(self, project_name: str, packages: Sequence[str], *, timeout: int = 900) -> dict[str, Any]:
        cleaned = [str(value).strip() for value in packages if str(value).strip()]
        if not cleaned:
            raise ValueError("至少提供一个 Python 包。")
        if len(cleaned) > 50 or any(len(value) > 300 or "\x00" in value for value in cleaned):
            raise ValueError("Python 包参数无效或数量过多。")
        return self.run(project_name, ["-m", "pip", "install", *cleaned], timeout=timeout)

    def freeze(self, project_name: str) -> list[str]:
        result = self.run(project_name, ["-m", "pip", "freeze"], timeout=120)
        if result["returncode"] != 0:
            raise RuntimeError(result["stderr"] or "pip freeze failed")
        return [line for line in str(result["stdout"]).splitlines() if line.strip()]


@dataclass(slots=True)
class DistributedWorker:
    id: str
    name: str
    base_url: str
    token_secret: str
    enabled: bool = True
    weight: int = 1


class DistributedWorkerService:
    






    def __init__(self, root: Path, vault: SecretVault) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "workers.json"
        self.vault = vault
        self._lock = threading.RLock()

    @staticmethod
    def _validate(worker: DistributedWorker) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", worker.id):
            raise ValueError("Worker ID 无效。")
        if not isinstance(worker.name, str) or not worker.name.strip() or len(worker.name.strip()) > 200:
            raise ValueError("Worker 名称无效。")
        worker.name = worker.name.strip()
        if not isinstance(worker.token_secret, str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.-]{0,127}", worker.token_secret.strip()
        ):
            raise ValueError("Worker Secret 引用名称无效。")
        worker.token_secret = worker.token_secret.strip()
        if not isinstance(worker.enabled, bool):
            raise ValueError("Worker enabled 字段必须是布尔值。")
        parsed = urlparse(worker.base_url)
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Worker URL 端口无效。") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise ValueError("Worker URL 必须是有效 http/https 地址。")
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("Worker URL 不允许内联凭据、query 或 fragment；凭据必须放入 Secrets Vault。")
        if parsed.path not in {"", "/"}:
            raise ValueError("Worker URL 必须指向服务器根路径。")
                                                                                                   
        if parsed.scheme == "http" and (parsed.hostname or "").casefold() not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("非本机 Worker 必须使用 HTTPS。")
        worker.weight = max(1, min(100, int(worker.weight)))

    def _load(self) -> list[DistributedWorker]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(read_text_limited(self.path, 4 * 1024 * 1024, encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError("worker registry root must be an array")
            result: list[DistributedWorker] = []
            seen_ids: set[str] = set()
            allowed = set(DistributedWorker.__dataclass_fields__)
            for item in raw:
                if not isinstance(item, dict) or set(item) - allowed:
                    raise ValueError("worker registry item has invalid fields")
                worker = DistributedWorker(**item)
                self._validate(worker)
                if worker.id in seen_ids:
                    raise ValueError("worker registry contains duplicate IDs")
                seen_ids.add(worker.id)
                result.append(worker)
            return result
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                                                                                        
                                                                                       
                                              
            raise ArenyxaError(
                "WORKER_REGISTRY_CORRUPT",
                "Distributed Worker 配置已损坏，已拒绝覆盖原文件。",
                domain="WORKER",
            ) from exc

    def _save(self, workers: Sequence[DistributedWorker]) -> None:
        atomic_write_json(self.path, [asdict(item) for item in workers], ensure_ascii=False, indent=2)

    def list(self) -> list[DistributedWorker]:
        with self._lock:
            return self._load()

    def upsert(self, worker: DistributedWorker, token: str | None = None) -> DistributedWorker:
        self._validate(worker)
        with self._lock:
                                                                                            
                                                                                             
                                                                  
            workers = [item for item in self._load() if item.id != worker.id]
            old_token = self.vault.get(worker.token_secret) if token is not None else None
            try:
                if token is not None:
                    self.vault.set(worker.token_secret, token)
                workers.append(worker)
                self._save(sorted(workers, key=lambda item: item.id))
            except Exception:
                if token is not None:
                    try:
                        if old_token is None:
                            self.vault.delete(worker.token_secret)
                        else:
                            self.vault.set(worker.token_secret, old_token)
                    except Exception:
                        LOGGER.exception(
                            "Distributed Worker token rollback failed for secret %s",
                            worker.token_secret,
                        )
                raise
        return worker

    def remove(self, worker_id: str) -> bool:
        with self._lock:
            workers = self._load()
            remaining = [item for item in workers if item.id != worker_id]
            if len(remaining) == len(workers):
                return False
            self._save(remaining)
            return True

    def _worker(self, worker_id: str) -> DistributedWorker:
        for worker in self.list():
            if worker.id == worker_id:
                return worker
        raise KeyError(worker_id)

    def _request(self, worker: DistributedWorker, path: str, *, method: str = "GET", payload: Mapping[str, Any] | None = None, timeout: float = 10.0) -> Any:
        token = self.vault.get(worker.token_secret)
        if path != "/health" and not token:
            raise RuntimeError(f"Worker {worker.id} 缺少 SecretVault token：{worker.token_secret}")
        headers = {"Accept": "application/json", "User-Agent": f"Arenyxa/{__version__}"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if payload is not None:
            data = json.dumps(dict(payload), ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(worker.base_url.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=max(1.0, min(60.0, float(timeout)))) as response:
                body = response.read(4 * 1024 * 1024 + 1)
                if len(body) > 4 * 1024 * 1024:
                    raise RuntimeError("Worker 响应超过 4 MiB 上限。")
                return json.loads(body.decode("utf-8")) if body else {}
        except urllib.error.HTTPError as exc:
            body = exc.read(8192).decode("utf-8", errors="replace")
            raise RuntimeError(f"Worker HTTP {exc.code}: {body}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeError) as exc:
            raise RuntimeError(f"Worker 请求失败：{exc}") from exc

    def health(self, worker_id: str) -> dict[str, Any]:
        worker = self._worker(worker_id)
        started = time.perf_counter()
        data = self._request(worker, "/health", timeout=5)
        return {"worker": asdict(worker), "latency_ms": round((time.perf_counter() - started) * 1000, 2), "health": data}

    def health_all(self, *, max_workers: int = 4) -> list[dict[str, Any]]:
        





        workers = self.list()
        if not workers:
            return []
        enabled = [item for item in workers if item.enabled]
        results: dict[str, dict[str, Any]] = {
            item.id: {
                "worker": asdict(item),
                "online": False,
                "latency_ms": None,
                "health": {},
                "error": "disabled" if not item.enabled else None,
            }
            for item in workers
        }
        if enabled:
            with ThreadPoolExecutor(
                max_workers=max(1, min(int(max_workers), 8, len(enabled))),
                thread_name_prefix="arenyxa-worker-health",
            ) as executor:
                future_map = {executor.submit(self.health, item.id): item.id for item in enabled}
                for future in as_completed(future_map):
                    worker_id = future_map[future]
                    try:
                        payload = future.result()
                        results[worker_id] = {
                            **payload,
                            "online": True,
                            "error": None,
                        }
                    except Exception as exc:                                          
                        results[worker_id]["error"] = f"{type(exc).__name__}: {exc}"[:500]
        return [results[item.id] for item in workers]

    def remote_tasks(self, worker_id: str) -> list[dict[str, Any]]:
        result = self._request(self._worker(worker_id), "/api/v1/tasks", timeout=15)
        return result if isinstance(result, list) else []

    def remote_runs(self, worker_id: str) -> list[dict[str, Any]]:
        result = self._request(self._worker(worker_id), "/api/v1/runs", timeout=15)
        return result if isinstance(result, list) else []

    def run_task(self, worker_id: str, task_id: str) -> dict[str, Any]:
        result = self._request(self._worker(worker_id), f"/api/v1/tasks/{quote(str(task_id), safe='')}/runs", method="POST", payload={}, timeout=15)
        if not isinstance(result, dict):
            raise RuntimeError("Worker 返回无效运行结果。")
        return result

    def partition(self, values: Sequence[Any], worker_ids: Sequence[str] | None = None) -> dict[str, list[Any]]:
        allowed_ids = None if not worker_ids else {str(item) for item in worker_ids}
        selected = [
            item for item in self.list()
            if item.enabled and (allowed_ids is None or item.id in allowed_ids)
        ]
        if not selected:
            return {"local": list(values)}
        wheel: list[str] = ["local"]
        for worker in selected:
            wheel.extend([worker.id] * worker.weight)
        result: dict[str, list[Any]] = {name: [] for name in dict.fromkeys(wheel)}
        for index, value in enumerate(values):
            result[wheel[index % len(wheel)]].append(value)
        return result


                                                                             
                                            
                                                                             


_VARIABLE = re.compile(r"\$\{([a-zA-Z][\w-]*)\.([\w.-]+)\}")


class WorkflowVariables:
    def resolve(self, value: Any, scopes: Mapping[str, Mapping[str, Any]], secret_resolver: Callable[[str], str | None] | None = None) -> Any:
        if isinstance(value, str):
            def replace(match: re.Match[str]) -> str:
                scope, key = match.group(1), match.group(2)
                if scope == "secret" and secret_resolver is not None:
                    resolved = secret_resolver(key)
                else:
                    resolved = scopes.get(scope, {}).get(key)
                if resolved is None:
                    raise KeyError(f"未找到变量 {scope}.{key}")
                return str(resolved)
            return _VARIABLE.sub(replace, value)
        if isinstance(value, list): return [self.resolve(item, scopes, secret_resolver) for item in value]
        if isinstance(value, tuple): return tuple(self.resolve(item, scopes, secret_resolver) for item in value)
        if isinstance(value, dict): return {key: self.resolve(item, scopes, secret_resolver) for key, item in value.items()}
        return value


@dataclass(slots=True)
class DebugSnapshot:
    node_id: str | None
    state: str
    queue_depth: int
    outputs: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    current_item: dict[str, Any] | None = None


class WorkflowDebugger:
    









    def __init__(self, buffer_size: int = 10_000) -> None:
        if not isinstance(buffer_size, int) or isinstance(buffer_size, bool) or buffer_size <= 0:
            raise ValueError("buffer_size 必须是正整数。")
        self.buffer_size = buffer_size
        self.workflow: Workflow | None = None
        self.nodes: dict[str, WorkflowNode] = {}
        self.queue: deque[tuple[str, dict[str, Any]]] = deque()
        self.outputs: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []
        self.breakpoints: set[str] = set()
        self.paused_before: str | None = None
        self.finished = False

    def _buffer_limit(self, *, area: str, node_id: str | None = None) -> ArenyxaError:
        context: dict[str, Any] = {"area": area, "limit": self.buffer_size}
        if node_id is not None:
            context["node_id"] = node_id
        return ArenyxaError(
            "WORKFLOW_DEBUGGER_BUFFER_LIMIT",
            "工作流调试器达到安全缓冲上限；请缩小输入或降低单步 fan-out。",
            domain="WORKFLOW",
            context=context,
        )

    def _enqueue(self, node_id: str, item: Mapping[str, Any], *, front: bool = False) -> None:
        if len(self.queue) >= self.buffer_size:
            raise self._buffer_limit(area="queue", node_id=node_id)
        value = (node_id, dict(item))
        if front:
            self.queue.appendleft(value)
        else:
            self.queue.append(value)

    def _append_output(self, item: Mapping[str, Any]) -> None:
        if len(self.outputs) >= self.buffer_size:
            raise self._buffer_limit(area="outputs")
        self.outputs.append(dict(item))

    def _append_error(self, node_id: str, error: Exception, item: Mapping[str, Any]) -> None:
        if len(self.errors) >= self.buffer_size:
            raise self._buffer_limit(area="errors", node_id=node_id)
        self.errors.append({"node_id": node_id, "error": str(error), "item": dict(item)})

    def prepare(self, workflow: Workflow, inputs: Iterable[Mapping[str, Any]], breakpoints: Iterable[str] = ()) -> DebugSnapshot:
        self.workflow = workflow
        self.nodes = {node.id: node for node in workflow.nodes}
        indegree = Counter()
        for node in workflow.nodes:
            for child in node.next_ids + node.failure_ids: indegree[child] += 1
        roots = [node.id for node in workflow.nodes if indegree[node.id] == 0]
        if not roots: raise ValueError("Workflow 没有入口节点。")
        self.queue.clear(); self.outputs.clear(); self.errors.clear()
                                                                                          
                                                                                               
                                                                 
        try:
            for item in inputs:
                if not isinstance(item, Mapping):
                    raise ArenyxaError(
                        "WORKFLOW_INPUT_INVALID",
                        "工作流调试输入必须是对象。",
                        domain="WORKFLOW",
                    )
                for root in roots:
                    self._enqueue(root, item)
        except Exception:
                                                                                      
                                                                                      
            self.queue.clear()
            self.breakpoints.clear()
            self.paused_before = None
            self.finished = True
            raise
        self.breakpoints = {item for item in breakpoints if item in self.nodes}
        self.paused_before = None; self.finished = False
        return self.snapshot("ready")

    def step(self, *, ignore_breakpoint: bool = False) -> DebugSnapshot:
        if self.finished or not self.queue:
            self.finished = True
            return self.snapshot("completed")
        node_id, item = self.queue[0]
        if node_id in self.breakpoints and not ignore_breakpoint and self.paused_before != node_id:
            self.paused_before = node_id
            return self.snapshot("breakpoint", node_id=node_id, current=item)
        self.paused_before = None
        self.queue.popleft()
        node = self.nodes[node_id]
        try:
            produced = self._execute_node(node, item)
            if node.next_ids:
                for output in produced:
                    for child in node.next_ids:
                        self._enqueue(child, output)
            else:
                for output in produced:
                    self._append_output(output)
        except ArenyxaError as exc:
            if exc.code == "WORKFLOW_DEBUGGER_BUFFER_LIMIT":
                                                                                             
                                                                                                
                                                                    
                self.queue.clear()
                self.finished = True
                raise
            self._append_error(node_id, exc, item)
            for child in node.failure_ids:
                self._enqueue(child, {**item, "_error": str(exc)})
        except Exception as exc:
            self._append_error(node_id, exc, item)
            for child in node.failure_ids:
                self._enqueue(child, {**item, "_error": str(exc)})
        if not self.queue: self.finished = True
        return self.snapshot("completed" if self.finished else "stepped", node_id=node_id, current=item)

    def continue_run(self, max_steps: int = 100_000) -> DebugSnapshot:
        for _ in range(max_steps):
            snapshot = self.step()
            if snapshot.state in {"completed", "breakpoint"}: return snapshot
        return self.snapshot("step_limit")

    def retry_node(self, node_id: str, item: Mapping[str, Any]) -> DebugSnapshot:
        if node_id not in self.nodes: raise KeyError(node_id)
        self._enqueue(node_id, item, front=True)
        self.finished = False
        return self.snapshot("retry_queued", node_id=node_id, current=dict(item))

    def snapshot(self, state: str, *, node_id: str | None = None, current: Mapping[str, Any] | None = None) -> DebugSnapshot:
        return DebugSnapshot(
            node_id, state, len(self.queue), list(self.outputs[-50:]), list(self.errors[-50:]),
            dict(current) if current is not None else None,
        )

    @staticmethod
    def _execute_node(node: WorkflowNode, item: dict[str, Any]) -> list[dict[str, Any]]:
        if node.kind in {"source", "sink"}: return [dict(item)]
        if node.kind == "filter":
            actual = item.get(str(node.config["field"])); expected = node.config.get("value"); op = node.config.get("operator", "equals")
            matched = {"equals": actual == expected, "not_equals": actual != expected, "contains": str(expected) in str(actual or ""), "exists": str(node.config["field"]) in item}.get(op, False)
            return [dict(item)] if matched else []
        if node.kind == "map":
            output = dict(item)
            for destination, source in node.config.get("fields", {}).items(): output[destination] = item.get(source) if isinstance(source, str) else source
            for destination, value in node.config.get("constants", {}).items(): output[destination] = value
            return [output]
        if node.kind == "validate":
            missing = [name for name in node.config.get("required", []) if item.get(name) in {None, ""}]
            if missing: raise ValueError(f"required fields missing: {', '.join(missing)}")
            return [dict(item)]
        if node.kind == "browser_action":
            return [{**item, "_browser_action": dict(node.config)}]
        raise ValueError(f"调试器暂不支持节点类型：{node.kind}")


class WorkflowTemplateLibrary:
    def templates(self) -> dict[str, dict[str, Any]]:
        return {
            "ecommerce-product": self._template("E-commerce Product", ["fetch", "extract", "validate", "deduplicate", "sink"]),
            "news-monitoring": self._template("News Monitoring", ["fetch", "extract", "diff", "sink"]),
            "api-pagination": self._template("API Pagination", ["request", "paginate", "extract", "sink"]),
            "infinite-scroll": self._template("Infinite Scroll", ["browser", "scroll", "extract", "sink"]),
            "login-capture": self._template("Login + Capture", ["browser", "login", "capture", "sink"]),
            "file-download": self._template("Download Files", ["fetch", "extract-links", "download", "sink"]),
            "rss": self._template("RSS Feed", ["fetch", "parse-xml", "extract", "sink"]),
            "sitemap": self._template("Sitemap Crawl", ["fetch", "parse-sitemap", "fan-out", "sink"]),
        }

    @staticmethod
    def _template(name: str, stages: Sequence[str]) -> dict[str, Any]:
        return {"name": name, "stages": list(stages), "variables": {"project.base_url": "https://example.com"}, "description": "Arenyxa built-in starter template"}


                                                                             
                                               
                                                                             


@dataclass(slots=True)
class NextGenFeatureHub:
    selector: SelectorStudio
    recorder: BrowserRecorderService
    request: HttpRequestWorkbench
    protocols: ProtocolInspector
    sources: DataSourceDiscovery
    smartpath: SmartPathV2
    quality: DataQualityStudio
    vault: SecretVault
    projects: ProjectEnvironmentService
    variables: WorkflowVariables
    templates: WorkflowTemplateLibrary
    activity: ActivityCenter
    python_envs: ProjectPythonEnvironmentService
    workers: DistributedWorkerService
    browser_profiles: BrowserProfileService
    marketplace: WorkflowMarketplaceService
    regression: RegressionLab
    intelligence: WebIntelligenceEngine
    context_bridge: ContextBridgeService
    portability: WorkflowPortabilityService
    compatibility: CompatibilityLab
    reliability: ReliabilityAdvisor
    web_intelligence: WebIntelligenceCenter
    time_machine: WebTimeMachine
    autopilot: AutopilotEngine

    @classmethod
    def create(
        cls, *, data_root: Path, projects_root: Path, max_response_bytes: int,
        browser_pool: ResourceLeasePool | None = None,
    ) -> "NextGenFeatureHub":
        vault = SecretVault(data_root / "secure")
        projects = ProjectEnvironmentService(projects_root)
        request = HttpRequestWorkbench(max_response_bytes)
        smartpath = SmartPathV2()
        intelligence = WebIntelligenceEngine(smartpath)
        selector = SelectorStudio()
        recorder = BrowserRecorderService(browser_pool)
        protocols = ProtocolInspector()
        sources = DataSourceDiscovery()
        context_bridge = ContextBridgeService(request.generator)
        time_machine = WebTimeMachine(data_root / "intelligence" / "time_machine.json")
        web_intelligence = WebIntelligenceCenter(
            intelligence=intelligence,
            sources=sources,
            protocols=protocols,
            context_bridge=context_bridge,
            selector=selector,
            recorder=recorder,
            time_machine=time_machine,
        )
        experience = ExperienceStore(data_root / "intelligence" / "experience.db")
        autopilot = AutopilotEngine(smartpath, experience)
        return cls(
            selector=selector,
            recorder=recorder,
            request=request,
            protocols=protocols,
            sources=sources,
            smartpath=smartpath,
            quality=DataQualityStudio(),
            vault=vault,
            projects=projects,
            variables=WorkflowVariables(),
            templates=WorkflowTemplateLibrary(),
            activity=ActivityCenter(),
            python_envs=ProjectPythonEnvironmentService(projects),
            workers=DistributedWorkerService(data_root / "workers", vault),
            browser_profiles=BrowserProfileService(data_root / "profiles"),
            marketplace=WorkflowMarketplaceService(),
            regression=RegressionLab(),
            intelligence=intelligence,
            context_bridge=context_bridge,
            portability=WorkflowPortabilityService(),
            compatibility=CompatibilityLab(intelligence),
            reliability=ReliabilityAdvisor(),
            web_intelligence=web_intelligence,
            time_machine=time_machine,
            autopilot=autopilot,
        )
