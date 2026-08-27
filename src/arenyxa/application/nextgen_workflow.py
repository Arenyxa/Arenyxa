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
from arenyxa.application.nextgen_core import ActivityCenter

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

