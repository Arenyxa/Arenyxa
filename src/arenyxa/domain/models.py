from __future__ import annotations

import hashlib
import json
import math
import re
import uuid
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from datetime import datetime
from arenyxa.compat import UTC
from typing import Any
from urllib.parse import urlparse

from arenyxa import __display_version__ as __version__

_HTTP_TOKEN = re.compile(r"^[!#$%&\'*+.^_`|~0-9A-Za-z-]+$")

from arenyxa.domain.enums import CaptureSource, CaptureState, RunStatus, SourceKind, TaskStatus, WorkspaceRole

SCHEMA_VERSION = 6
DEFAULT_USER_AGENT = f"Arenyxa/{__version__}"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class RetryPolicy:
    attempts: int = 2
    initial_backoff_seconds: float = 0.75
    max_backoff_seconds: float = 8.0
    retry_statuses: tuple[int, ...] = (408, 425, 429, 500, 502, 503, 504)
    allow_non_idempotent: bool = False


@dataclass(slots=True)
class RequestSpec:
    url: str
    method: str = "GET"
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    content_type: str | None = None
    connect_timeout: float = 10.0
    read_timeout: float = 30.0
    verify_tls: bool = True
    proxy: str | None = None
    user_agent: str = DEFAULT_USER_AGENT
    retry: RetryPolicy = field(default_factory=RetryPolicy)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.url, str):
            errors.append("URL 必须是字符串。")
        else:
            try:
                parsed = urlparse(self.url)
                hostname = parsed.hostname if parsed is not None else None
                _ = parsed.port if parsed is not None else None
                if hostname:
                    hostname.encode("idna")
            except (TypeError, ValueError, UnicodeError):
                parsed = None
                hostname = None
            if (
                parsed is None
                or parsed.scheme.casefold() not in {"http", "https"}
                or not parsed.netloc
                or not hostname
                or any(ord(ch) < 32 or ch.isspace() for ch in self.url)
            ):
                errors.append("URL 必须使用 http 或 https，且包含有效主机/端口且不能含控制或空白字符。")

        if not isinstance(self.method, str) or self.method.upper() not in {
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
        }:
            errors.append("HTTP 方法不受支持。")

        for label, value in (("连接超时", self.connect_timeout), ("读取超时", self.read_timeout)):
            try:
                numeric = float(value)
            except (TypeError, ValueError, OverflowError):
                errors.append(f"{label}必须是有效数字。")
            else:
                if not math.isfinite(numeric) or numeric <= 0:
                    errors.append(f"{label}必须是大于 0 的有限数字。")
                elif numeric > 600:
                    errors.append(f"{label}不能超过 600 秒，以保证取消和退出具有有限等待边界。")

        mappings = (("Headers", self.headers), ("Query", self.query), ("Cookies", self.cookies))
        for label, mapping in mappings:
            if not isinstance(mapping, dict):
                errors.append(f"{label} 必须是对象。")
                continue
            for key, value in mapping.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    errors.append(f"{label} 的键和值都必须是字符串。")
                    break
                                                                                         
                                                                                         
                                                                                          
                                                                                     
                if label == "Headers" and not _HTTP_TOKEN.fullmatch(key):
                    errors.append("Headers 包含无效的 HTTP 字段名称。")
                    break
                if any(ord(ch) < 32 or ord(ch) == 127 for ch in key):
                    errors.append(f"{label} 的键不允许包含控制字符。")
                    break
                if any((ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in value):
                    errors.append(f"{label} 不允许包含 CR/LF 或其他 HTTP 控制字符。")
                    break
        if not isinstance(self.verify_tls, bool):
            errors.append("verify_tls 必须是布尔值。")
        if self.body is not None and not isinstance(self.body, str):
            errors.append("请求正文必须是字符串或为空。")
        if self.content_type is not None and not isinstance(self.content_type, str):
            errors.append("Content-Type 必须是字符串或为空。")
        elif isinstance(self.content_type, str) and any(
            (ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in self.content_type
        ):
            errors.append("Content-Type 不允许包含 HTTP 控制字符。")
        if self.proxy is not None and not isinstance(self.proxy, str):
            errors.append("代理地址必须是字符串或为空。")
        elif isinstance(self.proxy, str) and self.proxy:
            try:
                proxy = urlparse(self.proxy)
                proxy_host = proxy.hostname
                _ = proxy.port
            except (TypeError, ValueError):
                proxy = None
                proxy_host = None
            if proxy is None or proxy.scheme.casefold() not in {"http", "https"} or not proxy_host:
                errors.append("代理地址必须是包含有效主机/端口的 http 或 https URL。")
        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            errors.append("User-Agent 必须是非空字符串。")
        elif any((ord(ch) < 32 and ch != "\t") or ord(ch) == 127 for ch in self.user_agent):
            errors.append("User-Agent 不允许包含 HTTP 控制字符。")

        if (
            not isinstance(self.retry, RetryPolicy)
            or isinstance(getattr(self.retry, "attempts", None), bool)
            or not isinstance(getattr(self.retry, "attempts", None), int)
        ):
            errors.append("重试次数必须是整数。")
        elif self.retry.attempts < 0 or self.retry.attempts > 10:
            errors.append("重试次数必须位于 0 到 10。")

        if isinstance(self.retry, RetryPolicy):
            try:
                initial = float(self.retry.initial_backoff_seconds)
                maximum = float(self.retry.max_backoff_seconds)
            except (TypeError, ValueError, OverflowError):
                errors.append("重试退避时间必须是有效数字。")
            else:
                if not math.isfinite(initial) or not math.isfinite(maximum) or initial < 0 or maximum < 0:
                    errors.append("重试退避时间必须是非负有限数字。")
                elif maximum < initial:
                    errors.append("最大重试退避时间不能小于初始退避时间。")
                elif maximum > 3600:
                    errors.append("最大重试退避时间不能超过 3600 秒。")
            try:
                statuses = tuple(int(value) for value in self.retry.retry_statuses)
            except (TypeError, ValueError, OverflowError):
                errors.append("重试 HTTP 状态码配置无效。")
            else:
                if any(status < 100 or status > 599 for status in statuses):
                    errors.append("重试 HTTP 状态码必须位于 100 到 599。")
            if not isinstance(self.retry.allow_non_idempotent, bool):
                errors.append("allow_non_idempotent 必须是布尔值。")
        return errors



@dataclass(slots=True)
class CleanerStep:
    kind: str
    options: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


@dataclass(slots=True)
class ValidationRule:
    kind: str
    options: dict[str, Any] = field(default_factory=dict)
    severity: str = "error"


@dataclass(slots=True)
class FieldSpec:
    name: str
    selector: str
    selector_type: str = "css"
    target: str = "text"
    attribute: str | None = None
    multiple: bool = False
    data_type: str = "string"
    required: bool = False
    default: Any = None
    cleaners: list[CleanerStep] = field(default_factory=list)
    validators: list[ValidationRule] = field(default_factory=list)

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.name, str) or not self.name.strip():
            errors.append("字段名称不能为空且必须是字符串。")
        if not isinstance(self.selector, str) or not self.selector.strip():
            errors.append("字段选择器不能为空且必须是字符串。")
        if self.selector_type not in {"css", "xpath"}:
            errors.append("selector_type 必须是 css 或 xpath。")
        if self.target not in {"text", "html", "attribute"}:
            errors.append("字段 target 必须是 text/html/attribute 之一。")
        if self.target == "attribute" and (not isinstance(self.attribute, str) or not self.attribute.strip()):
            errors.append("attribute 目标必须指定属性名。")
        if self.attribute is not None and not isinstance(self.attribute, str):
            errors.append("字段 attribute 必须是字符串或为空。")
        if not isinstance(self.multiple, bool) or not isinstance(self.required, bool):
            errors.append("字段 multiple/required 必须是布尔值。")
        if self.data_type not in {"string", "integer", "number", "boolean", "date", "json"}:
            errors.append("字段 data_type 不受支持。")

        cleaner_kinds = {
            "trim", "normalize_whitespace", "empty_to_null", "lower", "upper",
            "regex_extract", "regex_replace", "map",
        }
        if not isinstance(self.cleaners, list):
            errors.append("字段 cleaners 必须是列表。")
        else:
            for index, step in enumerate(self.cleaners, start=1):
                if not isinstance(step, CleanerStep):
                    errors.append(f"清洗步骤 {index} 类型无效。")
                    continue
                if step.kind not in cleaner_kinds:
                    errors.append(f"清洗步骤 {index} 类型不受支持：{step.kind}")
                if not isinstance(step.options, dict) or not isinstance(step.enabled, bool):
                    errors.append(f"清洗步骤 {index} 配置类型无效。")
                    continue
                if step.kind in {"regex_extract", "regex_replace"}:
                    pattern = step.options.get("pattern", "")
                    if not isinstance(pattern, str):
                        errors.append(f"清洗步骤 {index} 正则表达式必须是字符串。")
                    else:
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            errors.append(f"清洗步骤 {index} 正则表达式无效：{exc}")
                if step.kind == "regex_extract":
                    group = step.options.get("group", 0)
                    if isinstance(group, bool) or not isinstance(group, int) or group < 0:
                        errors.append(f"清洗步骤 {index} group 必须是非负整数。")
                if step.kind == "map" and not isinstance(step.options.get("values", {}), dict):
                    errors.append(f"清洗步骤 {index} map.values 必须是对象。")

        validator_kinds = {"regex", "range", "enum"}
        if not isinstance(self.validators, list):
            errors.append("字段 validators 必须是列表。")
        else:
            for index, rule in enumerate(self.validators, start=1):
                if not isinstance(rule, ValidationRule):
                    errors.append(f"验证规则 {index} 类型无效。")
                    continue
                if rule.kind not in validator_kinds:
                    errors.append(f"验证规则 {index} 类型不受支持：{rule.kind}")
                if not isinstance(rule.options, dict):
                    errors.append(f"验证规则 {index} 配置必须是对象。")
                    continue
                if rule.kind == "regex":
                    pattern = rule.options.get("pattern", "")
                    if not isinstance(pattern, str):
                        errors.append(f"验证规则 {index} 正则表达式必须是字符串。")
                    else:
                        try:
                            re.compile(pattern)
                        except re.error as exc:
                            errors.append(f"验证规则 {index} 正则表达式无效：{exc}")
                if rule.kind == "enum" and not isinstance(rule.options.get("values", []), list):
                    errors.append(f"验证规则 {index} enum.values 必须是列表。")
        return errors


@dataclass(slots=True)
class Task:
    name: str
    requests: list[RequestSpec]
    fields: list[FieldSpec] = field(default_factory=list)
    id: str = field(default_factory=lambda: new_id("task"))
    status: TaskStatus = TaskStatus.DRAFT
    tags: list[str] = field(default_factory=list)
    parser_hint: str = "auto"
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.name, str) or not self.name.strip():
            errors.append("任务名称不能为空且必须是字符串。")
        if not isinstance(self.requests, list) or not self.requests:
            errors.append("任务至少需要一个请求。")
        elif self.requests:
            for index, request in enumerate(self.requests, start=1):
                if not isinstance(request, RequestSpec):
                    errors.append(f"请求 {index}: 请求定义类型无效。")
                    continue
                errors.extend(f"请求 {index}: {error}" for error in request.validate())
        if not isinstance(self.fields, list):
            errors.append("字段定义必须是列表。")
        else:
            names: list[str] = []
            for index, spec in enumerate(self.fields, start=1):
                if not isinstance(spec, FieldSpec):
                    errors.append(f"字段 {index}: 字段定义类型无效。")
                    continue
                field_errors = spec.validate()
                errors.extend(f"字段 {index}: {error}" for error in field_errors)
                if isinstance(spec.name, str) and spec.name.strip():
                    names.append(spec.name)
            if len(names) != len(set(names)):
                errors.append("字段名称必须唯一。")
        if not isinstance(self.parser_hint, str) or self.parser_hint not in {"auto", "html", "json", "xml"}:
            errors.append("parser_hint 必须是 auto/html/json/xml 之一。")
        if not isinstance(self.tags, list) or any(not isinstance(tag, str) for tag in self.tags):
            errors.append("任务标签必须是字符串列表。")
        if not isinstance(self.status, TaskStatus):
            errors.append("任务状态无效。")
        return errors

    def snapshot_hash(self) -> str:
        payload = json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Run:
    task_id: str
    task_snapshot: dict[str, Any]
    id: str = field(default_factory=lambda: new_id("run"))
    status: RunStatus = RunStatus.QUEUED
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    stage: str = "queued"
    completed_units: int = 0
    total_units: int | None = None
    request_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    result_count: int = 0
    retry_count: int = 0
    error_code: str | None = None
    schema_version: int = SCHEMA_VERSION


@dataclass(slots=True)
class ResultRecord:
    task_id: str
    run_id: str
    source_url: str
    data: dict[str, Any]
    id: str = field(default_factory=lambda: new_id("record"))
    fetched_at: str = field(default_factory=utc_now)
    quality_flags: list[str] = field(default_factory=list)
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not self.content_hash:
            canonical = json.dumps(self.data, ensure_ascii=False, sort_keys=True, default=str)
            self.content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class FetchResponse:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    encoding: str
    content_type: str
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(slots=True)
class CaptureSession:
    name: str
    source_type: CaptureSource
    id: str = field(default_factory=lambda: new_id("capture"))
    state: CaptureState = CaptureState.IDLE
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    event_count: int = 0
    bytes_captured: int = 0
    dropped_events: int = 0
    filter_expression: str = ""
    permission_state: str = "not_required"
    schema_version: int = SCHEMA_VERSION
    project_id: str | None = None
    source_id: str | None = None


@dataclass(slots=True)
class NetworkEvent:
    session_id: str
    source_type: CaptureSource
    protocol: str
    direction: str
    size: int
    id: str = field(default_factory=lambda: new_id("net"))
    timestamp: str = field(default_factory=utc_now)
    process_ref: str | None = None
    flow_ref: str | None = None
    request_ref: str | None = None
    method: str | None = None
    url: str | None = None
    status: int | None = None
    host: str | None = None
    timing: dict[str, float] = field(default_factory=dict)
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    request_body_ref: str | None = None
    response_body_ref: str | None = None
    sensitivity_flags: list[str] = field(default_factory=list)
    initiator: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DatasetRevision:
    dataset_id: str
    source_run_ids: list[str]
    records: dict[str, dict[str, Any]]
    id: str = field(default_factory=lambda: new_id("revision"))
    parent_revision: str | None = None
    label: str | None = None
    schema: dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION


@dataclass(slots=True)
class WorkflowNode:
    kind: str
    config: dict[str, Any]
    id: str = field(default_factory=lambda: new_id("node"))
    next_ids: list[str] = field(default_factory=list)
    failure_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Workflow:
    name: str
    nodes: list[WorkflowNode]
    id: str = field(default_factory=lambda: new_id("workflow"))
    version: str = "1.0.0"
    created_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION


@dataclass(slots=True)
class MotionProfile:
    name: str = "Balanced Glass"
    glass_strength: float = 0.82
    transparency: float = 0.34
    blur: float = 22.0
    motion_strength: float = 0.88
    spring_response: float = 0.36
    spring_damping: float = 0.88
    edge_flow: bool = False
    live_data_motion: bool = True
    reduce_motion: bool = False
    animation_mode: str = "auto"
    quality: str = "balanced"
    schema_version: int = SCHEMA_VERSION


@dataclass(slots=True)
class WorkspaceMember:
    actor_id: str
    role: WorkspaceRole


@dataclass(slots=True)
class Workspace:
    name: str
    id: str = field(default_factory=lambda: new_id("workspace"))
    members: list[WorkspaceMember] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class Project:
    name: str
    workspace_id: str | None = None
    id: str = field(default_factory=lambda: new_id("project"))
    description: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.name, str) or not self.name.strip():
            errors.append("项目名称不能为空。")
        if self.workspace_id is not None and not isinstance(self.workspace_id, str):
            errors.append("workspace_id 必须是字符串或为空。")
        if not isinstance(self.description, str):
            errors.append("项目描述必须是字符串。")
        if not isinstance(self.tags, list) or any(not isinstance(tag, str) for tag in self.tags):
            errors.append("项目标签必须是字符串列表。")
        return errors


@dataclass(slots=True)
class ProjectSource:
    project_id: str
    name: str
    kind: SourceKind
    id: str = field(default_factory=lambda: new_id("source"))
    config: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not isinstance(self.project_id, str) or not self.project_id.strip():
            errors.append("数据源必须属于有效项目。")
        if not isinstance(self.name, str) or not self.name.strip():
            errors.append("数据源名称不能为空。")
        if not isinstance(self.kind, SourceKind):
            errors.append("数据源类型无效。")
        if not isinstance(self.config, dict):
            errors.append("数据源配置必须是对象。")
        return errors
