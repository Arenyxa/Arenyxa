from __future__ import annotations

from dataclasses import field
from arenyxa.compat import dataclass
from typing import Any

from arenyxa.domain.enums import Severity


@dataclass(slots=True)
class ArenyxaError(Exception):
    code: str
    message: str
    domain: str = "CORE"
    severity: Severity = Severity.ERROR
    retryable: bool = False
    context: dict[str, Any] = field(default_factory=dict)
    suggested_action: str = "查看诊断详情并重试。"

    def __str__(self) -> str:
        return f"[{self.domain}:{self.code}] {self.message}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
            "retryable": self.retryable,
            "context": self.context,
            "suggested_action": self.suggested_action,
        }


ERROR_CATALOG: dict[str, tuple[str, str]] = {
    "APP_INIT_FAILED": ("APP", "应用初始化失败"),
    "TASK_INVALID": ("TASK", "任务配置无效"),
    "FETCH_TIMEOUT": ("FETCH", "请求超时"),
    "FETCH_TOO_LARGE": ("FETCH", "响应超过大小上限"),
    "FETCH_TLS_ERROR": ("FETCH", "TLS 证书验证失败"),
    "PARSE_UNSUPPORTED": ("PARSE", "不支持的内容类型"),
    "EXTRACT_SELECTOR_INVALID": ("EXTRACT", "字段选择器无效"),
    "EXTRACT_DEPENDENCY_MISSING": ("EXTRACT", "字段提取依赖缺失"),
    "STORAGE_WRITE_FAILED": ("STORAGE", "数据写入失败"),
    "CAPTURE_PERMISSION_DENIED": ("CAPTURE", "捕获权限不足"),
    "CAPTURE_SOURCE_LOST": ("CAPTURE", "捕获源已断开"),
    "CAPTURE_DROPPED_DATA": ("CAPTURE", "捕获数据发生丢弃"),
    "REPLAY_SIDE_EFFECT_CONFIRMATION": ("REPLAY", "重放可能产生副作用"),
    "SERVER_AUTH_REQUIRED": ("SERVER", "服务器认证失败"),
    "PLUGIN_PERMISSION_DENIED": ("PLUGIN", "插件权限被拒绝"),
    "PLUGIN_BUDGET_EXCEEDED": ("PLUGIN", "插件资源预算耗尽"),
    "MOTION_QUALITY_DOWNGRADED": ("MOTION", "视觉质量已自适应降级"),
}


def domain_error(code: str, **context: Any) -> ArenyxaError:
    domain, message = ERROR_CATALOG.get(code, ("UNKNOWN", "未知错误"))
    return ArenyxaError(code=code, message=message, domain=domain, context=context)
