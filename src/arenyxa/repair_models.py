"""Repair Center domain models.

This module is deliberately dependency-light so scanner/planner/executor/recovery layers can
share stable contracts without importing one another.
"""
from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arenyxa.compat import StrEnum, dataclass
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited


class RepairCategory(StrEnum):
    ENCODING_UI = "encoding_ui"
    STARTUP_CRASH = "startup_crash"
    PROGRAM_FILES = "program_files"
    DEPENDENCIES = "dependencies"
    DATABASE_INDEX = "database_index"
    SETTINGS_UI = "settings_ui"
    PLUGINS = "plugins"
    CAPTURE_STACK = "capture_stack"
    PERMISSIONS_PATHS = "permissions_paths"
    CACHE_TEMP = "cache_temp"
    SERVER_RUNTIME = "server_runtime"
    PERFORMANCE_MOTION = "performance_motion"
    FEATURE_INTEGRATION = "feature_integration"
    RUNTIME_STATE = "runtime_state"
    OTHER = "other"


CATEGORY_LABELS: dict[RepairCategory, str] = {
    RepairCategory.ENCODING_UI: "乱码 / 语言 / 字体显示异常",
    RepairCategory.STARTUP_CRASH: "启动失败 / 崩溃 / 闪退 / 崩溃循环",
    RepairCategory.PROGRAM_FILES: "程序文件缺失 / 损坏 / 被意外修改",
    RepairCategory.DEPENDENCIES: "Python / Qt / 模块依赖加载异常",
    RepairCategory.DATABASE_INDEX: "数据库 / FTS 索引 / WAL 异常",
    RepairCategory.SETTINGS_UI: "设置 / 主题 / 窗口布局异常",
    RepairCategory.PLUGINS: "插件加载 / 插件权限 / 插件崩溃异常",
    RepairCategory.CAPTURE_STACK: "抓包 / tshark / dumpcap / 进程监控异常",
    RepairCategory.PERMISSIONS_PATHS: "目录 / 权限 / 写入 / 存储路径异常",
    RepairCategory.CACHE_TEMP: "缓存 / 临时文件 / 残留状态异常",
    RepairCategory.SERVER_RUNTIME: "本地服务 / 端口 / 运行时异常",
    RepairCategory.PERFORMANCE_MOTION: "动画 / 渲染 / 卡顿 / 性能配置异常",
    RepairCategory.FEATURE_INTEGRATION: "高级功能 / 模块接线 / 能力完整性异常",
    RepairCategory.RUNTIME_STATE: "运行状态 / 中断任务 / 恢复点异常",
    RepairCategory.OTHER: "其他 / 无法确定的问题",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fault_fingerprint(code: str, category: RepairCategory | str) -> str:
    category_value = category.value if isinstance(category, RepairCategory) else str(category)
    digest = hashlib.sha256(
        f"arenyxa-repair-v1\0{category_value}\0{str(code).strip().upper()}".encode("utf-8")
    ).hexdigest()
    return f"NXF-{digest[:12].upper()}"


@dataclass(slots=True)
class RepairFinding:
    code: str
    category: RepairCategory
    severity: str
    title: str
    detail: str
    evidence: str = ""
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = fault_fingerprint(self.code, self.category)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["category"] = self.category.value
        return payload


@dataclass(slots=True)
class HealthReport:
    generated_at: str
    install_root: str
    data_root: str
    source_mode: bool
    findings: list[RepairFinding] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not self.findings

    @property
    def categories(self) -> list[RepairCategory]:
        result: list[RepairCategory] = []
        for finding in self.findings:
            if finding.category not in result:
                result.append(finding.category)
        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "install_root": self.install_root,
            "data_root": self.data_root,
            "source_mode": self.source_mode,
            "healthy": self.healthy,
            "findings": [item.to_dict() for item in self.findings],
        }


@dataclass(slots=True)
class RepairPlan:
    install_root: str
    data_root: str
    categories: list[str]
    detected_findings: list[dict[str, Any]] = field(default_factory=list)
    parent_pid: int = 0
    relaunch: bool = True
    source_mode: bool = True
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = _utc_now()

    @classmethod
    def load(cls, path: Path) -> "RepairPlan":
        raw = json.loads(read_text_limited(path, 4 * 1024 * 1024, encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Repair plan root must be a JSON object")
        allowed_fields = set(cls.__dataclass_fields__)
        if set(raw) - allowed_fields:
            raise ValueError("Repair plan contains unsupported fields")
        plan = cls(**raw)
        plan.validate()
        return plan

    def validate(self) -> None:
        if not isinstance(self.install_root, str) or not self.install_root.strip():
            raise ValueError("Repair plan install_root is invalid")
        if not isinstance(self.data_root, str) or not self.data_root.strip():
            raise ValueError("Repair plan data_root is invalid")
        if not isinstance(self.categories, list) or not all(isinstance(item, str) for item in self.categories):
            raise ValueError("Repair plan categories are invalid")
        allowed_categories = {item.value for item in RepairCategory}
        unknown = set(self.categories) - allowed_categories
        if unknown:
            raise ValueError(f"Repair plan contains unknown categories: {sorted(unknown)}")
        if not isinstance(self.detected_findings, list) or not all(
            isinstance(item, dict) for item in self.detected_findings
        ):
            raise ValueError("Repair plan findings are invalid")
        if not isinstance(self.parent_pid, int) or self.parent_pid < 0:
            raise ValueError("Repair plan parent_pid is invalid")
        if not isinstance(self.relaunch, bool) or not isinstance(self.source_mode, bool):
            raise ValueError("Repair plan flags are invalid")

    def save(self, path: Path) -> Path:
        self.validate()
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(path, asdict(self), mode=stat.S_IRUSR | stat.S_IWUSR)
        return path


@dataclass(slots=True)
class RepairActionResult:
    action: str
    status: str
    detail: str


@dataclass(slots=True)
class RepairResult:
    started_at: str
    finished_at: str
    success: bool
    categories: list[str]
    backup_dir: str
    actions: list[RepairActionResult]
    unresolved: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "success": self.success,
            "categories": self.categories,
            "backup_dir": self.backup_dir,
            "actions": [asdict(item) for item in self.actions],
            "unresolved": self.unresolved,
        }
