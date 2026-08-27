from __future__ import annotations

from dataclasses import dataclass

from arenyxa.config import AppSettings


@dataclass(frozen=True, slots=True)
class ExperienceProfile:
    id: str
    title: str
    summary: str
    detail: tuple[str, ...]


EXPERIENCE_PROFILES: tuple[ExperienceProfile, ...] = (
    ExperienceProfile(
        "personal", "一般用户 · 简单模式", "用任务向导完成网络分析、安全检查、API 调试与数据工作",
        ("默认进入 Task Center", "隐藏不必要的专业导航和高级参数", "不改变任何安全权限"),
    ),
    ExperienceProfile(
        "power", "高级用户", "更快触达分析、恢复与高级工具",
        ("展开高级工具导航", "保留稳定性与资源治理默认值", "不授予 Developer capability"),
    ),
    ExperienceProfile(
        "professional", "专业工作", "面向长期自动化、Workflow 与数据工程",
        ("展开高级工作区", "保持完整诊断与恢复入口可发现", "权限仍由 Security Kernel 决定"),
    ),
    ExperienceProfile(
        "developer", "Developer Profile", "面向公开 API、插件 SDK 与开发工作流",
        ("立即进入 Developer Center", "高风险能力仍需单独接受风险协议", "不是 Official Developer Access"),
    ),
    ExperienceProfile(
        "enterprise", "企业工作模式", "进入企业管理、设备加入与企业运行工作区",
        ("未建立企业身份时显示创建/加入入口", "模式选择不会授予企业权限", "具体能力继续由 Security Kernel 决定"),
    ),
)

ROOT_DEVELOPER_PROFILE = ExperienceProfile(
    "root_developer", "Root Developer", "由启动阶段 Root Authority Challenge 自动启用",
    ("不可从普通模式选择器直接开启", "每次进程启动重新验证", "失败时回退普通 Developer 工作区"),
)

_ALL_PROFILES = (*EXPERIENCE_PROFILES, ROOT_DEVELOPER_PROFILE)
_PROFILE_IDS = frozenset(item.id for item in _ALL_PROFILES)


def get_experience_profile(profile_id: str) -> ExperienceProfile:
    normalized = str(profile_id).strip().casefold()
    for item in _ALL_PROFILES:
        if item.id == normalized:
            return item
    raise ValueError(f"unknown Arenyxa experience profile: {profile_id}")


def apply_experience_profile(settings: AppSettings, profile_id: str) -> ExperienceProfile:
    




    profile = get_experience_profile(profile_id)
    settings.experience_profile = profile.id
    settings.experience_setup_completed = True
    if profile.id == "personal":
        settings.advanced_nav_expanded = False
        settings.developer_nav_expanded = False
    else:
        settings.advanced_nav_expanded = True
        settings.developer_nav_expanded = profile.id in {"developer", "root_developer"}
    return profile


def profile_ids() -> frozenset[str]:
    return _PROFILE_IDS
