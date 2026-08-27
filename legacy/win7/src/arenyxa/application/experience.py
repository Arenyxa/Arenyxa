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
        "personal", "个人工作", "清爽的日常 Web / 数据工作区",
        ("突出核心任务、数据与抓取", "默认收起高级导航", "不改变任何安全权限"),
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
        ("突出开发工作入口", "Developer Mode 仍需单独接受风险协议", "不是 Official Developer Access"),
    ),
)

_PROFILE_IDS = frozenset(item.id for item in EXPERIENCE_PROFILES)


def get_experience_profile(profile_id: str) -> ExperienceProfile:
    normalized = str(profile_id).strip().casefold()
    for item in EXPERIENCE_PROFILES:
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
                                                                                             
        settings.developer_nav_expanded = bool(settings.developer_mode and profile.id == "developer")
    return profile


def profile_ids() -> frozenset[str]:
    return _PROFILE_IDS
