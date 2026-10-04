from __future__ import annotations

import re

CRITICAL_UI_PHRASES = {
    "欢迎使用 Arenyxa": "Welcome to Arenyxa",
    "选择最符合你的工作方式。这里只调整工作区呈现与默认导航，不是权限等级；企业身份和开发者身份由独立安全流程建立。": "Choose the mode that fits your work. This changes workspace presentation and default navigation only, not permission levels; enterprise and developer identities are established through separate security processes.",
    "Personal 首页场景": "Personal home scenario",
    "网站分析": "Website analysis",
    "API 调试": "API debugging",
    "网络诊断": "Network diagnostics",
    "数据采集": "Data collection",
    "网络安全学习": "Network security learning",
    "用任务向导完成网络分析、安全检查、API 调试与数据工作": "Use the task wizard for network analysis, security checks, API debugging and data work",
    "默认进入 Task Center": "Open Task Center by default",
    "隐藏不必要的专业导航和高级参数": "Hide unnecessary professional navigation and advanced parameters",
    "不改变任何安全权限": "Does not change any security permissions",
    "更快触达分析、恢复与高级工具": "Quick access to analysis, recovery and advanced tools",
    "展开高级工具导航": "Expand advanced tool navigation",
    "保留稳定性与资源治理默认值": "Keep stability and resource governance defaults",
    "不授予 Developer capability": "Does not grant Developer capability",
    "面向长期自动化、Workflow 与数据工程": "For long-running automation, Workflow and data engineering",
    "展开高级工作区": "Expand advanced workspaces",
    "保持完整诊断与恢复入口可发现": "Keep all diagnostics and recovery entry points discoverable",
    "权限仍由 Security Kernel 决定": "Permissions are still decided by Security Kernel",
    "面向公开 API、插件 SDK 与开发工作流": "For public APIs, the plugin SDK and development workflows",
    "立即进入 Developer Center": "Open Developer Center immediately",
    "高风险能力仍需单独接受风险协议": "High-risk capabilities still require a separate risk agreement",
    "不是 Official Developer Access": "Does not provide Official Developer Access",
    "进入企业管理、设备加入与企业运行工作区": "Open enterprise management, device enrollment and enterprise runtime workspaces",
    "未建立企业身份时显示创建/加入入口": "Show create/join options when no enterprise identity is established",
    "模式选择不会授予企业权限": "Selecting this mode does not grant enterprise permissions",
    "具体能力继续由 Security Kernel 决定": "Capabilities are still decided by Security Kernel",
    "设置": "Settings",
    "语言": "Language",
    "本地网络数据工作台": "Local network data workbench",
    "CPU 软阈值": "CPU soft threshold",
    "内存软阈值": "Memory soft threshold",
    "磁盘安全余量": "Minimum free disk space",
    "浏览器实例上限": "Maximum browser instances",
    "性能与资源治理": "Performance and resource governance",
    "系统、语言、性能、资源治理、诊断与高级维护": "System, language, performance, resource governance, diagnostics and maintenance",
    "一般用户 · 简单模式": "Personal user · Simple mode",
    "高级用户": "Advanced user",
    "专业工作": "Professional workspace",
    "企业工作模式": "Enterprise workspace",
    "尚未选择；下次启动将显示 Welcome Center": "Not selected; Welcome Center will appear at the next startup",
}

_CRITICAL_DIAGNOSTICS = {
    "数据目录仍被另一个 Arenyxa Desktop/Server 使用；为避免并发修改，修复已安全取消。": {
        "en_US": "The data directory is still in use by another Arenyxa Desktop/Server. Repair was safely cancelled to prevent concurrent changes.",
        "fr_FR": "Le dossier de données est encore utilisé par une autre instance Arenyxa Desktop/Server. La réparation a été annulée pour éviter des modifications simultanées.",
    },
    "Root Developer 认证组件当前不可用。": {
        "en_US": "The Root Developer authentication component is currently unavailable.",
        "fr_FR": "Le composant d’authentification Root Developer est actuellement indisponible.",
    },
    "Root Developer 信任信息尚未就绪，因此登录已安全关闭（fail-closed）。": {
        "en_US": "Root Developer trust information is not ready. Sign-in is disabled for safety (fail-closed).",
        "fr_FR": "Les informations de confiance Root Developer ne sont pas prêtes. La connexion est désactivée par sécurité (fail-closed).",
    },
    "后台任务尚未结束，请稍后重试关闭。": {
        "en_US": "Background tasks are still running. Please try closing again later.",
        "fr_FR": "Des tâches en arrière-plan sont encore en cours. Veuillez réessayer de fermer plus tard.",
    },
    "运行时尚未完成安全关闭，请稍后重试。": {
        "en_US": "Safe shutdown is not complete. Please try again later.",
        "fr_FR": "L’arrêt sécurisé n’est pas terminé. Veuillez réessayer plus tard.",
    },
    "关闭失败，恢复标记已保留，请重试关闭。": {
        "en_US": "Shutdown failed. The recovery marker was preserved. Please try closing again.",
        "fr_FR": "L’arrêt a échoué. Le marqueur de récupération a été conservé. Veuillez réessayer de fermer.",
    },
}


def critical_for_locale(source: str, locale: str) -> str | None:
    critical = _CRITICAL_DIAGNOSTICS.get(source)
    if critical is not None:
        return critical.get(locale, critical["en_US"])
    shutdown_prompt = re.fullmatch(r"仍有 (\d+) 个后台任务。停止任务并退出？", source)
    if shutdown_prompt:
        count = shutdown_prompt.group(1)
        if locale == "fr_FR":
            return f"{count} tâches en arrière-plan sont encore actives. Les arrêter et quitter ?"
        return f"{count} background tasks are still active. Stop them and exit?"

    return None
