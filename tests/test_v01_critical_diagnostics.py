from __future__ import annotations

import pytest

from arenyxa.presentation.language import literal_for_locale


@pytest.mark.parametrize('source,expected', [
    ('设置', 'Settings'), ('语言', 'Language'),
    ('本地网络数据工作台', 'Local network data workbench'),
    ('CPU 软阈值', 'CPU soft threshold'),
    ('内存软阈值', 'Memory soft threshold'),
    ('磁盘安全余量', 'Minimum free disk space'),
    ('浏览器实例上限', 'Maximum browser instances'),
    ('性能与资源治理', 'Performance and resource governance'),
    ('系统、语言、性能、资源治理、诊断与高级维护',
     'System, language, performance, resource governance, diagnostics and maintenance'),
])
def test_observed_settings_labels_retain_their_meaning_in_english(source, expected):
    assert literal_for_locale(source, 'en_US') == expected


@pytest.mark.parametrize('source,expected', [
    ('一般用户 · 简单模式', 'Personal user · Simple mode'),
    ('高级用户', 'Advanced user'),
    ('专业工作', 'Professional workspace'),
    ('企业工作模式', 'Enterprise workspace'),
    ('尚未选择；下次启动将显示 Welcome Center', 'Not selected; Welcome Center will appear at the next startup'),
    ('Developer Profile', 'Developer Profile'),
    ('Root Developer', 'Root Developer'),
])
def test_work_mode_labels_do_not_lose_the_selected_profile(source, expected):
    assert literal_for_locale(source, 'en_US') == expected


@pytest.mark.parametrize(("source", "expected"), [
    ("数据目录仍被另一个 Arenyxa Desktop/Server 使用；为避免并发修改，修复已安全取消。", "Repair was safely cancelled"),
    ("Root Developer 认证组件当前不可用。", "authentication component is currently unavailable"),
    ("Root Developer 信任信息尚未就绪，因此登录已安全关闭（fail-closed）。", "Sign-in is disabled"),
    ("后台任务尚未结束，请稍后重试关闭。", "Background tasks are still running"),
    ("运行时尚未完成安全关闭，请稍后重试。", "Safe shutdown is not complete"),
    ("关闭失败，恢复标记已保留，请重试关闭。", "The recovery marker was preserved"),
])
def test_critical_errors_keep_their_meaning_in_english(source, expected):
    assert expected in literal_for_locale(source, "en_US")


def test_critical_errors_have_complete_french_translation():
    assert literal_for_locale("Root Developer 认证组件当前不可用。", "fr_FR") == (
        "Le composant d’authentification Root Developer est actuellement indisponible."
    )


def test_shutdown_confirmation_keeps_active_job_count():
    assert literal_for_locale("仍有 7 个后台任务。停止任务并退出？", "en_US") == (
        "7 background tasks are still active. Stop them and exit?"
    )
