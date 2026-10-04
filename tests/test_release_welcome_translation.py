from __future__ import annotations

import pytest

from arenyxa.application.experience import EXPERIENCE_PROFILES
from arenyxa.presentation.language import literal_for_locale


EXPECTED = {
    'personal': ('Use the task wizard for network analysis, security checks, API debugging and data work', (
        'Open Task Center by default', 'Hide unnecessary professional navigation and advanced parameters',
        'Does not change any security permissions')),
    'power': ('Quick access to analysis, recovery and advanced tools', (
        'Expand advanced tool navigation', 'Keep stability and resource governance defaults',
        'Does not grant Developer capability')),
    'professional': ('For long-running automation, Workflow and data engineering', (
        'Expand advanced workspaces', 'Keep all diagnostics and recovery entry points discoverable',
        'Permissions are still decided by Security Kernel')),
    'developer': ('For public APIs, the plugin SDK and development workflows', (
        'Open Developer Center immediately', 'High-risk capabilities still require a separate risk agreement',
        'Does not provide Official Developer Access')),
    'enterprise': ('Open enterprise management, device enrollment and enterprise runtime workspaces', (
        'Show create/join options when no enterprise identity is established',
        'Selecting this mode does not grant enterprise permissions',
        'Capabilities are still decided by Security Kernel')),
}


@pytest.mark.parametrize('profile', EXPERIENCE_PROFILES, ids=lambda profile: profile.id)
def test_welcome_cards_keep_full_descriptions_and_permission_boundaries(profile):
    summary, details = EXPECTED[profile.id]
    assert literal_for_locale(profile.summary, 'en_US') == summary
    for source, expected in zip(profile.detail, details, strict=True):
        assert literal_for_locale('• ' + source, 'en_US') == '• ' + expected
        assert literal_for_locale('• ' + source, 'zh_CN') == '• ' + source


@pytest.mark.parametrize(('source', 'expected'), [
    ('欢迎使用 Arenyxa', 'Welcome to Arenyxa'),
    ('选择最符合你的工作方式。这里只调整工作区呈现与默认导航，不是权限等级；企业身份和开发者身份由独立安全流程建立。',
     'Choose the mode that fits your work. This changes workspace presentation and default navigation only, not permission levels; enterprise and developer identities are established through separate security processes.'),
    ('Personal 首页场景', 'Personal home scenario'),
    ('网站分析', 'Website analysis'), ('API 调试', 'API debugging'),
    ('网络诊断', 'Network diagnostics'), ('数据采集', 'Data collection'),
    ('网络安全学习', 'Network security learning'),
    ('之后可在 设置 → 使用模式 重新打开此独立窗口。主题、字体、缩放与动效继续放在独立“个性化”页面。',
     'You can reopen this independent window later from Settings → Experience. Themes, fonts, scaling, and motion remain in the separate Personalization page.'),
])
def test_welcome_explanations_and_scenarios_are_complete(source, expected):
    assert literal_for_locale(source, 'en_US') == expected
