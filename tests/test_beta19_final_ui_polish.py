from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_terminal_completion_popup_follows_live_theme() -> None:
    console = source("src/arenyxa/presentation/pages/tools_console.py")
    assert "self._command_completer = completer" in console
    assert "self.theme.changed.connect(self._refresh_completion_popup_theme)" in console
    assert "QPalette.ColorRole.Base" in console
    assert "selection-background-color:{tokens.selection}" in console


def test_official_and_root_developer_ui_are_separate() -> None:
    settings = source("src/arenyxa/presentation/pages/settings.py")
    official = settings.split("self.official_developer_card =", 1)[1].split("# Root Developer", 1)[0]
    assert "官方开发者授权" in official
    assert "Root Owner" not in official
    assert 'self.root_developer_logout_button = QPushButton("退出 Root Developer")' in settings
    assert "self.root_developer_logout_button.clicked.connect(self._root_developer_logout)" in settings
    assert "def _root_developer_logout" in settings
    assert "当前活动的是 Root Developer；请使用下方 Root Developer 区域退出。" in settings


def test_enterprise_ui_uses_plain_language() -> None:
    enterprise = source("src/arenyxa/presentation/pages/enterprise.py")
    actions = source("src/arenyxa/presentation/pages/enterprise_distributed_actions.py")
    welcome = source("src/arenyxa/presentation/pages/welcome.py")
    assert "设备加入与信任" in enterprise
    assert "加入现有企业" in enterprise
    assert "企业局域网协调器" in enterprise
    assert "Office Enterprise" not in enterprise
    assert "Office Coordinator" not in actions
    assert "企业工作模式提供本地企业身份" in welcome


def test_root_login_contract_is_still_reused_by_settings_ui() -> None:
    settings = source("src/arenyxa/presentation/pages/settings.py")
    assert "manager.begin_root_owner_login(raw_bundle)" in settings
    assert "manager.complete_root_owner_login(challenge.challenge_id, signature)" in settings
    assert "sign_owner_login_challenge" in settings
