from __future__ import annotations

from pathlib import Path


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_root_developer_entry_is_hidden_behind_developer_experience_and_mode() -> None:
    source = (_root() / "src/arenyxa/presentation/pages/settings.py").read_text(encoding="utf-8")
    assert 'settings.developer_mode and profile in {"developer", "root_developer"}' in source
    assert 'self.root_developer_card.setVisible(visible)' in source
    assert 'self.root_developer_login_button = QPushButton("登录 Root Developer")' in source


def test_root_developer_warning_is_explicit_and_requires_typed_root() -> None:
    source = (_root() / "src/arenyxa/presentation/root_developer_gate.py").read_text(encoding="utf-8")
    assert 'ROOT_CONFIRMATION_TEXT = "ROOT"' in source
    assert '最高技术权限区域' in source
    assert 'fail-closed' in source
    assert 'self.risk_ack.isChecked()' in source
    assert 'self.controlled_device_ack.isChecked()' in source
    assert 'self.recovery_ack.isChecked()' in source
    assert 'self.confirmation.text() == ROOT_CONFIRMATION_TEXT' in source
    assert 'QDialogButtonBox' not in source


def test_root_developer_login_reuses_existing_root_owner_challenge() -> None:
    source = (_root() / "src/arenyxa/presentation/pages/settings.py").read_text(encoding="utf-8")
    assert 'manager.begin_root_owner_login(raw_bundle)' in source
    assert 'manager.complete_root_owner_login(challenge.challenge_id, signature)' in source
    assert 'load_owner_device_vault' in source
    assert 'sign_owner_login_challenge' in source
    assert '"platform.root" in status.capabilities' in source
    assert 'binding = manager.root_workstation_status()' in source
    assert 'ROOT_WORKSTATION_BIND_REQUIRED' in source
    assert 'self.context.root_developer_workstation = True' in source
    assert 'self.developerModeChanged.emit(True)' in source


def test_root_private_key_is_not_requested_by_settings_login_flow() -> None:
    source = (_root() / "src/arenyxa/presentation/pages/settings.py").read_text(encoding="utf-8")
    root_method = source.split("def _root_developer_login", 1)[1].split("def _official_developer_logout", 1)[0]
    assert "developer-root-private.pem" not in root_method
    assert "Root Owner Login Bundle" in root_method
    assert "Root Owner Device Key Vault" in root_method
