from __future__ import annotations

from pathlib import Path


def test_root_owner_is_not_exposed_as_an_ordinary_settings_login_action() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/pages/settings.py").read_text(encoding="utf-8")
    assert 'QPushButton("登录 Root Owner / Authority")' not in source
    assert "root_owner_login_button" not in source
    assert "def _root_owner_login" not in source
    assert "Root Owner 不在普通设置界面提供登录入口" in source
    language = (root / "src/arenyxa/presentation/language.py").read_text(encoding="utf-8")
    assert "登录 Root Owner / Authority" not in language
    assert "导出 Root Owner Challenge" not in language
    assert "导入 Root Owner Proof" not in language


def test_registered_root_workstation_requires_gate_before_main_window_construction() -> None:
    root = Path(__file__).resolve().parents[1]
    app = (root / "src/arenyxa/app.py").read_text(encoding="utf-8")
    gate = (root / "src/arenyxa/presentation/root_owner_gate.py").read_text(encoding="utf-8")
    assert app.index("enforce_root_owner_startup_gate(context)") < app.index("window = MainWindow(")
    assert "检测到此设备曾由 Root Owner 注册为 Arenyxa Root Workstation" in gate
    assert "普通模式不会绕过此锁定" in gate
    assert "Developer Root Private Key 必须继续保持离线" in gate
    assert "ROOT_OWNER_MAX_STARTUP_FAILURES" in gate
    assert "record_root_startup_cancel" in gate
    assert "record_root_startup_failure" in gate
    assert "root_owner_startup_attempt_budget" in gate
    assert "if status.locked:" in gate


def test_root_binding_cannot_auto_mint_a_root_session_after_restart() -> None:
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "src/arenyxa/bootstrap.py").read_text(encoding="utf-8")
    access = (root / "src/arenyxa/application/developer_access.py").read_text(encoding="utf-8")
    access += "\n" + (root / "src/arenyxa/application/root_workstation_binding.py").read_text(encoding="utf-8")
    assert "developer_access.activate_root_workstation_session()" not in bootstrap
    assert "Root authority now requires a fresh" in access
    assert "return None" in access
    assert "A durable Root workstation binding is only a startup-authentication trigger" in bootstrap
    assert "Every desktop launch must prove the" in access
    assert "Owner device private key again" in access


def test_enterprise_ui_has_no_product_visible_phase_labels() -> None:
    root = Path(__file__).resolve().parents[1]
    enterprise = (root / "src/arenyxa/presentation/pages/enterprise.py").read_text(encoding="utf-8")
    language = (root / "src/arenyxa/presentation/language.py").read_text(encoding="utf-8")
    for phase in ("Phase 7", "Phase 8", "Phase 9", "Phase 10", "Phase 11", "Phase 12"):
        assert phase not in enterprise
        assert phase not in language
    assert 'SectionCard(theme, "Enrollment / Device Trust / Domain Lock")' in enterprise
    assert 'SectionCard(theme, "Office Enterprise Coordinator")' in enterprise
    assert 'SectionCard(theme, "Enterprise Workspace Governance")' in enterprise
    assert 'SectionCard(theme, "Enterprise Server / Distributed Worker")' in enterprise
