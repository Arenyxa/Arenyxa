from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from arenyxa.application.experience import apply_experience_profile, get_experience_profile
from arenyxa.config import AppSettings
from arenyxa.domain.enums import WorkspaceRole


def test_experience_profile_is_presentation_not_authority() -> None:
    settings = AppSettings()
    settings.developer_mode = False
    settings.request_concurrency = 17
    before_limits = (settings.request_concurrency, settings.resource_max_browser_instances)

    profile = apply_experience_profile(settings, "developer")

    assert profile.id == "developer"
    assert settings.experience_setup_completed is True
    assert settings.experience_profile == "developer"
                                                                                                 
    assert settings.developer_mode is False
    assert settings.developer_nav_expanded is False
    assert (settings.request_concurrency, settings.resource_max_browser_instances) == before_limits


def test_unknown_experience_profile_is_rejected() -> None:
    with pytest.raises(ValueError):
        get_experience_profile("root-admin-all")


def test_settings_schema_sanitizes_experience_fields(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text('{"experience_profile":"enterprise-root","experience_setup_completed":"yes"}', encoding="utf-8")
    settings = AppSettings.load(path)
    assert settings.experience_profile == ""
    assert settings.experience_setup_completed is False


def test_welcome_center_is_independent_dialog_and_not_workspace_page() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src" / "arenyxa" / "presentation" / "pages" / "welcome.py").read_text(encoding="utf-8")
    main = ((root / "src" / "arenyxa" / "presentation" / "main_window.py").read_text(encoding="utf-8") + "\n" + (root / "src" / "arenyxa" / "presentation" / "main_window_navigation.py").read_text(encoding="utf-8"))
    app = (root / "src" / "arenyxa" / "app.py").read_text(encoding="utf-8")
    assert "class WelcomeCenterDialog(QDialog)" in source
    assert "super().__init__(None)" in source
    assert "dialog.exec()" in main
    assert 'self.pages["welcome"]' not in main
    assert "window.show_pending_welcome()" in app
    assert 'server_button.clicked.connect(self.fleetRequested.emit)' in source
    assert 'dialog.fleetRequested.connect(open_fleet)' in main
    assert 'self.navigate("server_ops")' in main
    assert 'server_button.setEnabled(False)' not in source
    assert "不是权限等级" in source


def test_headless_viewer_is_denied_by_security_kernel(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from arenyxa.infrastructure.server import create_app

    token = "viewer-token"
    digest = hashlib.sha256(token.encode()).hexdigest()
    app = create_app(tmp_path / "viewer-server", {digest: ("viewer", WorkspaceRole.VIEWER)})
    try:
        with TestClient(app) as client:
                                                                                
            assert client.get("/api/v1/tasks", headers={"Authorization": f"Bearer {token}"}).status_code == 200
                                                                                        
            response = client.post(
                "/api/v1/tasks/nonexistent/runs",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 403
        assert app.state.security_kernel.audit.verify()[0] is True
    finally:
        app.state.data_root_lease.release()
