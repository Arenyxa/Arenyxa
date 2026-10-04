from __future__ import annotations

import sys
from pathlib import Path

import pytest

from arenyxa.application.windows_runtime import _bounded_process
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.zero_trust import ZeroTrustPolicy
from test_bug_v82_hunt004_worker_http_zero_trust import _IdentityStub, _authed_session
from arenyxa.enterprise.distributed_runtime import EnterpriseServerRuntime
from types import SimpleNamespace


def test_worker_session_cannot_supply_another_identity_or_permissions(tmp_path: Path) -> None:
    runtime = EnterpriseServerRuntime(_IdentityStub(), SimpleNamespace(), tmp_path)
    token = _authed_session(runtime, "ordinary")
    runtime.set_network_policy(ZeroTrustPolicy(
        enabled=True, allowed_worker_ids=("trusted",), required_permissions=("jobs.admin",),
    ))
    with pytest.raises(ArenyxaError) as caught:
        runtime.authorize_worker_session_context(token, {
            "worker_id": "trusted", "permissions": ["jobs.admin"],
            "via_server_relay": True,
        })
    assert {"worker_id", "permissions"}.issubset(caught.value.context["reasons"])


def test_native_probe_decodes_non_utf8_output_without_losing_reader_thread() -> None:
    result = _bounded_process([
        sys.executable, "-B", "-c", "import sys; sys.stdout.buffer.write(bytes([0xb0, 0xa1]))",
    ])
    assert result["ok"] is True
    assert isinstance(result["stdout"], str)
    assert result["stdout"]
    assert result["stderr"] == ""


@pytest.mark.parametrize("profile,mode,expected", [
    ("personal", False, False), ("personal", True, False),
    ("enterprise", True, False), ("developer", False, False),
    ("developer", True, True), ("root_developer", True, True),
])
def test_root_settings_entry_enforces_profile_and_mode(profile: str, mode: bool, expected: bool) -> None:
    from arenyxa.config import AppSettings
    from arenyxa.presentation.pages.settings import SettingsPage

    settings = AppSettings(experience_profile=profile, developer_mode=mode)
    refreshed: list[bool] = []
    owner = SimpleNamespace(context=SimpleNamespace(settings=settings),
                            _refresh_root_developer_entry=lambda: refreshed.append(True))
    allowed = lambda: SettingsPage._root_developer_entry_allowed(owner)
    owner._root_developer_entry_allowed = allowed
    assert allowed() is expected
    if not expected:
        # The actual handler returns before accessing any identity manager/dialog.
        SettingsPage._root_developer_login(owner)
        assert refreshed == [True]
