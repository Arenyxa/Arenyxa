from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed import _ALLOWED_JOB_TRANSITIONS
from arenyxa.infrastructure.capture.proxy import InterceptingProxy, ProxySettings
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


def test_arenyxa_is_primary_runtime_namespace() -> None:
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'arenyxa = "arenyxa.cli:main"' in pyproject
    assert 'arenyxa-gui = "arenyxa.app:main"' in pyproject
    assert 'arenyxa-server = "arenyxa.infrastructure.server:main"' in pyproject
    assert 'python_version = "3.11"' in pyproject
    assert 'exclude = []' in pyproject
    assert (root / "src" / "arenyxa" / "enterprise" / "distributed.py").is_file()
    assert not (root / "src" / ("n" + "exora")).exists()


def test_distributed_facade_is_native_arenyxa_only() -> None:
    root = Path(__file__).resolve().parents[1]
    facade = (root / "src" / "arenyxa" / "enterprise" / "distributed.py").read_text(encoding="utf-8")
    assert "DurableDistributedQueue" in facade
    assert "EnterpriseServerRuntime" in facade
    assert ("n" + "exora") not in facade.casefold()


def test_error_identity_is_canonical_arenyxa() -> None:
    assert ArenyxaError.__name__ == "ArenyxaError"


def test_network_guard_blocks_metadata_endpoint() -> None:
    guard = NetworkUseGuard(NetworkGuardPolicy())
    with pytest.raises(ArenyxaError) as captured:
        guard.check_target("169.254.169.254")
    assert captured.value.code == "NETWORK_PROTECTED_TARGET"


def test_network_guard_has_bounded_connection_budgets() -> None:
    policy = NetworkGuardPolicy(max_concurrent_connections=2, max_global_connects_per_minute=3, max_target_connects_per_minute=2)
    policy.validate()


def test_proxy_exposes_single_request_repeater_and_governance(tmp_path: Path) -> None:
    proxy = InterceptingProxy(tmp_path, ProxySettings())
    assert callable(proxy.repeat_raw)
    assert proxy.network_guard.snapshot()["enabled"] is True


def test_distributed_terminal_states_cannot_transition_back_to_active() -> None:
    for terminal in ("completed", "failed", "cancelled"):
        assert (terminal, "queued") not in _ALLOWED_JOB_TRANSITIONS
        assert (terminal, "leased") not in _ALLOWED_JOB_TRANSITIONS
        assert (terminal, "running") not in _ALLOWED_JOB_TRANSITIONS
