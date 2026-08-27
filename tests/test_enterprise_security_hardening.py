from __future__ import annotations

import json
import ssl
from pathlib import Path

import pytest

from arenyxa.enterprise.coordinator import CoordinatorClient
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.enterprise.server_api import create_enterprise_server_app
from arenyxa.enterprise.transport_security import BoundedWindowRateLimiter, normalize_correlation_id
from arenyxa.security import SecurityKernel

ADMIN_PASSWORD = "Enterprise-Security-Admin-Password-0001"
VAULT_PASSWORD = "Enterprise-Security-Vault-Passphrase-0001"


def _service(root: Path) -> LocalEnterpriseIdentityService:
    service = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(root), root)
    service.create_enterprise("Security Hardening Enterprise", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    return service


def test_enterprise_auth_throttle_persists_across_restart(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.enterprise.identity as identity_module
    import arenyxa.enterprise.transport_security as transport_module

    now = [1_700_000_000.0]
    monkeypatch.setattr(identity_module.time, "time", lambda: now[0])
    monkeypatch.setattr(transport_module.time, "time", lambda: now[0])
    service = _service(tmp_path)
    for _ in range(3):
        with pytest.raises(Exception):
            service.login("root", "Wrong-Password-Long-0001")
    assert service._auth_throttle_path.is_file()
    raw = service._auth_throttle_path.read_text(encoding="utf-8")
    assert "root" not in raw.casefold()
    assert "Wrong-Password" not in raw
    service.lock()

    restarted = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    restarted.unlock(VAULT_PASSWORD)
    with pytest.raises(Exception) as limited:
        restarted.login("root", ADMIN_PASSWORD)
    assert getattr(limited.value, "code", "") == "ENTERPRISE_AUTH_RATE_LIMITED"


def test_enterprise_auth_throttle_tamper_is_fail_closed(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.enterprise.identity as identity_module
    import arenyxa.enterprise.transport_security as transport_module

    monkeypatch.setattr(identity_module.time, "time", lambda: 1_700_000_000.0)
    monkeypatch.setattr(transport_module.time, "time", lambda: 1_700_000_000.0)
    service = _service(tmp_path)
    with pytest.raises(Exception):
        service.login("root", "Wrong-Password-Long-0001")
    state = json.loads(service._auth_throttle_path.read_text(encoding="utf-8"))
    bucket = next(iter(state["entries"]))
    state["entries"][bucket]["attempts"] = 0
    service._auth_throttle_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(Exception) as tampered:
        service.login("root", ADMIN_PASSWORD)
    assert getattr(tampered.value, "code", "") == "ENTERPRISE_AUTH_THROTTLE_INVALID"


def test_bounded_rate_limiter_rejects_burst_and_bounds_keys() -> None:
    limiter = BoundedWindowRateLimiter(4)
    assert limiter.allow("peer-a", limit=2) is True
    assert limiter.allow("peer-a", limit=2) is True
    assert limiter.allow("peer-a", limit=2) is False
    for index in range(20):
        limiter.allow(f"attacker-{index}", limit=1)
    assert limiter.bucket_count() <= 4


def test_correlation_id_is_bounded_and_sanitized() -> None:
    assert normalize_correlation_id("job:abc-123") == "job:abc-123"
    generated = normalize_correlation_id("bad header with spaces\r\n")
    assert generated.startswith("corr-")
    assert " " not in generated and "\r" not in generated and "\n" not in generated
    assert len(generated) <= 128


def test_coordinator_supports_ca_plus_enterprise_identity_mode() -> None:
    compatibility = CoordinatorClient("127.0.0.1", 443, "a" * 64)
    context = compatibility._client_tls_context()
    assert context.verify_mode == ssl.CERT_NONE
    assert compatibility.tls_mode == "enterprise-identity-pinned"

    hardened = CoordinatorClient("127.0.0.1", 443, "a" * 64, require_ca_validation=True)
    hardened_context = hardened._client_tls_context()
    assert hardened_context.verify_mode == ssl.CERT_REQUIRED
    assert hardened_context.check_hostname is False
    assert hardened.tls_mode == "ca+enterprise-identity"


def test_enterprise_server_echoes_correlation_and_rate_limits(tmp_path: Path, monkeypatch) -> None:
    from fastapi.testclient import TestClient
    import arenyxa.enterprise.server_api as server_api

    monkeypatch.setattr(server_api, "MAX_SERVER_REQUESTS_PER_MINUTE", 2)

    class Queue:
        @staticmethod
        def health():
            return {"healthy": True}

    class Runtime:
        queue = Queue()

    app = create_enterprise_server_app(Runtime(), {"schema": "test-identity"})
    with TestClient(app) as client:
        first = client.get("/enterprise/v1/identity", headers={"x-arenyxa-correlation-id": "trace:one"})
        assert first.status_code == 200
        assert first.headers["x-arenyxa-correlation-id"] == "trace:one"
        assert first.headers["cache-control"] == "no-store"
        assert first.headers["x-content-type-options"] == "nosniff"
        second = client.get("/enterprise/v1/health")
        assert second.status_code == 200
        third = client.get("/enterprise/v1/health")
        assert third.status_code == 429
        assert third.headers.get("x-arenyxa-correlation-id", "").startswith("corr-")


def test_authenticated_restore_rekeys_auth_throttle_state(tmp_path: Path, monkeypatch) -> None:
    import arenyxa.enterprise.identity as identity_module
    import arenyxa.enterprise.transport_security as transport_module

    now = [1_700_000_000.0]
    monkeypatch.setattr(identity_module.time, "time", lambda: now[0])
    monkeypatch.setattr(transport_module.time, "time", lambda: now[0])
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    backup = service.backup(tmp_path / "security-backup.aryxbak.json", VAULT_PASSWORD)
    service.logout()
    with pytest.raises(Exception):
        service.login("root", "Wrong-Password-Long-0001")
    assert service._auth_throttle_path.exists()
    service.lock()
    service.restore(backup, VAULT_PASSWORD)
    service.unlock(VAULT_PASSWORD)
                                                                                                  
                                                                                                     
    assert service.login("root", ADMIN_PASSWORD)
