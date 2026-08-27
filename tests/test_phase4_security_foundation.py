from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from arenyxa.compat import UTC
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security import (
    AuditLog,
    CNGKeyProtectionAdapter,
    PolicyEffect,
    PolicyRule,
    SecurityKernel,
    SecretBuffer,
    TPMKeyProtectionAdapter,
    TrustDomain,
)


def _allow(kernel: SecurityKernel, domain: TrustDomain, capability: str, resource: str = "*") -> None:
    kernel.add_policy(PolicyRule(
        id=f"allow-{domain.value}-{capability}",
        trust_domain=domain,
        capabilities=(capability,),
        resources=(resource,),
        effect=PolicyEffect.ALLOW,
    ))


def test_trust_domains_are_strictly_separated() -> None:
    kernel = SecurityKernel()
    developer = kernel.state.create_identity(TrustDomain.DEVELOPER)
    device = kernel.state.create_device(TrustDomain.DEVELOPER)
    session = kernel.issue_session(developer.id, capabilities=["runtime.debug"], device_id=device.id)
    _allow(kernel, TrustDomain.DEVELOPER, "runtime.debug")
    assert kernel.authorize(session, "runtime.debug", "runtime/core").allowed is True
                                                                          
    denied = kernel.authorize(session, "dataset.read", "dataset:Finance")
    assert denied.allowed is False
    assert denied.code == "TRUST_DOMAIN_VIOLATION"
    with pytest.raises(ArenyxaError) as captured:
        kernel.issue_session(developer.id, capabilities=["enterprise.account.manage"], device_id=device.id)
    assert captured.value.code == "TRUST_DOMAIN_VIOLATION"


def test_default_deny_and_backend_require_path() -> None:
    kernel = SecurityKernel()
    identity = kernel.state.create_identity(TrustDomain.PERSONAL)
    session = kernel.issue_session(identity.id, capabilities=["project.read"])
    assert kernel.authorize(session, "project.read", "project:one").allowed is False
    with pytest.raises(ArenyxaError) as captured:
        kernel.require(session, "project.read", "project:one")
    assert captured.value.code == "AUTHORIZATION_DENIED"
    _allow(kernel, TrustDomain.PERSONAL, "project.read", "project:*")
    assert kernel.execute(session, "project.read", "project:one", lambda: 42) == 42


def test_unauthorized_expired_and_revoked_device_paths_are_denied() -> None:
    kernel = SecurityKernel()
    identity = kernel.state.create_identity(TrustDomain.PERSONAL)
    device = kernel.state.create_device(TrustDomain.PERSONAL)
    session = kernel.issue_session(identity.id, capabilities=["task.run"], device_id=device.id)
    _allow(kernel, TrustDomain.PERSONAL, "task.run")
    assert kernel.authorize(None, "task.run", "task:x").code == "SESSION_REQUIRED"

    expired = kernel.issue_session(identity.id, capabilities=["task.run"], device_id=device.id)
    expired.issued_at = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    expired.expires_at = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    assert kernel.authorize(expired, "task.run", "task:x").code == "SESSION_EXPIRED"

    kernel.state.revoke_device(device.id)
    denied = kernel.authorize(session, "task.run", "task:x")
    assert denied.allowed is False
    assert denied.code in {"DEVICE_REVOKED", "DEVICE_GENERATION_REVOKED"}


def test_identity_generation_revokes_existing_session() -> None:
    kernel = SecurityKernel()
    identity = kernel.state.create_identity(TrustDomain.PERSONAL)
    session = kernel.issue_session(identity.id, capabilities=["project.read"])
    _allow(kernel, TrustDomain.PERSONAL, "project.read")
    assert kernel.authorize(session, "project.read", "p").allowed is True
    kernel.state.bump_identity_generation(identity.id)
    assert kernel.authorize(session, "project.read", "p").code == "SESSION_GENERATION_REVOKED"


def test_policy_context_and_explicit_deny_override_allow() -> None:
    kernel = SecurityKernel()
    identity = kernel.state.create_identity(TrustDomain.ENTERPRISE)
    session = kernel.issue_session(identity.id, capabilities=["dataset.read"])
    kernel.add_policy(PolicyRule(
        id="finance-allow", trust_domain=TrustDomain.ENTERPRISE,
        capabilities=("dataset.read",), resources=("dataset:Finance",),
        conditions={"network": "office"}, effect=PolicyEffect.ALLOW, priority=10,
    ))
    assert kernel.authorize(session, "dataset.read", "dataset:Finance", context={"network": "office"}).allowed
    assert not kernel.authorize(session, "dataset.read", "dataset:Finance", context={"network": "public"}).allowed
    kernel.add_policy(PolicyRule(
        id="maintenance-deny", trust_domain=TrustDomain.ENTERPRISE,
        capabilities=("dataset.read",), resources=("dataset:Finance",),
        conditions={"maintenance": True}, effect=PolicyEffect.DENY, priority=100,
    ))
    denied = kernel.authorize(
        session, "dataset.read", "dataset:Finance", context={"network": "office", "maintenance": True}
    )
    assert denied.allowed is False
    assert denied.code == "POLICY_DENY"


def test_audit_event_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    kernel = SecurityKernel(audit=AuditLog(path))
    identity = kernel.state.create_identity(TrustDomain.PERSONAL)
    session = kernel.issue_session(identity.id, capabilities=["project.read"])
    _allow(kernel, TrustDomain.PERSONAL, "project.read")
    kernel.authorize(session, "project.read", "project:1", correlation_id="corr-1")
    assert kernel.audit.verify() == (True, "ok")
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("project:1", "project:tampered", 1), encoding="utf-8")
    valid, reason = AuditLog(path).verify()
    assert valid is False
    assert "hash" in reason


def test_secret_buffer_zeroization_best_effort() -> None:
    secret = SecretBuffer(bytearray(b"super-secret"))
    view = secret.view()
    assert bytes(view) == b"super-secret"
    secret.zeroize()
    assert bytes(view) == b"\x00" * len(b"super-secret")
    with pytest.raises(RuntimeError):
        secret.copy_bytes()


def test_cng_and_tpm_adapters_refuse_unconfigured_use() -> None:
    for adapter in (CNGKeyProtectionAdapter(), TPMKeyProtectionAdapter()):
        assert adapter.available() is False
        with pytest.raises(ArenyxaError) as captured:
            adapter.protect(b"secret")
        assert captured.value.code == "KEY_PROTECTION_NOT_CONFIGURED"


def test_audit_fields_are_bounded_before_persistence(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.emit(
        actor="a" * 10_000,
        action="b" * 10_000,
        resource="r" * 100_000,
        decision="deny" * 1000,
        trust_domain=TrustDomain.PERSONAL,
        device="d" * 10_000,
        correlation_id="c" * 10_000,
        reason="x" * 10_000,
    )
    assert path.stat().st_size < 16 * 1024
    assert audit.verify() == (True, "ok")


def test_corrupted_existing_audit_chain_refuses_append(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.emit(
        actor="actor",
        action="project.read",
        resource="project:1",
        decision="allow",
        trust_domain=TrustDomain.PERSONAL,
    )
    path.write_bytes(path.read_bytes() + b'{"partial":')
    reopened = AuditLog(path)
    assert reopened.appendable is False
    valid, reason = reopened.verify()
    assert valid is False
    assert "invalid" in reason
    with pytest.raises(ArenyxaError) as captured:
        reopened.emit(
            actor="actor",
            action="project.read",
            resource="project:2",
            decision="allow",
            trust_domain=TrustDomain.PERSONAL,
        )
    assert captured.value.code == "AUDIT_INTEGRITY_BROKEN"


def test_session_validator_accepts_naive_test_clock_as_utc() -> None:
    kernel = SecurityKernel()
    identity = kernel.state.create_identity(TrustDomain.PERSONAL)
    session = kernel.issue_session(identity.id, capabilities=["project.read"])
    naive_now = datetime.now(UTC).replace(tzinfo=None)
    validation = kernel.sessions.validate(session, now=naive_now)
    assert validation.valid is True
