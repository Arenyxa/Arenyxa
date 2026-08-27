from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.application.developer_access import (
    DeveloperAccessManager,
    RootStartupSecurityStatus,
    RootWorkstationBinding,
    root_owner_startup_attempt_budget,
)
from arenyxa.application.developer_identity import create_developer_identity, sign_login_challenge
from arenyxa.application.developer_validation import DeveloperFaultInjectionSuite
from arenyxa.application.reliability import RecoveryTaxonomy
from arenyxa.compat import UTC
from arenyxa.security import SecurityKernel
from arenyxa.security.key_protection import KeyProtectionAdapter
from arenyxa.security.developer_trust_anchors import EMBEDDED_DEVELOPER_ROOTS
from arenyxa.security.developer_credentials import (
    DEVELOPER_SCHEMA,
    ISSUER_SCHEMA,
    LOGIN_BUNDLE_SCHEMA,
    OWNER_LOGIN_BUNDLE_SCHEMA,
    OWNER_SCHEMA,
    ROOT_SCHEMA,
    DEVELOPER_CAPABILITIES,
    DeveloperRevocationSet,
    DeveloperTrustStore,
    b64u_encode,
    canonical_json,
    key_fingerprint,
)


def _raw_public(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _signed(payload: dict, private: Ed25519PrivateKey, signer_key_id: str) -> dict:
    value = b64u_encode(private.sign(canonical_json(payload)))
    return {
        **payload,
        "signature": {"algorithm": "Ed25519", "signer_key_id": signer_key_id, "value": value},
    }


def _chain(capabilities=("runtime.debug",), *, developer_request: dict | None = None):
    now = datetime.now(UTC).replace(microsecond=0)
    root_private = Ed25519PrivateKey.generate()
    root_public = _raw_public(root_private)
    root_key_id = "devroot_phase6_test"
    root = _signed(
        {
            "schema": ROOT_SCHEMA,
            "key_id": root_key_id,
            "algorithm": "Ed25519",
            "public_key": b64u_encode(root_public),
            "fingerprint": key_fingerprint(root_public),
            "owner_label": "Arenyxa Phase6 Test Root",
            "created_at": now.isoformat(),
        },
        root_private,
        root_key_id,
    )

    issuer_private = Ed25519PrivateKey.generate()
    issuer_public = _raw_public(issuer_private)
    issuer_key_id = "issuer_phase6_test"
    allowed = ["runtime.debug", "profiler", "stress_test", "fault_injection", "internal_logs", "release.verify"]
    issuer = _signed(
        {
            "schema": ISSUER_SCHEMA,
            "issuer_key_id": issuer_key_id,
            "root_key_id": root_key_id,
            "algorithm": "Ed25519",
            "public_key": b64u_encode(issuer_public),
            "fingerprint": key_fingerprint(issuer_public),
            "label": "Phase6 Test Issuer",
            "allowed_capabilities": allowed,
            "not_before": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "created_at": now.isoformat(),
        },
        root_private,
        root_key_id,
    )

    if developer_request is None:
        developer_private = Ed25519PrivateKey.generate()
        developer_public = _raw_public(developer_private)
        developer_id = "dev.phase6"
        email = "developer@example.com"
    else:
        developer_private = None
        developer_public = __import__("base64").urlsafe_b64decode(
            str(developer_request["public_key"]) + "=" * ((4 - len(str(developer_request["public_key"])) % 4) % 4)
        )
        developer_id = str(developer_request["developer_id"])
        email = str(developer_request["email"])
    cert = _signed(
        {
            "schema": DEVELOPER_SCHEMA,
            "serial": "0123456789abcdef0123456789abcdef",
            "developer_id": developer_id,
            "email": email,
            "public_key": b64u_encode(developer_public),
            "fingerprint": key_fingerprint(developer_public),
            "capabilities": sorted(capabilities),
            "issuer_key_id": issuer_key_id,
            "not_before": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(days=7)).isoformat(),
            "issued_at": now.isoformat(),
        },
        issuer_private,
        issuer_key_id,
    )
    bundle = {"schema": LOGIN_BUNDLE_SCHEMA, "developer_certificate": cert, "issuer_certificate": issuer}
    return root_private, root, issuer, developer_private, cert, bundle


def _owner_chain():
    now = datetime.now(UTC).replace(microsecond=0)
    root_private = Ed25519PrivateKey.generate()
    root_public = _raw_public(root_private)
    root_key_id = "devroot_owner_phase6_test"
    root = _signed({
        "schema": ROOT_SCHEMA, "key_id": root_key_id, "algorithm": "Ed25519",
        "public_key": b64u_encode(root_public), "fingerprint": key_fingerprint(root_public),
        "owner_label": "Arenyxa Owner Test Root", "created_at": now.isoformat(),
    }, root_private, root_key_id)

    issuer_private = Ed25519PrivateKey.generate()
    issuer_public = _raw_public(issuer_private)
    issuer_key_id = "issuer_owner_phase6_test"
    capabilities = sorted(DEVELOPER_CAPABILITIES)
    issuer = _signed({
        "schema": ISSUER_SCHEMA, "issuer_key_id": issuer_key_id, "root_key_id": root_key_id,
        "algorithm": "Ed25519", "public_key": b64u_encode(issuer_public),
        "fingerprint": key_fingerprint(issuer_public), "label": "Owner Test Issuer",
        "allowed_capabilities": capabilities,
        "not_before": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(), "created_at": now.isoformat(),
    }, root_private, root_key_id)

    owner_private = Ed25519PrivateKey.generate()
    owner_public = _raw_public(owner_private)
    owner = _signed({
        "schema": OWNER_SCHEMA, "serial": "abcdef0123456789abcdef0123456789",
        "owner_id": "root.owner", "email": "root-owner@example.com",
        "public_key": b64u_encode(owner_public), "fingerprint": key_fingerprint(owner_public),
        "capabilities": capabilities, "issuer_key_id": issuer_key_id,
        "not_before": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=7)).isoformat(), "issued_at": now.isoformat(),
    }, issuer_private, issuer_key_id)
    bundle = {"schema": OWNER_LOGIN_BUNDLE_SCHEMA, "owner_certificate": owner, "issuer_certificate": issuer}
    return root_private, root, issuer, owner_private, owner, bundle


def _manager(root: dict) -> tuple[SecurityKernel, DeveloperAccessManager]:
    kernel = SecurityKernel()
    manager = DeveloperAccessManager(kernel, trust_store=DeveloperTrustStore([root]))
    return kernel, manager


def test_certificate_copy_without_private_key_cannot_login_and_challenge_is_one_shot() -> None:
    _, root, _, developer_private, _, bundle = _chain(["runtime.debug"])
    assert developer_private is not None
    _, manager = _manager(root)
    challenge = manager.begin_login(bundle)
    wrong_private = Ed25519PrivateKey.generate()
    wrong_signature = b64u_encode(wrong_private.sign(canonical_json(challenge.to_dict())))
    with pytest.raises(Exception) as captured:
        manager.complete_login(challenge.challenge_id, wrong_signature)
    assert getattr(captured.value, "code", "") == "DEVELOPER_PRIVATE_KEY_PROOF_INVALID"

                                                                                                 
    correct_signature = b64u_encode(developer_private.sign(canonical_json(challenge.to_dict())))
    with pytest.raises(Exception) as captured:
        manager.complete_login(challenge.challenge_id, correct_signature)
    assert getattr(captured.value, "code", "") == "DEVELOPER_CHALLENGE_INVALID"


def test_capabilities_are_certificate_scoped_and_do_not_cross_enterprise_boundary() -> None:
    _, root, _, developer_private, _, bundle = _chain(["runtime.debug"])
    assert developer_private is not None
    kernel, manager = _manager(root)
    challenge = manager.begin_login(bundle)
    session = manager.complete_login(
        challenge.challenge_id,
        b64u_encode(developer_private.sign(canonical_json(challenge.to_dict()))),
    )
    manager.require("runtime.debug", "debug-console")
    with pytest.raises(Exception):
        manager.require("stress_test", "stress-test/standard")
    with pytest.raises(Exception):
        kernel.require(session, "dataset.read", "dataset:Finance")
    assert "dataset.read" not in session.granted_capabilities
    assert "all" not in session.granted_capabilities


def test_stress_capability_and_high_risk_confirmation_are_both_required() -> None:
    _, root, _, developer_private, _, bundle = _chain(["stress_test"])
    assert developer_private is not None
    _, manager = _manager(root)
    challenge = manager.begin_login(bundle)
    manager.complete_login(
        challenge.challenge_id,
        b64u_encode(developer_private.sign(canonical_json(challenge.to_dict()))),
    )
    with pytest.raises(Exception) as captured:
        manager.require("stress_test", "stress-test/extreme", high_risk=True, risk_confirmed=False)
    assert getattr(captured.value, "code", "") == "DEVELOPER_HIGH_RISK_CONFIRMATION_REQUIRED"
    manager.require("stress_test", "stress-test/extreme", high_risk=True, risk_confirmed=True)


def test_personal_key_vault_interoperates_with_official_certificate_challenge() -> None:
    passphrase = "developer-personal-passphrase-0001"
    vault, request = create_developer_identity("dev.personal", "personal@example.com", passphrase, scrypt_n=2**14)
    _, root, _, _, _, bundle = _chain(["runtime.debug", "profiler"], developer_request=request)
    _, manager = _manager(root)
    challenge = manager.begin_login(bundle)
    signature = sign_login_challenge(vault, passphrase, challenge.to_dict())
    manager.complete_login(challenge.challenge_id, signature)
    status = manager.status()
    assert status.authenticated is True
    assert status.developer_id == "dev.personal"
    assert set(status.capabilities) == {"runtime.debug", "profiler"}
    with pytest.raises(Exception):
        sign_login_challenge(vault, "incorrect-passphrase-0000", challenge.to_dict())


def test_tampered_email_or_capability_cannot_use_email_as_security_root() -> None:
    _, root, _, _, _, bundle = _chain(["runtime.debug"])
    _, manager = _manager(root)
    tampered = {
        **bundle,
        "developer_certificate": {**bundle["developer_certificate"], "email": "attacker@example.com"},
    }
    with pytest.raises(Exception):
        manager.begin_login(tampered)
    escalated = {
        **bundle,
        "developer_certificate": {**bundle["developer_certificate"], "capabilities": ["runtime.debug", "stress_test"]},
    }
    with pytest.raises(Exception):
        manager.begin_login(escalated)


def test_untrusted_root_fails_closed() -> None:
    _, _, _, _, _, bundle = _chain(["runtime.debug"])
    manager = DeveloperAccessManager(SecurityKernel(), trust_store=DeveloperTrustStore())
    assert manager.ready is False
    with pytest.raises(Exception):
        manager.begin_login(bundle)


def test_root_owner_uses_owner_device_certificate_not_root_private_key_and_remains_developer_trust() -> None:
    root_private, root, _, owner_private, _, bundle = _owner_chain()
    kernel, manager = _manager(root)
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    session = manager.complete_root_owner_login(challenge.challenge_id, signature)
    assert manager.status().kind == "root_owner"
    manager.require("stress_test", "stress-test/standard", high_risk=True, risk_confirmed=True)
    with pytest.raises(Exception):
        kernel.require(session, "enterprise.account.manage", "enterprise:accounts")
    assert "enterprise.account.manage" not in session.granted_capabilities

                                                                                                 
    challenge = manager.begin_root_owner_login(bundle)
    wrong_signature = b64u_encode(root_private.sign(canonical_json(challenge.to_dict())))
    with pytest.raises(Exception) as captured:
        manager.complete_root_owner_login(challenge.challenge_id, wrong_signature)
    assert getattr(captured.value, "code", "") == "ROOT_OWNER_PRIVATE_KEY_PROOF_INVALID"


def test_synthetic_fault_injection_is_bounded_to_recovery_taxonomy() -> None:
    context = SimpleNamespace(recovery_taxonomy=RecoveryTaxonomy())
    report = DeveloperFaultInjectionSuite(context).run("all")
    assert report.healthy is True
    assert [item.classification for item in report.scenarios] == [
        "transient", "recoverable", "configuration", "permission", "corruption", "fatal"
    ]


def test_runtime_json_cannot_promote_an_arbitrary_developer_root(tmp_path: Path) -> None:
    
    _, malicious_root, _, _, _, _ = _chain(["runtime.debug"])
    package_root = tmp_path / "package"
    resources = package_root / "resources"
    resources.mkdir(parents=True)
    (resources / "developer_trust_store.json").write_text(
        __import__("json").dumps({"schema": "arenyxa.developer-trust-store/v1", "roots": [malicious_root]}),
        encoding="utf-8",
    )
    (resources / "developer_revocations.json").write_text(
        __import__("json").dumps({"schema": "arenyxa.developer-revocation-set/v1", "revocations": []}),
        encoding="utf-8",
    )
    manager = DeveloperAccessManager.local(SecurityKernel(), tmp_path / "data", package_root)
    trusted_ids = {str(item["key_id"]) for item in manager.trust_store.roots()}
    embedded_ids = {str(item["key_id"]) for item in EMBEDDED_DEVELOPER_ROOTS}
    assert trusted_ids == embedded_ids
    assert str(malicious_root["key_id"]) not in trusted_ids
    assert manager.ready is bool(embedded_ids)


def test_failed_mandatory_login_audit_never_publishes_a_session() -> None:
    from arenyxa.security.audit import AuditLog

    class FailLoginAudit(AuditLog):
        def emit(self, **kwargs):                          
            if kwargs.get("action") == "developer.login" and kwargs.get("decision") == "allow":
                raise OSError("synthetic audit disk failure")
            return super().emit(**kwargs)

    _, root, _, developer_private, _, bundle = _chain(["runtime.debug"])
    assert developer_private is not None
    kernel = SecurityKernel(audit=FailLoginAudit())
    manager = DeveloperAccessManager(kernel, trust_store=DeveloperTrustStore([root]))
    challenge = manager.begin_login(bundle)
    signature = b64u_encode(developer_private.sign(canonical_json(challenge.to_dict())))
    with pytest.raises(OSError):
        manager.complete_login(challenge.challenge_id, signature)
    assert manager.status().authenticated is False
    assert len(kernel.state._identities) == 0
    assert len(kernel.state._revoked_sessions) == 0


def test_login_logout_cycles_do_not_grow_ephemeral_security_state() -> None:
    _, root, _, developer_private, _, bundle = _chain(["runtime.debug"])
    assert developer_private is not None
    kernel, manager = _manager(root)
    for _ in range(25):
        challenge = manager.begin_login(bundle)
        signature = b64u_encode(developer_private.sign(canonical_json(challenge.to_dict())))
        manager.complete_login(challenge.challenge_id, signature)
        assert len(kernel.state._identities) == 1
        manager.logout()
        assert len(kernel.state._identities) == 0
        assert len(kernel.state._revoked_sessions) == 0


def test_security_json_rejects_duplicate_keys_and_base64_is_canonical(tmp_path: Path) -> None:
    from arenyxa.security.developer_credentials import b64u_decode, load_json_object

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
    with pytest.raises(Exception) as captured:
        load_json_object(duplicate)
    assert getattr(captured.value, "code", "") == "DEVELOPER_ARTIFACT_INVALID"
    with pytest.raises(Exception):
        b64u_decode("AQ==", max_bytes=16)
    assert b64u_decode("AQ", max_bytes=16) == b"\x01"


def test_personal_vault_rejects_malformed_kdf_before_unlock_and_will_not_sign_arbitrary_payload() -> None:
    from arenyxa.application.developer_identity import sign_login_challenge

    vault, _ = create_developer_identity("dev.vault", "vault@example.com", "developer-passphrase-long-001", scrypt_n=2**14)
    malformed = {**vault, "kdf": {**vault["kdf"], "n": "not-an-integer"}}
    with pytest.raises(Exception) as captured:
        sign_login_challenge(malformed, "developer-passphrase-long-001", {"not": "a-login-challenge"})
    assert getattr(captured.value, "code", "") == "DEVELOPER_VAULT_INVALID"

    with pytest.raises(Exception) as captured:
        sign_login_challenge(vault, "developer-passphrase-long-001", {"not": "a-login-challenge"})
    assert getattr(captured.value, "code", "") == "DEVELOPER_CHALLENGE_INVALID"


def test_build_embedding_tool_targets_python_trust_anchors_not_runtime_json() -> None:
    source = (Path(__file__).resolve().parents[1] / "scripts" / "embed_developer_root.py").read_text(encoding="utf-8")
    assert "developer_trust_anchors.py" in source
    assert "developer_trust_store.json" not in source


def test_challenge_audit_failure_removes_unpublished_pending_challenge() -> None:
    from arenyxa.security.audit import AuditLog

    class FailChallengeAudit(AuditLog):
        def emit(self, **kwargs):                          
            if str(kwargs.get("action", "")).endswith(".challenge"):
                raise OSError("synthetic challenge audit failure")
            return super().emit(**kwargs)

    _, root, _, _, _, bundle = _chain(["runtime.debug"])
    kernel = SecurityKernel(audit=FailChallengeAudit())
    manager = DeveloperAccessManager(kernel, trust_store=DeveloperTrustStore([root]))
    with pytest.raises(OSError):
        manager.begin_login(bundle)
    assert manager._pending == {}
    _, owner_root, _, _, _, owner_bundle = _owner_chain()
    owner_manager = DeveloperAccessManager(kernel, trust_store=DeveloperTrustStore([owner_root]))
    with pytest.raises(OSError):
        owner_manager.begin_root_owner_login(owner_bundle)
    assert owner_manager._pending == {}


def test_root_owner_challenge_is_short_lived_for_local_device_proof() -> None:
    from datetime import datetime

    _, root, _, _, _, bundle = _owner_chain()
    _, manager = _manager(root)
    challenge = manager.begin_root_owner_login(bundle)
    issued = datetime.fromisoformat(challenge.to_dict()["issued_at"])
    expires = datetime.fromisoformat(challenge.to_dict()["expires_at"])
    assert (expires - issued).total_seconds() == 60


def test_public_developer_profile_has_no_stress_test_command_bypass() -> None:
    source = ((Path(__file__).resolve().parents[1] / "src" / "arenyxa" / "presentation" / "pages" / "tools.py").read_text(encoding="utf-8") + "\n" + (Path(__file__).resolve().parents[1] / "src" / "arenyxa" / "presentation" / "pages" / "tools_terminal_execution.py").read_text(encoding="utf-8"))
    assert 'if profile == "quick":\n            if not self._developer_validation_authorized()' not in source
    assert 'manager.require("stress_test", "stress-test/quick")' in source
    assert "Developer Profile 不能运行内部压力测试" in source


class _BoundTestProtector(KeyProtectionAdapter):
    name = "test-device-bound"

    def __init__(self, key: bytes) -> None:
        self.key = bytes(key)

    def available(self) -> bool:
        return True

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        import hashlib, hmac
        payload = bytes(plaintext)
        mac = hmac.new(self.key, purpose.encode("utf-8") + payload, hashlib.sha256).digest()
        return mac + payload

    def unprotect(self, ciphertext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        import hashlib, hmac
        raw = bytes(ciphertext)
        if len(raw) < 32:
            raise ValueError("invalid protected value")
        mac, payload = raw[:32], raw[32:]
        expected = hmac.new(self.key, purpose.encode("utf-8") + payload, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise ValueError("wrong workstation binding")
        return payload


def test_root_workstation_binding_issues_explicit_platform_root_but_not_enterprise_backdoor(tmp_path: Path) -> None:
    _, root, _, owner_private, _, bundle = _owner_chain()
    kernel = SecurityKernel()
    trust = DeveloperTrustStore([root])
    revocations = DeveloperRevocationSet()
    binding = RootWorkstationBinding(
        tmp_path, trust, revocations, protector=_BoundTestProtector(b"root-workstation-a"),
    )
    manager = DeveloperAccessManager(
        kernel, trust_store=trust, revocations=revocations, root_workstation=binding,
    )
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    session = manager.complete_root_owner_login(challenge.challenge_id, signature)
    assert "platform.root" in session.granted_capabilities
    assert binding.detect().active is True

                                                                               
    decision = kernel.authorize(session, "project.read", "project:any")
    assert decision.allowed is True and decision.code == "PLATFORM_ROOT_ALLOW"
                                                                             
    enterprise = kernel.authorize(session, "enterprise.account.manage", "enterprise:customer/accounts")
    assert enterprise.allowed is False and enterprise.code == "ROOT_ENTERPRISE_BOUNDARY"

    manager.logout()

    # Full restart: the protected binding is only a re-authentication trigger.
    # It must never mint platform.root without a fresh Owner-device key proof.
    restarted_kernel = SecurityKernel()
    restarted_binding = RootWorkstationBinding(
        tmp_path, trust, revocations, protector=_BoundTestProtector(b"root-workstation-a"),
    )
    restarted_manager = DeveloperAccessManager(
        restarted_kernel, trust_store=trust, revocations=revocations, root_workstation=restarted_binding,
    )
    assert restarted_manager.activate_root_workstation_session() is None
    assert restarted_manager.status().authenticated is False
    assert restarted_binding.detect().reason == "VERIFIED"
    assert restarted_manager.root_startup_security_status().registered is True

    rebound_bundle = restarted_manager.load_bound_root_owner_bundle()
    challenge = restarted_manager.begin_root_owner_login(rebound_bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    renewed = restarted_manager.complete_root_owner_login(challenge.challenge_id, signature)
    assert "platform.root" in renewed.granted_capabilities
    assert restarted_manager.status().kind == "root_owner"
    assert restarted_manager.root_startup_security_status().locked is False

                                                                               
    copied = RootWorkstationBinding(
        tmp_path, trust, revocations, protector=_BoundTestProtector(b"different-device"),
    )
    assert copied.detect().active is False


class _FailingBoundTestProtector(_BoundTestProtector):
    name = "bound-test-failing"

    def protect(self, plaintext: bytes, *, purpose: str = "Arenyxa") -> bytes:
        raise OSError("simulated workstation protector failure")


def test_root_owner_login_fails_closed_when_supported_workstation_binding_cannot_persist(tmp_path: Path) -> None:
    _, root, _, owner_private, _, bundle = _owner_chain()
    kernel = SecurityKernel()
    trust = DeveloperTrustStore([root])
    revocations = DeveloperRevocationSet()
    binding = RootWorkstationBinding(
        tmp_path, trust, revocations, protector=_FailingBoundTestProtector(b"root-workstation-failure"),
    )
    manager = DeveloperAccessManager(
        kernel, trust_store=trust, revocations=revocations, root_workstation=binding,
    )
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    with pytest.raises(Exception) as failure:
        manager.complete_root_owner_login(challenge.challenge_id, signature)
    assert getattr(failure.value, "code", "") == "ROOT_WORKSTATION_BIND_FAILED"
    assert manager.status().authenticated is False
    assert binding.path.exists() is False


def test_root_workstation_startup_failures_persist_and_valid_owner_reauth_clears_lock(tmp_path: Path) -> None:
    _, root, _, owner_private, _, bundle = _owner_chain()
    trust = DeveloperTrustStore([root])
    revocations = DeveloperRevocationSet()
    protector = _BoundTestProtector(b"root-workstation-lock-state")
    manager = DeveloperAccessManager(
        SecurityKernel(),
        trust_store=trust,
        revocations=revocations,
        root_workstation=RootWorkstationBinding(tmp_path, trust, revocations, protector=protector),
    )
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    manager.complete_root_owner_login(challenge.challenge_id, signature)
    manager.logout()

    for index in range(3):
        state = manager.record_root_startup_failure(f"FAIL_{index}")
    assert state.locked is True
    assert state.failed_attempts == 3

    restarted = DeveloperAccessManager(
        SecurityKernel(),
        trust_store=trust,
        revocations=revocations,
        root_workstation=RootWorkstationBinding(tmp_path, trust, revocations, protector=protector),
    )
    assert restarted.root_startup_security_status().locked is True
    assert restarted.activate_root_workstation_session() is None

    challenge = restarted.begin_root_owner_login(restarted.load_bound_root_owner_bundle())
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    restarted.complete_root_owner_login(challenge.challenge_id, signature)
    cleared = restarted.root_startup_security_status()
    assert cleared.locked is False
    assert cleared.failed_attempts == 0


def test_root_workstation_startup_cancel_enters_recoverable_security_lock(tmp_path: Path) -> None:
    _, root, _, owner_private, _, bundle = _owner_chain()
    trust = DeveloperTrustStore([root])
    revocations = DeveloperRevocationSet()
    protector = _BoundTestProtector(b"root-workstation-cancel-lock")
    manager = DeveloperAccessManager(
        SecurityKernel(), trust_store=trust, revocations=revocations,
        root_workstation=RootWorkstationBinding(tmp_path, trust, revocations, protector=protector),
    )
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    manager.complete_root_owner_login(challenge.challenge_id, signature)
    manager.logout()

    locked = manager.record_root_startup_cancel()
    assert locked.locked is True
    assert locked.reason == "ROOT_OWNER_STARTUP_AUTH_CANCELLED"
    assert manager.activate_root_workstation_session() is None


def test_root_owner_startup_attempt_budget_persists_failures_across_process_restarts() -> None:
    fresh = RootStartupSecurityStatus(True, False, 0, 3, "READY")
    one_failed = RootStartupSecurityStatus(True, False, 1, 3, "FAIL_1")
    two_failed = RootStartupSecurityStatus(True, False, 2, 3, "FAIL_2")
    locked = RootStartupSecurityStatus(True, True, 3, 3, "LOCKED")
    assert root_owner_startup_attempt_budget(fresh) == 3
    assert root_owner_startup_attempt_budget(one_failed) == 2
    assert root_owner_startup_attempt_budget(two_failed) == 1
    assert root_owner_startup_attempt_budget(locked) == 1


def test_root_capability_state_detects_trusted_root_key_without_auto_authority(tmp_path: Path) -> None:
    _, root, _, owner_private, _, bundle = _owner_chain()
    trust = DeveloperTrustStore([root])
    revocations = DeveloperRevocationSet()
    protector = _BoundTestProtector(b"root-capability-phase1")
    manager = DeveloperAccessManager(
        SecurityKernel(),
        trust_store=trust,
        revocations=revocations,
        root_workstation=RootWorkstationBinding(tmp_path, trust, revocations, protector=protector),
    )
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    manager.complete_root_owner_login(challenge.challenge_id, signature)

    active = manager.root_capability_state()
    assert active.registered is True
    assert active.binding_valid is True
    assert active.root_key_present is True
    assert active.device_binding_valid is True
    assert active.available is True
    assert active.authority_active is True
    assert active.authentication_required is False
    assert active.root_key_id == root["key_id"]
    assert active.root_fingerprint == root["fingerprint"]

    manager.logout()
    restarted = DeveloperAccessManager(
        SecurityKernel(),
        trust_store=trust,
        revocations=revocations,
        root_workstation=RootWorkstationBinding(tmp_path, trust, revocations, protector=protector),
    )
    restored = restarted.root_capability_state()
    assert restored.registered is True
    assert restored.binding_valid is True
    assert restored.root_key_present is True
    assert restored.device_binding_valid is True
    assert restored.available is True
    assert restored.authority_active is False
    assert restored.authentication_required is True
    assert restored.reason == "ROOT_OWNER_AUTH_REQUIRED"
    assert restarted.activate_root_workstation_session() is None


def test_root_capability_probe_is_read_only_and_preserves_binding_bytes(tmp_path: Path) -> None:
    _, root, _, owner_private, _, bundle = _owner_chain()
    trust = DeveloperTrustStore([root])
    revocations = DeveloperRevocationSet()
    protector = _BoundTestProtector(b"root-capability-read-only")
    binding = RootWorkstationBinding(tmp_path, trust, revocations, protector=protector)
    manager = DeveloperAccessManager(
        SecurityKernel(), trust_store=trust, revocations=revocations, root_workstation=binding,
    )
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    manager.complete_root_owner_login(challenge.challenge_id, signature)
    manager.logout()

    binding_before = binding.path.read_bytes()
    auth_before = binding.auth_state_path.read_bytes()
    first = manager.root_capability_state()
    second = manager.root_capability_state()

    assert first == second
    assert first.available is True
    assert binding.path.read_bytes() == binding_before
    assert binding.auth_state_path.read_bytes() == auth_before


def test_root_capability_probe_fails_closed_on_wrong_device_binding(tmp_path: Path) -> None:
    _, root, _, owner_private, _, bundle = _owner_chain()
    trust = DeveloperTrustStore([root])
    revocations = DeveloperRevocationSet()
    original = RootWorkstationBinding(
        tmp_path, trust, revocations, protector=_BoundTestProtector(b"root-capability-device-a"),
    )
    manager = DeveloperAccessManager(
        SecurityKernel(), trust_store=trust, revocations=revocations, root_workstation=original,
    )
    challenge = manager.begin_root_owner_login(bundle)
    signature = b64u_encode(owner_private.sign(canonical_json(challenge.to_dict())))
    manager.complete_root_owner_login(challenge.challenge_id, signature)
    manager.logout()

    copied = DeveloperAccessManager(
        SecurityKernel(),
        trust_store=trust,
        revocations=revocations,
        root_workstation=RootWorkstationBinding(
            tmp_path, trust, revocations, protector=_BoundTestProtector(b"root-capability-device-b"),
        ),
    )
    state = copied.root_capability_state()
    assert state.registered is True
    assert state.binding_valid is False
    assert state.available is False
    assert state.authority_active is False
    assert state.authentication_required is False
