from __future__ import annotations

from pathlib import Path

import pytest

from arenyxa.enterprise import EnterpriseGovernanceService, EnrollmentService, LocalEnterpriseIdentityService
from arenyxa.enterprise.coordinator import CoordinatorClient, OfficeCoordinatorService
from arenyxa.enterprise.enrollment import DeviceKeyStore, verify_enrollment_token, _canonical
from arenyxa.security import SecurityKernel

ADMIN_PASSWORD = "Phase8-Admin-Password!"
VAULT_PASSWORD = "Phase8-Vault-Passphrase!"


def stack(tmp_path: Path):
    identity = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    identity.create_enterprise("Arenyxa Test Enterprise", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    identity.login("root", ADMIN_PASSWORD)
    identity.step_up(ADMIN_PASSWORD)
    enrollment = EnrollmentService(identity, tmp_path)
    governance = EnterpriseGovernanceService(identity)
    coordinator = OfficeCoordinatorService(identity, enrollment, tmp_path)
    return identity, enrollment, governance, coordinator


def test_phase8_enrollment_is_one_shot_and_device_private_key_never_enters_token(tmp_path: Path) -> None:
    identity, enrollment, _governance, _coordinator = stack(tmp_path)
    account_id = identity.create_account("employee", "Employee", "Employee-Password-123!", ["member"])
    identity.step_up(ADMIN_PASSWORD)
    result = enrollment.create_campaign("First Wave", [account_id], ttl_seconds=3600)
    token = result["tokens"][0]
    payload = verify_enrollment_token(token)
    assert payload["account_id"] == account_id
    assert "private" not in str(token).lower()

    device_store = DeviceKeyStore(tmp_path / "employee-device.aryxdevice")
    public = device_store.create(payload["enterprise_id"], account_id)
    enrolled = enrollment.consume(token, public)
    assert enrolled["device_id"] == public["device_id"]
    assert device_store.path.read_text(encoding="utf-8").find(public["public_key"]) >= 0
    assert payload["secret"] not in device_store.path.read_text(encoding="utf-8")
    with pytest.raises(Exception) as replay:
        enrollment.consume(token, public)
    assert getattr(replay.value, "code", "") == "ENROLLMENT_REPLAY"


def test_phase8_domain_lock_requires_explicit_allow_once_for_other_enterprise(tmp_path: Path) -> None:
    store = DeviceKeyStore(tmp_path / "device.aryxdevice")
    store.create("enterprise-a", "account-a")
    with pytest.raises(Exception) as locked:
        store.assert_domain("enterprise-b")
    assert getattr(locked.value, "code", "") == "ENTERPRISE_DOMAIN_LOCKED"
    store.allow_once(300)
    store.assert_domain("enterprise-b")


def test_phase9_tls_coordinator_verifies_enterprise_identity_and_device_challenge(tmp_path: Path) -> None:
    identity, enrollment, _governance, coordinator = stack(tmp_path)
    account_id = identity.create_account("office-user", "Office User", "Office-User-Password!", ["member"])
    identity.step_up(ADMIN_PASSWORD)
    token = enrollment.create_campaign("Office", [account_id], ttl_seconds=3600)["tokens"][0]
    payload = verify_enrollment_token(token)
    device = DeviceKeyStore(tmp_path / "office-client.aryxdevice")
    public = device.create(payload["enterprise_id"], account_id)

    identity.step_up(ADMIN_PASSWORD)
    host, port = coordinator.start_tls("127.0.0.1", 0)
    try:
        client = CoordinatorClient(host, port, token["root_fingerprint"])
        health = client.verify_peer()
        assert health["running"] is True
        enrolled = client.enroll(token, public)
        assert enrolled["device_id"] == public["device_id"]
        challenge = client.challenge(public["device_id"])
        signature = device.sign(_canonical(challenge))
        session = client.authenticate(challenge["challenge_id"], signature)
        assert coordinator.validate_session(session["session_token"])["device_id"] == public["device_id"]
        with pytest.raises(Exception):
            client.authenticate(challenge["challenge_id"], signature)
    finally:
        coordinator.stop()


def test_phase10_workspace_resource_rbac_quota_and_two_person_approval(tmp_path: Path) -> None:
    identity, _enrollment, governance, _coordinator = stack(tmp_path)
    workspace = governance.create_workspace("Research")
    dataset = governance.register_resource("dataset", "Finance", workspace, quota={"rows": 100})
    identity.step_up(ADMIN_PASSWORD)
    governance.grant_role(dataset, "analyst", ["dataset.read", "dataset.export"])
    assert governance.reserve_quota(dataset, "rows", 80) == 80
    with pytest.raises(Exception) as exceeded:
        governance.reserve_quota(dataset, "rows", 30)
    assert getattr(exceeded.value, "code", "") == "GOVERNANCE_QUOTA_EXCEEDED"
    assert governance.release_quota(dataset, "rows", 20) == 60

    analyst_id = identity.create_account("analyst", "Analyst", "Analyst-Password-123!", ["analyst"])
    identity.logout()
    identity.login("analyst", "Analyst-Password-123!")
    assert governance.require_resource("dataset.read", dataset)["id"] == dataset
    with pytest.raises(Exception):
        governance.require_resource("dataset.write", dataset)
    identity.logout()
    identity.login("root", ADMIN_PASSWORD)
    identity.step_up(ADMIN_PASSWORD)

    second_admin = identity.create_account("admin2", "Admin Two", "Second-Admin-Password!", ["administrator"])
    approval = governance.request_approval("dataset.export", dataset, reason="Quarterly export")
    with pytest.raises(Exception) as self_review:
        governance.decide_approval(approval, True)
    assert getattr(self_review.value, "code", "") == "APPROVAL_SELF_REVIEW_DENIED"
    identity.logout()
    identity.login("admin2", "Second-Admin-Password!")
    identity.step_up("Second-Admin-Password!")
    governance.decide_approval(approval, True)
    governance.require_approval(approval, "dataset.export", dataset)
    assert governance.query_audit(resource="enterprise:governance", limit=50)


def test_phase8_failed_cross_enterprise_prepare_can_restore_exact_prior_device(tmp_path: Path) -> None:
    store = DeviceKeyStore(tmp_path / "device.aryxdevice")
    original = store.create("enterprise-a", "account-a")
    store.allow_once(300)
    before = store.path.read_bytes()
    replacement, rollback = store.prepare_enrollment("enterprise-b", "account-b")
    assert replacement["device_id"] != original["device_id"]
    assert store.load_public()["enterprise_id"] == "enterprise-b"
    store.rollback_prepared_enrollment(rollback)
    assert store.path.read_bytes() == before
    assert store.load_public()["enterprise_id"] == "enterprise-a"


def test_phase9_coordinator_service_lease_survives_human_logout_but_vault_lock_fails_closed(tmp_path: Path) -> None:
    identity, enrollment, _governance, coordinator = stack(tmp_path)
    account_id = identity.create_account("service-user", "Service User", "Service-User-Password!", ["member"])
    identity.step_up(ADMIN_PASSWORD)
    token = enrollment.create_campaign("Service", [account_id], ttl_seconds=3600)["tokens"][0]
    payload = verify_enrollment_token(token)
    device = DeviceKeyStore(tmp_path / "service-client.aryxdevice")
    public = device.create(payload["enterprise_id"], account_id)
    identity.step_up(ADMIN_PASSWORD)
    coordinator.start_tls("127.0.0.1", 0)
    try:
                                                                                                
                                                                       
        identity.logout()
        enrolled = coordinator.enroll(token, public)
        challenge = coordinator.create_challenge(enrolled["device_id"])
        signature = device.sign(_canonical(challenge))
                                                                                                    
        import base64
        sig_b64 = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
        session = coordinator.authenticate_device(challenge["challenge_id"], sig_b64)
        assert coordinator.validate_session(session["session_token"])["account_id"] == account_id
        identity.lock()
        with pytest.raises(Exception):
            coordinator.validate_session(session["session_token"])
    finally:
        coordinator.stop()


def test_phase9_device_session_retires_after_account_generation_change(tmp_path: Path) -> None:
    identity, enrollment, _governance, coordinator = stack(tmp_path)
    account_id = identity.create_account("generation-user", "Generation User", "Generation-User-Password!", ["member"])
    identity.step_up(ADMIN_PASSWORD)
    token = enrollment.create_campaign("Generation", [account_id], ttl_seconds=3600)["tokens"][0]
    payload = verify_enrollment_token(token)
    device = DeviceKeyStore(tmp_path / "generation-client.aryxdevice")
    public = device.create(payload["enterprise_id"], account_id)
    identity.step_up(ADMIN_PASSWORD)
    coordinator.start_tls("127.0.0.1", 0)
    try:
        enrolled = coordinator.enroll(token, public)
        challenge = coordinator.create_challenge(enrolled["device_id"])
        import base64
        signature = base64.urlsafe_b64encode(device.sign(_canonical(challenge))).decode("ascii").rstrip("=")
        session = coordinator.authenticate_device(challenge["challenge_id"], signature)
        assert coordinator.validate_session(session["session_token"])
        identity.step_up(ADMIN_PASSWORD)
        identity.change_password(account_id, "Generation-User-Password-2!")
        with pytest.raises(Exception) as stale:
            coordinator.validate_session(session["session_token"])
        assert getattr(stale.value, "code", "") in {"ENTERPRISE_DEVICE_STALE", "COORDINATOR_SESSION_STALE"}
    finally:
        coordinator.stop()


def test_phase10_runtime_authorization_boundary_and_ops_snapshot(tmp_path: Path) -> None:
    identity, _enrollment, governance, _coordinator = stack(tmp_path)
    workspace = governance.create_workspace("Ops")
    dataset = governance.register_resource("dataset", "OpsData", workspace, quota={"rows": 10})
    identity.step_up(ADMIN_PASSWORD)
    governance.grant_role(dataset, "analyst", ["dataset.read"])
    analyst_id = identity.create_account("ops-analyst", "Ops Analyst", "Ops-Analyst-Password!", ["analyst"])
    assert analyst_id
    identity.logout()
    identity.login("ops-analyst", "Ops-Analyst-Password!")
    decision = governance.authorize_operation("dataset.read", dataset, quota_metric="rows", quota_amount=4)
    assert decision["quota_reserved"] == 4
    assert governance.release_for_operation(dataset, "dataset.read", "rows", 4) == 0
    identity.logout()
    identity.login("root", ADMIN_PASSWORD)
    summary = governance.operations_snapshot()
    assert summary["workspaces"] == 1
    assert summary["resources"] == 1
    assert summary["resources_by_kind"]["dataset"] == 1


def test_phase9_device_persists_only_verified_coordinator_binding_not_session_secret(tmp_path: Path) -> None:
    store = DeviceKeyStore(tmp_path / "bound-device.aryxdevice")
    store.create("enterprise-a", "account-a")
    root_fp = "a" * 64
    store.set_office_binding("127.0.0.1", 9443, root_fp, "coordinator-test")
    binding = store.office_binding()
    assert binding["host"] == "127.0.0.1"
    assert binding["port"] == 9443
    assert binding["root_fingerprint"] == root_fp
    raw = store.path.read_text(encoding="utf-8")
    assert "session_token" not in raw
    assert "private_key" in raw                                                                                


def test_phase8_device_key_prefers_provisioned_hardware_provider(tmp_path: Path) -> None:
    from arenyxa.security.key_protection import CNGKeyProtectionAdapter, KeyProtectionRegistry
    registry = KeyProtectionRegistry()
    registry.adapters["cng"] = CNGKeyProtectionAdapter(
        protect_callback=lambda raw, _purpose: b"wrapped:" + raw,
        unprotect_callback=lambda raw, _purpose: raw.removeprefix(b"wrapped:"),
    )
    store = DeviceKeyStore(tmp_path / "hardware.aryxdevice", key_protection=registry)
    public = store.create("enterprise-a", "account-a")
    payload = __import__("json").loads(store.path.read_text(encoding="utf-8"))
    assert payload["protector"] == "cng"
    assert store.sign(b"challenge")
    assert public["device_id"]


def test_phase10_approval_is_requester_bound_and_one_shot_when_operation_is_authorized(tmp_path: Path) -> None:
    identity, _enrollment, governance, _coordinator = stack(tmp_path)
    workspace = governance.create_workspace("Approval")
    dataset = governance.register_resource("dataset", "Exports", workspace)
    identity.step_up(ADMIN_PASSWORD)
    governance.grant_role(dataset, "analyst", ["dataset.read", "dataset.export"])
    governance.grant_role(dataset, "administrator", ["dataset.read", "dataset.export"])
    identity.create_account("requester", "Requester", "Requester-Password!", ["analyst"])
    identity.create_account("approver", "Approver", "Approver-Password!", ["administrator"])
    identity.logout()
    identity.login("requester", "Requester-Password!")
    approval_id = governance.request_approval("dataset.export", dataset, reason="Export")
    identity.logout()
    identity.login("approver", "Approver-Password!")
    identity.step_up("Approver-Password!")
    governance.decide_approval(approval_id, True)
    with pytest.raises(Exception) as wrong_requester:
        governance.authorize_operation("dataset.export", dataset, approval_id=approval_id)
    assert getattr(wrong_requester.value, "code", "") == "APPROVAL_REQUESTER_MISMATCH"
    identity.logout()
    identity.login("requester", "Requester-Password!")
    decision = governance.authorize_operation("dataset.export", dataset, approval_id=approval_id)
    assert decision["approval_consumed"] is True
    with pytest.raises(Exception):
        governance.authorize_operation("dataset.export", dataset, approval_id=approval_id)


def test_phase10_team_scope_blocks_role_holder_outside_assigned_team(tmp_path: Path) -> None:
    identity, _enrollment, governance, _coordinator = stack(tmp_path)
    workspace = governance.create_workspace("Team Scope")
    identity.step_up(ADMIN_PASSWORD)
    in_team = identity.create_account("in-team", "In Team", "In-Team-Password!", ["analyst"])
    out_team = identity.create_account("out-team", "Out Team", "Out-Team-Password!", ["analyst"])
    team = governance.create_team(workspace, "Research", [in_team])
    dataset = governance.register_resource("dataset", "ResearchData", workspace, team_id=team, scope="team")
    identity.step_up(ADMIN_PASSWORD)
    governance.grant_role(dataset, "analyst", ["dataset.read"])
    identity.logout()
    identity.login("out-team", "Out-Team-Password!")
    with pytest.raises(Exception) as denied:
        governance.require_resource("dataset.read", dataset)
    assert getattr(denied.value, "code", "") == "GOVERNANCE_SCOPE_DENIED"
    identity.logout()
    identity.login("in-team", "In-Team-Password!")
    assert governance.require_resource("dataset.read", dataset)["id"] == dataset


def test_phase8_enrollment_parser_rejects_duplicate_json_keys() -> None:
    from arenyxa.enterprise.enrollment import parse_enrollment_token
    raw = b'{"schema":"a","schema":"b"}'
    with pytest.raises(Exception) as duplicate:
        parse_enrollment_token(raw)
    assert getattr(duplicate.value, "code", "") == "ENROLLMENT_ARTIFACT_INVALID"
