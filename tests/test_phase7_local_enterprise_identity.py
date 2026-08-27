from __future__ import annotations

import json
from pathlib import Path

import pytest

from arenyxa.enterprise import EnterpriseVault, LocalEnterpriseIdentityService
from arenyxa.security import SecurityKernel

ADMIN_PASSWORD = "Admin-Password-Phase7-0001"
VAULT_PASSWORD = "Vault-Passphrase-Phase7-0001"


def _service(tmp_path: Path) -> LocalEnterpriseIdentityService:
    service = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    service.create_enterprise("Phase7 Test Enterprise", "root", "Root Administrator", ADMIN_PASSWORD, VAULT_PASSWORD)
    return service


def test_vault_is_authenticated_encrypted_and_contains_no_plaintext_credentials(tmp_path: Path) -> None:
    service = _service(tmp_path)
    raw = service.vault.path.read_bytes()
    assert b"Phase7 Test Enterprise" not in raw
    assert b"Root Administrator" not in raw
    assert ADMIN_PASSWORD.encode() not in raw
    assert VAULT_PASSWORD.encode() not in raw
    outer = json.loads(raw.decode("utf-8"))
    assert outer["schema"] == "arenyxa.enterprise-vault/v1"
    assert "payload" in outer and "wrapped_key" in outer
    assert "ciphertext" in outer["payload"] and "ciphertext" in outer["wrapped_key"]
    service.lock()
    with pytest.raises(Exception):
        service.unlock("wrong-passphrase-that-is-long-enough")
    assert service.unlock(VAULT_PASSWORD).unlocked is True


def test_login_rbac_and_developer_enterprise_trust_separation(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    status = service.status()
    assert status.authenticated is True
    assert "enterprise.account.manage" in status.permissions
    assert "stress_test" not in status.permissions
    service.require("enterprise.account.manage", "enterprise:accounts")
    with pytest.raises(Exception):
        service.require("stress_test", "developer:internal/stress-test")


def test_last_super_admin_cannot_be_disabled_or_demoted(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    root = service.accounts()[0]
    with pytest.raises(Exception) as disabled:
        service.set_account_enabled(root["id"], False)
    assert getattr(disabled.value, "code", "") == "ENTERPRISE_LAST_SUPER_ADMIN"
    with pytest.raises(Exception) as demoted:
        service.set_account_roles(root["id"], ["administrator"])
    assert getattr(demoted.value, "code", "") == "ENTERPRISE_LAST_SUPER_ADMIN"


def test_disable_generation_revokes_live_session_immediately(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    second_id = service.create_account("backup-admin", "Backup Admin", "Backup-Admin-Password-0001", ["super_admin"])
    assert second_id
    root = next(row for row in service.accounts() if row["username"] == "root")
    old_generation = root["auth_generation"]
    service.set_account_enabled(root["id"], False)
    assert service.status().authenticated is False
    service.lock()
    service.unlock(VAULT_PASSWORD)
    with pytest.raises(Exception):
        service.login("root", ADMIN_PASSWORD)
    service.login("backup-admin", "Backup-Admin-Password-0001")
    changed = next(row for row in service.accounts() if row["username"] == "root")
    assert changed["auth_generation"] == old_generation + 1
    assert changed["enabled"] is False


def test_wrong_password_rate_limit_is_bounded_and_fail_closed(tmp_path: Path) -> None:
    service = _service(tmp_path)
    for _ in range(3):
        with pytest.raises(Exception):
            service.login("root", "Wrong-Password-Long-0001")
    with pytest.raises(Exception) as limited:
        service.login("root", ADMIN_PASSWORD)
    assert getattr(limited.value, "code", "") == "ENTERPRISE_AUTH_RATE_LIMITED"
    assert len(service._failures) <= 256


def test_atomic_save_failure_keeps_previous_complete_vault(tmp_path: Path, monkeypatch) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    before = service.vault.path.read_bytes()
    handle = service._require_handle()
    handle.payload["display_name"] = "Changed but not committed"

    def fail_write(*_args, **_kwargs):
        raise OSError("synthetic write failure")

    monkeypatch.setattr("arenyxa.enterprise.vault.atomic_write_json", fail_write)
    with pytest.raises(OSError):
        service.vault.save(handle)
    assert service.vault.path.read_bytes() == before


def test_backup_restore_roundtrip_and_corruption_rejected(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    destination = tmp_path / "backup.aryxbak.json"
    service.backup(destination, VAULT_PASSWORD)
    assert destination.is_file()
    service.lock()
    original = service.vault.path.read_bytes()
    service.vault.path.unlink()
    service.restore(destination, VAULT_PASSWORD)
    assert service.vault.path.is_file()
    service.unlock(VAULT_PASSWORD)
    assert service.status().enterprise_name == "Phase7 Test Enterprise"
    service.lock()
    service.vault.path.write_bytes(original)
    corrupt = json.loads(destination.read_text(encoding="utf-8"))
    corrupt["vault_sha256"] = "0" * 64
    broken = tmp_path / "broken.aryxbak.json"
    broken.write_text(json.dumps(corrupt), encoding="utf-8")
    with pytest.raises(Exception):
        service.restore(broken, VAULT_PASSWORD)


def test_vault_payload_validation_does_not_run_password_kdf(tmp_path: Path, monkeypatch) -> None:
    vault = EnterpriseVault(tmp_path / "identity.aryxvault")
    handle = vault.create("Corp", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD, scrypt_n=2**14)
                                                                                               
    def forbidden(*_args, **_kwargs):
        raise AssertionError("password KDF should not run during structural validation")
    monkeypatch.setattr("arenyxa.enterprise.vault.verify_password", forbidden)
    vault.save(handle)
    handle.close()


def test_failed_account_mutation_rolls_back_live_in_memory_state(tmp_path: Path, monkeypatch) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    before_accounts = service.accounts()

    def fail_save(_handle):
        raise OSError("synthetic persistence failure")

    monkeypatch.setattr(service.vault, "save", fail_save)
    with pytest.raises(OSError):
        service.create_account("ghost", "Ghost", "Ghost-Password-Phase7-0001", ["member"])
    assert service.accounts() == before_accounts


def test_unlocked_session_refuses_externally_replaced_passphrase_envelope(tmp_path: Path) -> None:
    service = _service(tmp_path)
    handle = service._require_handle()
    outer = json.loads(service.vault.path.read_text(encoding="utf-8"))
                                                                                           
                                                                                                 
    outer["wrapped_key"]["ciphertext"] = outer["wrapped_key"]["ciphertext"][:-1] + (
        "A" if outer["wrapped_key"]["ciphertext"][-1] != "A" else "B"
    )
    service.vault.path.write_text(json.dumps(outer), encoding="utf-8")
    with pytest.raises(Exception) as captured:
        service.vault.save(handle)
    assert getattr(captured.value, "code", "") == "ENTERPRISE_VAULT_INTEGRITY"


def test_create_audit_failure_rolls_back_new_vault(tmp_path: Path) -> None:
    from arenyxa.security.audit import AuditLog

    class FailCreateAudit(AuditLog):
        def emit(self, **kwargs):                          
            if kwargs.get("action") == "enterprise.create":
                raise OSError("synthetic audit failure")
            return super().emit(**kwargs)

    service = LocalEnterpriseIdentityService(SecurityKernel(audit=FailCreateAudit()), tmp_path)
    with pytest.raises(OSError):
        service.create_enterprise("Corp", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    assert service.configured is False
    assert service.unlocked is False


def test_unlock_audit_failure_never_publishes_decrypted_handle(tmp_path: Path) -> None:
    seed = _service(tmp_path)
    seed.lock()
    from arenyxa.security.audit import AuditLog

    class FailUnlockAudit(AuditLog):
        def emit(self, **kwargs):                          
            if kwargs.get("action") == "enterprise.vault.unlock":
                raise OSError("synthetic audit failure")
            return super().emit(**kwargs)

    service = LocalEnterpriseIdentityService(SecurityKernel(audit=FailUnlockAudit()), tmp_path)
    with pytest.raises(OSError):
        service.unlock(VAULT_PASSWORD)
    assert service.unlocked is False


def test_account_audit_failure_rolls_back_durable_and_live_state(tmp_path: Path) -> None:
    from arenyxa.security.audit import AuditLog

    class FailAccountAudit(AuditLog):
        def emit(self, **kwargs):                          
            if kwargs.get("action") == "enterprise.account.create":
                raise OSError("synthetic account audit failure")
            return super().emit(**kwargs)

                                                                                         
    seed = _service(tmp_path)
    seed.lock()
    service = LocalEnterpriseIdentityService(SecurityKernel(audit=FailAccountAudit()), tmp_path)
    service.unlock(VAULT_PASSWORD)
    service.login("root", ADMIN_PASSWORD)
    before_bytes = service.vault.path.read_bytes()
    before_rows = service.accounts()
    with pytest.raises(OSError):
        service.create_account("ghost", "Ghost", "Ghost-Password-Phase7-0001", ["member"])
    assert service.accounts() == before_rows
    assert service.vault.path.read_bytes() != b""
    service.lock()
                                                                                                          
    service.unlock(VAULT_PASSWORD)
    service.login("root", ADMIN_PASSWORD)
    assert all(row["username"] != "ghost" for row in service.accounts())


def test_login_audit_failure_rolls_back_durable_login_metadata(tmp_path: Path) -> None:
    from arenyxa.security.audit import AuditLog

    seed = _service(tmp_path)
    seed.lock()

    class FailLoginAudit(AuditLog):
        def emit(self, **kwargs):                          
            if kwargs.get("action") == "enterprise.login" and kwargs.get("decision") == "allow":
                raise OSError("synthetic login audit failure")
            return super().emit(**kwargs)

    service = LocalEnterpriseIdentityService(SecurityKernel(audit=FailLoginAudit()), tmp_path)
    service.unlock(VAULT_PASSWORD)
    with pytest.raises(OSError):
        service.login("root", ADMIN_PASSWORD)
    assert service.status().authenticated is False
    account = next(row for row in service._require_handle().payload["accounts"].values() if row["username"] == "root")
    assert account["last_login_at"] == ""
    service.lock()

                                                                
    check = LocalEnterpriseIdentityService(SecurityKernel(), tmp_path)
    check.unlock(VAULT_PASSWORD)
    account = next(row for row in check._require_handle().payload["accounts"].values() if row["username"] == "root")
    assert account["last_login_at"] == ""


def test_restore_audit_failure_restores_previous_complete_vault(tmp_path: Path) -> None:
    from arenyxa.security.audit import AuditLog

    seed = _service(tmp_path)
    original_id = seed.status().enterprise_id
    seed.lock()

    replacement_passphrase = "Replacement-Vault-Passphrase-0001"
    replacement = EnterpriseVault(tmp_path / "replacement.aryxvault")
    replacement_handle = replacement.create(
        "Replacement Enterprise", "replacement-root", "Replacement Root",
        "Replacement-Admin-Password-0001", replacement_passphrase, scrypt_n=2**14,
    )
    replacement_handle.close()
    replacement_backup = tmp_path / "replacement.aryxbak.json"
    replacement.backup(replacement_backup, vault_passphrase=replacement_passphrase)

    class FailRestoreAudit(AuditLog):
        def emit(self, **kwargs):                          
            if kwargs.get("action") == "enterprise.vault.restore":
                raise OSError("synthetic restore audit failure")
            return super().emit(**kwargs)

    service = LocalEnterpriseIdentityService(SecurityKernel(audit=FailRestoreAudit()), tmp_path)
    with pytest.raises(OSError):
        service.restore(replacement_backup, replacement_passphrase)

                                                                                            
    status = service.unlock(VAULT_PASSWORD)
    assert status.enterprise_id == original_id
    assert status.enterprise_name == "Phase7 Test Enterprise"


def test_durable_account_mutations_are_serialized(tmp_path: Path, monkeypatch) -> None:
    import threading
    import time
    import arenyxa.enterprise.identity_accounts as identity_module

    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    original = identity_module.password_verifier
    state_lock = threading.Lock()
    active = 0
    max_active = 0

    def guarded(password: str):
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
        try:
            time.sleep(0.04)
            return original(password, n=2**14)
        finally:
            with state_lock:
                active -= 1

    monkeypatch.setattr(identity_module, "password_verifier", guarded)
    errors: list[BaseException] = []

    def create(index: int) -> None:
        try:
            service.create_account(
                f"parallel-{index}", f"Parallel {index}",
                f"Parallel-Password-{index:04d}-Secure", ["member"],
            )
        except BaseException as exc:                                                           
            errors.append(exc)

    threads = [threading.Thread(target=create, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not errors
    assert max_active == 1
    usernames = {row["username"] for row in service.accounts()}
    assert {"parallel-0", "parallel-1"}.issubset(usernames)


def test_password_verifier_rejects_unbounded_kdf_before_work() -> None:
    from arenyxa.enterprise.vault import MAX_SCRYPT_N, password_verifier

    with pytest.raises(Exception) as captured:
        password_verifier("Strong-Password-Phase7-0001", n=MAX_SCRYPT_N * 2)
    assert getattr(captured.value, "code", "") == "ENTERPRISE_KDF_INVALID"


def test_backup_refuses_live_vault_destination_without_corrupting_vault(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    before = service.vault.path.read_bytes()
    with pytest.raises(Exception) as captured:
        service.backup(service.vault.path, VAULT_PASSWORD)
    assert getattr(captured.value, "code", "") == "ENTERPRISE_BACKUP_DESTINATION_CONFLICT"
    assert service.vault.path.read_bytes() == before
    service.lock()
    assert service.unlock(VAULT_PASSWORD).unlocked is True


def test_last_super_admin_cannot_be_deleted_but_redundant_super_admin_can(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    root = service.accounts()[0]
    with pytest.raises(Exception) as captured:
        service.delete_account(root["id"])
    assert getattr(captured.value, "code", "") == "ENTERPRISE_LAST_SUPER_ADMIN"

    backup_id = service.create_account(
        "backup-admin-delete", "Backup Admin", "Backup-Admin-Delete-Password-0001", ["super_admin"]
    )
    service.delete_account(root["id"])
    assert service.status().authenticated is False
    service.login("backup-admin-delete", "Backup-Admin-Delete-Password-0001")
    assert {row["id"] for row in service.accounts()} == {backup_id}


def test_custom_role_permission_set_is_validated_and_update_revokes_affected_session(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    role_id = service.create_role("research_reader", "Research Reader", ["dataset.read"])
    assert role_id == "research_reader"
    assert any(row["id"] == role_id and not row["builtin"] for row in service.roles())
    with pytest.raises(Exception):
        service.create_role("bad_role", "Bad", ["stress_test"])

    user_id = service.create_account(
        "researcher", "Researcher", "Researcher-Password-Phase7-0001", [role_id]
    )
    service.logout()
    service.login("researcher", "Researcher-Password-Phase7-0001")
    service.require("dataset.read", "dataset:Research")
    with pytest.raises(Exception):
        service.require("dataset.write", "dataset:Research")

                                                                                               
                                                                           
    service.logout()
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    service.update_role(role_id, "Research Writer", ["dataset.read", "dataset.write"])
    account = next(row for row in service.accounts() if row["id"] == user_id)
    assert account["auth_generation"] == 2
    with pytest.raises(Exception):
        service.delete_role(role_id)


def test_backup_audit_failure_restores_existing_backup_destination(tmp_path: Path) -> None:
    from arenyxa.security.audit import AuditLog

    seed = _service(tmp_path)
    seed.login("root", ADMIN_PASSWORD)
    seed.step_up(ADMIN_PASSWORD)
    destination = tmp_path / "governed-backup.aryxbak.json"
    seed.backup(destination, VAULT_PASSWORD)
    previous = destination.read_bytes()
    seed.lock()

    class FailBackupAudit(AuditLog):
        def emit(self, **kwargs):                          
            if kwargs.get("action") == "enterprise.vault.backup":
                raise OSError("synthetic backup audit failure")
            return super().emit(**kwargs)

    service = LocalEnterpriseIdentityService(SecurityKernel(audit=FailBackupAudit()), tmp_path)
    service.unlock(VAULT_PASSWORD)
    service.login("root", ADMIN_PASSWORD)
    service.step_up(ADMIN_PASSWORD)
    with pytest.raises(OSError):
        service.backup(destination, VAULT_PASSWORD)
    assert destination.read_bytes() == previous
