from __future__ import annotations

import collections
import copy
import hashlib
import logging
import secrets
import threading
import time
from dataclasses import asdict, field
from pathlib import Path
from typing import Any, Callable, Mapping
from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.enterprise.vault import (
    ENTERPRISE_PERMISSION_CATALOG,
    MAX_BACKUP_BYTES,
    MAX_VAULT_BYTES,
    EnterpriseVault,
    EnterpriseVaultHandle,
    password_verifier,
    verify_password,
    validate_payload,
)
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, read_bytes_limited
from arenyxa.enterprise.transport_security import (
    AuthThrottleIntegrityError, MAX_AUTH_THROTTLE_BYTES, auth_bucket_id, load_auth_throttle, save_auth_throttle,
)
from arenyxa.security import PolicyEffect, PolicyRule, SecurityKernel, Session, TrustDomain

from arenyxa.enterprise.identity_models import (
    EnterpriseStatus, _fail, ENTERPRISE_SESSION_TTL_SECONDS, STEP_UP_MAX_AGE_SECONDS, MAX_FAILURE_BUCKETS,
    MAX_SERVICE_LEASES, MAX_SERVICE_LEASE_TTL_SECONDS,
)

class IdentityAccountMixin:
    def _current_account_is_super_admin(self, handle: EnterpriseVaultHandle | None = None) -> bool:
        active_handle = handle or self._require_handle()
        with self._lock:
            account_id = self._account_id
        account = active_handle.payload.get("accounts", {}).get(account_id)
        return bool(isinstance(account, dict) and account.get("enabled") and "super_admin" in account.get("roles", []))

    def _guard_super_admin_assignment(self, before_roles: list[str] | tuple[str, ...], after_roles: list[str] | tuple[str, ...], handle: EnterpriseVaultHandle) -> None:
        before = "super_admin" in set(str(item) for item in before_roles)
        after = "super_admin" in set(str(item) for item in after_roles)
        if before == after:
            return
        self._require_step_up()
        if not self._current_account_is_super_admin(handle):
            raise _fail("ENTERPRISE_SUPER_ADMIN_REQUIRED", "Only an authenticated Super Administrator may grant or revoke the Super Administrator role")

    def _guard_super_admin_target(self, account: Mapping[str, Any], handle: EnterpriseVaultHandle) -> None:
        if "super_admin" in account.get("roles", []) and not self._current_account_is_super_admin(handle):
            raise _fail("ENTERPRISE_SUPER_ADMIN_REQUIRED", "Only an authenticated Super Administrator may govern a Super Administrator account")

    def accounts(self) -> list[dict[str, Any]]:
        self.require("enterprise.account.manage", "enterprise:accounts")
        payload = self._require_handle().payload
        rows = []
        for account in payload["accounts"].values():
            rows.append({
                "id": account["id"], "username": account["username"], "display_name": account["display_name"],
                "roles": list(account["roles"]), "enabled": bool(account["enabled"]),
                "auth_generation": int(account["auth_generation"]), "last_login_at": account.get("last_login_at", ""),
            })
        return sorted(rows, key=lambda row: (str(row["username"]), str(row["id"])))

    def _commit_with_rollback(
        self, handle: EnterpriseVaultHandle, before: dict[str, Any], action: str, resource: str,
        *, actor_override: str = "",
    ) -> None:
        validate_payload(handle.payload)
        handle.payload["revision"] = int(handle.payload.get("revision", 0)) + 1
        handle.payload["audit_metadata"]["generation"] = int(handle.payload["audit_metadata"].get("generation", 0)) + 1
        handle.payload["audit_metadata"]["last_mutation_at"] = utc_now()
        saved = False
        try:
            self.vault.save(handle)
            saved = True
            status = self.status()
            self.security.audit.emit(
                actor=actor_override or status.account_id or "enterprise-operator", action=action,
                resource=resource, decision="allow",
                trust_domain=TrustDomain.ENTERPRISE, reason="LOCAL_VAULT_MUTATION_COMMITTED",
            )
        except Exception as original:
            handle.payload.clear()
            handle.payload.update(before)
            if saved:
                try:
                    self.vault.save(handle)
                except Exception as rollback_error:
                                                                                                 
                                                                                               
                                                                                      
                    with self._lock:
                        session = self._session
                        identity_id = self._identity_id
                        self._session = None
                        self._identity_id = ""
                        self._account_id = ""
                        self._step_up_at = 0.0
                        current_handle = self._handle
                        self._handle = None
                    self._retire(session, identity_id)
                    if current_handle is not None:
                        current_handle.close()
                    raise _fail(
                        "ENTERPRISE_VAULT_ROLLBACK_FAILED",
                        "Enterprise mutation failed and the prior Vault state could not be restored; Vault locked fail-closed",
                        original=type(original).__name__, rollback=type(rollback_error).__name__,
                    ) from rollback_error
            raise

    def create_account(self, username: str, display_name: str, password: str, roles: list[str]) -> str:
        with self._mutation_lock:
            return self._create_account_locked(username, display_name, password, roles)

    def _create_account_locked(self, username: str, display_name: str, password: str, roles: list[str]) -> str:
        self.require("enterprise.account.manage", "enterprise:accounts")
        handle = self._require_handle()
        before = copy.deepcopy(handle.payload)
        normalized = str(username).strip().casefold()
        if not normalized or len(normalized) > 128 or any(ch.isspace() for ch in normalized):
            raise _fail("ENTERPRISE_USERNAME_INVALID", "Enterprise username is invalid")
        if self._account_by_username(handle.payload, normalized) is not None:
            raise _fail("ENTERPRISE_USERNAME_EXISTS", "Enterprise username already exists")
        if not roles or any(role not in handle.payload["roles"] for role in roles):
            raise _fail("ENTERPRISE_ROLE_INVALID", "Enterprise account roles are invalid")
        self._guard_super_admin_assignment((), roles, handle)
        account_id = new_id("account")
        now = utc_now()
        handle.payload["accounts"][account_id] = {
            "id": account_id, "username": normalized, "display_name": str(display_name).strip() or normalized,
            "password_verifier": password_verifier(password), "roles": sorted(set(roles)), "enabled": True,
            "auth_generation": 1, "created_at": now, "updated_at": now, "last_login_at": "",
        }
        self._commit_with_rollback(handle, before, "enterprise.account.create", f"enterprise:account:{account_id}")
        return account_id

    def roles(self) -> list[dict[str, Any]]:
        self.require("enterprise.account.manage", "enterprise:roles")
        payload = self._require_handle().payload
        rows = []
        for role in payload["roles"].values():
            rows.append({
                "id": str(role["id"]), "title": str(role["title"]), "builtin": bool(role["builtin"]),
                "permissions": tuple(str(item) for item in role.get("permissions", [])),
            })
        return sorted(rows, key=lambda row: (not bool(row["builtin"]), str(row["id"])))

    @staticmethod
    def _normalize_role(role_id: str, title: str, permissions: list[str]) -> tuple[str, str, list[str]]:
        key = str(role_id).strip()
        label = str(title).strip()
        normalized = sorted(set(str(item).strip() for item in permissions if str(item).strip()))
        if not key or len(key) > 64 or any(not (ch.isascii() and (ch.isalnum() or ch in "._-")) for ch in key):
            raise _fail("ENTERPRISE_ROLE_INVALID", "Enterprise role ID is invalid")
        if not label or len(label) > 160:
            raise _fail("ENTERPRISE_ROLE_INVALID", "Enterprise role title is invalid")
        if len(normalized) > 32 or any(item not in ENTERPRISE_PERMISSION_CATALOG for item in normalized):
            raise _fail("ENTERPRISE_ROLE_INVALID", "Enterprise role contains an unsupported permission")
        return key, label, normalized

    def effective_permissions(self, account_id: str) -> dict[str, Any]:
        self.require("enterprise.account.manage", "enterprise:accounts")
        handle = self._require_handle()
        account = handle.payload.get("accounts", {}).get(str(account_id))
        if not isinstance(account, dict):
            raise _fail("ENTERPRISE_ACCOUNT_MISSING", "Enterprise account does not exist")
        permissions = self._permissions_for_account(handle.payload, account)
        return {
            "account_id": str(account.get("id", "")),
            "username": str(account.get("username", "")),
            "enabled": bool(account.get("enabled")),
            "roles": tuple(str(item) for item in account.get("roles", [])),
            "permissions": permissions,
            "auth_generation": int(account.get("auth_generation", 0)),
        }

    def rbac_matrix(self) -> dict[str, Any]:
        self.require("enterprise.account.manage", "enterprise:roles")
        handle = self._require_handle()
        roles = []
        for role in handle.payload.get("roles", {}).values():
            if isinstance(role, dict):
                roles.append({
                    "id": str(role.get("id", "")),
                    "title": str(role.get("title", "")),
                    "builtin": bool(role.get("builtin")),
                    "permissions": tuple(sorted(str(item) for item in role.get("permissions", []))),
                })
        accounts = []
        for account in handle.payload.get("accounts", {}).values():
            if isinstance(account, dict):
                accounts.append(self.effective_permissions(str(account.get("id", ""))))
        return {
            "permission_catalog": tuple(sorted(ENTERPRISE_PERMISSION_CATALOG)),
            "roles": sorted(roles, key=lambda row: (not row["builtin"], row["id"])),
            "accounts": sorted(accounts, key=lambda row: (row["username"], row["account_id"])),
        }

    def create_role(self, role_id: str, title: str, permissions: list[str]) -> str:
        with self._mutation_lock:
            self.require("enterprise.policy.modify", "enterprise:roles")
            self._require_step_up()
            handle = self._require_handle()
            key, label, normalized = self._normalize_role(role_id, title, permissions)
            if key in handle.payload["roles"]:
                raise _fail("ENTERPRISE_ROLE_EXISTS", "Enterprise role already exists")
            before = copy.deepcopy(handle.payload)
            handle.payload["roles"][key] = {"id": key, "title": label, "builtin": False, "permissions": normalized}
            self._commit_with_rollback(handle, before, "enterprise.role.create", f"enterprise:role:{key}")
            return key

    def update_role(self, role_id: str, title: str, permissions: list[str]) -> None:
        with self._mutation_lock:
            self.require("enterprise.policy.modify", "enterprise:roles")
            self._require_step_up()
            handle = self._require_handle()
            current = handle.payload["roles"].get(str(role_id))
            if not isinstance(current, dict):
                raise _fail("ENTERPRISE_ROLE_MISSING", "Enterprise role does not exist")
            if current.get("builtin"):
                raise _fail("ENTERPRISE_BUILTIN_ROLE_IMMUTABLE", "Built-in enterprise roles cannot be modified")
            key, label, normalized = self._normalize_role(str(role_id), title, permissions)
            before = copy.deepcopy(handle.payload)
            current.update({"id": key, "title": label, "builtin": False, "permissions": normalized})
            affected = []
            for account in handle.payload["accounts"].values():
                if key in account.get("roles", []):
                    account["auth_generation"] = int(account.get("auth_generation", 1)) + 1
                    account["updated_at"] = utc_now()
                    affected.append(str(account["id"]))
            self._commit_with_rollback(handle, before, "enterprise.role.update", f"enterprise:role:{key}")
            for account_id in affected:
                self._revoke_if_account(account_id)

    def delete_role(self, role_id: str) -> None:
        with self._mutation_lock:
            self.require("enterprise.policy.modify", "enterprise:roles")
            self._require_step_up()
            handle = self._require_handle()
            key = str(role_id)
            current = handle.payload["roles"].get(key)
            if not isinstance(current, dict):
                raise _fail("ENTERPRISE_ROLE_MISSING", "Enterprise role does not exist")
            if current.get("builtin"):
                raise _fail("ENTERPRISE_BUILTIN_ROLE_IMMUTABLE", "Built-in enterprise roles cannot be deleted")
            if any(key in account.get("roles", []) for account in handle.payload["accounts"].values()):
                raise _fail("ENTERPRISE_ROLE_IN_USE", "Enterprise role is assigned to one or more accounts")
            before = copy.deepcopy(handle.payload)
            del handle.payload["roles"][key]
            self._commit_with_rollback(handle, before, "enterprise.role.delete", f"enterprise:role:{key}")

    def delete_account(self, account_id: str) -> None:
        with self._mutation_lock:
            self.require("enterprise.account.manage", "enterprise:accounts")
            self._require_step_up()
            handle = self._require_handle()
            key = str(account_id)
            account = handle.payload["accounts"].get(key)
            if not isinstance(account, dict):
                raise _fail("ENTERPRISE_ACCOUNT_MISSING", "Enterprise account does not exist")
            self._guard_super_admin_target(account, handle)
            if account.get("enabled") and "super_admin" in account.get("roles", []):
                other = [row for row in handle.payload["accounts"].values()
                         if row.get("enabled") and "super_admin" in row.get("roles", []) and row.get("id") != key]
                if not other:
                    raise _fail("ENTERPRISE_LAST_SUPER_ADMIN", "The last enabled Super Administrator cannot be deleted")
            before = copy.deepcopy(handle.payload)
            del handle.payload["accounts"][key]
            self._commit_with_rollback(handle, before, "enterprise.account.delete", f"enterprise:account:{key}")
            self._revoke_if_account(key)

    def set_account_enabled(self, account_id: str, enabled: bool) -> None:
        with self._mutation_lock:
            self._set_account_enabled_locked(account_id, enabled)

    def _set_account_enabled_locked(self, account_id: str, enabled: bool) -> None:
        self.require("enterprise.account.manage", "enterprise:accounts")
        self._require_step_up()
        handle = self._require_handle()
        before = copy.deepcopy(handle.payload)
        account = handle.payload["accounts"].get(str(account_id))
        if not isinstance(account, dict):
            raise _fail("ENTERPRISE_ACCOUNT_MISSING", "Enterprise account does not exist")
        self._guard_super_admin_target(account, handle)
        if not enabled and "super_admin" in account.get("roles", []):
            active_super = [row for row in handle.payload["accounts"].values()
                            if row.get("enabled") and "super_admin" in row.get("roles", []) and row.get("id") != account.get("id")]
            if not active_super:
                raise _fail("ENTERPRISE_LAST_SUPER_ADMIN", "The last enabled Super Administrator cannot be disabled")
        account["enabled"] = bool(enabled)
        account["auth_generation"] = int(account.get("auth_generation", 1)) + 1
        account["updated_at"] = utc_now()
        self._commit_with_rollback(handle, before, "enterprise.account.enable" if enabled else "enterprise.account.disable", f"enterprise:account:{account_id}")
        self._revoke_if_account(str(account_id))

    def set_account_roles(self, account_id: str, roles: list[str]) -> None:
        with self._mutation_lock:
            self._set_account_roles_locked(account_id, roles)

    def _set_account_roles_locked(self, account_id: str, roles: list[str]) -> None:
        self.require("enterprise.account.manage", "enterprise:accounts")
        self._require_step_up()
        handle = self._require_handle()
        before = copy.deepcopy(handle.payload)
        if not roles or any(role not in handle.payload["roles"] for role in roles):
            raise _fail("ENTERPRISE_ROLE_INVALID", "Enterprise account roles are invalid")
        account = handle.payload["accounts"].get(str(account_id))
        if not isinstance(account, dict):
            raise _fail("ENTERPRISE_ACCOUNT_MISSING", "Enterprise account does not exist")
        self._guard_super_admin_assignment(list(account.get("roles", [])), roles, handle)
        losing_super = "super_admin" in account.get("roles", []) and "super_admin" not in roles
        if losing_super and account.get("enabled"):
            other = [row for row in handle.payload["accounts"].values()
                     if row.get("enabled") and "super_admin" in row.get("roles", []) and row.get("id") != account.get("id")]
            if not other:
                raise _fail("ENTERPRISE_LAST_SUPER_ADMIN", "The last enabled Super Administrator cannot be demoted")
        account["roles"] = sorted(set(str(role) for role in roles))
        account["auth_generation"] = int(account.get("auth_generation", 1)) + 1
        account["updated_at"] = utc_now()
        self._commit_with_rollback(handle, before, "enterprise.account.roles", f"enterprise:account:{account_id}")
        self._revoke_if_account(str(account_id))

    def change_password(self, account_id: str, new_password: str) -> None:
        with self._mutation_lock:
            self._change_password_locked(account_id, new_password)

    def _change_password_locked(self, account_id: str, new_password: str) -> None:
        self.require("enterprise.account.manage", "enterprise:accounts")
        self._require_step_up()
        handle = self._require_handle()
        before = copy.deepcopy(handle.payload)
        account = handle.payload["accounts"].get(str(account_id))
        if not isinstance(account, dict):
            raise _fail("ENTERPRISE_ACCOUNT_MISSING", "Enterprise account does not exist")
        self._guard_super_admin_target(account, handle)
        account["password_verifier"] = password_verifier(new_password)
        account["auth_generation"] = int(account.get("auth_generation", 1)) + 1
        account["updated_at"] = utc_now()
        self._commit_with_rollback(handle, before, "enterprise.account.password", f"enterprise:account:{account_id}")
        self._revoke_if_account(str(account_id))

    def _revoke_if_account(self, account_id: str) -> None:
        with self._lock:
            active = self._account_id == account_id
        if active:
            self.logout(reason="ACCOUNT_GENERATION_CHANGED")

