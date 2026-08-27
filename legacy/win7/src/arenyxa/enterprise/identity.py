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

ENTERPRISE_SESSION_TTL_SECONDS = 8 * 60 * 60
STEP_UP_MAX_AGE_SECONDS = 5 * 60
MAX_FAILURE_BUCKETS = 256
MAX_SERVICE_LEASES = 16
MAX_SERVICE_LEASE_TTL_SECONDS = 24 * 60 * 60
LOGGER = logging.getLogger(__name__)


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE", context=context)


@dataclass(frozen=True, slots=True)
class EnterpriseStatus:
    configured: bool
    unlocked: bool
    authenticated: bool
    enterprise_id: str = ""
    enterprise_name: str = ""
    account_id: str = ""
    username: str = ""
    roles: tuple[str, ...] = field(default_factory=tuple)
    permissions: tuple[str, ...] = field(default_factory=tuple)
    session_expires_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LocalEnterpriseIdentityService:
    






    def __init__(self, security: SecurityKernel, data_root: Path) -> None:
        self.security = security
        self.vault = EnterpriseVault(Path(data_root) / "enterprise" / "identity.aryxvault")
        self._lock = threading.Lock()
                                                                                            
        self._mutation_lock = threading.Lock()
        self._handle: EnterpriseVaultHandle | None = None
        self._session: Session | None = None
        self._account_id = ""
        self._identity_id = ""
        self._step_up_at = 0.0
        self._failures: "collections.OrderedDict[str, tuple[int, float]]" = collections.OrderedDict()
        self._auth_throttle_path = Path(data_root) / "enterprise" / "auth_throttle.json"
        self._service_leases: dict[str, dict[str, Any]] = {}
        self._install_policies()

    def _install_policies(self) -> None:
        for capability in (
            "enterprise.account.manage", "enterprise.policy.modify", "enterprise.audit.read",
            "enterprise.enrollment.manage", "enterprise.device.manage", "enterprise.coordinator.manage",
            "enterprise.workspace.manage", "enterprise.approval.manage", "enterprise.quota.manage",
            "dataset.read", "dataset.write", "dataset.export", "workflow.execute", "workflow.publish",
            "enterprise.capture.run", "schedule.manage", "worker.use",
            "enterprise.worker.manage", "enterprise.server.manage", "enterprise.remote_ops",
        ):
            resources = ("enterprise:*", "dataset:*", "workflow:*", "capture:*", "schedule:*", "worker:*", "server:*", "project:*", "workspace:*")
            try:
                self.security.add_policy(PolicyRule(
                    id=f"local-enterprise-{capability}",
                    trust_domain=TrustDomain.ENTERPRISE,
                    capabilities=(capability,),
                    resources=resources,
                    effect=PolicyEffect.ALLOW,
                    priority=80,
                    conditions={"surface": "local-enterprise"},
                ))
            except ValueError as exc:
                if "duplicate policy id" not in str(exc):
                    raise

    @property
    def configured(self) -> bool:
        return self.vault.exists

    @property
    def unlocked(self) -> bool:
        with self._lock:
            return self._handle is not None

    def create_enterprise(self, enterprise_name: str, admin_username: str, admin_display_name: str,
                          admin_password: str, vault_passphrase: str) -> EnterpriseStatus:
        with self._mutation_lock:
                                                                                                  
                                                                                                              
            if not self.vault.exists:
                try:
                    self._auth_throttle_path.unlink(missing_ok=True)
                except OSError as exc:
                    raise _fail("ENTERPRISE_AUTH_THROTTLE_WRITE_FAILED", "Cannot reset stale Enterprise authentication throttle state") from exc
            handle = self.vault.create(enterprise_name, admin_username, admin_display_name, admin_password, vault_passphrase)
            try:
                self.security.audit.emit(
                    actor="enterprise-bootstrap", action="enterprise.create", resource=f"enterprise:{handle.payload['enterprise_id']}",
                    decision="allow", trust_domain=TrustDomain.ENTERPRISE, reason="LOCAL_ENTERPRISE_INITIALIZED",
                )
            except Exception as original:
                handle.close()
                try:
                    self.vault.path.unlink(missing_ok=True)
                except OSError as rollback_error:
                    raise _fail(
                        "ENTERPRISE_CREATE_ROLLBACK_FAILED",
                        "Enterprise creation audit failed and the newly-created Vault could not be removed; leave it locked and inspect storage",
                        original=type(original).__name__, rollback=type(rollback_error).__name__,
                    ) from rollback_error
                raise
            with self._lock:
                old = self._handle
                self._handle = handle
            if old is not None:
                old.close()
        return self.status()

    def unlock(self, vault_passphrase: str) -> EnterpriseStatus:
        with self._mutation_lock:
            handle = self.vault.open(vault_passphrase)
            try:
                self.security.audit.emit(
                    actor="local-operator", action="enterprise.vault.unlock", resource=f"enterprise:{handle.payload['enterprise_id']}",
                    decision="allow", trust_domain=TrustDomain.ENTERPRISE, reason="VAULT_AUTHENTICATED",
                )
            except Exception:
                handle.close()
                raise
            with self._lock:
                old = self._handle
                self._handle = handle
            if old is not None:
                old.close()
        return self.status()

    def _require_handle(self) -> EnterpriseVaultHandle:
        with self._lock:
            handle = self._handle
        if handle is None:
            raise _fail("ENTERPRISE_VAULT_LOCKED", "Local Enterprise Vault is locked")
        return handle

    @staticmethod
    def _account_by_username(payload: Mapping[str, Any], username: str) -> dict[str, Any] | None:
        target = str(username).strip().casefold()
        for account in payload.get("accounts", {}).values():
            if isinstance(account, dict) and str(account.get("username", "")).casefold() == target:
                return account
        return None

    def _auth_failure_state(self) -> tuple["collections.OrderedDict[str, tuple[int, float]]", EnterpriseVaultHandle]:
        handle = self._require_handle()
        try:
            entries = load_auth_throttle(self._auth_throttle_path, handle.data_key())
        except AuthThrottleIntegrityError as exc:
                                                                                                   
                                                                                                     
            raise _fail(
                "ENTERPRISE_AUTH_THROTTLE_INVALID",
                "Enterprise authentication throttle state failed integrity verification",
            ) from exc
        with self._lock:
            self._failures = collections.OrderedDict(entries)
        return entries, handle

    def _persist_auth_failure_state(
        self, entries: "collections.OrderedDict[str, tuple[int, float]]", handle: EnterpriseVaultHandle,
    ) -> None:
        try:
            save_auth_throttle(self._auth_throttle_path, handle.data_key(), entries)
        except Exception as exc:
            raise _fail(
                "ENTERPRISE_AUTH_THROTTLE_WRITE_FAILED",
                "Enterprise authentication throttle state could not be durably updated",
            ) from exc
        with self._lock:
            self._failures = collections.OrderedDict(entries)

    def _check_rate_limit(self, username: str) -> None:
        entries, handle = self._auth_failure_state()
        key = auth_bucket_id(handle.data_key(), username)
        now = time.time()
        attempts, retry_at = entries.get(key, (0, 0.0))
        if retry_at > now:
            raise _fail("ENTERPRISE_AUTH_RATE_LIMITED", "Too many password failures; retry later", retry_after=round(retry_at - now, 2))

    def _record_auth_failure(self, username: str) -> None:
        entries, handle = self._auth_failure_state()
        key = auth_bucket_id(handle.data_key(), username)
        now = time.time()
        attempts, _ = entries.get(key, (0, 0.0))
        attempts = min(16, attempts + 1)
        delay = min(30.0, 0.5 * (2 ** max(0, attempts - 2))) if attempts >= 3 else 0.0
        entries[key] = (attempts, now + delay)
        entries.move_to_end(key)
        while len(entries) > MAX_FAILURE_BUCKETS:
            entries.popitem(last=False)
        self._persist_auth_failure_state(entries, handle)

    def _clear_auth_failures(self, username: str) -> None:
        entries, handle = self._auth_failure_state()
        key = auth_bucket_id(handle.data_key(), username)
        if key in entries:
            entries.pop(key, None)
            self._persist_auth_failure_state(entries, handle)

    def login(self, username: str, password: str) -> Session:
                                                                                              
                                                                                                
                                                                        
        with self._mutation_lock:
            return self._login_locked(username, password)

    def _login_locked(self, username: str, password: str) -> Session:
        self._check_rate_limit(username)
        handle = self._require_handle()
        account = self._account_by_username(handle.payload, username)
        if account is None or not bool(account.get("enabled")) or not verify_password(password, account.get("password_verifier", {})):
            self._record_auth_failure(username)
            self.security.audit.emit(
                actor=str(username)[:128] or "unknown", action="enterprise.login", resource=f"enterprise:{handle.payload['enterprise_id']}",
                decision="deny", trust_domain=TrustDomain.ENTERPRISE, reason="INVALID_CREDENTIAL_OR_DISABLED",
            )
            raise _fail("ENTERPRISE_AUTH_FAILED", "Enterprise username/password is invalid or account is disabled")
        self._clear_auth_failures(username)
        permissions = self._permissions_for_account(handle.payload, account)
        identity = self.security.state.create_identity(
            TrustDomain.ENTERPRISE,
            principal_id=f"enterprise:{handle.payload['enterprise_id']}:{account['id']}:{new_id('principal')}",
            display_name=str(account.get("display_name") or account.get("username")),
            kind="enterprise_user",
        )
        identity.metadata.update({
            "enterprise_id": str(handle.payload["enterprise_id"]),
            "account_id": str(account["id"]),
            "auth_generation": int(account["auth_generation"]),
        })
        session = self.security.issue_session(
            identity.id, capabilities=list(permissions), ttl_seconds=ENTERPRISE_SESSION_TTL_SECONDS,
            metadata={"surface": "local-enterprise", "enterprise_id": str(handle.payload["enterprise_id"]),
                      "account_id": str(account["id"]), "auth_generation": int(account["auth_generation"]),
                      "roles": list(account.get("roles", []))},
        )
        before_login = copy.deepcopy(handle.payload)
        account["last_login_at"] = utc_now()
        account["updated_at"] = utc_now()
        handle.payload["audit_metadata"]["last_mutation_at"] = utc_now()
        saved = False
        try:
            self.vault.save(handle)
            saved = True
            self.security.audit.emit(
                actor=session.principal_id, action="enterprise.login", resource=f"enterprise:{handle.payload['enterprise_id']}",
                decision="allow", trust_domain=TrustDomain.ENTERPRISE, reason="PASSWORD_VERIFIED",
            )
        except Exception as original:
                                                                                                 
                                                                                                
                                                                                     
            handle.payload.clear()
            handle.payload.update(before_login)
            if saved:
                try:
                    self.vault.save(handle)
                except Exception as rollback_error:
                    self.security.state.revoke_session(session.id)
                    self.security.state.remove_identity(identity.id)
                    self.security.state.forget_session_revocation(session.id)
                    raise _fail(
                        "ENTERPRISE_LOGIN_ROLLBACK_FAILED",
                        "Enterprise login audit failed and prior Vault metadata could not be restored",
                        original=type(original).__name__, rollback=type(rollback_error).__name__,
                    ) from rollback_error
            self.security.state.revoke_session(session.id)
            self.security.state.remove_identity(identity.id)
            self.security.state.forget_session_revocation(session.id)
            raise
        with self._lock:
            old_session = self._session
            old_identity = self._identity_id
            self._session = session
            self._identity_id = identity.id
            self._account_id = str(account["id"])
            self._step_up_at = 0.0
        self._retire(old_session, old_identity)
        return session

    @staticmethod
    def _permissions_for_account(payload: Mapping[str, Any], account: Mapping[str, Any]) -> tuple[str, ...]:
        permissions: set[str] = set()
        roles = payload.get("roles", {})
        for role_id in account.get("roles", []):
            role = roles.get(role_id) if isinstance(roles, dict) else None
            if isinstance(role, dict):
                permissions.update(str(item) for item in role.get("permissions", []) if isinstance(item, str))
        return tuple(sorted(permissions))

    def _retire(self, session: Session | None, identity_id: str = "") -> None:
        if session is not None:
            self.security.state.revoke_session(session.id)
        if identity_id:
            self.security.state.remove_identity(identity_id)
        if session is not None:
            self.security.state.forget_session_revocation(session.id)

    def logout(self, *, reason: str = "USER_LOGOUT") -> None:
        with self._lock:
            session = self._session
            identity_id = self._identity_id
            self._session = None
            self._identity_id = ""
            self._account_id = ""
            self._step_up_at = 0.0
        if session is not None:
            actor = session.principal_id
            self._retire(session, identity_id)
            self.security.audit.emit(actor=actor, action="enterprise.logout", resource="enterprise:session", decision="allow",
                                     trust_domain=TrustDomain.ENTERPRISE, reason=reason)

    def lock(self) -> None:
        error: Exception | None = None
                                                                                     
                                                                                                
        with self._lock:
            self._service_leases.clear()
        try:
            self.logout(reason="VAULT_LOCK")
        except Exception as exc:
                                                                                              
                                                                                            
            error = exc
        finally:
            with self._lock:
                handle = self._handle
                self._handle = None
            if handle is not None:
                handle.close()
        if error is not None:
            raise error

    def close(self) -> None:
        self.lock()

    def status(self) -> EnterpriseStatus:
        with self._lock:
            handle = self._handle
            session = self._session
            account_id = self._account_id
        if handle is None:
            return EnterpriseStatus(self.configured, False, False)
        payload = handle.payload
        if session is None:
            return EnterpriseStatus(True, True, False, str(payload["enterprise_id"]), str(payload["display_name"]))
        if not self._session_is_current(session, payload, account_id):
                                                                                                 
                                                                                                  
            with self._lock:
                stale_session = self._session
                stale_identity = self._identity_id
                self._session = None
                self._identity_id = ""
                self._account_id = ""
                self._step_up_at = 0.0
            if stale_session is not None:
                actor = stale_session.principal_id
                self._retire(stale_session, stale_identity)
                try:
                    self.security.audit.emit(
                        actor=actor, action="enterprise.logout", resource="enterprise:session", decision="allow",
                        trust_domain=TrustDomain.ENTERPRISE, reason="ACCOUNT_GENERATION_REVOKED",
                    )
                except Exception:
                    LOGGER.exception("Failed to persist passive enterprise-session retirement audit")
            return EnterpriseStatus(True, True, False, str(payload["enterprise_id"]), str(payload["display_name"]))
        account = payload["accounts"].get(account_id, {})
        return EnterpriseStatus(
            True, True, True, str(payload["enterprise_id"]), str(payload["display_name"]), account_id,
            str(account.get("username", "")), tuple(str(x) for x in account.get("roles", [])),
            tuple(session.granted_capabilities), session.expires_at,
        )

    def _session_is_current(self, session: Session, payload: Mapping[str, Any], account_id: str) -> bool:
        validation = self.security.sessions.validate(session)
        if not validation.valid:
            return False
        account = payload.get("accounts", {}).get(account_id) if isinstance(payload.get("accounts"), dict) else None
        if not isinstance(account, dict) or not account.get("enabled"):
            return False
        return int(session.metadata.get("auth_generation", 0)) == int(account.get("auth_generation", -1))

    def require(self, capability: str, resource: str) -> None:
        handle = self._require_handle()
        with self._lock:
            session = self._session
            account_id = self._account_id
        if session is None or not self._session_is_current(session, handle.payload, account_id):
            raise _fail("ENTERPRISE_SESSION_INVALID", "Enterprise session is missing, expired, disabled, or revoked")
        self.security.require(session, capability, resource, context={"surface": "local-enterprise"})

    def step_up(self, password: str) -> None:
        handle = self._require_handle()
        with self._lock:
            account_id = self._account_id
            session = self._session
        if session is None or not self._session_is_current(session, handle.payload, account_id):
            raise _fail("ENTERPRISE_SESSION_INVALID", "Enterprise session is not valid for step-up authentication")
        account = handle.payload["accounts"].get(account_id)
        if not isinstance(account, dict) or not verify_password(password, account.get("password_verifier", {})):
            self.security.audit.emit(actor=session.principal_id, action="enterprise.step_up", resource="enterprise:session", decision="deny",
                                     trust_domain=TrustDomain.ENTERPRISE, reason="PASSWORD_INVALID")
            raise _fail("ENTERPRISE_STEP_UP_FAILED", "Step-up password verification failed")
        with self._lock:
            self._step_up_at = time.monotonic()
        self.security.audit.emit(actor=session.principal_id, action="enterprise.step_up", resource="enterprise:session", decision="allow",
                                 trust_domain=TrustDomain.ENTERPRISE, reason="PASSWORD_VERIFIED")

    def require_recent_step_up(self) -> None:
        
        self._require_step_up()

    def _require_step_up(self) -> None:
        with self._lock:
            age = time.monotonic() - self._step_up_at if self._step_up_at else 10 ** 9
        if age > STEP_UP_MAX_AGE_SECONDS:
            raise _fail("ENTERPRISE_STEP_UP_REQUIRED", "High-risk enterprise operation requires recent step-up authentication")

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


    def extension_snapshot(self, namespace: str, capability: str, resource: str) -> dict[str, Any]:
        
        self.require(capability, resource)
        handle = self._require_handle()
        extensions = handle.payload.get("extensions", {})
        value = extensions.get(str(namespace), {}) if isinstance(extensions, dict) else {}
        if not isinstance(value, dict):
            raise _fail("ENTERPRISE_EXTENSION_INVALID", "Enterprise extension state is invalid", namespace=namespace)
        return copy.deepcopy(value)

    def mutate_extension(
        self,
        namespace: str,
        capability: str,
        resource: str,
        action: str,
        mutator: Callable[[dict[str, Any], dict[str, Any]], Any],
        *,
        step_up: bool = False,
    ) -> Any:
        




        with self._mutation_lock:
            self.require(capability, resource)
            if step_up:
                self._require_step_up()
            handle = self._require_handle()
            before = copy.deepcopy(handle.payload)
            extensions = handle.payload.setdefault("extensions", {})
            if not isinstance(extensions, dict):
                raise _fail("ENTERPRISE_EXTENSION_INVALID", "Enterprise extension state is invalid")
            state = extensions.setdefault(str(namespace), {})
            if not isinstance(state, dict):
                raise _fail("ENTERPRISE_EXTENSION_INVALID", "Enterprise extension namespace is invalid", namespace=namespace)
            result = mutator(state, handle.payload)
            validate_payload(handle.payload)
            self._commit_with_rollback(handle, before, action, resource)
            return result

    def issue_service_lease(
        self,
        service_name: str,
        namespaces: tuple[str, ...],
        authorizations: tuple[tuple[str, str], ...],
        *,
        ttl_seconds: int = MAX_SERVICE_LEASE_TTL_SECONDS,
    ) -> str:
        





        name = str(service_name).strip()[:96]
        allowed_namespaces = tuple(dict.fromkeys(str(item).strip() for item in namespaces if str(item).strip()))
        if not name or not allowed_namespaces or len(allowed_namespaces) > 8:
            raise _fail("ENTERPRISE_SERVICE_LEASE_INVALID", "Enterprise service lease scope is invalid")
        for capability, resource in authorizations:
            self.require(str(capability), str(resource))
        self._require_step_up()
        handle = self._require_handle()
        ttl = min(MAX_SERVICE_LEASE_TTL_SECONDS, max(300, int(ttl_seconds)))
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        with self._lock:
            now = time.monotonic()
            self._service_leases = {
                key: value for key, value in self._service_leases.items()
                if float(value.get("expires_mono", 0.0)) > now
            }
            if len(self._service_leases) >= MAX_SERVICE_LEASES:
                raise _fail("ENTERPRISE_SERVICE_LEASE_CAPACITY", "Enterprise service lease capacity is full")
            self._service_leases[digest] = {
                "service_name": name,
                "enterprise_id": str(handle.payload.get("enterprise_id", "")),
                "namespaces": allowed_namespaces,
                "expires_mono": now + ttl,
            }
        try:
            self.security.audit.emit(
                actor=self.status().account_id or "enterprise-operator",
                action="enterprise.service_lease.issue",
                resource=f"enterprise:service:{name}",
                decision="allow", trust_domain=TrustDomain.ENTERPRISE, reason="IN_MEMORY_SCOPED_LEASE",
            )
        except Exception:
                                                                                                 
                                                                                       
            with self._lock:
                self._service_leases.pop(digest, None)
            raise
        return token

    def renew_service_lease(
        self, token: str, namespace: str, *, ttl_seconds: int = MAX_SERVICE_LEASE_TTL_SECONDS,
    ) -> float:
        





        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        ttl = min(MAX_SERVICE_LEASE_TTL_SECONDS, max(300, int(ttl_seconds)))
                                                                                                
        self._require_service_lease(token, namespace)
        with self._lock:
            row = self._service_leases.get(digest)
            if not isinstance(row, dict) or str(namespace) not in tuple(row.get("namespaces", ())):
                raise _fail("ENTERPRISE_SERVICE_LEASE_INVALID", "Enterprise service lease cannot be renewed")
            row["expires_mono"] = time.monotonic() + ttl
            return float(row["expires_mono"])

    def service_sign_enterprise_artifact(self, token: str, namespace: str, message: bytes) -> dict[str, str]:
        





        _row, handle = self._require_service_lease(token, namespace)
        raw = bytes(message)
        if not raw or len(raw) > 256 * 1024:
            raise _fail("ENTERPRISE_ARTIFACT_INVALID", "Enterprise signed artifact payload is empty or too large")
        root = handle.payload.get("root_identity", {})
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private_raw = base64.urlsafe_b64decode(str(root.get("private_key", "")) + "==")
            signer = Ed25519PrivateKey.from_private_bytes(private_raw)
            signature = signer.sign(raw)
            return {
                "enterprise_id": str(handle.payload.get("enterprise_id", "")),
                "root_public_key": str(root.get("public_key", "")),
                "root_fingerprint": str(root.get("fingerprint", "")),
                "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            }
        except Exception as exc:
            raise _fail("ENTERPRISE_ROOT_SIGN_FAILED", "Enterprise service artifact signing failed") from exc

    def revoke_service_lease(self, token: str, *, reason: str = "SERVICE_STOP") -> None:
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        with self._lock:
            row = self._service_leases.pop(digest, None)
        if row is not None:
            try:
                self.security.audit.emit(
                    actor=f"enterprise-service:{row.get('service_name', 'unknown')}",
                    action="enterprise.service_lease.revoke",
                    resource=f"enterprise:service:{row.get('service_name', 'unknown')}",
                    decision="allow", trust_domain=TrustDomain.ENTERPRISE, reason=str(reason)[:128],
                )
            except Exception:
                LOGGER.exception("Failed to persist enterprise service-lease revocation audit")

    def _require_service_lease(self, token: str, namespace: str) -> tuple[dict[str, Any], EnterpriseVaultHandle]:
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        now = time.monotonic()
        with self._lock:
            row = self._service_leases.get(digest)
            if row is not None and float(row.get("expires_mono", 0.0)) <= now:
                self._service_leases.pop(digest, None)
                row = None
        if not isinstance(row, dict) or str(namespace) not in tuple(row.get("namespaces", ())):
            raise _fail("ENTERPRISE_SERVICE_LEASE_INVALID", "Enterprise service lease is missing, expired, or outside its scope")
        handle = self._require_handle()
        if str(handle.payload.get("enterprise_id", "")) != str(row.get("enterprise_id", "")):
            raise _fail("ENTERPRISE_SERVICE_LEASE_INVALID", "Enterprise service lease is bound to a different Vault identity")
        return row, handle

    def service_extension_snapshot(self, token: str, namespace: str) -> dict[str, Any]:
        _row, handle = self._require_service_lease(token, namespace)
        extensions = handle.payload.get("extensions", {})
        value = extensions.get(str(namespace), {}) if isinstance(extensions, dict) else {}
        if not isinstance(value, dict):
            raise _fail("ENTERPRISE_EXTENSION_INVALID", "Enterprise service extension state is invalid", namespace=namespace)
        return copy.deepcopy(value)

    def service_account_snapshot(self, token: str, namespace: str, account_id: str) -> dict[str, Any]:
        _row, handle = self._require_service_lease(token, namespace)
        account = handle.payload.get("accounts", {}).get(str(account_id))
        if not isinstance(account, dict):
            raise _fail("ENTERPRISE_ACCOUNT_MISSING", "Enterprise service account reference does not exist")
        return {
            "id": str(account.get("id", "")),
            "username": str(account.get("username", "")),
            "roles": list(account.get("roles", [])),
            "enabled": bool(account.get("enabled")),
            "auth_generation": int(account.get("auth_generation", 0)),
        }

    def service_mutate_extension(
        self, token: str, namespace: str, action: str, resource: str,
        mutator: Callable[[dict[str, Any], dict[str, Any]], Any],
    ) -> Any:
        with self._mutation_lock:
            row, handle = self._require_service_lease(token, namespace)
            before = copy.deepcopy(handle.payload)
            extensions = handle.payload.setdefault("extensions", {})
            if not isinstance(extensions, dict):
                raise _fail("ENTERPRISE_EXTENSION_INVALID", "Enterprise extension state is invalid")
            state = extensions.setdefault(str(namespace), {})
            if not isinstance(state, dict):
                raise _fail("ENTERPRISE_EXTENSION_INVALID", "Enterprise extension namespace is invalid", namespace=namespace)
            result = mutator(state, handle.payload)
            validate_payload(handle.payload)
            self._commit_with_rollback(
                handle, before, action, resource,
                actor_override=f"enterprise-service:{row.get('service_name', 'unknown')}",
            )
            return result

    def root_public_identity(self) -> dict[str, str]:
        
        handle = self._require_handle()
        root = handle.payload.get("root_identity", {})
        return {
            "enterprise_id": str(handle.payload.get("enterprise_id", "")),
            "public_key": str(root.get("public_key", "")),
            "fingerprint": str(root.get("fingerprint", "")),
        }

    def sign_enterprise_artifact(self, message: bytes, *, capability: str, resource: str, step_up: bool = True) -> dict[str, str]:
        




        self.require(capability, resource)
        if step_up:
            self._require_step_up()
        raw = bytes(message)
        if not raw or len(raw) > 256 * 1024:
            raise _fail("ENTERPRISE_ARTIFACT_INVALID", "Enterprise signed artifact payload is empty or too large")
        handle = self._require_handle()
        root = handle.payload.get("root_identity", {})
        try:
            import base64
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            private_raw = base64.urlsafe_b64decode(str(root.get("private_key", "")) + "==")
            signer = Ed25519PrivateKey.from_private_bytes(private_raw)
            signature = signer.sign(raw)
            return {
                "enterprise_id": str(handle.payload.get("enterprise_id", "")),
                "root_public_key": str(root.get("public_key", "")),
                "root_fingerprint": str(root.get("fingerprint", "")),
                "signature": base64.urlsafe_b64encode(signature).decode("ascii").rstrip("="),
            }
        except Exception as exc:
            raise _fail("ENTERPRISE_ROOT_SIGN_FAILED", "Enterprise Root artifact signing failed") from exc

    def bulk_create_accounts(self, rows: list[dict[str, Any]]) -> list[dict[str, str]]:
        
        if not rows or len(rows) > 1000:
            raise _fail("ENTERPRISE_BATCH_INVALID", "Enterprise member batch must contain 1-1000 rows")
        with self._mutation_lock:
            self.require("enterprise.account.manage", "enterprise:accounts")
            self._require_step_up()
            handle = self._require_handle()
            before = copy.deepcopy(handle.payload)
            seen = {str(item.get("username", "")).casefold() for item in handle.payload["accounts"].values()}
            created: list[dict[str, str]] = []
            now = utc_now()
            for row in rows:
                username = str(row.get("username", "")).strip().casefold()
                display_name = str(row.get("display_name", "")).strip() or username
                roles = sorted(set(str(item) for item in (row.get("roles") or ["member"])))
                password = str(row.get("password", ""))
                if not username or len(username) > 128 or any(ch.isspace() for ch in username) or username in seen:
                    raise _fail("ENTERPRISE_USERNAME_INVALID", "Batch contains an invalid or duplicate username", username=username)
                if not roles or any(role not in handle.payload["roles"] for role in roles):
                    raise _fail("ENTERPRISE_ROLE_INVALID", "Batch contains an invalid role", username=username)
                if not password:
                    import secrets
                    password = "Tmp-" + secrets.token_urlsafe(18)
                account_id = new_id("account")
                handle.payload["accounts"][account_id] = {
                    "id": account_id, "username": username, "display_name": display_name,
                    "password_verifier": password_verifier(password), "roles": roles, "enabled": True,
                    "auth_generation": 1, "created_at": now, "updated_at": now, "last_login_at": "",
                }
                seen.add(username)
                created.append({"account_id": account_id, "username": username, "temporary_password": password})
            self._commit_with_rollback(handle, before, "enterprise.account.bulk_create", "enterprise:accounts")
            return created

    def backup(self, destination: Path, vault_passphrase: str) -> Path:
        with self._mutation_lock:
            return self._backup_locked(destination, vault_passphrase)

    def _backup_locked(self, destination: Path, vault_passphrase: str) -> Path:
        self.require("enterprise.policy.modify", "enterprise:vault")
        self._require_step_up()
        handle = self._require_handle()
        before = copy.deepcopy(handle.payload)
        destination = Path(destination)
        destination_existed = destination.exists()
        previous_backup = read_bytes_limited(destination, MAX_BACKUP_BYTES) if destination_existed and destination.is_file() else None
        path = self.vault.backup(destination, vault_passphrase=vault_passphrase)
        handle.payload["audit_metadata"]["last_backup_at"] = utc_now()
        try:
            self._commit_with_rollback(handle, before, "enterprise.vault.backup", "enterprise:vault")
        except Exception:
                                                                                                 
                                                                                                  
                                                                                       
            try:
                if previous_backup is not None:
                    atomic_write_bytes(path, previous_backup, mode=0o600)
                elif not destination_existed:
                    path.unlink(missing_ok=True)
            except OSError:
                LOGGER.exception("Failed to restore backup destination after enterprise backup transaction failure")
            raise
        return path

    def restore(self, source: Path, vault_passphrase: str) -> None:
                                                                                               
                                                                                               
        if self.unlocked:
            raise _fail("ENTERPRISE_RESTORE_REQUIRES_LOCK", "Lock the Enterprise Vault before restore")
        with self._mutation_lock:
            before_raw = read_bytes_limited(self.vault.path, MAX_VAULT_BYTES) if self.configured else None
            before_throttle = (
                read_bytes_limited(self._auth_throttle_path, MAX_AUTH_THROTTLE_BYTES)
                if self._auth_throttle_path.exists() and self._auth_throttle_path.is_file() else None
            )

            def rollback_restore(original: Exception) -> None:
                try:
                    if before_raw is None:
                        self.vault.path.unlink(missing_ok=True)
                    else:
                        atomic_write_bytes(self.vault.path, before_raw, mode=0o600)
                    if before_throttle is None:
                        self._auth_throttle_path.unlink(missing_ok=True)
                    else:
                        atomic_write_bytes(self._auth_throttle_path, before_throttle, mode=0o600)
                except Exception as rollback_error:
                    raise _fail(
                        "ENTERPRISE_RESTORE_ROLLBACK_FAILED",
                        "Enterprise restore failed and the prior Vault/security throttle state could not be restored",
                        original=type(original).__name__, rollback=type(rollback_error).__name__,
                    ) from rollback_error

            self.vault.restore(source, vault_passphrase=vault_passphrase, overwrite=self.configured)
                                                                                                    
                                                                                                 
                                                                                                
            try:
                restored_handle = self.vault.open(vault_passphrase)
                try:
                    save_auth_throttle(self._auth_throttle_path, restored_handle.data_key(), collections.OrderedDict())
                finally:
                    restored_handle.close()
            except Exception as original:
                rollback_restore(original)
                raise
            try:
                self.security.audit.emit(
                    actor="local-operator", action="enterprise.vault.restore", resource="enterprise:vault",
                    decision="allow", trust_domain=TrustDomain.ENTERPRISE, reason="AUTHENTICATED_BACKUP_RESTORED",
                )
            except Exception as original:
                rollback_restore(original)
                raise
