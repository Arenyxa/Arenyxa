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
from datetime import datetime
from typing import Any, Callable, Mapping
from arenyxa.compat import UTC, dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.timebase import PROCESS_CLOCK
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

LOGGER = logging.getLogger(__name__)

from arenyxa.enterprise.identity_models import (
    EnterpriseStatus, _fail, ENTERPRISE_SESSION_TTL_SECONDS, STEP_UP_MAX_AGE_SECONDS, MAX_FAILURE_BUCKETS,
    MAX_SERVICE_LEASES, MAX_SERVICE_LEASE_TTL_SECONDS,
)

class IdentityAuthMixin:
    def _install_policies(self) -> None:
        for capability in (
            "enterprise.account.manage", "enterprise.policy.modify", "enterprise.audit.read",
            "enterprise.enrollment.manage", "enterprise.device.manage", "enterprise.coordinator.manage",
            "enterprise.workspace.manage", "enterprise.approval.manage", "enterprise.quota.manage",
            "dataset.read", "dataset.write", "dataset.export", "workflow.execute", "workflow.publish",
            "enterprise.capture.run", "schedule.manage", "worker.use",
            "enterprise.worker.manage", "enterprise.server.manage", "enterprise.remote_ops",
            "enterprise.vault.manage", "enterprise.proxy.manage", "enterprise.mitm.manage",
            "enterprise.packet.analyze", "enterprise.network.observe",
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
        now = PROCESS_CLOCK.stable_epoch()
        attempts, retry_at = entries.get(key, (0, 0.0))
        if retry_at > now:
            raise _fail("ENTERPRISE_AUTH_RATE_LIMITED", "Too many password failures; retry later", retry_after=round(retry_at - now, 2))

    def _record_auth_failure(self, username: str) -> None:
        entries, handle = self._auth_failure_state()
        key = auth_bucket_id(handle.data_key(), username)
        now = PROCESS_CLOCK.stable_epoch()
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
            LOGGER.exception("Enterprise logout failed during vault lock; cleanup will continue before re-raising")
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

    def dynamic_access_context(self) -> dict[str, Any]:
        """Return conservative real-time signals for Zero Trust authorization.

        Missing telemetry is represented conservatively (risk=100, unknown
        network, no MFA) so enabling stricter resource policy fails closed.
        Device posture is supplied separately by the enrollment subsystem.
        """
        status = self.status()
        with self._lock:
            session = self._session
        if not status.authenticated or session is None:
            return {
                "managed_device": False,
                "device_compliant": False,
                "mfa_verified": False,
                "network_trust": "unknown",
                "risk_score": 100,
                "auth_age_seconds": 7 * 24 * 60 * 60 + 1,
            }
        try:
            issued = datetime.fromisoformat(str(session.issued_at))
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=UTC)
            else:
                issued = issued.astimezone(UTC)
            auth_age = max(0, int((datetime.now(UTC) - issued).total_seconds()))
        except (TypeError, ValueError, OverflowError):
            auth_age = 7 * 24 * 60 * 60 + 1
        metadata = dict(session.metadata or {})
        try:
            risk = max(0, min(100, int(metadata.get("risk_score", 100))))
        except (TypeError, ValueError, OverflowError):
            risk = 100
        network = str(metadata.get("network_trust", "unknown")).strip().casefold() or "unknown"
        return {
            "managed_device": False,
            "device_compliant": False,
            "mfa_verified": metadata.get("mfa_verified") is True,
            "network_trust": network,
            "risk_score": risk,
            "auth_age_seconds": auth_age,
        }

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

