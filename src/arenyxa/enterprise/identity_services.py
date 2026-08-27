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

LOGGER = logging.getLogger(__name__)

class IdentityServiceMixin:
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
        except (OSError, RuntimeError, ValueError, TypeError):
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
        except (ValueError, TypeError, KeyError) as exc:
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
                self._guard_super_admin_assignment((), roles, handle)
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

    def vault_health(self) -> dict[str, Any]:
        self.require("enterprise.vault.manage", "enterprise:vault")
        return self.vault.envelope_health(self._require_handle())

    def rotate_vault_passphrase(self, current_passphrase: str, new_passphrase: str) -> None:
        with self._mutation_lock:
            self.require("enterprise.vault.manage", "enterprise:vault")
            self._require_step_up()
            handle = self._require_handle()
            before_raw = read_bytes_limited(self.vault.path, MAX_VAULT_BYTES)
            before_binding = str(handle._envelope_binding)
            self.vault.rewrap_passphrase(
                handle, current_passphrase=current_passphrase, new_passphrase=new_passphrase,
            )
            status = self.status()
            try:
                self.security.audit.emit(
                    actor=status.account_id or "enterprise-operator", action="enterprise.vault.passphrase.rotate",
                    resource="enterprise:vault", decision="allow", trust_domain=TrustDomain.ENTERPRISE,
                    reason="VAULT_KEY_ENVELOPE_REWRAPPED",
                )
            except Exception as original:
                try:
                    atomic_write_bytes(self.vault.path, before_raw, mode=0o600)
                    handle._envelope_binding = before_binding
                except Exception as rollback_error:
                    with self._lock:
                        session = self._session
                        identity_id = self._identity_id
                        current_handle = self._handle
                        self._session = None
                        self._identity_id = ""
                        self._account_id = ""
                        self._step_up_at = 0.0
                        self._handle = None
                    self._retire(session, identity_id)
                    if current_handle is not None:
                        current_handle.close()
                    raise _fail(
                        "ENTERPRISE_VAULT_ROTATION_ROLLBACK_FAILED",
                        "Vault passphrase rotation audit failed and the prior key envelope could not be restored; Vault locked fail-closed",
                        original=type(original).__name__, rollback=type(rollback_error).__name__,
                    ) from rollback_error
                raise

    def backup(self, destination: Path, vault_passphrase: str) -> Path:
        with self._mutation_lock:
            return self._backup_locked(destination, vault_passphrase)

    def _backup_locked(self, destination: Path, vault_passphrase: str) -> Path:
        self.require("enterprise.vault.manage", "enterprise:vault")
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
