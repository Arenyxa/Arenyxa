from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
from dataclasses import asdict, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arenyxa.compat import UTC, dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id
from arenyxa.security import PolicyEffect, PolicyRule, SecurityKernel, Session, TrustDomain
from arenyxa.security.key_protection import DPAPIKeyProtectionAdapter, KeyProtectionAdapter
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider
from arenyxa.security.hardware_root_lifecycle import RootIntegrityStatus, probe_root_integrity
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.security.developer_credentials import (
    DEVELOPER_CAPABILITIES,
    DeveloperRevocationSet,
    DeveloperTrustStore,
    VerifiedDeveloperCredential,
    VerifiedOwnerCredential,
    b64u_decode,
    b64u_encode,
    canonical_json,
    load_json_object,
    verify_login_bundle,
    verify_owner_login_bundle,
)
from arenyxa.security.developer_trust_anchors import (
    EMBEDDED_DEVELOPER_REVOCATIONS,
    EMBEDDED_DEVELOPER_ROOTS,
)

CHALLENGE_SCHEMA = "arenyxa.developer-login-challenge/v1"
OWNER_CHALLENGE_SCHEMA = "arenyxa.developer-owner-login-challenge/v1"
DEVELOPER_CHALLENGE_TTL_SECONDS = 60
OWNER_CHALLENGE_TTL_SECONDS = 60
MAX_PENDING_CHALLENGES = 32
OFFICIAL_SESSION_TTL_SECONDS = 60 * 60
OWNER_SESSION_TTL_SECONDS = 15 * 60
LOGGER = logging.getLogger(__name__)

from arenyxa.application.root_workstation_binding import (
    ROOT_OWNER_MAX_STARTUP_FAILURES,
    RootWorkstationBinding,
    detect_root_capability_state,
    detect_root_developer_workstation,
)
from arenyxa.application.root_owner_security import (
    RootCapabilityState,
    RootStartupSecurityStatus,
    RootWorkstationStatus,
    root_owner_startup_attempt_budget,
)


def _error(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="DEVELOPER_ACCESS", context=context)


@dataclass(frozen=True, slots=True)
class DeveloperLoginChallenge:
    challenge_id: str
    schema: str
    payload: dict[str, Any]
    expires_at: str

    @property
    def signing_bytes(self) -> bytes:
        return canonical_json(self.payload)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass(slots=True)
class _PendingChallenge:
    kind: str
    payload: dict[str, Any]
    expires_at: datetime
    credential: VerifiedDeveloperCredential | VerifiedOwnerCredential | None = None
    bundle: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class DeveloperAccessStatus:
    authenticated: bool
    kind: str = ""
    developer_id: str = ""
    certificate_serial: str = ""
    certificate_sha256: str = ""
    fingerprint: str = ""
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    session_expires_at: str = ""
    credential_expires_at: str = ""
    root_key_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeveloperAccessManager:
    






    def __init__(
        self,
        security: SecurityKernel,
        *,
        trust_store: DeveloperTrustStore,
        revocations: DeveloperRevocationSet | None = None,
        root_workstation: RootWorkstationBinding | None = None,
    ) -> None:
        self.security = security
        self.trust_store = trust_store
        self.revocations = revocations or DeveloperRevocationSet()
        self.root_workstation = root_workstation
        self._lock = threading.Lock()
        self._pending: dict[str, _PendingChallenge] = {}
        self._session: Session | None = None
        self._status = DeveloperAccessStatus(False)
        self._root_integrity: RootIntegrityStatus | None = None
        self._process_nonce = secrets.token_hex(16)
        self._install_policies()

    @classmethod
    def local(cls, security: SecurityKernel, data_root: Path, package_root: Path) -> "DeveloperAccessManager":
                                                                                            
                                                                                               
                                                                                                
                                                                                                
                                                                           
        del package_root
        trust = DeveloperTrustStore(EMBEDDED_DEVELOPER_ROOTS)
        revocations = DeveloperRevocationSet(EMBEDDED_DEVELOPER_REVOCATIONS)
        binding = RootWorkstationBinding(Path(data_root), trust, revocations)
        return cls(security, trust_store=trust, revocations=revocations, root_workstation=binding)

    def _install_policies(self) -> None:
                                                                                               
                                                                                                  
        for capability in sorted(DEVELOPER_CAPABILITIES):
            try:
                self.security.add_policy(
                    PolicyRule(
                        id=f"official-developer-{capability}",
                        trust_domain=TrustDomain.DEVELOPER,
                        capabilities=(capability,),
                        resources=("developer:internal/*",),
                        effect=PolicyEffect.ALLOW,
                        priority=100,
                    )
                )
            except ValueError as exc:
                if "duplicate policy id" not in str(exc):
                    raise

    @property
    def ready(self) -> bool:
        return self.trust_store.ready

    def status(self) -> DeveloperAccessStatus:
        with self._lock:
            session = self._session
            status = self._status
        if session is None:
            return DeveloperAccessStatus(False)
        validation = self.security.sessions.validate(session)
        if not validation.valid:
                                                                                                 
                                                                                                 
            with self._lock:
                stale = self._session
                self._session = None
                self._status = DeveloperAccessStatus(False)
                self._root_integrity = None
                self._pending.clear()
            if stale is not None:
                self._retire_session(stale)
                try:
                    self.security.audit.emit(
                        actor=stale.principal_id, action="developer.logout", resource="developer:internal/session",
                        decision="allow", trust_domain=TrustDomain.DEVELOPER, reason=validation.code,
                    )
                except Exception:
                    LOGGER.exception("Failed to persist passive Developer session retirement audit")
            return DeveloperAccessStatus(False)
        return status

    def _prune_pending_locked(self, now: datetime) -> None:
        expired = [key for key, item in self._pending.items() if now >= item.expires_at]
        for key in expired:
            self._pending.pop(key, None)
        if len(self._pending) >= MAX_PENDING_CHALLENGES:
                                                                                          
            oldest = min(self._pending.items(), key=lambda pair: pair[1].expires_at)[0]
            self._pending.pop(oldest, None)

    def begin_login(self, bundle: Mapping[str, Any], *, now: datetime | None = None) -> DeveloperLoginChallenge:
        current = datetime.now(UTC) if now is None else (now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC))
        credential = verify_login_bundle(bundle, self.trust_store, self.revocations, at=current)
        challenge_id = new_id("dev-challenge")
        expires = current + timedelta(seconds=DEVELOPER_CHALLENGE_TTL_SECONDS)
        payload = {
            "schema": CHALLENGE_SCHEMA,
            "challenge_id": challenge_id,
            "nonce": b64u_encode(secrets.token_bytes(32)),
            "process_nonce": self._process_nonce,
            "certificate_sha256": credential.certificate_sha256,
            "developer_id": credential.developer_id,
            "issued_at": current.isoformat(),
            "expires_at": expires.isoformat(),
            "purpose": "official-developer-login",
        }
        with self._lock:
            self._prune_pending_locked(current)
            self._pending[challenge_id] = _PendingChallenge(
                kind="developer", payload=payload, expires_at=expires, credential=credential
            )
        try:
            self.security.audit.emit(
                actor=credential.developer_id,
                action="developer.login.challenge",
                resource="developer:internal/login",
                decision="issued",
                trust_domain=TrustDomain.DEVELOPER,
                reason="CERTIFICATE_CHAIN_VALID",
                correlation_id=challenge_id,
            )
        except Exception:
                                                                                                
                                                                                                 
                                                           
            with self._lock:
                self._pending.pop(challenge_id, None)
            raise
        return DeveloperLoginChallenge(challenge_id, CHALLENGE_SCHEMA, payload, expires.isoformat())

    def complete_login(
        self,
        challenge_id: str,
        signature_b64u: str,
        *,
        now: datetime | None = None,
    ) -> Session:
        current = datetime.now(UTC) if now is None else (now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC))
                                                                                        
        with self._lock:
            pending = self._pending.pop(str(challenge_id), None)
        if pending is None or pending.kind != "developer" or pending.credential is None:
            raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge is missing, expired, or already consumed")
        credential = pending.credential
        if current >= pending.expires_at:
            self._audit_login_failure(credential.developer_id, challenge_id, "CHALLENGE_EXPIRED")
            raise _error("DEVELOPER_CHALLENGE_EXPIRED", "Developer login challenge has expired")
        try:
            signature = b64u_decode(signature_b64u, max_bytes=128)
            if len(signature) != 64:
                raise ValueError("wrong signature size")
            Ed25519PublicKey.from_public_bytes(credential.public_key).verify(signature, canonical_json(pending.payload))
        except (InvalidSignature, ValueError, ArenyxaError) as exc:
            self._audit_login_failure(credential.developer_id, challenge_id, "PRIVATE_KEY_PROOF_INVALID")
            raise _error("DEVELOPER_PRIVATE_KEY_PROOF_INVALID", "Developer private-key challenge proof failed") from exc

                                                                                            
                                                                       
        credential_expiry = datetime.fromisoformat(credential.expires_at).astimezone(UTC)
        remaining = max(0, int((credential_expiry - current).total_seconds()))
        ttl = min(OFFICIAL_SESSION_TTL_SECONDS, remaining)
        if ttl < 1:
            self._audit_login_failure(credential.developer_id, challenge_id, "CERTIFICATE_EXPIRED")
            raise _error("DEVELOPER_CERT_TIME_INVALID", "Developer certificate expired before login completed")

        identity = self.security.state.create_identity(
            TrustDomain.DEVELOPER,
            principal_id=f"developer:{credential.developer_id}:{credential.certificate_serial}",
            display_name=credential.developer_id,
            kind="official_developer",
        )
        identity.metadata.update(
            {
                "developer_id": credential.developer_id,
                "certificate_serial": credential.certificate_serial,
                "certificate_sha256": credential.certificate_sha256,
                "root_key_id": credential.root_key_id,
                "developer_fingerprint": credential.developer_fingerprint,
            }
        )
        session = self.security.issue_session(
            identity.id,
            capabilities=list(credential.capabilities),
            ttl_seconds=ttl,
            metadata={
                "authentication": "certificate+ed25519-challenge",
                "certificate_sha256": credential.certificate_sha256,
                "developer_id": credential.developer_id,
            },
        )
        status = DeveloperAccessStatus(
            True,
            kind="official_developer",
            developer_id=credential.developer_id,
            certificate_serial=credential.certificate_serial,
            certificate_sha256=credential.certificate_sha256,
            fingerprint=credential.developer_fingerprint,
            capabilities=tuple(session.granted_capabilities),
            session_expires_at=session.expires_at,
            credential_expires_at=credential.expires_at,
            root_key_id=credential.root_key_id,
        )
                                                                                            
                                                                                           
                                                                                             
                                          
        try:
            self.security.audit.emit(
                actor=session.principal_id,
                action="developer.login",
                resource="developer:internal/session",
                decision="allow",
                trust_domain=TrustDomain.DEVELOPER,
                correlation_id=challenge_id,
                reason="CERTIFICATE_AND_PRIVATE_KEY_PROOF_VALID",
            )
        except Exception:
            self._retire_session(session)
            raise
        with self._lock:
            old = self._session
            self._session = session
            self._status = status
        self._retire_session(old)
        return session

    def _audit_login_failure(self, actor: str, correlation_id: str, reason: str) -> None:
        self.security.audit.emit(
            actor=str(actor)[:256] or "unknown-developer",
            action="developer.login",
            resource="developer:internal/session",
            decision="deny",
            trust_domain=TrustDomain.DEVELOPER,
            correlation_id=correlation_id,
            reason=reason,
        )

    def _retire_session(self, session: Session | None) -> None:
        if session is None:
            return
                                                                                           
                                                                                                
                                                                                              
                                                                        
        self.security.state.revoke_session(session.id)
        self.security.state.remove_identity(session.identity_id)
        self.security.state.forget_session_revocation(session.id)

    def logout(self, *, reason: str = "USER_LOGOUT") -> None:
        with self._lock:
            session = self._session
            self._session = None
            self._status = DeveloperAccessStatus(False)
            self._root_integrity = None
            self._pending.clear()
        if session is not None:
            self._retire_session(session)
            self.security.audit.emit(
                actor=session.principal_id,
                action="developer.logout",
                resource="developer:internal/session",
                decision="allow",
                trust_domain=TrustDomain.DEVELOPER,
                reason=reason,
            )

    def require(
        self,
        capability: str,
        action: str,
        *,
        high_risk: bool = False,
        risk_confirmed: bool = False,
    ) -> None:
        if high_risk and not risk_confirmed:
            status = self.status()
            self.security.audit.emit(
                actor=status.developer_id or "anonymous",
                action=str(capability),
                resource=f"developer:internal/{action}",
                decision="deny",
                trust_domain=TrustDomain.DEVELOPER,
                reason="HIGH_RISK_CONFIRMATION_REQUIRED",
            )
            raise _error("DEVELOPER_HIGH_RISK_CONFIRMATION_REQUIRED", "High-risk developer operation requires explicit confirmation")
        with self._lock:
            session = self._session
        self.security.require(session, str(capability), f"developer:internal/{action}")

    def _probe_root_integrity_for_key(
        self, root_key_id: str, *, active_proof: bool = False
    ) -> RootIntegrityStatus:
        if self.root_workstation is not None:
            return self.root_workstation.root_integrity_for_key(
                root_key_id, active_proof=active_proof
            )
        root = self.trust_store.root(str(root_key_id))
        if root is None:
            return RootIntegrityStatus(
                root_key_id=str(root_key_id), reason="DEVELOPER_ROOT_UNTRUSTED"
            )
        return probe_root_integrity(root, active_proof=active_proof)

    def begin_root_owner_login(
        self, bundle: Mapping[str, Any], *, now: datetime | None = None
    ) -> DeveloperLoginChallenge:
        





        current = datetime.now(UTC) if now is None else (
            now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
        )
        credential = verify_owner_login_bundle(bundle, self.trust_store, self.revocations, at=current)
        passive_integrity = self._probe_root_integrity_for_key(credential.root_key_id, active_proof=False)
        if not passive_integrity.integrity_valid:
            self._audit_login_failure(credential.owner_id, "root-integrity", passive_integrity.reason or "ROOT_INTEGRITY_INVALID")
            raise _error(
                "ROOT_INTEGRITY_INVALID",
                "Root Owner login was denied because the trusted Root integrity check failed",
                reason=passive_integrity.reason,
                root_key_id=credential.root_key_id,
            )
        challenge_id = new_id("owner-challenge")
        expires = current + timedelta(seconds=OWNER_CHALLENGE_TTL_SECONDS)
        payload = {
            "schema": OWNER_CHALLENGE_SCHEMA,
            "challenge_id": challenge_id,
            "nonce": b64u_encode(secrets.token_bytes(32)),
            "process_nonce": self._process_nonce,
            "certificate_sha256": credential.certificate_sha256,
            "developer_id": credential.owner_id,
            "issued_at": current.isoformat(),
            "expires_at": expires.isoformat(),
            "purpose": "root-owner-authority-login",
        }
        with self._lock:
            self._prune_pending_locked(current)
            self._pending[challenge_id] = _PendingChallenge(
                kind="root_owner", payload=payload, expires_at=expires, credential=credential, bundle=dict(bundle)
            )
        try:
            self.security.audit.emit(
                actor=credential.owner_id,
                action="developer.root_owner_login.challenge",
                resource="developer:internal/login",
                decision="issued",
                trust_domain=TrustDomain.DEVELOPER,
                correlation_id=challenge_id,
                reason="OWNER_CERTIFICATE_CHAIN_AND_ROOT_INTEGRITY_VALID",
            )
        except Exception:
            with self._lock:
                self._pending.pop(challenge_id, None)
            raise
        return DeveloperLoginChallenge(challenge_id, OWNER_CHALLENGE_SCHEMA, payload, expires.isoformat())

    def complete_root_owner_login(
        self,
        challenge_id: str,
        signature_b64u: str,
        *,
        now: datetime | None = None,
    ) -> Session:
        current = datetime.now(UTC) if now is None else (
            now.replace(tzinfo=UTC) if now.tzinfo is None else now.astimezone(UTC)
        )
                                                                               
        with self._lock:
            pending = self._pending.pop(str(challenge_id), None)
        if pending is None or pending.kind != "root_owner" or not isinstance(pending.credential, VerifiedOwnerCredential):
            raise _error("ROOT_OWNER_CHALLENGE_INVALID", "Root Owner login challenge is missing, expired, or already consumed")
        credential = pending.credential
        if current >= pending.expires_at:
            self._audit_login_failure(credential.owner_id, str(challenge_id), "OWNER_CHALLENGE_EXPIRED")
            raise _error("ROOT_OWNER_CHALLENGE_EXPIRED", "Root Owner login challenge has expired")
        try:
            signature = b64u_decode(signature_b64u, max_bytes=128)
            if len(signature) != 64:
                raise ValueError("wrong signature size")
            Ed25519PublicKey.from_public_bytes(credential.public_key).verify(
                signature, canonical_json(pending.payload)
            )
        except (InvalidSignature, ValueError, ArenyxaError) as exc:
            self._audit_login_failure(credential.owner_id, str(challenge_id), "OWNER_PRIVATE_KEY_PROOF_INVALID")
            raise _error("ROOT_OWNER_PRIVATE_KEY_PROOF_INVALID", "Root Owner private-key challenge proof failed") from exc

        root_integrity = self._probe_root_integrity_for_key(credential.root_key_id, active_proof=True)
        if not root_integrity.authority_ready:
            reason = root_integrity.reason or "ROOT_INTEGRITY_PROOF_FAILED"
            self._audit_login_failure(credential.owner_id, str(challenge_id), reason)
            raise _error(
                "ROOT_INTEGRITY_PROOF_FAILED",
                "Root Owner authentication succeeded but Root key integrity proof failed",
                reason=reason,
                root_key_id=credential.root_key_id,
            )

        expiry_text = credential.expires_at.strip()
        if expiry_text.endswith("Z"):
            expiry_text = expiry_text[:-1] + "+00:00"
        try:
            credential_expiry = datetime.fromisoformat(expiry_text)
        except (TypeError, ValueError, OverflowError) as exc:
            raise _error("DEVELOPER_OWNER_CERT_TIME_INVALID", "Root Owner Authority certificate expiry is invalid") from exc
        if credential_expiry.tzinfo is None:
            raise _error("DEVELOPER_OWNER_CERT_TIME_INVALID", "Root Owner Authority certificate expiry has no timezone")
        credential_expiry = credential_expiry.astimezone(UTC)
        remaining = max(0, int((credential_expiry - current).total_seconds()))
        ttl = min(OWNER_SESSION_TTL_SECONDS, remaining)
        if ttl < 1:
            self._audit_login_failure(credential.owner_id, str(challenge_id), "OWNER_CERTIFICATE_EXPIRED")
            raise _error("DEVELOPER_OWNER_CERT_TIME_INVALID", "Root Owner Authority certificate expired before login completed")

        identity = self.security.state.create_identity(
            TrustDomain.DEVELOPER,
            principal_id=f"root-owner:{credential.owner_id}:{credential.certificate_serial}",
            display_name=credential.owner_id,
            kind="root_owner",
        )
        identity.metadata.update(
            {
                "owner_id": credential.owner_id,
                "certificate_serial": credential.certificate_serial,
                "certificate_sha256": credential.certificate_sha256,
                "root_key_id": credential.root_key_id,
                "owner_fingerprint": credential.owner_fingerprint,
                "root_integrity_verified": True,
                "root_artifact_sha256": root_integrity.artifact_sha256,
                "root_schema": root_integrity.root_schema,
                "root_generation": root_integrity.generation,
                "root_hardware_backed": root_integrity.hardware_required,
            }
        )
        session = self.security.issue_session(
            identity.id,
            capabilities=list(credential.capabilities) + ["platform.root"],
            ttl_seconds=ttl,
            metadata={
                "authentication": "owner-certificate+ed25519-challenge",
                "certificate_sha256": credential.certificate_sha256,
                "owner_id": credential.owner_id,
                "root_integrity_verified": True,
                "root_artifact_sha256": root_integrity.artifact_sha256,
                "root_schema": root_integrity.root_schema,
                "root_generation": root_integrity.generation,
                "root_hardware_backed": root_integrity.hardware_required,
                "root_hardware_proof": root_integrity.proof_of_possession,
            },
        )
        status = DeveloperAccessStatus(
            True,
            kind="root_owner",
            developer_id=credential.owner_id,
            certificate_serial=credential.certificate_serial,
            certificate_sha256=credential.certificate_sha256,
            fingerprint=credential.owner_fingerprint,
            capabilities=tuple(session.granted_capabilities),
            session_expires_at=session.expires_at,
            credential_expires_at=credential.expires_at,
            root_key_id=credential.root_key_id,
        )
                                                                                                  
                                                     
        try:
            self.security.audit.emit(
                actor=session.principal_id,
                action="developer.root_owner_login",
                resource="developer:internal/session",
                decision="allow",
                trust_domain=TrustDomain.DEVELOPER,
                correlation_id=str(challenge_id),
                reason="OWNER_CERTIFICATE_PRIVATE_KEY_AND_ROOT_INTEGRITY_VALID",
            )
        except Exception:
            self._retire_session(session)
            raise

        workstation_bound = False
        if (
            self.root_workstation is not None
            and pending.bundle is not None
            and self.root_workstation.supported
        ):
            try:
                binding = self.root_workstation.provision(pending.bundle, at=current)
                workstation_bound = bool(binding.active)
                self.security.audit.emit(
                    actor=session.principal_id,
                    action="developer.root_workstation.bind",
                    resource="developer:internal/root-workstation",
                    decision="allow",
                    trust_domain=TrustDomain.DEVELOPER,
                    correlation_id=str(challenge_id),
                    reason="OWNER_AUTHORITY_AND_DPAPI_BOUND_VERIFIED",
                )
            except (ArenyxaError, OSError, ValueError, TypeError) as exc:
                if workstation_bound:
                    try:
                        self.root_workstation.clear()
                    except ArenyxaError:
                        LOGGER.exception("Failed to roll back Root workstation binding after activation failure")
                self._retire_session(session)
                try:
                    self.security.audit.emit(
                        actor=credential.owner_id,
                        action="developer.root_workstation.bind",
                        resource="developer:internal/root-workstation",
                        decision="deny",
                        trust_domain=TrustDomain.DEVELOPER,
                        correlation_id=str(challenge_id),
                        reason=getattr(exc, "code", "ROOT_WORKSTATION_BIND_FAILED"),
                    )
                except (OSError, ValueError, TypeError):
                    LOGGER.exception("Failed to persist Root workstation binding failure audit")
                raise _error(
                    "ROOT_WORKSTATION_BIND_FAILED",
                    "Root Owner authentication succeeded but the protected workstation binding could not be established",
                ) from exc

        with self._lock:
            old = self._session
            self._session = session
            self._status = status
            self._root_integrity = root_integrity
        self._retire_session(old)
        return session

    def root_workstation_status(self) -> RootWorkstationStatus:
        if self.root_workstation is None:
            return RootWorkstationStatus(False, reason="UNAVAILABLE")
        return self.root_workstation.detect()

    def root_capability_state(self) -> RootCapabilityState:
        if self.root_workstation is None:
            return RootCapabilityState(
                False, False, False, False, False, False, False, reason="UNAVAILABLE"
            )
        status = self.status()
        authenticated = bool(
            status.authenticated
            and status.kind == "root_owner"
            and "platform.root" in status.capabilities
        )
        with self._lock:
            cached_integrity = self._root_integrity if authenticated else None
        return self.root_workstation.capability_state(
            authenticated=authenticated, integrity_state=cached_integrity
        )

    def root_integrity_state(self, *, active_proof: bool = False) -> RootIntegrityStatus:
        if self.root_workstation is None:
            return RootIntegrityStatus(reason="UNAVAILABLE")
        if active_proof:
            return self.root_workstation.integrity_state(active_proof=True)
        status = self.status()
        authenticated = bool(
            status.authenticated and status.kind == "root_owner" and "platform.root" in status.capabilities
        )
        if authenticated:
            with self._lock:
                cached = self._root_integrity
            if cached is not None:
                return cached
        return self.root_workstation.integrity_state(active_proof=False)

    def root_workstation_registered(self) -> bool:
        return bool(self.root_workstation is not None and self.root_workstation.registered)

    def root_startup_security_status(self) -> RootStartupSecurityStatus:
        if self.root_workstation is None:
            return RootStartupSecurityStatus(False, False, 0, ROOT_OWNER_MAX_STARTUP_FAILURES, "UNAVAILABLE")
        return self.root_workstation.startup_security_status()

    def load_bound_root_owner_bundle(self) -> dict[str, Any]:
        if self.root_workstation is None:
            raise _error("ROOT_WORKSTATION_UNAVAILABLE", "Root workstation binding backend is unavailable")
        return self.root_workstation.load_bound_owner_bundle()

    def _audit_root_startup_security_state(
        self, status: RootStartupSecurityStatus, *, action: str, decision: str
    ) -> None:
        binding = self.root_workstation_status()
        actor = binding.owner_id or "root-workstation"
        reason = (
            f"{status.reason or 'ROOT_OWNER_AUTH_REQUIRED'};"
            f"attempts={status.failed_attempts}/{status.max_attempts};locked={str(status.locked).lower()}"
        )
        self.security.audit.emit(
            actor=actor,
            action=action,
            resource="developer:internal/root-workstation/startup",
            decision=decision,
            trust_domain=TrustDomain.DEVELOPER,
            reason=reason,
        )

    def record_root_startup_failure(self, reason: str) -> RootStartupSecurityStatus:
        if self.root_workstation is None:
            raise _error("ROOT_WORKSTATION_UNAVAILABLE", "Root workstation binding backend is unavailable")
        status = self.root_workstation.record_startup_failure(reason)
        self._audit_root_startup_security_state(
            status, action="developer.root_owner_startup_auth", decision="deny"
        )
        return status

    def record_root_startup_cancel(self) -> RootStartupSecurityStatus:
        if self.root_workstation is None:
            raise _error("ROOT_WORKSTATION_UNAVAILABLE", "Root workstation binding backend is unavailable")
        status = self.root_workstation.record_startup_cancel()
        self._audit_root_startup_security_state(
            status, action="developer.root_owner_startup_auth", decision="cancel"
        )
        return status

    def activate_root_workstation_session(self) -> Session | None:
        """Never mint Root authority from workstation binding alone.

        Previous versions previously treated a valid DPAPI binding as sufficient to recreate
        a Root session after restart.  Root authority now requires a fresh
        Owner-device private-key challenge on every desktop launch.
        """
        status = self.status()
        if status.authenticated and status.kind == "root_owner" and "platform.root" in status.capabilities:
            with self._lock:
                return self._session
        return None

    def ensure_root_workstation_session(self) -> Session | None:
        """Return an already-authenticated Root session; never auto-reactivate one."""
        return self.activate_root_workstation_session()

    def load_bundle(self, path: Path) -> dict[str, Any]:
        return load_json_object(Path(path))
