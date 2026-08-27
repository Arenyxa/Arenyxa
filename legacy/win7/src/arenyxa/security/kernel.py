from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping, TypeVar

from arenyxa.compat import UTC
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id
from arenyxa.security.audit import AuditLog
from arenyxa.security.capabilities import (
    AuthorizationDecision,
    CapabilityCatalog,
    PolicyEvaluator,
    PolicyRule,
)
from arenyxa.security.key_protection import KeyProtectionRegistry
from arenyxa.security.models import SecurityState, Session, SessionValidator, TrustDomain

T = TypeVar("T")


class SecurityKernel:
    





    def __init__(
        self,
        *,
        state: SecurityState | None = None,
        catalog: CapabilityCatalog | None = None,
        policy: PolicyEvaluator | None = None,
        audit: AuditLog | None = None,
        key_protection: KeyProtectionRegistry | None = None,
    ) -> None:
        self.state = state or SecurityState()
        self.catalog = catalog or CapabilityCatalog()
        self.policy = policy or PolicyEvaluator()
        self.audit = audit or AuditLog()
        self.key_protection = key_protection or KeyProtectionRegistry()
        self.sessions = SessionValidator(self.state)

    @classmethod
    def local_foundation(cls, data_root: Path) -> "SecurityKernel":
        return cls(audit=AuditLog(Path(data_root) / "security" / "audit.jsonl"))

    def add_policy(self, rule: PolicyRule) -> None:
        self.policy.add(rule)

    def issue_session(
        self,
        identity_id: str,
        *,
        capabilities: tuple[str, ...] | list[str],
        device_id: str = "",
        ttl_seconds: int = 3600,
        metadata: Mapping[str, Any] | None = None,
    ) -> Session:
        identity = self.state.identity(identity_id)
        if identity is None or not identity.enabled:
            raise ArenyxaError("IDENTITY_INVALID", "identity is missing or disabled", domain="SECURITY")
        ttl = int(ttl_seconds)
        if ttl < 1 or ttl > 24 * 60 * 60:
            raise ValueError("session TTL must be within 1 second and 24 hours")
        granted: list[str] = []
        for capability in capabilities:
            definition = self.catalog.require(str(capability))
            if definition.trust_domain != identity.principal.trust_domain:
                raise ArenyxaError(
                    "TRUST_DOMAIN_VIOLATION",
                    "capability belongs to another trust domain",
                    domain="SECURITY",
                    context={"capability": definition.name, "capability_domain": definition.trust_domain.value},
                )
            granted.append(definition.name)
        device_generation = 0
        if device_id:
            device = self.state.device(device_id)
            if device is None or device.revoked:
                raise ArenyxaError("DEVICE_INVALID", "device is missing or revoked", domain="SECURITY")
            if device.trust_domain != identity.principal.trust_domain:
                raise ArenyxaError("TRUST_DOMAIN_VIOLATION", "device belongs to another trust domain", domain="SECURITY")
            device_generation = device.generation
        issued = datetime.now(UTC)
        expires = issued + timedelta(seconds=ttl)
        return Session(
            id=new_id("session"),
            principal_id=identity.principal.id,
            identity_id=identity.id,
            trust_domain=identity.principal.trust_domain,
            issued_at=issued.isoformat(),
            expires_at=expires.isoformat(),
            identity_generation=identity.generation,
            device_id=str(device_id),
            device_generation=device_generation,
            granted_capabilities=tuple(sorted(set(granted))),
            metadata=dict(metadata or {}),
        )

    def authorize(
        self,
        session: Session | None,
        capability: str,
        resource: str,
        *,
        context: Mapping[str, Any] | None = None,
        correlation_id: str = "",
    ) -> AuthorizationDecision:
        correlation = str(correlation_id or new_id("corr"))
        if session is None:
            decision = AuthorizationDecision(False, "SESSION_REQUIRED", "protected operation requires a session")
            self.audit.emit(
                actor="anonymous", action=capability, resource=resource, decision="deny",
                trust_domain=self._capability_domain_or_personal(capability), correlation_id=correlation,
                reason=decision.code,
            )
            return decision

        validation = self.sessions.validate(session)
        if not validation.valid:
            decision = AuthorizationDecision(False, validation.code, validation.reason)
            self.audit.emit(
                actor=session.principal_id, action=capability, resource=resource, decision="deny",
                trust_domain=session.trust_domain, device=session.device_id, correlation_id=correlation,
                reason=decision.code,
            )
            return decision

        definition = self.catalog.get(capability)
        platform_root = (
            session.trust_domain is TrustDomain.DEVELOPER
            and "platform.root" in session.granted_capabilities
        )
        if definition is None:
            decision = AuthorizationDecision(False, "CAPABILITY_UNKNOWN", "capability is not registered")
        elif platform_root and definition.trust_domain in {TrustDomain.PERSONAL, TrustDomain.DEVELOPER}:
                                                                                                
                                                                                                 
                                                                                                   
                                                                                       
            decision = AuthorizationDecision(True, "PLATFORM_ROOT_ALLOW", "verified Root Developer platform authority")
        elif definition.trust_domain != session.trust_domain:
                                                                                                  
                                                                    
            code = "ROOT_ENTERPRISE_BOUNDARY" if platform_root and definition.trust_domain is TrustDomain.ENTERPRISE else "TRUST_DOMAIN_VIOLATION"
            decision = AuthorizationDecision(False, code, "capability belongs to another trust domain")
        else:
            decision = self.policy.evaluate(session, capability, resource, context)
        self.audit.emit(
            actor=session.principal_id,
            action=capability,
            resource=resource,
            decision="allow" if decision.allowed else "deny",
            trust_domain=session.trust_domain,
            device=session.device_id,
            correlation_id=correlation,
            reason=decision.code,
        )
        return decision

    def require(
        self,
        session: Session | None,
        capability: str,
        resource: str,
        *,
        context: Mapping[str, Any] | None = None,
        correlation_id: str = "",
    ) -> AuthorizationDecision:
        decision = self.authorize(
            session, capability, resource, context=context, correlation_id=correlation_id
        )
        if not decision.allowed:
            raise ArenyxaError(
                "AUTHORIZATION_DENIED",
                "protected operation was denied",
                domain="SECURITY",
                context={"capability": capability, "resource": resource, "decision": decision.code},
            )
        return decision

    def execute(
        self,
        session: Session | None,
        capability: str,
        resource: str,
        operation: Callable[[], T],
        *,
        context: Mapping[str, Any] | None = None,
        correlation_id: str = "",
    ) -> T:
        self.require(session, capability, resource, context=context, correlation_id=correlation_id)
        return operation()

    def _capability_domain_or_personal(self, capability: str) -> TrustDomain:
        definition = self.catalog.get(capability)
        return TrustDomain.PERSONAL if definition is None else definition.trust_domain
