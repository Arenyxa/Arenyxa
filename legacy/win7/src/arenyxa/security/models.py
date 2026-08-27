from __future__ import annotations

import threading
from dataclasses import field
from datetime import datetime, timedelta
from typing import Any

from arenyxa.compat import UTC, StrEnum, dataclass
from arenyxa.domain.models import new_id


class TrustDomain(StrEnum):
    PERSONAL = "personal"
    DEVELOPER = "developer"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    trust_domain: TrustDomain
    kind: str = "user"


@dataclass(slots=True)
class Identity:
    id: str
    principal: Principal
    display_name: str = ""
    enabled: bool = True
    generation: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Credential:
    id: str
    principal_id: str
    trust_domain: TrustDomain
    kind: str
    public_reference: str = ""
    expires_at: str | None = None
    revoked: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DeviceIdentity:
    id: str
    trust_domain: TrustDomain
    public_key_fingerprint: str = ""
    revoked: bool = False
    generation: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Session:
    id: str
    principal_id: str
    identity_id: str
    trust_domain: TrustDomain
    issued_at: str
    expires_at: str
    identity_generation: int
    device_id: str = ""
    device_generation: int = 0
    granted_capabilities: tuple[str, ...] = field(default_factory=tuple)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SessionValidation:
    valid: bool
    code: str
    reason: str


class SecurityState:
    






    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._identities: dict[str, Identity] = {}
        self._devices: dict[str, DeviceIdentity] = {}
        self._revoked_sessions: set[str] = set()

    def register_identity(self, identity: Identity) -> None:
        with self._lock:
            if identity.id in self._identities:
                raise ValueError(f"identity already exists: {identity.id}")
            self._identities[identity.id] = identity

    def create_identity(
        self,
        trust_domain: TrustDomain,
        *,
        principal_id: str | None = None,
        display_name: str = "",
        kind: str = "user",
    ) -> Identity:
        principal = Principal(principal_id or new_id("principal"), trust_domain, kind)
        identity = Identity(new_id("identity"), principal, display_name=display_name)
        self.register_identity(identity)
        return identity

    def identity(self, identity_id: str) -> Identity | None:
        with self._lock:
            return self._identities.get(str(identity_id))

    def remove_identity(self, identity_id: str) -> bool:
        
        with self._lock:
            return self._identities.pop(str(identity_id), None) is not None

    def disable_identity(self, identity_id: str) -> None:
        with self._lock:
            identity = self._identities[str(identity_id)]
            identity.enabled = False
            identity.generation += 1

    def bump_identity_generation(self, identity_id: str) -> int:
        with self._lock:
            identity = self._identities[str(identity_id)]
            identity.generation += 1
            return identity.generation

    def register_device(self, device: DeviceIdentity) -> None:
        with self._lock:
            if device.id in self._devices:
                raise ValueError(f"device already exists: {device.id}")
            self._devices[device.id] = device

    def create_device(self, trust_domain: TrustDomain, public_key_fingerprint: str = "") -> DeviceIdentity:
        device = DeviceIdentity(new_id("device"), trust_domain, public_key_fingerprint=public_key_fingerprint)
        self.register_device(device)
        return device

    def device(self, device_id: str) -> DeviceIdentity | None:
        with self._lock:
            return self._devices.get(str(device_id))

    def revoke_device(self, device_id: str) -> None:
        with self._lock:
            device = self._devices[str(device_id)]
            device.revoked = True
            device.generation += 1

    def revoke_session(self, session_id: str) -> None:
        with self._lock:
            self._revoked_sessions.add(str(session_id))

    def session_revoked(self, session_id: str) -> bool:
        with self._lock:
            return str(session_id) in self._revoked_sessions

    def forget_session_revocation(self, session_id: str) -> None:
        
        with self._lock:
            self._revoked_sessions.discard(str(session_id))


class SessionValidator:
    def __init__(self, state: SecurityState) -> None:
        self.state = state

    @staticmethod
    def _parse(value: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(str(value))
        except (TypeError, ValueError, OverflowError):
            return None
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)

    @staticmethod
    def _normalize_now(value: datetime | None) -> datetime:
        if value is None:
            return datetime.now(UTC)
        if not isinstance(value, datetime):
            raise TypeError("now must be a datetime or None")
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def validate(self, session: Session, *, now: datetime | None = None) -> SessionValidation:
        current = self._normalize_now(now)
        issued = self._parse(session.issued_at)
        expires = self._parse(session.expires_at)
        if issued is None or expires is None or expires <= issued:
            return SessionValidation(False, "SESSION_TIME_INVALID", "session timestamps are invalid")
        if current >= expires:
            return SessionValidation(False, "SESSION_EXPIRED", "session has expired")
        if issued - current > timedelta(minutes=5):
            return SessionValidation(False, "SESSION_NOT_YET_VALID", "session issue time is in the future")
        if self.state.session_revoked(session.id):
            return SessionValidation(False, "SESSION_REVOKED", "session has been revoked")
        identity = self.state.identity(session.identity_id)
        if identity is None:
            return SessionValidation(False, "IDENTITY_MISSING", "session identity no longer exists")
        if not identity.enabled:
            return SessionValidation(False, "IDENTITY_DISABLED", "identity is disabled")
        if identity.principal.id != session.principal_id:
            return SessionValidation(False, "SESSION_PRINCIPAL_MISMATCH", "session principal does not match identity")
        if identity.principal.trust_domain != session.trust_domain:
            return SessionValidation(False, "SESSION_TRUST_MISMATCH", "identity/session trust domains differ")
        if identity.generation != session.identity_generation:
            return SessionValidation(False, "SESSION_GENERATION_REVOKED", "identity generation changed")
        if session.device_id:
            device = self.state.device(session.device_id)
            if device is None:
                return SessionValidation(False, "DEVICE_MISSING", "session device no longer exists")
            if device.trust_domain != session.trust_domain:
                return SessionValidation(False, "DEVICE_TRUST_MISMATCH", "device/session trust domains differ")
            if device.revoked:
                return SessionValidation(False, "DEVICE_REVOKED", "device has been revoked")
            if device.generation != session.device_generation:
                return SessionValidation(False, "DEVICE_GENERATION_REVOKED", "device generation changed")
        return SessionValidation(True, "OK", "session is valid")
