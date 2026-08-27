from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from arenyxa.compat import UTC
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.security.developer_credentials import (
    DeveloperRevocationSet,
    DeveloperTrustStore,
    VerifiedOwnerCredential,
    b64u_decode,
    b64u_encode,
    canonical_json,
    load_json_object,
    verify_owner_login_bundle,
)
from arenyxa.security.developer_trust_anchors import (
    EMBEDDED_DEVELOPER_REVOCATIONS,
    EMBEDDED_DEVELOPER_ROOTS,
)
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider
from arenyxa.security.hardware_root_lifecycle import RootIntegrityStatus, probe_root_integrity
from arenyxa.security.key_protection import DPAPIKeyProtectionAdapter, KeyProtectionAdapter
from arenyxa.application.root_owner_security import (
    RootCapabilityState,
    RootStartupSecurityStatus,
    RootWorkstationStatus,
    root_owner_startup_attempt_budget,
)

LOGGER = logging.getLogger(__name__)


def _error(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="DEVELOPER_ACCESS", context=context)


ROOT_WORKSTATION_BINDING_SCHEMA_V1 = "arenyxa.root-developer-workstation-binding/v1"
ROOT_WORKSTATION_PAYLOAD_SCHEMA_V1 = "arenyxa.root-developer-workstation-payload/v1"
ROOT_WORKSTATION_BINDING_SCHEMA = "arenyxa.root-developer-workstation-binding/v2"
ROOT_WORKSTATION_PAYLOAD_SCHEMA = "arenyxa.root-developer-workstation-payload/v2"
ROOT_WORKSTATION_PURPOSE = "Arenyxa Root Developer Workstation v1"
ROOT_WORKSTATION_AUTH_SCHEMA = "arenyxa.root-owner-startup-auth-state/v1"
ROOT_WORKSTATION_AUTH_WRAPPER_SCHEMA = "arenyxa.root-owner-startup-auth-wrapper/v1"
ROOT_WORKSTATION_AUTH_PURPOSE = "Arenyxa Root Owner Startup Authentication v1"
ROOT_WORKSTATION_MAX_BYTES = 512 * 1024
ROOT_OWNER_MAX_STARTUP_FAILURES = 3
ROOT_WORKSTATION_PROBE_ERRORS = (ArenyxaError, OSError, RuntimeError, ValueError, TypeError, KeyError)


def _json_object_no_duplicates(raw: bytes) -> dict[str, Any]:
    if len(raw) > ROOT_WORKSTATION_MAX_BYTES:
        raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation binding exceeds size limit")

    def hook(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON key: {key}")
            value[key] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=hook)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation binding JSON is invalid") from exc
    if not isinstance(value, dict):
        raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation binding must be an object")
    return value


from arenyxa.application.root_owner_security import (
    RootCapabilityState,
    RootStartupSecurityStatus,
    RootWorkstationStatus,
    root_owner_startup_attempt_budget,
)


class RootWorkstationBinding:
    """DPAPI-bound Root workstation identity plus persistent startup-auth lock state.

    A workstation binding is evidence that this Windows profile has previously
    enrolled a Root Owner credential.  It is deliberately *not* sufficient to
    mint a Root session on process start.  Every desktop launch must prove the
    Owner device private key again through the normal challenge protocol.
    """

    def __init__(
        self,
        data_root: Path,
        trust_store: DeveloperTrustStore,
        revocations: DeveloperRevocationSet,
        *,
        protector: KeyProtectionAdapter | None = None,
        hardware_root_provider: Any | None = None,
    ) -> None:
        developer_dir = Path(data_root) / "developer"
        self.path = developer_dir / "root_workstation.binding.json"
        self.auth_state_path = developer_dir / "root_workstation.auth_state.json"
        self.trust_store = trust_store
        self.revocations = revocations
        self.protector = protector or DPAPIKeyProtectionAdapter()
        # Passive startup inspection never creates or mutates a TPM key. Active
        # proof is requested only while completing explicit Root Owner login.
        self.hardware_root_provider = hardware_root_provider or WindowsTPMEcdsaP256Provider()

    @property
    def supported(self) -> bool:
        return bool(self.protector.available())

    @property
    def registered(self) -> bool:
        return self.path.is_file()

    @staticmethod
    def _at(value: datetime | None) -> datetime:
        if value is None:
            return datetime.now(UTC)
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    def _decode_binding(
        self, *, at: datetime | None = None
    ) -> tuple[dict[str, Any], dict[str, Any], VerifiedOwnerCredential]:
        if not self.path.is_file():
            raise _error("ROOT_WORKSTATION_NOT_PROVISIONED", "Root Developer workstation is not provisioned")
        if not self.supported:
            raise _error(
                "ROOT_WORKSTATION_PROTECTION_UNAVAILABLE",
                "Root Developer workstation binding requires an available machine/user key protector",
            )
        wrapper = load_json_object(self.path, max_bytes=ROOT_WORKSTATION_MAX_BYTES)
        if set(wrapper) != {"schema", "protection", "ciphertext"}:
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation wrapper fields are invalid")
        wrapper_schema = str(wrapper.get("schema", ""))
        if wrapper_schema not in {ROOT_WORKSTATION_BINDING_SCHEMA_V1, ROOT_WORKSTATION_BINDING_SCHEMA}:
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation wrapper schema is invalid")
        if str(wrapper.get("protection")) != str(self.protector.name):
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation protection provider changed")
        protected = b64u_decode(str(wrapper.get("ciphertext", "")), max_bytes=ROOT_WORKSTATION_MAX_BYTES)
        plaintext = self.protector.unprotect(protected, purpose=ROOT_WORKSTATION_PURPOSE)
        payload = _json_object_no_duplicates(plaintext)
        if set(payload) != {
            "schema", "bundle", "owner_id", "root_key_id", "certificate_sha256",
            "fingerprint", "nonce", "provisioned_at",
        }:
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation payload fields are invalid")
        payload_schema = str(payload.get("schema", ""))
        expected_payload = (
            ROOT_WORKSTATION_PAYLOAD_SCHEMA_V1
            if wrapper_schema == ROOT_WORKSTATION_BINDING_SCHEMA_V1
            else ROOT_WORKSTATION_PAYLOAD_SCHEMA
        )
        if payload_schema != expected_payload:
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation payload schema is invalid")
        bundle = payload.get("bundle")
        if not isinstance(bundle, dict):
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation Owner bundle is invalid")
        credential = verify_owner_login_bundle(bundle, self.trust_store, self.revocations, at=at)
        if not hmac.compare_digest(str(payload.get("owner_id", "")), credential.owner_id):
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation owner binding changed")
        if not hmac.compare_digest(str(payload.get("root_key_id", "")), credential.root_key_id):
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation Root binding changed")
        if not hmac.compare_digest(str(payload.get("certificate_sha256", "")), credential.certificate_sha256):
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation certificate binding changed")
        if not hmac.compare_digest(str(payload.get("fingerprint", "")), credential.owner_fingerprint):
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation device fingerprint changed")
        nonce = b64u_decode(str(payload.get("nonce", "")), max_bytes=64)
        if len(nonce) != 32:
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation nonce is invalid")
        return wrapper, payload, credential

    def _write_auth_state(
        self,
        *,
        failed_attempts: int,
        locked: bool,
        reason: str,
        at: datetime | None = None,
    ) -> None:
        if not self.supported:
            raise _error("ROOT_WORKSTATION_PROTECTION_UNAVAILABLE", "Root Owner startup state cannot be protected")
        current = self._at(at)
        state = {
            "schema": ROOT_WORKSTATION_AUTH_SCHEMA,
            "failed_attempts": max(0, min(int(failed_attempts), ROOT_OWNER_MAX_STARTUP_FAILURES)),
            "locked": bool(locked),
            "reason": str(reason)[:128],
            "updated_at": current.isoformat(),
            "nonce": b64u_encode(secrets.token_bytes(32)),
        }
        plaintext = canonical_json(state)
        protected = self.protector.protect(plaintext, purpose=ROOT_WORKSTATION_AUTH_PURPOSE)
        round_trip = self.protector.unprotect(protected, purpose=ROOT_WORKSTATION_AUTH_PURPOSE)
        if not hmac.compare_digest(round_trip, plaintext):
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup state protection round-trip failed")
        wrapper = {
            "schema": ROOT_WORKSTATION_AUTH_WRAPPER_SCHEMA,
            "protection": str(self.protector.name),
            "ciphertext": b64u_encode(protected),
        }
        self.auth_state_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.auth_state_path, wrapper)

    def _read_auth_state(self) -> dict[str, Any]:
        wrapper = load_json_object(self.auth_state_path, max_bytes=ROOT_WORKSTATION_MAX_BYTES)
        if set(wrapper) != {"schema", "protection", "ciphertext"}:
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup state wrapper fields are invalid")
        if wrapper.get("schema") != ROOT_WORKSTATION_AUTH_WRAPPER_SCHEMA:
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup state wrapper schema is invalid")
        if str(wrapper.get("protection")) != str(self.protector.name):
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup state protection provider changed")
        protected = b64u_decode(str(wrapper.get("ciphertext", "")), max_bytes=ROOT_WORKSTATION_MAX_BYTES)
        plaintext = self.protector.unprotect(protected, purpose=ROOT_WORKSTATION_AUTH_PURPOSE)
        state = _json_object_no_duplicates(plaintext)
        if set(state) != {"schema", "failed_attempts", "locked", "reason", "updated_at", "nonce"}:
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup state fields are invalid")
        if state.get("schema") != ROOT_WORKSTATION_AUTH_SCHEMA:
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup state schema is invalid")
        attempts = int(state.get("failed_attempts", -1))
        if attempts < 0 or attempts > ROOT_OWNER_MAX_STARTUP_FAILURES:
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup failure counter is invalid")
        if not isinstance(state.get("locked"), bool):
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup lock flag is invalid")
        nonce = b64u_decode(str(state.get("nonce", "")), max_bytes=64)
        if len(nonce) != 32:
            raise _error("ROOT_WORKSTATION_AUTH_STATE_INVALID", "Root Owner startup state nonce is invalid")
        return state

    def provision(self, bundle: Mapping[str, Any], *, at: datetime | None = None) -> RootWorkstationStatus:
        if not self.supported:
            raise _error(
                "ROOT_WORKSTATION_PROTECTION_UNAVAILABLE",
                "Root Developer workstation binding requires an available machine/user key protector",
            )
        current = self._at(at)
        credential = verify_owner_login_bundle(bundle, self.trust_store, self.revocations, at=current)
        payload = {
            "schema": ROOT_WORKSTATION_PAYLOAD_SCHEMA,
            "bundle": dict(bundle),
            "owner_id": credential.owner_id,
            "root_key_id": credential.root_key_id,
            "certificate_sha256": credential.certificate_sha256,
            "fingerprint": credential.owner_fingerprint,
            "nonce": b64u_encode(secrets.token_bytes(32)),
            "provisioned_at": current.isoformat(),
        }
        plaintext = canonical_json(payload)
        protected = self.protector.protect(plaintext, purpose=ROOT_WORKSTATION_PURPOSE)
        round_trip = self.protector.unprotect(protected, purpose=ROOT_WORKSTATION_PURPOSE)
        if not hmac.compare_digest(round_trip, plaintext):
            raise _error(
                "ROOT_WORKSTATION_BINDING_INVALID",
                "Root Developer workstation key protector failed its round-trip verification",
            )
        wrapper = {
            "schema": ROOT_WORKSTATION_BINDING_SCHEMA,
            "protection": str(self.protector.name),
            "ciphertext": b64u_encode(protected),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.path, wrapper)
        self._write_auth_state(failed_attempts=0, locked=False, reason="ROOT_OWNER_AUTHENTICATED", at=current)
        verified = self.detect(at=current)
        if not verified.active:
            raise _error(
                "ROOT_WORKSTATION_BINDING_INVALID",
                "Root Developer workstation binding failed post-write verification",
                reason=verified.reason,
            )
        return RootWorkstationStatus(
            True, credential.owner_id, credential.root_key_id, credential.certificate_sha256,
            credential.owner_fingerprint, "BOUND_VERIFIED",
        )

    def detect(self, *, at: datetime | None = None) -> RootWorkstationStatus:
        if not self.path.is_file():
            return RootWorkstationStatus(False, reason="NOT_PROVISIONED")
        if not self.supported:
            return RootWorkstationStatus(False, reason="PROTECTOR_UNAVAILABLE")
        try:
            _wrapper, _payload, credential = self._decode_binding(at=at)
            return RootWorkstationStatus(
                True, credential.owner_id, credential.root_key_id, credential.certificate_sha256,
                credential.owner_fingerprint, "VERIFIED", credential.root_fingerprint,
            )
        except ROOT_WORKSTATION_PROBE_ERRORS as exc:
            LOGGER.warning("Root Developer workstation binding rejected: %s", exc)
            return RootWorkstationStatus(False, reason=getattr(exc, "code", type(exc).__name__))

    def root_integrity_for_key(
        self,
        root_key_id: str,
        *,
        active_proof: bool = False,
    ) -> RootIntegrityStatus:
        """Probe a trusted Root artifact and its local hardware key read-only.

        ``active_proof`` may invoke the TPM signing policy and therefore is used
        only after an explicit Root Owner private-key challenge succeeds.
        """
        root = self.trust_store.root(str(root_key_id))
        if root is None:
            return RootIntegrityStatus(
                root_key_id=str(root_key_id),
                integrity_valid=False,
                authority_ready=False,
                reason="DEVELOPER_ROOT_UNTRUSTED",
            )
        return probe_root_integrity(
            root, active_proof=bool(active_proof), provider=self.hardware_root_provider
        )

    def integrity_state(
        self,
        *,
        active_proof: bool = False,
        at: datetime | None = None,
    ) -> RootIntegrityStatus:
        binding = self.detect(at=at)
        if not binding.active:
            return RootIntegrityStatus(
                root_key_id=binding.root_key_id,
                integrity_valid=False,
                authority_ready=False,
                reason=binding.reason or "ROOT_WORKSTATION_BINDING_INVALID",
            )
        state = self.root_integrity_for_key(binding.root_key_id, active_proof=active_proof)
        if not state.integrity_valid:
            return state
        if binding.root_fingerprint and self.trust_store.root(binding.root_key_id) is not None:
            root = self.trust_store.root(binding.root_key_id) or {}
            if not hmac.compare_digest(str(root.get("fingerprint", "")), binding.root_fingerprint):
                return RootIntegrityStatus(
                    root_key_id=state.root_key_id,
                    root_schema=state.root_schema,
                    generation=state.generation,
                    artifact_sha256=state.artifact_sha256,
                    artifact_valid=state.artifact_valid,
                    hardware_required=state.hardware_required,
                    provider=state.provider,
                    key_name=state.key_name,
                    provider_available=state.provider_available,
                    hardware_backed=state.hardware_backed,
                    key_present=state.key_present,
                    policy_valid=state.policy_valid,
                    public_key_match=state.public_key_match,
                    key_binding_match=state.key_binding_match,
                    proof_of_possession=state.proof_of_possession,
                    integrity_valid=False,
                    authority_ready=False,
                    reason="ROOT_TRUST_FINGERPRINT_MISMATCH",
                )
        return state

    def capability_state(
        self,
        *,
        authenticated: bool = False,
        at: datetime | None = None,
        integrity_state: RootIntegrityStatus | None = None,
    ) -> RootCapabilityState:
        """Return a non-mutating Root health projection for startup/UI consumers.

        This probe intentionally performs no provisioning, repair, rotation, or
        session creation.  A valid state only establishes that the registered
        workstation can proceed to the mandatory Owner private-key challenge.
        """
        if not self.registered:
            return RootCapabilityState(
                False, False, False, False, False, False, False, reason="NOT_PROVISIONED"
            )
        if not self.supported:
            return RootCapabilityState(
                True, False, False, False, False, False, False,
                reason="PROTECTOR_UNAVAILABLE",
            )

        binding = self.detect(at=at)
        if not binding.active:
            return RootCapabilityState(
                True, False, False, False, False, False, False,
                owner_id=binding.owner_id,
                root_key_id=binding.root_key_id,
                root_fingerprint=binding.root_fingerprint,
                certificate_sha256=binding.certificate_sha256,
                owner_fingerprint=binding.fingerprint,
                reason=binding.reason or "ROOT_WORKSTATION_BINDING_INVALID",
            )

        root = self.trust_store.root(binding.root_key_id)
        if root is None:
            return RootCapabilityState(
                True, True, False, True, False, False, False,
                owner_id=binding.owner_id,
                root_key_id=binding.root_key_id,
                root_fingerprint=binding.root_fingerprint,
                certificate_sha256=binding.certificate_sha256,
                owner_fingerprint=binding.fingerprint,
                reason="DEVELOPER_ROOT_UNTRUSTED",
            )

        root_fingerprint = str(root.get("fingerprint", ""))
        if not root_fingerprint or not hmac.compare_digest(root_fingerprint, binding.root_fingerprint):
            return RootCapabilityState(
                True, True, True, True, False, False, False,
                owner_id=binding.owner_id,
                root_key_id=binding.root_key_id,
                root_fingerprint=root_fingerprint,
                certificate_sha256=binding.certificate_sha256,
                owner_fingerprint=binding.fingerprint,
                reason="ROOT_TRUST_FINGERPRINT_MISMATCH",
            )

        integrity = integrity_state
        if integrity is None or integrity.root_key_id != binding.root_key_id:
            integrity = self.root_integrity_for_key(binding.root_key_id, active_proof=False)
        if not integrity.integrity_valid:
            return RootCapabilityState(
                True, True, True, True, False, False, False,
                owner_id=binding.owner_id,
                root_key_id=binding.root_key_id,
                root_fingerprint=root_fingerprint,
                certificate_sha256=binding.certificate_sha256,
                owner_fingerprint=binding.fingerprint,
                reason=integrity.reason or "ROOT_INTEGRITY_INVALID",
                integrity_valid=False,
                hardware_root=integrity.hardware_required,
                hardware_proof_required=integrity.hardware_required,
                root_artifact_sha256=integrity.artifact_sha256,
                integrity_reason=integrity.reason,
            )

        authority_active = bool(
            authenticated
            and (not integrity.hardware_required or integrity.authority_ready)
        )
        proof_required = bool(integrity.hardware_required and not integrity.authority_ready)
        return RootCapabilityState(
            True,
            True,
            True,
            True,
            True,
            authority_active,
            not authority_active,
            owner_id=binding.owner_id,
            root_key_id=binding.root_key_id,
            root_fingerprint=root_fingerprint,
            certificate_sha256=binding.certificate_sha256,
            owner_fingerprint=binding.fingerprint,
            reason=(
                "AUTHENTICATED" if authority_active
                else "ROOT_HARDWARE_PROOF_REQUIRED" if proof_required and authenticated
                else "ROOT_OWNER_AUTH_REQUIRED"
            ),
            integrity_valid=True,
            hardware_root=integrity.hardware_required,
            hardware_proof_required=proof_required,
            root_artifact_sha256=integrity.artifact_sha256,
            integrity_reason=integrity.reason,
        )

    def load_bound_owner_bundle(self, *, at: datetime | None = None) -> dict[str, Any]:
        _wrapper, payload, _credential = self._decode_binding(at=at)
        bundle = payload.get("bundle")
        if not isinstance(bundle, dict):
            raise _error("ROOT_WORKSTATION_BINDING_INVALID", "Root Developer workstation Owner bundle is invalid")
        return dict(bundle)

    def startup_security_status(self) -> "RootStartupSecurityStatus":
        if not self.registered:
            return RootStartupSecurityStatus(False, False, 0, ROOT_OWNER_MAX_STARTUP_FAILURES, "NOT_PROVISIONED")
        binding = self.detect()
        if not binding.active:
            return RootStartupSecurityStatus(
                True, True, ROOT_OWNER_MAX_STARTUP_FAILURES, ROOT_OWNER_MAX_STARTUP_FAILURES,
                binding.reason or "ROOT_WORKSTATION_BINDING_INVALID",
            )
        try:
            wrapper = load_json_object(self.path, max_bytes=ROOT_WORKSTATION_MAX_BYTES)
            legacy = wrapper.get("schema") == ROOT_WORKSTATION_BINDING_SCHEMA_V1
            if not self.auth_state_path.is_file():
                if legacy:
                    return RootStartupSecurityStatus(
                        True, False, 0, ROOT_OWNER_MAX_STARTUP_FAILURES, "LEGACY_REAUTH_REQUIRED"
                    )
                return RootStartupSecurityStatus(
                    True, True, ROOT_OWNER_MAX_STARTUP_FAILURES, ROOT_OWNER_MAX_STARTUP_FAILURES,
                    "ROOT_WORKSTATION_AUTH_STATE_MISSING",
                )
            state = self._read_auth_state()
            attempts = int(state["failed_attempts"])
            return RootStartupSecurityStatus(
                True, bool(state["locked"]), attempts, ROOT_OWNER_MAX_STARTUP_FAILURES, str(state["reason"]),
            )
        except ROOT_WORKSTATION_PROBE_ERRORS as exc:
            LOGGER.warning("Root Owner startup authentication state rejected: %s", exc)
            return RootStartupSecurityStatus(
                True, True, ROOT_OWNER_MAX_STARTUP_FAILURES, ROOT_OWNER_MAX_STARTUP_FAILURES,
                getattr(exc, "code", type(exc).__name__),
            )

    def record_startup_failure(self, reason: str, *, at: datetime | None = None) -> "RootStartupSecurityStatus":
        status = self.startup_security_status()
        attempts = min(ROOT_OWNER_MAX_STARTUP_FAILURES, max(0, status.failed_attempts) + 1)
        locked = bool(status.locked or attempts >= ROOT_OWNER_MAX_STARTUP_FAILURES)
        self._write_auth_state(failed_attempts=attempts, locked=locked, reason=str(reason), at=at)
        return RootStartupSecurityStatus(True, locked, attempts, ROOT_OWNER_MAX_STARTUP_FAILURES, str(reason))

    def record_startup_cancel(self, *, at: datetime | None = None) -> "RootStartupSecurityStatus":
        status = self.startup_security_status()
        attempts = max(1, min(ROOT_OWNER_MAX_STARTUP_FAILURES, status.failed_attempts))
        self._write_auth_state(
            failed_attempts=attempts, locked=True, reason="ROOT_OWNER_STARTUP_AUTH_CANCELLED", at=at
        )
        return RootStartupSecurityStatus(True, True, attempts, ROOT_OWNER_MAX_STARTUP_FAILURES, "ROOT_OWNER_STARTUP_AUTH_CANCELLED")

    def clear(self) -> None:
        errors: list[OSError] = []
        for path in (self.auth_state_path, self.path):
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                errors.append(exc)
        if errors:
            raise _error("ROOT_WORKSTATION_CLEAR_FAILED", "Root Developer workstation binding could not be removed") from errors[0]


def detect_root_developer_workstation(data_root: Path) -> RootWorkstationStatus:
    
    try:
        trust = DeveloperTrustStore(EMBEDDED_DEVELOPER_ROOTS)
        revocations = DeveloperRevocationSet(EMBEDDED_DEVELOPER_REVOCATIONS)
        if not trust.ready:
            return RootWorkstationStatus(False, reason="DEVELOPER_TRUST_NOT_PROVISIONED")
        return RootWorkstationBinding(Path(data_root), trust, revocations).detect()
    except ROOT_WORKSTATION_PROBE_ERRORS as exc:
        LOGGER.warning("Root Developer workstation startup probe failed closed: %s", exc)
        return RootWorkstationStatus(False, reason=getattr(exc, "code", type(exc).__name__))


def detect_root_capability_state(data_root: Path) -> RootCapabilityState:
    """Probe Root workstation/key health without granting or mutating authority."""
    try:
        trust = DeveloperTrustStore(EMBEDDED_DEVELOPER_ROOTS)
        revocations = DeveloperRevocationSet(EMBEDDED_DEVELOPER_REVOCATIONS)
        if not trust.ready:
            return RootCapabilityState(
                False, False, False, False, False, False, False,
                reason="DEVELOPER_TRUST_NOT_PROVISIONED",
            )
        return RootWorkstationBinding(Path(data_root), trust, revocations).capability_state()
    except ROOT_WORKSTATION_PROBE_ERRORS as exc:
        LOGGER.warning("Root capability startup probe failed closed: %s", exc)
        return RootCapabilityState(
            (Path(data_root) / "developer" / "root_workstation.binding.json").is_file(),
            False,
            False,
            False,
            False,
            False,
            False,
            reason=getattr(exc, "code", type(exc).__name__),
        )



__all__ = [
    "ROOT_OWNER_MAX_STARTUP_FAILURES",
    "RootWorkstationBinding",
    "detect_root_capability_state",
    "detect_root_developer_workstation",
]
