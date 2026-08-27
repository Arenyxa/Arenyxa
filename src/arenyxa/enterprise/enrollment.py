from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.enterprise.vault import password_verifier
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited
from arenyxa.security.key_protection import KeyProtectionRegistry, SecretBuffer, TPMKeyProtectionAdapter

ENROLLMENT_SCHEMA = "arenyxa.enterprise-enrollment/v1"
DEVICE_VAULT_SCHEMA = "arenyxa.enterprise-device-key/v1"
ENROLLMENT_STATE_SCHEMA = "arenyxa.enterprise-enrollment-state/v1"
MAX_TOKEN_BYTES = 64 * 1024
MAX_DEVICE_VAULT_BYTES = 256 * 1024
MAX_CAMPAIGNS = 256
MAX_CREDENTIALS = 10000
MAX_DEVICES = 10000
DEFAULT_TTL_SECONDS = 24 * 60 * 60
ALLOW_ONCE_SECONDS = 10 * 60
LOGGER = logging.getLogger(__name__)


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE", context=context)


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64u(value: str, max_bytes: int = 4096) -> bytes:
    raw = str(value)
    if not raw or "=" in raw or len(raw) > max_bytes * 2:
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment artifact contains invalid base64url data")
    try:
        data = base64.urlsafe_b64decode(raw + "=" * ((4 - len(raw) % 4) % 4))
    except (binascii.Error, ValueError) as exc:
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment artifact base64url decoding failed") from exc
    if len(data) > max_bytes or _b64u(data) != raw:
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment artifact contains non-canonical base64url data")
    return data


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _strict_json_loads(raw: bytes | str, *, code: str = "ENROLLMENT_ARTIFACT_INVALID") -> Any:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _fail(code, "JSON contains duplicate object keys", key=key)
            result[key] = value
        return result
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        return json.loads(text, object_pairs_hook=hook)
    except ArenyxaError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise _fail(code, "JSON cannot be decoded") from exc


def parse_enrollment_token(raw: bytes | str) -> dict[str, Any]:
    data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    if not data or len(data) > MAX_TOKEN_BYTES:
        raise _fail("ENROLLMENT_ARTIFACT_TOO_LARGE", "Enrollment artifact is empty or exceeds safety bound")
    token = _strict_json_loads(data)
    if not isinstance(token, dict):
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment artifact must contain a JSON object")
    verify_enrollment_token(token)
    return token


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment timestamp is invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _future_iso(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=max(60, int(seconds)))).isoformat()


def verify_enrollment_token(token: Mapping[str, Any]) -> dict[str, Any]:
    required = {"schema", "payload", "root_public_key", "root_fingerprint", "signature"}
    if set(token) != required or token.get("schema") != ENROLLMENT_SCHEMA or not isinstance(token.get("payload"), dict):
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment artifact schema is invalid")
    payload = dict(token["payload"])
    payload_required = {
        "enterprise_id", "credential_id", "campaign_id", "account_id", "username", "roles",
        "issued_at", "expires_at", "purpose", "nonce", "secret",
    }
    if set(payload) != payload_required:
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment payload fields are invalid")
    if payload.get("purpose") != "device-enrollment" or not isinstance(payload.get("roles"), list):
        raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment purpose/roles are invalid")
    root_public = _unb64u(str(token.get("root_public_key", "")), 64)
    if len(root_public) != 32 or hashlib.sha256(root_public).hexdigest() != str(token.get("root_fingerprint", "")):
        raise _fail("ENROLLMENT_ROOT_INVALID", "Enrollment Enterprise Root identity is invalid")
    signature = _unb64u(str(token.get("signature", "")), 96)
    try:
        Ed25519PublicKey.from_public_bytes(root_public).verify(signature, _canonical(payload))
    except (ValueError, InvalidSignature) as exc:
        raise _fail("ENROLLMENT_SIGNATURE_INVALID", "Enrollment credential signature is invalid") from exc
    if _parse_time(str(payload["expires_at"])) <= datetime.now(timezone.utc):
        raise _fail("ENROLLMENT_EXPIRED", "Enrollment credential has expired")
    _unb64u(str(payload["secret"]), 64)
    _unb64u(str(payload["nonce"]), 64)
    return payload


class DeviceKeyStore:
    






    def __init__(self, path: Path, key_protection: KeyProtectionRegistry | None = None) -> None:
        self.path = Path(path)
        self.local_key_path = self.path.with_suffix(self.path.suffix + ".localkey")
        self._lock = threading.RLock()
        self.key_protection = key_protection or KeyProtectionRegistry()

    def _protect(self, raw: bytes, purpose: str) -> tuple[str, dict[str, str]]:
                                                                                            
                                                                                                
                                                            
        available: list[str] = []
        tpm_adapter = self.key_protection.get("tpm")
        if isinstance(tpm_adapter, TPMKeyProtectionAdapter):
            tpm_status = tpm_adapter.capability_status()
            if tpm_status.get("hardware_present") and not tpm_status.get("sealing_provider_configured"):
                LOGGER.critical(
                    "TPM hardware provider is present but Arenyxa TPM seal/unseal provider is not configured; hardware protection will not be claimed"
                )
        for name in ("tpm", "cng", "dpapi"):
            adapter = self.key_protection.get(name)
            if adapter.available():
                available.append(name)
                if name != "tpm":
                    LOGGER.critical(
                        "Hardware key protection downgrade: TPM unavailable; using %s for %s",
                        name, purpose,
                    )
                return name, {"ciphertext": _b64u(adapter.protect(raw, purpose=purpose))}
        if os.getenv("ARENYXA_REQUIRE_TPM", "0").strip().casefold() in {"1", "true", "yes", "on"}:
            raise _fail(
                "TPM_KEY_PROTECTION_REQUIRED",
                "TPM-backed key protection is required by policy but no TPM provider is available",
                available_protectors=available,
            )
        LOGGER.critical(
            "Hardware key protection unavailable; falling back to local AES-GCM for %s", purpose
        )
        if self.local_key_path.is_symlink():
            raise _fail("DEVICE_KEY_UNSAFE_PATH", "Device local protector key cannot be a symbolic link")
        if self.local_key_path.exists():
            key = read_bytes_limited(self.local_key_path, 64)
            if len(key) != 32:
                raise _fail("DEVICE_KEY_INVALID", "Device local protector key is invalid")
        else:
            key = secrets.token_bytes(32)
            self.local_key_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(self.local_key_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, key)
                os.fsync(fd)
            finally:
                os.close(fd)
        nonce = secrets.token_bytes(12)
        aad = purpose.encode("utf-8")
        return "local-aesgcm", {"nonce": _b64u(nonce), "ciphertext": _b64u(AESGCM(key).encrypt(nonce, raw, aad))}

    def _unprotect(self, mode: str, protected: Mapping[str, str], purpose: str) -> bytes:
        if mode in {"tpm", "cng", "dpapi"}:
            adapter = self.key_protection.get(mode)
            if not adapter.available():
                raise _fail("DEVICE_KEY_PROTECTOR_UNAVAILABLE", "The device key protector used by this identity is unavailable", protector=mode)
            return adapter.unprotect(_unb64u(str(protected.get("ciphertext", "")), 8192), purpose=purpose)
        if mode != "local-aesgcm":
            raise _fail("DEVICE_KEY_INVALID", "Device key protection mode is unsupported")
        key = read_bytes_limited(self.local_key_path, 64)
        if len(key) != 32:
            raise _fail("DEVICE_KEY_INVALID", "Device local protector key is invalid")
        nonce = _unb64u(str(protected.get("nonce", "")), 32)
        ciphertext = _unb64u(str(protected.get("ciphertext", "")), 8192)
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, purpose.encode("utf-8"))
        except InvalidTag as exc:
            raise _fail("DEVICE_KEY_INVALID", "Device private key authentication failed") from exc

    def create(self, enterprise_id: str, account_id: str, *, allow_replace: bool = False) -> dict[str, str]:
        with self._lock:
            if self.path.is_symlink():
                raise _fail("DEVICE_KEY_UNSAFE_PATH", "Device identity file cannot be a symbolic link")
            if self.path.exists() and not allow_replace:
                raise _fail("DEVICE_KEY_EXISTS", "A device identity already exists on this device")
            private = Ed25519PrivateKey.generate()
            private_raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
            public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            device_id = new_id("device")
            purpose = f"Arenyxa Enterprise Device:{device_id}:{enterprise_id}"
            try:
                mode, protected = self._protect(private_raw, purpose)
            finally:
                with SecretBuffer(private_raw) as secret:
                    _ = secret
            payload = {
                "schema": DEVICE_VAULT_SCHEMA,
                "device_id": device_id,
                "enterprise_id": str(enterprise_id),
                "account_id": str(account_id),
                "public_key": _b64u(public_raw),
                "fingerprint": hashlib.sha256(public_raw).hexdigest(),
                "protector": mode,
                "protected_private_key": protected,
                "created_at": utc_now(),
                "domain_lock": {"enabled": True, "allow_once_until": ""},
                "office_binding": {},
            }
            atomic_write_json(self.path, payload, ensure_ascii=False, indent=2, mode=0o600)
            return {"device_id": device_id, "public_key": payload["public_key"], "fingerprint": payload["fingerprint"]}

    def load_public(self) -> dict[str, str]:
        raw = read_bytes_limited(self.path, MAX_DEVICE_VAULT_BYTES)
        payload = _strict_json_loads(raw, code="DEVICE_KEY_INVALID")
        required = {"schema", "device_id", "enterprise_id", "account_id", "public_key", "fingerprint", "protector", "protected_private_key", "created_at", "domain_lock"}
        allowed = required | {"office_binding"}
        if not isinstance(payload, dict) or not required.issubset(payload) or not set(payload).issubset(allowed) or payload.get("schema") != DEVICE_VAULT_SCHEMA:
            raise _fail("DEVICE_KEY_INVALID", "Device identity schema is invalid")
        binding = payload.get("office_binding", {})
        if not isinstance(binding, dict) or len(binding) > 8:
            raise _fail("DEVICE_KEY_INVALID", "Device office binding is invalid")
        public_raw = _unb64u(str(payload.get("public_key", "")), 64)
        if len(public_raw) != 32 or hashlib.sha256(public_raw).hexdigest() != str(payload.get("fingerprint", "")):
            raise _fail("DEVICE_KEY_INVALID", "Device public-key fingerprint is invalid")
        return {k: str(payload[k]) for k in ("device_id", "enterprise_id", "account_id", "public_key", "fingerprint")}

    def _load_full(self) -> dict[str, Any]:
        self.load_public()
        return _strict_json_loads(read_bytes_limited(self.path, MAX_DEVICE_VAULT_BYTES), code="DEVICE_KEY_INVALID")

    def sign(self, message: bytes) -> bytes:
        raw = bytes(message)
        if not raw or len(raw) > 256 * 1024:
            raise _fail("DEVICE_CHALLENGE_INVALID", "Device challenge payload is empty or too large")
        with self._lock:
            payload = self._load_full()
            purpose = f"Arenyxa Enterprise Device:{payload['device_id']}:{payload['enterprise_id']}"
            private_raw = self._unprotect(str(payload["protector"]), payload["protected_private_key"], purpose)
            try:
                return Ed25519PrivateKey.from_private_bytes(private_raw).sign(raw)
            finally:
                with SecretBuffer(private_raw) as secret:
                    _ = secret

    def assert_domain(self, enterprise_id: str) -> None:
        if not self.path.exists():
            return
        payload = self._load_full()
        current = str(payload.get("enterprise_id", ""))
        if current == str(enterprise_id):
            return
        lock = payload.get("domain_lock", {})
        allow_until = str(lock.get("allow_once_until", "")) if isinstance(lock, dict) else ""
        allowed = False
        if allow_until:
            try:
                allowed = _parse_time(allow_until) > datetime.now(timezone.utc)
            except ArenyxaError:
                allowed = False
        if bool(lock.get("enabled", True)) and not allowed:
            raise _fail("ENTERPRISE_DOMAIN_LOCKED", "This device is locked to another Enterprise identity", current_enterprise_id=current)

    def set_office_binding(self, host: str, port: int, root_fingerprint: str, coordinator_id: str = "") -> None:
        with self._lock:
            payload = self._load_full()
            fingerprint = str(root_fingerprint).strip().casefold()
            if len(fingerprint) != 64 or any(ch not in "0123456789abcdef" for ch in fingerprint):
                raise _fail("DEVICE_BINDING_INVALID", "Office Coordinator root fingerprint is invalid")
            endpoint = str(host).strip()[:255]
            numeric_port = int(port)
            if not endpoint or numeric_port <= 0 or numeric_port > 65535:
                raise _fail("DEVICE_BINDING_INVALID", "Office Coordinator endpoint is invalid")
            payload["office_binding"] = {
                "host": endpoint, "port": numeric_port, "root_fingerprint": fingerprint,
                "coordinator_id": str(coordinator_id)[:160], "verified_at": utc_now(),
            }
            atomic_write_json(self.path, payload, ensure_ascii=False, indent=2, mode=0o600)

    def office_binding(self) -> dict[str, Any]:
        with self._lock:
            payload = self._load_full()
            binding = payload.get("office_binding", {})
            return dict(binding) if isinstance(binding, dict) else {}

    def allow_once(self, seconds: int = ALLOW_ONCE_SECONDS) -> None:
        with self._lock:
            payload = self._load_full()
            lock = payload.setdefault("domain_lock", {"enabled": True, "allow_once_until": ""})
            lock["allow_once_until"] = _future_iso(min(ALLOW_ONCE_SECONDS, max(60, int(seconds))))
            atomic_write_json(self.path, payload, ensure_ascii=False, indent=2, mode=0o600)

    def prepare_enrollment(self, enterprise_id: str, account_id: str) -> tuple[dict[str, str], dict[str, Any]]:
        





        enterprise = str(enterprise_id)
        account = str(account_id)
        with self._lock:
            existed = self.path.exists()
            local_key_existed = self.local_key_path.exists()
            previous = read_bytes_limited(self.path, MAX_DEVICE_VAULT_BYTES) if existed else b""
            if existed:
                current = self.load_public()
                if current["enterprise_id"] == enterprise and current["account_id"] == account:
                    return current, {"changed": False}
                if current["enterprise_id"] == enterprise:
                    raise _fail("DEVICE_ACCOUNT_BOUND", "This device identity is already bound to another account in the same Enterprise")
                self.assert_domain(enterprise)
            public = self.create(enterprise, account, allow_replace=existed)
            return public, {
                "changed": True, "previous": previous, "had_device": existed,
                "local_key_existed": local_key_existed,
            }

    def rollback_prepared_enrollment(self, rollback: Mapping[str, Any]) -> None:
        if not bool(rollback.get("changed")):
            return
        with self._lock:
            previous = rollback.get("previous", b"")
            if bool(rollback.get("had_device")) and isinstance(previous, (bytes, bytearray)):
                atomic_write_bytes(self.path, bytes(previous), mode=0o600)
            else:
                self.path.unlink(missing_ok=True)
                if not bool(rollback.get("local_key_existed")):
                    self.local_key_path.unlink(missing_ok=True)


class EnrollmentService:
    def __init__(self, identity: LocalEnterpriseIdentityService, data_root: Path) -> None:
        self.identity = identity
        self.data_root = Path(data_root)
        self.device_store = DeviceKeyStore(self.data_root / "enterprise" / "device_identity.aryxdevice")

    @staticmethod
    def _empty_state() -> dict[str, Any]:
        return {"schema": ENROLLMENT_STATE_SCHEMA, "campaigns": {}, "credentials": {}, "devices": {}}

    @staticmethod
    def _state(state: dict[str, Any]) -> dict[str, Any]:
        if not state:
            state.update(EnrollmentService._empty_state())
        if state.get("schema") != ENROLLMENT_STATE_SCHEMA:
            raise _fail("ENROLLMENT_STATE_INVALID", "Enrollment state schema is invalid")
        for key, limit in (("campaigns", MAX_CAMPAIGNS), ("credentials", MAX_CREDENTIALS), ("devices", MAX_DEVICES)):
            value = state.get(key)
            if not isinstance(value, dict) or len(value) > limit:
                raise _fail("ENROLLMENT_STATE_INVALID", f"Enrollment {key} state exceeds safety bounds")
        return state

    def _signed_token(self, payload: dict[str, Any]) -> dict[str, Any]:
        signed = self.identity.sign_enterprise_artifact(
            _canonical(payload), capability="enterprise.enrollment.manage", resource="enterprise:enrollment", step_up=True
        )
        return {
            "schema": ENROLLMENT_SCHEMA,
            "payload": payload,
            "root_public_key": signed["root_public_key"],
            "root_fingerprint": signed["root_fingerprint"],
            "signature": signed["signature"],
        }

    def create_campaign(self, title: str, account_ids: Iterable[str], *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict[str, Any]:
        ids = tuple(dict.fromkeys(str(item) for item in account_ids if str(item)))
        if not ids or len(ids) > 1000:
            raise _fail("ENROLLMENT_CAMPAIGN_INVALID", "Enrollment campaign must contain 1-1000 accounts")
        campaign_id = new_id("enroll_campaign")
        now = utc_now()
        expires_at = _future_iso(min(7 * 24 * 3600, max(300, int(ttl_seconds))))
        root = self.identity.root_public_identity()
        tokens: list[dict[str, Any]] = []
        accounts = {row["id"]: row for row in self.identity.accounts()}
        for account_id in ids:
            account = accounts.get(account_id)
            if account is None or not account.get("enabled"):
                raise _fail("ENROLLMENT_ACCOUNT_INVALID", "Enrollment account is missing or disabled", account_id=account_id)
            credential_id = new_id("enroll")
            secret = secrets.token_bytes(32)
            payload = {
                "enterprise_id": root["enterprise_id"], "credential_id": credential_id, "campaign_id": campaign_id,
                "account_id": account_id, "username": str(account["username"]), "roles": list(account["roles"]),
                "issued_at": now, "expires_at": expires_at, "purpose": "device-enrollment",
                "nonce": _b64u(secrets.token_bytes(24)), "secret": _b64u(secret),
            }
            token = self._signed_token(payload)
            tokens.append(token)
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = self._state(state)
            if len(state["campaigns"]) >= MAX_CAMPAIGNS or len(state["credentials"]) + len(tokens) > MAX_CREDENTIALS:
                raise _fail("ENROLLMENT_CAPACITY", "Enrollment state capacity has been reached")
            state["campaigns"][campaign_id] = {
                "id": campaign_id, "title": str(title).strip()[:160] or "Enrollment Campaign",
                "created_at": now, "expires_at": expires_at, "status": "active",
                "credential_ids": [str(token["payload"]["credential_id"]) for token in tokens],
            }
            for token in tokens:
                payload = token["payload"]
                state["credentials"][payload["credential_id"]] = {
                    "id": payload["credential_id"], "campaign_id": campaign_id, "account_id": payload["account_id"],
                    "username": payload["username"], "roles": list(payload["roles"]), "issued_at": now,
                    "expires_at": expires_at, "secret_sha256": hashlib.sha256(_unb64u(payload["secret"], 64)).hexdigest(),
                    "token_sha256": hashlib.sha256(_canonical(token)).hexdigest(), "state": "unused", "used_at": "", "device_id": "",
                }
        self.identity.mutate_extension("enrollment", "enterprise.enrollment.manage", "enterprise:enrollment", "enterprise.enrollment.campaign.create", mutate, step_up=True)
        return {"campaign_id": campaign_id, "expires_at": expires_at, "tokens": tokens}

    def revoke_campaign(self, campaign_id: str) -> None:
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = self._state(state)
            campaign = state["campaigns"].get(str(campaign_id))
            if not isinstance(campaign, dict):
                raise _fail("ENROLLMENT_CAMPAIGN_MISSING", "Enrollment campaign does not exist")
            campaign["status"] = "revoked"
            for credential_id in campaign.get("credential_ids", []):
                item = state["credentials"].get(str(credential_id))
                if isinstance(item, dict) and item.get("state") == "unused":
                    item["state"] = "revoked"
        self.identity.mutate_extension("enrollment", "enterprise.enrollment.manage", "enterprise:enrollment", "enterprise.enrollment.campaign.revoke", mutate, step_up=True)

    def list_campaigns(self) -> list[dict[str, Any]]:
        state = self._state(self.identity.extension_snapshot("enrollment", "enterprise.enrollment.manage", "enterprise:enrollment"))
        return sorted((dict(item) for item in state["campaigns"].values()), key=lambda row: str(row.get("created_at", "")), reverse=True)

    def list_devices(self) -> list[dict[str, Any]]:
        state = self._state(self.identity.extension_snapshot("enrollment", "enterprise.device.manage", "enterprise:devices"))
        return sorted((dict(item) for item in state["devices"].values()), key=lambda row: str(row.get("enrolled_at", "")), reverse=True)

    def consume(
        self, token: Mapping[str, Any], device_public: Mapping[str, str], *, service_lease: str = "",
    ) -> dict[str, Any]:
        payload = verify_enrollment_token(token)
        current_root = self.identity.root_public_identity()
        if str(payload["enterprise_id"]) != current_root["enterprise_id"] or str(token["root_fingerprint"]) != current_root["fingerprint"]:
            raise _fail("ENROLLMENT_ENTERPRISE_MISMATCH", "Enrollment credential belongs to a different Enterprise")
        public_raw = _unb64u(str(device_public.get("public_key", "")), 64)
        fingerprint = str(device_public.get("fingerprint", ""))
        device_id = str(device_public.get("device_id", ""))
        device_enterprise = str(device_public.get("enterprise_id", payload["enterprise_id"]))
        device_account = str(device_public.get("account_id", payload["account_id"]))
        if len(public_raw) != 32 or hashlib.sha256(public_raw).hexdigest() != fingerprint or not device_id:
            raise _fail("ENROLLMENT_DEVICE_INVALID", "Enrollment device identity is invalid")
        if device_enterprise != str(payload["enterprise_id"]) or device_account != str(payload["account_id"]):
            raise _fail("ENROLLMENT_DEVICE_BINDING_INVALID", "Device identity does not match the Enrollment enterprise/account binding")
        token_sha = hashlib.sha256(_canonical(dict(token))).hexdigest()
        secret_sha = hashlib.sha256(_unb64u(str(payload["secret"]), 64)).hexdigest()
        result: dict[str, Any] = {}
        def mutate(state: dict[str, Any], vault: dict[str, Any]) -> None:
            state = self._state(state)
            credential = state["credentials"].get(str(payload["credential_id"]))
            if not isinstance(credential, dict):
                raise _fail("ENROLLMENT_CREDENTIAL_MISSING", "Enrollment credential is not recognized")
            campaign = state["campaigns"].get(str(credential.get("campaign_id", "")))
            if not isinstance(campaign, dict) or campaign.get("status") != "active":
                raise _fail("ENROLLMENT_CAMPAIGN_REVOKED", "Enrollment campaign is not active")
            if credential.get("state") != "unused":
                raise _fail("ENROLLMENT_REPLAY", "Enrollment credential has already been used or revoked")
            if _parse_time(str(credential["expires_at"])) <= datetime.now(timezone.utc):
                credential["state"] = "expired"
                raise _fail("ENROLLMENT_EXPIRED", "Enrollment credential has expired")
            if not secrets.compare_digest(str(credential.get("secret_sha256", "")), secret_sha) or not secrets.compare_digest(str(credential.get("token_sha256", "")), token_sha):
                raise _fail("ENROLLMENT_CREDENTIAL_INVALID", "Enrollment credential secret or signed artifact does not match")
            account = vault["accounts"].get(str(credential["account_id"]))
            if not isinstance(account, dict) or not account.get("enabled"):
                raise _fail("ENROLLMENT_ACCOUNT_INVALID", "Enrollment account is missing or disabled")
            if list(account.get("roles", [])) != list(credential.get("roles", [])):
                raise _fail("ENROLLMENT_ROLE_CHANGED", "Account roles changed after credential issuance; reissue enrollment")
            if device_id in state["devices"]:
                raise _fail("ENROLLMENT_DEVICE_EXISTS", "Device ID is already enrolled")
            row = {
                "id": device_id, "device_id": device_id, "account_id": account["id"], "username": account["username"],
                "public_key": str(device_public["public_key"]), "fingerprint": fingerprint,
                "status": "active", "enrolled_at": utc_now(), "auth_generation": int(account["auth_generation"]),
            }
            state["devices"][device_id] = row
            vault["devices"][device_id] = dict(row)
            credential["state"] = "used"
            credential["used_at"] = utc_now()
            credential["device_id"] = device_id
            result.update(row)
        if service_lease:
            self.identity.service_mutate_extension(
                service_lease, "enrollment", "enterprise.enrollment.consume", "enterprise:enrollment", mutate,
            )
        else:
            self.identity.mutate_extension(
                "enrollment", "enterprise.enrollment.manage", "enterprise:enrollment",
                "enterprise.enrollment.consume", mutate, step_up=False,
            )
        return result

    def enroll_this_device(self, token: Mapping[str, Any]) -> dict[str, Any]:
        payload = verify_enrollment_token(token)
        public, rollback = self.device_store.prepare_enrollment(str(payload["enterprise_id"]), str(payload["account_id"]))
        try:
            return self.consume(token, public)
        except Exception:
            self.device_store.rollback_prepared_enrollment(rollback)
            raise

    def allow_join_other_enterprise_once(self) -> None:
        self.identity.require("enterprise.device.manage", "enterprise:devices")
        self.identity._require_step_up()
        self.device_store.allow_once()

    def revoke_device(self, device_id: str) -> None:
        def mutate(state: dict[str, Any], vault: dict[str, Any]) -> None:
            state = self._state(state)
            row = state["devices"].get(str(device_id))
            if not isinstance(row, dict):
                raise _fail("ENTERPRISE_DEVICE_MISSING", "Enterprise device is not registered")
            row["status"] = "revoked"
            if str(device_id) in vault.get("devices", {}):
                vault["devices"][str(device_id)]["status"] = "revoked"
        self.identity.mutate_extension("enrollment", "enterprise.device.manage", "enterprise:devices", "enterprise.device.revoke", mutate, step_up=True)

    def local_device_posture(self) -> dict[str, Any]:
        """Evaluate this workstation's enrolled-device posture without admin grants.

        This is an internal authorization signal, not an administrative device
        listing API. It validates the local public identity against the current
        Enterprise Vault registration and account authorization generation.
        """
        posture = {"managed_device": False, "device_compliant": False, "device_id": ""}
        status = self.identity.status()
        if not status.authenticated or not status.enterprise_id or not status.account_id:
            return posture
        try:
            public = self.device_store.load_public()
        except (OSError, ArenyxaError, ValueError, TypeError):
            return posture
        device_id = str(public.get("device_id", ""))
        if (
            not device_id
            or str(public.get("enterprise_id", "")) != status.enterprise_id
            or str(public.get("account_id", "")) != status.account_id
        ):
            return posture
        posture["device_id"] = device_id
        try:
            handle = self.identity._require_handle()
            extensions = handle.payload.get("extensions", {})
            enrollment_state = extensions.get("enrollment", {}) if isinstance(extensions, dict) else {}
            devices = enrollment_state.get("devices", {}) if isinstance(enrollment_state, dict) else {}
            row = devices.get(device_id) if isinstance(devices, dict) else None
            account = handle.payload.get("accounts", {}).get(status.account_id)
        except (AttributeError, TypeError):
            return posture
        if not isinstance(row, dict) or not isinstance(account, dict):
            return posture
        active = (
            row.get("status") == "active"
            and str(row.get("account_id", "")) == status.account_id
            and str(row.get("fingerprint", "")) == str(public.get("fingerprint", ""))
        )
        posture["managed_device"] = bool(active)
        posture["device_compliant"] = bool(
            active
            and account.get("enabled") is True
            and int(row.get("auth_generation", -1)) == int(account.get("auth_generation", 0))
        )
        return posture

    def validate_active_device(self, device_id: str, *, service_lease: str = "") -> dict[str, Any]:
        if service_lease:
            state = self._state(self.identity.service_extension_snapshot(service_lease, "enrollment"))
        else:
            state = self._state(self.identity.extension_snapshot("enrollment", "enterprise.device.manage", "enterprise:devices"))
        row = state["devices"].get(str(device_id))
        if not isinstance(row, dict) or row.get("status") != "active":
            raise _fail("ENTERPRISE_DEVICE_INVALID", "Enterprise device is missing or revoked")
        if service_lease:
            account = self.identity.service_account_snapshot(service_lease, "enrollment", str(row.get("account_id", "")))
        else:
            accounts = {item["id"]: item for item in self.identity.accounts()}
            account = accounts.get(str(row.get("account_id", "")))
        if not isinstance(account, dict) or not account.get("enabled"):
            raise _fail("ENTERPRISE_DEVICE_ACCOUNT_INVALID", "Enterprise device account is disabled or missing")
        if int(account.get("auth_generation", 0)) != int(row.get("auth_generation", -1)):
            raise _fail("ENTERPRISE_DEVICE_STALE", "Enterprise device authorization generation is stale; re-enrollment is required")
        return dict(row)

    @staticmethod
    def token_to_qr_payload(token: Mapping[str, Any]) -> str:
        verified = verify_enrollment_token(token)
        _ = verified
        encoded = _b64u(_canonical(dict(token)))
        if len(encoded) > 48 * 1024:
            raise _fail("ENROLLMENT_ARTIFACT_TOO_LARGE", "Enrollment QR payload exceeds safety bound")
        return "arenyxa-enroll:" + encoded

    @staticmethod
    def token_from_qr_payload(value: str) -> dict[str, Any]:
        raw = str(value).strip()
        prefix = "arenyxa-enroll:"
        if not raw.startswith(prefix):
            raise _fail("ENROLLMENT_ARTIFACT_INVALID", "Enrollment QR payload prefix is invalid")
        decoded = _unb64u(raw[len(prefix):], MAX_TOKEN_BYTES)
        return parse_enrollment_token(decoded)

    def reissue_campaign(self, campaign_id: str, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict[str, Any]:
        state = self._state(self.identity.extension_snapshot("enrollment", "enterprise.enrollment.manage", "enterprise:enrollment"))
        campaign = state["campaigns"].get(str(campaign_id))
        if not isinstance(campaign, dict):
            raise _fail("ENROLLMENT_CAMPAIGN_MISSING", "Enrollment campaign does not exist")
        account_ids = []
        for credential_id in campaign.get("credential_ids", []):
            credential = state["credentials"].get(str(credential_id))
            if isinstance(credential, dict):
                account_ids.append(str(credential.get("account_id", "")))
        self.revoke_campaign(campaign_id)
        return self.create_campaign(str(campaign.get("title", "Enrollment Campaign")) + " · reissued", account_ids, ttl_seconds=ttl_seconds)

    def import_members_csv(self, source: Path, *, campaign_title: str = "CSV Enrollment", ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict[str, Any]:
        raw = read_bytes_limited(Path(source), 2 * 1024 * 1024)
        try:
            text = raw.decode("utf-8-sig")
            rows = list(csv.DictReader(text.splitlines()))
        except (UnicodeError, csv.Error) as exc:
            raise _fail("ENTERPRISE_CSV_INVALID", "Enterprise member CSV is invalid") from exc
        if not rows or len(rows) > 1000:
            raise _fail("ENTERPRISE_CSV_INVALID", "Enterprise member CSV must contain 1-1000 rows")

        existing_accounts = self.identity.accounts()
        existing_usernames = {str(item["username"]).casefold() for item in existing_accounts}
        roles_catalog = {str(item["id"]) for item in self.identity.roles()}
        root = self.identity.root_public_identity()
        now = utc_now()
        expires_at = _future_iso(min(7 * 24 * 3600, max(300, int(ttl_seconds))))
        campaign_id = new_id("enroll_campaign")
        prepared_accounts: list[dict[str, Any]] = []
        tokens: list[dict[str, Any]] = []
        seen = set(existing_usernames)

        for row in rows:
            username = str(row.get("username", "")).strip().casefold()
            display = str(row.get("display_name", "")).strip() or username
            roles = sorted(set(part.strip() for part in str(row.get("roles", "member")).split(";") if part.strip())) or ["member"]
            if not username or len(username) > 128 or any(ch.isspace() for ch in username) or username in seen:
                raise _fail("ENTERPRISE_CSV_INVALID", "CSV contains an invalid or duplicate username", username=username)
            if any(role not in roles_catalog for role in roles):
                raise _fail("ENTERPRISE_CSV_INVALID", "CSV contains an unknown Enterprise role", username=username)
            password = str(row.get("temporary_password", "")).strip() or ("Tmp-" + secrets.token_urlsafe(18))
            account_id = new_id("account")
            prepared_accounts.append({
                "id": account_id, "username": username, "display_name": display,
                "password_verifier": password_verifier(password), "roles": roles, "enabled": True,
                "auth_generation": 1, "created_at": now, "updated_at": now, "last_login_at": "",
                "temporary_password": password,
            })
            seen.add(username)
            payload = {
                "enterprise_id": root["enterprise_id"], "credential_id": new_id("enroll"), "campaign_id": campaign_id,
                "account_id": account_id, "username": username, "roles": roles,
                "issued_at": now, "expires_at": expires_at, "purpose": "device-enrollment",
                "nonce": _b64u(secrets.token_bytes(24)), "secret": _b64u(secrets.token_bytes(32)),
            }
            tokens.append(self._signed_token(payload))

        def mutate(state: dict[str, Any], vault: dict[str, Any]) -> None:
            state = self._state(state)
            if len(state["campaigns"]) >= MAX_CAMPAIGNS or len(state["credentials"]) + len(tokens) > MAX_CREDENTIALS:
                raise _fail("ENROLLMENT_CAPACITY", "Enrollment state capacity has been reached")
            for account in prepared_accounts:
                stored = dict(account)
                stored.pop("temporary_password", None)
                vault["accounts"][stored["id"]] = stored
            state["campaigns"][campaign_id] = {
                "id": campaign_id, "title": str(campaign_title).strip()[:160] or "CSV Enrollment",
                "created_at": now, "expires_at": expires_at, "status": "active",
                "credential_ids": [str(token["payload"]["credential_id"]) for token in tokens],
            }
            for token in tokens:
                payload = token["payload"]
                state["credentials"][payload["credential_id"]] = {
                    "id": payload["credential_id"], "campaign_id": campaign_id, "account_id": payload["account_id"],
                    "username": payload["username"], "roles": list(payload["roles"]), "issued_at": now,
                    "expires_at": expires_at, "secret_sha256": hashlib.sha256(_unb64u(payload["secret"], 64)).hexdigest(),
                    "token_sha256": hashlib.sha256(_canonical(token)).hexdigest(), "state": "unused", "used_at": "", "device_id": "",
                }

        self.identity.mutate_extension(
            "enrollment", "enterprise.enrollment.manage", "enterprise:enrollment",
            "enterprise.enrollment.csv_import", mutate, step_up=True,
        )
        return {
            "accounts": [
                {"account_id": item["id"], "username": item["username"], "temporary_password": item["temporary_password"]}
                for item in prepared_accounts
            ],
            "campaign_id": campaign_id, "expires_at": expires_at, "tokens": tokens,
        }
