from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_bytes_limited
from arenyxa.security.key_protection import SecretBuffer

VAULT_SCHEMA = "arenyxa.enterprise-vault/v1"
VAULT_DATA_SCHEMA = "arenyxa.enterprise-vault-data/v1"
BACKUP_SCHEMA = "arenyxa.enterprise-vault-backup/v1"
PASSWORD_SCHEMA = "arenyxa.password-verifier/scrypt-v1"
MAX_VAULT_BYTES = 8 * 1024 * 1024
MAX_BACKUP_BYTES = 12 * 1024 * 1024
DEFAULT_SCRYPT_N = 2 ** 15
MIN_SCRYPT_N = 2 ** 14
MAX_SCRYPT_N = 2 ** 18
SCRYPT_R = 8
SCRYPT_P = 1
LOGGER = logging.getLogger(__name__)
ENTERPRISE_PERMISSION_CATALOG = frozenset({
    "enterprise.account.manage", "enterprise.policy.modify", "enterprise.audit.read",
    "enterprise.enrollment.manage", "enterprise.device.manage", "enterprise.coordinator.manage",
    "enterprise.workspace.manage", "enterprise.approval.manage", "enterprise.quota.manage",
    "dataset.read", "dataset.write", "dataset.export",
    "workflow.execute", "workflow.publish", "enterprise.capture.run", "schedule.manage", "worker.use",
    "enterprise.worker.manage", "enterprise.server.manage", "enterprise.remote_ops",
})
MAX_ROLES = 128
MAX_ROLE_PERMISSIONS = 32


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE", context=context)


def _b64u_encode(value: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64u_decode(value: str, *, max_bytes: int) -> bytes:
    import base64
    raw = str(value).strip()
    if not raw or "=" in raw:
        raise _fail("ENTERPRISE_ARTIFACT_INVALID", "base64url value is empty or non-canonical")
    if len(raw) > ((max_bytes + 2) // 3) * 4 + 4:
        raise _fail("ENTERPRISE_ARTIFACT_TOO_LARGE", "encoded value exceeds safety bound")
    try:
        data = base64.urlsafe_b64decode(raw + "=" * ((4 - len(raw) % 4) % 4))
    except Exception as exc:
        raise _fail("ENTERPRISE_ARTIFACT_INVALID", "base64url decoding failed") from exc
    if len(data) > max_bytes or _b64u_encode(data) != raw:
        raise _fail("ENTERPRISE_ARTIFACT_INVALID", "base64url value is non-canonical")
    return data


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _load_object_bytes(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault JSON is invalid") from exc
    if not isinstance(value, dict):
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault root must be an object")
    return value


def _validate_passphrase(value: str) -> str:
    text = str(value)
    if len(text) < 12 or len(text) > 1024:
        raise _fail("ENTERPRISE_PASSPHRASE_INVALID", "Vault passphrase must contain 12-1024 characters")
    return text


def _derive_key(passphrase: str, salt: bytes, n: int) -> bytes:
    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1):
        raise _fail("ENTERPRISE_KDF_INVALID", "Vault KDF work factor is outside the allowed range")
    return hashlib.scrypt(
        _validate_passphrase(passphrase).encode("utf-8"),
        salt=salt,
        n=n,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
        maxmem=max(128 * 1024 * 1024, 256 * n * SCRYPT_R),
    )


def password_verifier(password: str, *, n: int = DEFAULT_SCRYPT_N) -> dict[str, Any]:
    text = str(password)
    if len(text) < 12 or len(text) > 1024:
        raise _fail("ENTERPRISE_PASSWORD_INVALID", "Enterprise password must contain 12-1024 characters")
    if n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1):
        raise _fail("ENTERPRISE_KDF_INVALID", "Password-verifier KDF work factor is outside the allowed range")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(text.encode("utf-8"), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                            maxmem=max(128 * 1024 * 1024, 256 * n * SCRYPT_R))
    return {
        "schema": PASSWORD_SCHEMA,
        "salt": _b64u_encode(salt),
        "digest": _b64u_encode(digest),
        "n": n,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }


def verify_password(password: str, verifier: Mapping[str, Any]) -> bool:
    try:
        if set(verifier) != {"schema", "salt", "digest", "n", "r", "p"}:
            return False
        if verifier.get("schema") != PASSWORD_SCHEMA or int(verifier.get("r", 0)) != SCRYPT_R or int(verifier.get("p", 0)) != SCRYPT_P:
            return False
        n = int(verifier.get("n", 0))
        salt = _b64u_decode(str(verifier.get("salt", "")), max_bytes=64)
        expected = _b64u_decode(str(verifier.get("digest", "")), max_bytes=64)
        if len(salt) < 16 or len(expected) != 32 or n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1):
            return False
        candidate = hashlib.scrypt(str(password).encode("utf-8"), salt=salt, n=n, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                                   maxmem=max(128 * 1024 * 1024, 256 * n * SCRYPT_R))
        return hmac.compare_digest(candidate, expected)
    except (TypeError, ValueError, MemoryError, ArenyxaError):
        return False


def _new_enterprise_payload(enterprise_name: str, admin_username: str, admin_display_name: str, admin_password: str) -> dict[str, Any]:
    name = str(enterprise_name).strip()
    username = str(admin_username).strip().casefold()
    if not name or len(name) > 160:
        raise _fail("ENTERPRISE_NAME_INVALID", "Enterprise name must contain 1-160 characters")
    if not username or len(username) > 128 or any(ch.isspace() for ch in username):
        raise _fail("ENTERPRISE_USERNAME_INVALID", "Super Administrator username is invalid")
    now = utc_now()
    enterprise_id = new_id("enterprise")
    account_id = new_id("account")
    root_private = Ed25519PrivateKey.generate()
    root_private_raw = root_private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    root_public_raw = root_private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {
        "schema": VAULT_DATA_SCHEMA,
        "revision": 1,
        "enterprise_id": enterprise_id,
        "display_name": name,
        "created_at": now,
        "updated_at": now,
        "root_identity": {
            "algorithm": "Ed25519",
            "public_key": _b64u_encode(root_public_raw),
            "private_key": _b64u_encode(root_private_raw),
            "fingerprint": hashlib.sha256(root_public_raw).hexdigest(),
        },
        "accounts": {
            account_id: {
                "id": account_id,
                "username": username,
                "display_name": str(admin_display_name).strip() or username,
                "password_verifier": password_verifier(admin_password),
                "roles": ["super_admin"],
                "enabled": True,
                "auth_generation": 1,
                "created_at": now,
                "updated_at": now,
                "last_login_at": "",
            }
        },
        "roles": default_roles(),
        "devices": {},
        "extensions": {},
        "audit_metadata": {"generation": 1, "last_mutation_at": now, "last_backup_at": ""},
    }


def default_roles() -> dict[str, dict[str, Any]]:
    return {
        "super_admin": {
            "id": "super_admin", "title": "Super Administrator", "builtin": True,
            "permissions": [
                "enterprise.account.manage", "enterprise.policy.modify", "enterprise.audit.read",
                "enterprise.enrollment.manage", "enterprise.device.manage", "enterprise.coordinator.manage",
                "enterprise.workspace.manage", "enterprise.approval.manage", "enterprise.quota.manage",
                "dataset.read", "dataset.write", "dataset.export", "workflow.execute", "workflow.publish",
                "enterprise.capture.run", "schedule.manage", "worker.use",
                "enterprise.worker.manage", "enterprise.server.manage", "enterprise.remote_ops",
            ],
        },
        "administrator": {
            "id": "administrator", "title": "Administrator", "builtin": True,
            "permissions": ["enterprise.account.manage", "enterprise.audit.read", "enterprise.enrollment.manage", "enterprise.device.manage", "enterprise.workspace.manage", "enterprise.approval.manage", "enterprise.quota.manage", "dataset.read", "dataset.write", "dataset.export", "workflow.execute", "workflow.publish", "enterprise.capture.run", "schedule.manage", "worker.use", "enterprise.worker.manage", "enterprise.server.manage", "enterprise.remote_ops"],
        },
        "operator": {
            "id": "operator", "title": "Operator", "builtin": True,
            "permissions": ["dataset.read", "dataset.write", "workflow.execute", "enterprise.capture.run", "schedule.manage", "worker.use"],
        },
        "analyst": {
            "id": "analyst", "title": "Analyst", "builtin": True,
            "permissions": ["dataset.read", "dataset.export", "workflow.execute"],
        },
        "auditor": {
            "id": "auditor", "title": "Auditor", "builtin": True,
            "permissions": ["enterprise.audit.read", "dataset.read"],
        },
        "member": {
            "id": "member", "title": "Member", "builtin": True,
            "permissions": ["dataset.read"],
        },
    }


def validate_payload(payload: Mapping[str, Any]) -> None:
    required = {"schema", "revision", "enterprise_id", "display_name", "created_at", "updated_at", "root_identity", "accounts", "roles", "devices", "audit_metadata"}
    optional = {"extensions"}
    keys = set(payload)
    if not required.issubset(keys) or keys - required - optional or payload.get("schema") != VAULT_DATA_SCHEMA:
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault payload schema is invalid")
    if not isinstance(payload.get("accounts"), dict) or not isinstance(payload.get("roles"), dict) or not isinstance(payload.get("devices"), dict):
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault collections are invalid")
    extensions = payload.get("extensions", {})
    if not isinstance(extensions, dict) or len(extensions) > 32:
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise extension state is invalid")
    for namespace, value in extensions.items():
        key = str(namespace)
        if not key or len(key) > 64 or any(not (ch.isascii() and (ch.isalnum() or ch in "._-")) for ch in key):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise extension namespace is invalid")
        if not isinstance(value, dict):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise extension payload must be an object")
    try:
        extension_size = len(json.dumps(extensions, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise extension payload is not serializable") from exc
    if extension_size > 4 * 1024 * 1024:
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise extension payload exceeds the safety bound")
    root = payload.get("root_identity")
    if not isinstance(root, dict) or root.get("algorithm") != "Ed25519":
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Root Identity is invalid")
    public_raw = _b64u_decode(str(root.get("public_key", "")), max_bytes=64)
    private_raw = _b64u_decode(str(root.get("private_key", "")), max_bytes=64)
    if len(public_raw) != 32 or len(private_raw) != 32 or hashlib.sha256(public_raw).hexdigest() != root.get("fingerprint"):
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Root Identity fingerprint is invalid")
    try:
        derived = Ed25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except ValueError as exc:
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Root private key is invalid") from exc
    if not hmac.compare_digest(derived, public_raw):
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Root public/private key mismatch")
    roles_payload = payload["roles"]
    if not roles_payload or len(roles_payload) > MAX_ROLES:
        raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise role collection is empty or exceeds the safety bound")
    for role_id, role in roles_payload.items():
        role_key = str(role_id)
        if (
            not role_key or len(role_key) > 64 or role_key.strip() != role_key
            or any(not (ch.isascii() and (ch.isalnum() or ch in "._-")) for ch in role_key)
            or not isinstance(role, dict) or set(role) != {"id", "title", "builtin", "permissions"}
            or str(role.get("id", "")) != role_key
        ):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise role record is invalid")
        title = str(role.get("title", "")).strip()
        permissions = role.get("permissions")
        if not title or len(title) > 160 or not isinstance(role.get("builtin"), bool):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise role metadata is invalid")
        if not isinstance(permissions, list) or len(permissions) > MAX_ROLE_PERMISSIONS:
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise role permission set is invalid")
        normalized_permissions = [str(item) for item in permissions]
        if (
            len(normalized_permissions) != len(set(normalized_permissions))
            or any(item not in ENTERPRISE_PERMISSION_CATALOG for item in normalized_permissions)
        ):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise role permission is outside the supported catalog")

    accounts = payload["accounts"]
    super_admins = 0
    usernames: set[str] = set()
    for account_id, account in accounts.items():
        if not isinstance(account, dict) or str(account.get("id", "")) != str(account_id):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise account record is invalid")
        username = str(account.get("username", "")).casefold()
        if not username or username in usernames:
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise account username is empty or duplicated")
        usernames.add(username)
        roles = account.get("roles")
        if not isinstance(roles, list) or not roles or any(role not in payload["roles"] for role in roles):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise account role reference is invalid")
        if not isinstance(account.get("auth_generation"), int) or int(account["auth_generation"]) < 1:
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise account generation is invalid")
        verifier = account.get("password_verifier")
        if not isinstance(verifier, dict) or set(verifier) != {"schema", "salt", "digest", "n", "r", "p"}:
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise account password verifier is invalid")
        try:
            n = int(verifier.get("n", 0))
            r = int(verifier.get("r", 0))
            p = int(verifier.get("p", 0))
            salt = _b64u_decode(str(verifier.get("salt", "")), max_bytes=64)
            digest = _b64u_decode(str(verifier.get("digest", "")), max_bytes=64)
        except (TypeError, ValueError, ArenyxaError) as exc:
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise account password verifier parameters are invalid") from exc
        if (
            verifier.get("schema") != PASSWORD_SCHEMA
            or r != SCRYPT_R or p != SCRYPT_P
            or n < MIN_SCRYPT_N or n > MAX_SCRYPT_N or n & (n - 1)
            or len(salt) < 16 or len(digest) != 32
        ):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise account password verifier parameters are invalid")
        if account.get("enabled") and "super_admin" in roles:
            super_admins += 1
    if super_admins < 1:
        raise _fail("ENTERPRISE_LAST_SUPER_ADMIN", "Enterprise Vault must contain at least one enabled Super Administrator")


@dataclass(slots=True)
class EnterpriseVaultHandle:
    path: Path
    payload: dict[str, Any]
    _data_key: SecretBuffer
    _lock: threading.Lock
    _envelope_binding: str = ""

    def data_key(self) -> bytes:
        return self._data_key.copy_bytes()

    def close(self) -> None:
        self._data_key.zeroize()


class EnterpriseVault:
    

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    @property
    def exists(self) -> bool:
        return self.path.is_file() and not self.path.is_symlink()

    @staticmethod
    def _outer_aad(enterprise_id: str, kdf: Mapping[str, Any]) -> bytes:
        return _canonical({"schema": VAULT_SCHEMA, "version": 1, "enterprise_id": enterprise_id, "kdf": dict(kdf)})

    @staticmethod
    def _payload_aad(enterprise_id: str) -> bytes:
        return _canonical({"schema": VAULT_DATA_SCHEMA, "enterprise_id": enterprise_id, "version": 1})

    @staticmethod
    def _envelope_binding(enterprise_id: str, kdf: Mapping[str, Any], wrapped: Mapping[str, Any]) -> str:
        return hashlib.sha256(_canonical({
            "enterprise_id": enterprise_id, "kdf": dict(kdf), "wrapped_key": dict(wrapped),
        })).hexdigest()

    def create(self, enterprise_name: str, admin_username: str, admin_display_name: str, admin_password: str,
               vault_passphrase: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> EnterpriseVaultHandle:
        if self.path.exists() or self.path.is_symlink():
            raise _fail("ENTERPRISE_ALREADY_EXISTS", "Local Enterprise Vault already exists")
        payload = _new_enterprise_payload(enterprise_name, admin_username, admin_display_name, admin_password)
        data_key = secrets.token_bytes(32)
        handle = EnterpriseVaultHandle(self.path, payload, SecretBuffer(data_key), threading.Lock())
        try:
            self._write(handle, vault_passphrase=vault_passphrase, scrypt_n=scrypt_n, initial=True)
        except Exception:
            handle.close()
            raise
        return handle

    def open(self, vault_passphrase: str) -> EnterpriseVaultHandle:
        if self.path.is_symlink():
            raise _fail("ENTERPRISE_VAULT_UNSAFE_PATH", "Enterprise Vault cannot be a symbolic link")
        raw = read_bytes_limited(self.path, MAX_VAULT_BYTES)
        outer = _load_object_bytes(raw)
        expected = {"schema", "version", "enterprise_id", "kdf", "wrapped_key", "payload"}
        if set(outer) != expected or outer.get("schema") != VAULT_SCHEMA or outer.get("version") != 1:
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault envelope schema is invalid")
        enterprise_id = str(outer.get("enterprise_id", ""))
        kdf = outer.get("kdf")
        wrapped = outer.get("wrapped_key")
        encrypted_payload = outer.get("payload")
        if not enterprise_id or not isinstance(kdf, dict) or not isinstance(wrapped, dict) or not isinstance(encrypted_payload, dict):
            raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault envelope is incomplete")
        if set(kdf) != {"algorithm", "salt", "n", "r", "p"} or kdf.get("algorithm") != "scrypt" or int(kdf.get("r", 0)) != SCRYPT_R or int(kdf.get("p", 0)) != SCRYPT_P:
            raise _fail("ENTERPRISE_KDF_INVALID", "Enterprise Vault KDF is invalid")
        salt = _b64u_decode(str(kdf.get("salt", "")), max_bytes=64)
        kek = _derive_key(vault_passphrase, salt, int(kdf.get("n", 0)))
        try:
            if set(wrapped) != {"algorithm", "nonce", "ciphertext"} or wrapped.get("algorithm") != "AES-256-GCM":
                raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault wrapped-key cipher is invalid")
            wrapped_nonce = _b64u_decode(str(wrapped.get("nonce", "")), max_bytes=32)
            wrapped_ciphertext = _b64u_decode(str(wrapped.get("ciphertext", "")), max_bytes=128)
            data_key = AESGCM(kek).decrypt(wrapped_nonce, wrapped_ciphertext, self._outer_aad(enterprise_id, kdf))
        except InvalidTag as exc:
            raise _fail("ENTERPRISE_VAULT_UNLOCK_FAILED", "Vault passphrase or wrapped-key integrity is invalid") from exc
        finally:
            mutable = bytearray(kek)
            for index in range(len(mutable)):
                mutable[index] = 0
        try:
            if len(data_key) != 32 or set(encrypted_payload) != {"algorithm", "nonce", "ciphertext", "sha256"} or encrypted_payload.get("algorithm") != "AES-256-GCM":
                raise _fail("ENTERPRISE_VAULT_INVALID", "Enterprise Vault payload cipher is invalid")
            payload_nonce = _b64u_decode(str(encrypted_payload.get("nonce", "")), max_bytes=32)
            payload_ciphertext = _b64u_decode(str(encrypted_payload.get("ciphertext", "")), max_bytes=MAX_VAULT_BYTES)
            if hashlib.sha256(payload_ciphertext).hexdigest() != str(encrypted_payload.get("sha256", "")):
                raise _fail("ENTERPRISE_VAULT_INTEGRITY", "Enterprise Vault ciphertext digest is invalid")
            plaintext = AESGCM(data_key).decrypt(payload_nonce, payload_ciphertext, self._payload_aad(enterprise_id))
            payload = _load_object_bytes(plaintext)
            validate_payload(payload)
            if payload.get("enterprise_id") != enterprise_id:
                raise _fail("ENTERPRISE_VAULT_INTEGRITY", "Enterprise ID does not match authenticated envelope")
            return EnterpriseVaultHandle(
                self.path, payload, SecretBuffer(data_key), threading.Lock(),
                self._envelope_binding(enterprise_id, kdf, wrapped),
            )
        except InvalidTag as exc:
            raise _fail("ENTERPRISE_VAULT_INTEGRITY", "Enterprise Vault authenticated payload failed verification") from exc
        except Exception:
            mutable = bytearray(data_key)
            for index in range(len(mutable)):
                mutable[index] = 0
            raise

    def save(self, handle: EnterpriseVaultHandle) -> None:
        self._write(handle, initial=False)

    def _write(self, handle: EnterpriseVaultHandle, *, vault_passphrase: str | None = None,
               scrypt_n: int = DEFAULT_SCRYPT_N, initial: bool = False) -> None:
        with handle._lock:
            validate_payload(handle.payload)
            enterprise_id = str(handle.payload["enterprise_id"])
            previous_updated_at = handle.payload.get("updated_at", "")
            handle.payload["updated_at"] = utc_now()
            plaintext = _canonical(handle.payload)
            payload_nonce = secrets.token_bytes(12)
            payload_ciphertext = AESGCM(handle.data_key()).encrypt(payload_nonce, plaintext, self._payload_aad(enterprise_id))
            if initial:
                salt = secrets.token_bytes(16)
                kdf = {"algorithm": "scrypt", "salt": _b64u_encode(salt), "n": int(scrypt_n), "r": SCRYPT_R, "p": SCRYPT_P}
                kek = _derive_key(str(vault_passphrase or ""), salt, int(scrypt_n))
                wrap_nonce = secrets.token_bytes(12)
                try:
                    wrapped_ciphertext = AESGCM(kek).encrypt(wrap_nonce, handle.data_key(), self._outer_aad(enterprise_id, kdf))
                finally:
                    mutable = bytearray(kek)
                    for index in range(len(mutable)):
                        mutable[index] = 0
                wrapped = {"algorithm": "AES-256-GCM", "nonce": _b64u_encode(wrap_nonce), "ciphertext": _b64u_encode(wrapped_ciphertext)}
            else:
                                                                                                  
                                                                                            
                existing = _load_object_bytes(read_bytes_limited(self.path, MAX_VAULT_BYTES))
                kdf = existing.get("kdf")
                wrapped = existing.get("wrapped_key")
                if not isinstance(kdf, dict) or not isinstance(wrapped, dict) or str(existing.get("enterprise_id", "")) != enterprise_id:
                    handle.payload["updated_at"] = previous_updated_at
                    raise _fail("ENTERPRISE_VAULT_INTEGRITY", "Existing Vault envelope changed while unlocked")
                current_binding = self._envelope_binding(enterprise_id, kdf, wrapped)
                if not handle._envelope_binding or not hmac.compare_digest(current_binding, handle._envelope_binding):
                    handle.payload["updated_at"] = previous_updated_at
                    raise _fail("ENTERPRISE_VAULT_INTEGRITY", "Vault passphrase envelope changed while this session was unlocked")
            outer = {
                "schema": VAULT_SCHEMA,
                "version": 1,
                "enterprise_id": enterprise_id,
                "kdf": kdf,
                "wrapped_key": wrapped,
                "payload": {
                    "algorithm": "AES-256-GCM",
                    "nonce": _b64u_encode(payload_nonce),
                    "ciphertext": _b64u_encode(payload_ciphertext),
                    "sha256": hashlib.sha256(payload_ciphertext).hexdigest(),
                },
            }
            try:
                atomic_write_json(self.path, outer, ensure_ascii=False, indent=2, mode=0o600)
            except Exception:
                handle.payload["updated_at"] = previous_updated_at
                raise
            handle._envelope_binding = self._envelope_binding(enterprise_id, kdf, wrapped)

    def backup(self, destination: Path, *, vault_passphrase: str) -> Path:
        destination = Path(destination)
        if destination.is_symlink():
            raise _fail("ENTERPRISE_BACKUP_UNSAFE_PATH", "Enterprise backup destination cannot be a symbolic link")
                                                                                                 
                                                                                         
        try:
            same_target = destination.resolve(strict=False) == self.path.resolve(strict=False)
            if destination.exists() and self.path.exists():
                same_target = same_target or destination.samefile(self.path)
        except OSError:
            same_target = destination.absolute() == self.path.absolute()
        if same_target:
            raise _fail("ENTERPRISE_BACKUP_DESTINATION_CONFLICT", "Enterprise backup destination cannot be the live Vault path")
                                                                          
        handle = self.open(vault_passphrase)
        try:
            raw = read_bytes_limited(self.path, MAX_VAULT_BYTES)
            payload = {
                "schema": BACKUP_SCHEMA,
                "created_at": utc_now(),
                "enterprise_id": str(handle.payload["enterprise_id"]),
                "vault_sha256": hashlib.sha256(raw).hexdigest(),
                "vault": _b64u_encode(raw),
            }
            atomic_write_json(destination, payload, ensure_ascii=False, indent=2, mode=0o600)
            return destination
        finally:
            handle.close()

    def restore(self, source: Path, *, vault_passphrase: str, overwrite: bool = False) -> None:
        source = Path(source)
        if source.is_symlink() or self.path.is_symlink():
            raise _fail("ENTERPRISE_BACKUP_UNSAFE_PATH", "Enterprise restore cannot use symbolic links")
        if self.path.exists() and not overwrite:
            raise _fail("ENTERPRISE_RESTORE_DESTINATION_EXISTS", "Enterprise Vault destination already exists")
        raw_backup = read_bytes_limited(source, MAX_BACKUP_BYTES)
        backup = _load_object_bytes(raw_backup)
        if set(backup) != {"schema", "created_at", "enterprise_id", "vault_sha256", "vault"} or backup.get("schema") != BACKUP_SCHEMA:
            raise _fail("ENTERPRISE_BACKUP_INVALID", "Enterprise backup schema is invalid")
        vault_raw = _b64u_decode(str(backup.get("vault", "")), max_bytes=MAX_VAULT_BYTES)
        if hashlib.sha256(vault_raw).hexdigest() != str(backup.get("vault_sha256", "")):
            raise _fail("ENTERPRISE_BACKUP_INVALID", "Enterprise backup checksum mismatch")
                                                                                              
        temp_path = self.path.with_name(f".{self.path.name}.{new_id('restore')}.verify")
        try:
            atomic_write_json(temp_path, _load_object_bytes(vault_raw), ensure_ascii=False, indent=2, mode=0o600)
            probe = EnterpriseVault(temp_path).open(vault_passphrase)
            try:
                if str(probe.payload["enterprise_id"]) != str(backup.get("enterprise_id", "")):
                    raise _fail("ENTERPRISE_BACKUP_INVALID", "Enterprise backup identity mismatch")
            finally:
                probe.close()
            atomic_write_json(self.path, _load_object_bytes(vault_raw), ensure_ascii=False, indent=2, mode=0o600)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as exc:
                LOGGER.warning("Failed to remove temporary Enterprise Vault restore probe %s: %s", temp_path, exc)
