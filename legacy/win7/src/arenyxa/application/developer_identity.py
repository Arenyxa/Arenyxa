from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.security.developer_credentials import (
    b64u_decode,
    b64u_encode,
    canonical_json,
    key_fingerprint,
    load_json_object,
)

VAULT_SCHEMA = "arenyxa.developer-personal-vault/v1"
REQUEST_SCHEMA = "arenyxa.developer-key-request/v1"
LOGIN_CHALLENGE_SCHEMA = "arenyxa.developer-login-challenge/v1"
OWNER_CHALLENGE_SCHEMA = "arenyxa.developer-owner-login-challenge/v1"
DEFAULT_SCRYPT_N = 2**18


def _error(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="DEVELOPER_ACCESS", context=context)


def _private_raw(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _public_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _key_id(public_raw: bytes) -> str:
    return "developer_" + hashlib.sha256(public_raw).hexdigest()[:20]


def _derive(passphrase: str, salt: bytes, *, n: int) -> bytes:
    if not isinstance(passphrase, str) or len(passphrase) < 16 or len(passphrase) > 4096:
        raise _error("DEVELOPER_PASSPHRASE_INVALID", "Developer key passphrase must contain 16-4096 characters")
    if n < 2**14 or n > 2**20 or n & (n - 1):
        raise _error("DEVELOPER_VAULT_INVALID", "Developer vault scrypt cost is outside supported bounds")
    material = bytearray(passphrase.encode("utf-8"))
    try:
        return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(material)
    finally:
        for index in range(len(material)):
            material[index] = 0


def create_developer_identity(developer_id: str, email: str, passphrase: str, *, scrypt_n: int = DEFAULT_SCRYPT_N) -> tuple[dict[str, Any], dict[str, Any]]:
    developer_id = str(developer_id).strip()
    email = str(email).strip()
    if not developer_id or len(developer_id) > 128:
        raise _error("DEVELOPER_ID_INVALID", "Developer ID is invalid")
    if email.count("@") != 1 or len(email) > 254:
        raise _error("DEVELOPER_EMAIL_INVALID", "Developer email is invalid")
    private = Ed25519PrivateKey.generate()
    public_raw = _public_raw(private)
    private_raw = bytearray(_private_raw(private))
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key_id = _key_id(public_raw)
    fingerprint = key_fingerprint(public_raw)
    header = {
        "schema": VAULT_SCHEMA,
        "key_id": key_id,
        "developer_id": developer_id,
        "email": email,
        "public_key": b64u_encode(public_raw),
        "fingerprint": fingerprint,
        "kdf": {"name": "scrypt", "n": scrypt_n, "r": 8, "p": 1, "salt": b64u_encode(salt)},
        "cipher": {"name": "AES-256-GCM", "nonce": b64u_encode(nonce)},
    }
    key = _derive(passphrase, salt, n=scrypt_n)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, bytes(private_raw), canonical_json(header))
    finally:
        for index in range(len(private_raw)):
            private_raw[index] = 0
        key_buffer = bytearray(key)
        for index in range(len(key_buffer)):
            key_buffer[index] = 0
    vault = {**header, "ciphertext": b64u_encode(ciphertext)}
    request = {
        "schema": REQUEST_SCHEMA,
        "developer_id": developer_id,
        "email": email,
        "public_key": b64u_encode(public_raw),
        "fingerprint": fingerprint,
        "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
    }
    return vault, request


def write_developer_identity(vault_path: Path, request_path: Path, developer_id: str, email: str, passphrase: str) -> tuple[dict[str, Any], dict[str, Any]]:
    vault_path = Path(vault_path)
    request_path = Path(request_path)
    if os.path.abspath(str(vault_path)) == os.path.abspath(str(request_path)):
        raise _error("DEVELOPER_IDENTITY_PATH_CONFLICT", "Developer private vault and public request must use different paths")
    vault, request = create_developer_identity(developer_id, email, passphrase)
                                                                                          
                                                                                                  
    atomic_write_json(Path(vault_path), vault, mode=0o600)
    atomic_write_json(Path(request_path), request)
    return vault, request


def _validate_vault(vault: Mapping[str, Any]) -> dict[str, Any]:
    expected = {"schema", "key_id", "developer_id", "email", "public_key", "fingerprint", "kdf", "cipher", "ciphertext"}
    if set(vault) != expected or vault.get("schema") != VAULT_SCHEMA:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault schema is invalid")

    key_id = str(vault.get("key_id", ""))
    if not key_id.startswith("developer_") or len(key_id) != 30 or any(ch not in "0123456789abcdef" for ch in key_id[10:]):
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault key id is invalid")
    developer_id = str(vault.get("developer_id", "")).strip()
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-:@"
    if not 1 <= len(developer_id) <= 128 or any(ch not in allowed for ch in developer_id):
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault Developer ID is invalid")
    email = str(vault.get("email", "")).strip()
    if not 3 <= len(email) <= 254 or email.count("@") != 1 or any(ch.isspace() for ch in email):
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault email is invalid")

    public_raw = b64u_decode(str(vault.get("public_key", "")), max_bytes=64)
    if len(public_raw) != 32 or key_fingerprint(public_raw) != str(vault.get("fingerprint", "")):
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault public identity is invalid")
    if _key_id(public_raw) != key_id:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault key id does not match public key")

    kdf = vault.get("kdf")
    cipher = vault.get("cipher")
    if not isinstance(kdf, dict) or set(kdf) != {"name", "n", "r", "p", "salt"}:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault KDF block is invalid")
    if not isinstance(cipher, dict) or set(cipher) != {"name", "nonce"}:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault cipher block is invalid")
    if kdf.get("name") != "scrypt" or cipher.get("name") != "AES-256-GCM":
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault cryptographic parameters are invalid")
    try:
        n = int(kdf.get("n"))
        r = int(kdf.get("r"))
        p_cost = int(kdf.get("p"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault KDF parameters are invalid") from exc
    if isinstance(kdf.get("n"), bool) or isinstance(kdf.get("r"), bool) or isinstance(kdf.get("p"), bool):
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault KDF parameters are invalid")
    if n < 2**14 or n > 2**20 or n & (n - 1) or r != 8 or p_cost != 1:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault KDF parameters are outside supported bounds")
    salt = b64u_decode(str(kdf.get("salt", "")), max_bytes=64)
    nonce = b64u_decode(str(cipher.get("nonce", "")), max_bytes=32)
    ciphertext = b64u_decode(str(vault.get("ciphertext", "")), max_bytes=256)
    if not 16 <= len(salt) <= 64 or len(nonce) != 12 or len(ciphertext) != 48:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault salt/nonce/ciphertext size is invalid")
    return dict(vault)


def _validate_login_challenge(challenge: Mapping[str, Any], vault: Mapping[str, Any]) -> dict[str, Any]:
    expected = {
        "schema", "challenge_id", "nonce", "process_nonce", "certificate_sha256",
        "developer_id", "issued_at", "expires_at", "purpose",
    }
    schema = str(challenge.get("schema", ""))
    expected_purpose = {
        LOGIN_CHALLENGE_SCHEMA: "official-developer-login",
        OWNER_CHALLENGE_SCHEMA: "root-owner-authority-login",
    }.get(schema)
    if set(challenge) != expected or expected_purpose is None:
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer/Owner login challenge schema is invalid")
    if challenge.get("purpose") != expected_purpose:
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer/Owner login challenge purpose is invalid")
    if str(challenge.get("developer_id", "")) != str(vault.get("developer_id", "")):
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge belongs to another Developer ID")
    challenge_id = str(challenge.get("challenge_id", ""))
    if not 1 <= len(challenge_id) <= 160 or any(ord(ch) < 33 or ord(ch) > 126 for ch in challenge_id):
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge id is invalid")
    nonce = b64u_decode(str(challenge.get("nonce", "")), max_bytes=64)
    process_nonce = str(challenge.get("process_nonce", ""))
    digest = str(challenge.get("certificate_sha256", "")).lower()
    if len(nonce) != 32 or len(process_nonce) != 32 or any(ch not in "0123456789abcdef" for ch in process_nonce):
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge nonce is invalid")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge certificate binding is invalid")
    try:
        issued = datetime.fromisoformat(str(challenge.get("issued_at")))
        expires = datetime.fromisoformat(str(challenge.get("expires_at")))
    except (TypeError, ValueError, OverflowError) as exc:
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge time is invalid") from exc
    if issued.tzinfo is None or expires.tzinfo is None:
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge time must include a timezone")
    if expires <= issued or expires - issued > timedelta(minutes=2):
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge validity interval is invalid")
    current = datetime.now(issued.tzinfo)
    if issued > current + timedelta(seconds=30):
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge issuance time is in the future")
    if current >= expires:
        raise _error("DEVELOPER_CHALLENGE_INVALID", "Developer login challenge has expired")
    return dict(challenge)


def sign_login_challenge(vault: Mapping[str, Any], passphrase: str, challenge: Mapping[str, Any]) -> str:
    vault = _validate_vault(vault)
    challenge = _validate_login_challenge(challenge, vault)
    kdf = dict(vault["kdf"])
    cipher = dict(vault["cipher"])
    salt = b64u_decode(str(kdf["salt"]), max_bytes=64)
    nonce = b64u_decode(str(cipher["nonce"]), max_bytes=64)
    if len(salt) < 16 or len(nonce) != 12:
        raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal vault salt/nonce is invalid")
    n = int(kdf["n"])
    header = {key: item for key, item in vault.items() if key != "ciphertext"}
    key = _derive(passphrase, salt, n=n)
    private_raw: bytearray | None = None
    try:
        ciphertext = b64u_decode(str(vault["ciphertext"]), max_bytes=256)
        raw = AESGCM(key).decrypt(nonce, ciphertext, canonical_json(header))
        if len(raw) != 32:
            raise _error("DEVELOPER_VAULT_INVALID", "Developer Personal private key has invalid size")
        private_raw = bytearray(raw)
        private = Ed25519PrivateKey.from_private_bytes(bytes(private_raw))
        public_raw = _public_raw(private)
        expected_public = b64u_decode(str(vault["public_key"]), max_bytes=64)
        if public_raw != expected_public or key_fingerprint(public_raw) != vault["fingerprint"]:
            raise _error("DEVELOPER_VAULT_KEY_MISMATCH", "Developer Personal private key does not match vault public identity")
        return b64u_encode(private.sign(canonical_json(challenge)))
    except InvalidTag as exc:
        raise _error("DEVELOPER_VAULT_UNLOCK_FAILED", "Developer Personal vault passphrase or integrity check failed") from exc
    finally:
        if private_raw is not None:
            for index in range(len(private_raw)):
                private_raw[index] = 0
        key_buffer = bytearray(key)
        for index in range(len(key_buffer)):
            key_buffer[index] = 0


def load_vault(path: Path) -> dict[str, Any]:
                                                                                              
                                                                                              
                                                    
    return _validate_vault(load_json_object(Path(path), max_bytes=256 * 1024))
