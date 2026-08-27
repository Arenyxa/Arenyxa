from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from arenyxa.application.developer_identity import load_vault, sign_login_challenge
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.developer_credentials import OWNER_LOGIN_BUNDLE_SCHEMA


def _error(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="DEVELOPER_ACCESS", context=context)


def _translate_vault_error(exc: ArenyxaError) -> ArenyxaError:
    code = str(getattr(exc, "code", ""))
    mapping = {
        "DEVELOPER_VAULT_UNLOCK_FAILED": (
            "ROOT_OWNER_VAULT_UNLOCK_FAILED",
            "Root Owner Device Key passphrase is incorrect or the encrypted vault integrity check failed",
        ),
        "DEVELOPER_PASSPHRASE_INVALID": (
            "ROOT_OWNER_PASSPHRASE_INVALID",
            "Root Owner Device Key passphrase must satisfy the protected key-vault policy",
        ),
        "DEVELOPER_VAULT_KEY_MISMATCH": (
            "ROOT_OWNER_DEVICE_KEY_MISMATCH",
            "Root Owner Device Key private key does not match its public identity",
        ),
        "DEVELOPER_VAULT_INVALID": (
            "ROOT_OWNER_VAULT_INVALID",
            "Root Owner Device Key Vault format or cryptographic parameters are invalid",
        ),
        "DEVELOPER_CHALLENGE_INVALID": (
            "ROOT_OWNER_CHALLENGE_INVALID",
            "Root Owner login challenge is invalid, expired, or belongs to another identity",
        ),
    }
    translated = mapping.get(code)
    if translated is None:
        return exc
    return _error(translated[0], translated[1], source_code=code)


def _owner_certificate(bundle: Mapping[str, Any]) -> dict[str, Any]:
    if bundle.get("schema") != OWNER_LOGIN_BUNDLE_SCHEMA:
        raise _error("ROOT_OWNER_BUNDLE_INVALID", "Root Owner Login Bundle schema is invalid")
    owner = bundle.get("owner_certificate")
    if not isinstance(owner, dict):
        raise _error("ROOT_OWNER_BUNDLE_INVALID", "Root Owner Login Bundle has no owner certificate")
    return dict(owner)


def load_owner_device_vault(path: Path) -> dict[str, Any]:
    """Load a Root Owner device key using the established encrypted .aryxkey container.

    The on-disk container is deliberately shared with the hardened Developer Personal
    vault implementation. Root authority is *not* shared: the selected vault must bind
    to the Root Owner certificate and is only accepted for a Root Owner challenge.
    """
    try:
        return load_vault(Path(path))
    except ArenyxaError as exc:
        translated = _translate_vault_error(exc)
        if translated is exc:
            raise
        raise translated from exc


def validate_owner_device_binding(vault: Mapping[str, Any], bundle: Mapping[str, Any]) -> None:
    owner = _owner_certificate(bundle)
    expected_owner = str(owner.get("owner_id", ""))
    expected_email = str(owner.get("email", ""))
    expected_public = str(owner.get("public_key", ""))
    expected_fingerprint = str(owner.get("fingerprint", ""))

    if str(vault.get("developer_id", "")) != expected_owner:
        raise _error(
            "ROOT_OWNER_DEVICE_IDENTITY_MISMATCH",
            "Selected Root Owner Device Key belongs to another Owner identity",
            expected_owner_id=expected_owner,
        )
    if expected_email and str(vault.get("email", "")) != expected_email:
        raise _error(
            "ROOT_OWNER_DEVICE_IDENTITY_MISMATCH",
            "Selected Root Owner Device Key email does not match the Owner certificate",
            expected_owner_id=expected_owner,
        )
    if str(vault.get("public_key", "")) != expected_public or str(vault.get("fingerprint", "")) != expected_fingerprint:
        raise _error(
            "ROOT_OWNER_DEVICE_KEY_MISMATCH",
            "Selected Root Owner Device Key does not match the public key in the Owner certificate",
            expected_owner_id=expected_owner,
        )


def sign_owner_login_challenge(
    vault: Mapping[str, Any],
    passphrase: str,
    challenge: Mapping[str, Any],
    bundle: Mapping[str, Any],
) -> str:
    """Sign only a Root Owner challenge with the certificate-bound Owner device key."""
    validate_owner_device_binding(vault, bundle)
    if str(challenge.get("purpose", "")) != "root-owner-authority-login":
        raise _error("ROOT_OWNER_CHALLENGE_INVALID", "Refusing to sign a non-Root Owner challenge")
    if str(challenge.get("developer_id", "")) != str(vault.get("developer_id", "")):
        raise _error("ROOT_OWNER_CHALLENGE_INVALID", "Root Owner challenge identity does not match the selected device key")
    try:
        return sign_login_challenge(vault, passphrase, challenge)
    except ArenyxaError as exc:
        translated = _translate_vault_error(exc)
        if translated is exc:
            raise
        raise translated from exc
