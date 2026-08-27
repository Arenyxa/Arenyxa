from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from arenyxa.application.developer_access import OWNER_CHALLENGE_SCHEMA
from arenyxa.application.developer_identity import create_developer_identity
from arenyxa.application.root_owner_identity import sign_owner_login_challenge
from arenyxa.security.developer_credentials import OWNER_LOGIN_BUNDLE_SCHEMA


def _fixture(passphrase: str = "root-owner-device-passphrase-0001"):
    vault, request = create_developer_identity(
        "root.owner",
        "root-owner@example.com",
        passphrase,
        scrypt_n=2**14,
    )
    owner = {
        "owner_id": "root.owner",
        "email": "root-owner@example.com",
        "public_key": request["public_key"],
        "fingerprint": request["fingerprint"],
    }
    bundle = {
        "schema": OWNER_LOGIN_BUNDLE_SCHEMA,
        "owner_certificate": owner,
        "issuer_certificate": {},
    }
    now = datetime.now(UTC)
    challenge = {
        "schema": OWNER_CHALLENGE_SCHEMA,
        "challenge_id": "owner-challenge-v8.1",
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "process_nonce": "0" * 32,
        "certificate_sha256": "0" * 64,
        "developer_id": "root.owner",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=45)).isoformat(),
        "purpose": "root-owner-authority-login",
    }
    return vault, bundle, challenge, passphrase


def test_root_owner_adapter_uses_existing_encrypted_aryxkey_container() -> None:
    vault, bundle, challenge, passphrase = _fixture()
    signature = sign_owner_login_challenge(vault, passphrase, challenge, bundle)
    assert isinstance(signature, str) and signature


def test_root_owner_adapter_rejects_wrong_passphrase_with_root_specific_error() -> None:
    vault, bundle, challenge, _passphrase = _fixture()
    with pytest.raises(Exception) as captured:
        sign_owner_login_challenge(vault, "wrong-root-owner-passphrase-0000", challenge, bundle)
    assert getattr(captured.value, "code", "") == "ROOT_OWNER_VAULT_UNLOCK_FAILED"


def test_root_owner_adapter_rejects_vault_for_another_owner_before_signing() -> None:
    vault, bundle, challenge, passphrase = _fixture()
    bundle["owner_certificate"] = {**bundle["owner_certificate"], "owner_id": "another.owner"}
    with pytest.raises(Exception) as captured:
        sign_owner_login_challenge(vault, passphrase, challenge, bundle)
    assert getattr(captured.value, "code", "") == "ROOT_OWNER_DEVICE_IDENTITY_MISMATCH"
