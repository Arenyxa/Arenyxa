from __future__ import annotations

"""Explicit headless Developer login for trusted CI agents.

No authentication bypass exists here: the same signed bundle, encrypted private vault,
challenge, signature verification and scoped session issuance used by the UI are reused.
Secrets are supplied by a callback/secret broker, never implicitly read from environment.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from arenyxa.application.developer_access import DeveloperAccessManager
from arenyxa.application.developer_identity import load_vault, sign_login_challenge
from arenyxa.security import Session


@dataclass(frozen=True, slots=True)
class HeadlessDeveloperCredential:
    bundle_path: Path
    vault_path: Path
    passphrase_provider: Callable[[], str]


def login_headless(manager: DeveloperAccessManager, credential: HeadlessDeveloperCredential) -> Session:
    bundle = manager.load_bundle(credential.bundle_path)
    vault = load_vault(credential.vault_path)
    challenge = manager.begin_login(bundle)
    passphrase = credential.passphrase_provider()
    if not isinstance(passphrase, str) or not passphrase:
        raise ValueError("headless Developer passphrase provider returned no secret")
    try:
        signature = sign_login_challenge(vault, passphrase, challenge.payload)
    finally:
        passphrase = ""
    return manager.complete_login(challenge.challenge_id, signature)
