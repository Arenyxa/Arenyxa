"""BUG-V82-HUNT-004: Worker HTTP Zero Trust must not hardcode risk/auth_age to 0.

Regression: auth_age comes from session.created_at; without a risk engine the
worker plane fails closed at risk_score=100 (callers cannot advertise optimistic 0).
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed_runtime import EnterpriseServerRuntime
from arenyxa.infrastructure.timebase import PROCESS_CLOCK
from arenyxa.security.zero_trust import ZeroTrustPolicy


class _IdentityStub:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()
        public_raw = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self._public = base64.urlsafe_b64encode(public_raw).decode("ascii").rstrip("=")
        self._fingerprint = hashlib.sha256(public_raw).hexdigest()

    def require(self, *_args, **_kwargs) -> None:
        return None

    def require_recent_step_up(self) -> None:
        return None

    def root_public_identity(self) -> dict[str, str]:
        return {"enterprise_id": "test", "public_key": self._public, "fingerprint": self._fingerprint}

    def sign_enterprise_artifact(self, message: bytes, **_kwargs) -> dict[str, str]:
        return {
            "enterprise_id": "test",
            "root_public_key": self._public,
            "root_fingerprint": self._fingerprint,
            "signature": base64.urlsafe_b64encode(self._key.sign(bytes(message))).decode("ascii").rstrip("="),
        }


def _worker_key():
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return private, public


def _authed_session(runtime: EnterpriseServerRuntime, worker_id: str = "w-hunt004"):
    private, public = _worker_key()
    runtime.register_worker(worker_id, public, {"slots": 1})
    challenge = runtime.create_worker_challenge(worker_id)
    signature = base64.urlsafe_b64encode(private.sign(runtime._challenge_message(challenge))).decode("ascii").rstrip("=")
    # Optimistic zeros must not win — runtime fail-closes risk and uses fresh age.
    session = runtime.authenticate_worker(
        challenge,
        signature,
        access_context={
            "source_ip": "10.0.0.5",
            "transport": "tls13",
            "via_server_relay": True,
            "peer_to_peer": False,
            "network_trust": "private",
            "risk_score": 0,
            "auth_age_seconds": 0,
        },
    )
    return session["session_token"]


def test_hunt004_server_api_does_not_hardcode_zero_risk_or_age() -> None:
    source = Path(__file__).resolve().parents[1] / "src/arenyxa/enterprise/server_api.py"
    text = source.read_text(encoding="utf-8")
    assert '"risk_score": 0' not in text
    assert '"auth_age_seconds": 0' not in text


def test_hunt004_max_risk_score_zero_fails_closed_without_engine(tmp_path: Path) -> None:
    runtime = EnterpriseServerRuntime(_IdentityStub(), SimpleNamespace(), tmp_path)
    runtime.set_network_policy(
        ZeroTrustPolicy(
            enabled=True,
            max_risk_score=0,
            max_auth_age_seconds=24 * 60 * 60,
            allowed_network_trust=("private", "trusted", "unknown"),
        )
    )
    private, public = _worker_key()
    runtime.register_worker("w-risk", public, {"slots": 1})
    challenge = runtime.create_worker_challenge("w-risk")
    signature = base64.urlsafe_b64encode(private.sign(runtime._challenge_message(challenge))).decode("ascii").rstrip("=")
    with pytest.raises(ArenyxaError) as caught:
        runtime.authenticate_worker(
            challenge,
            signature,
            access_context={
                "source_ip": "10.0.0.5",
                "via_server_relay": True,
                "network_trust": "private",
                "risk_score": 0,
                "auth_age_seconds": 0,
            },
        )
    assert caught.value.code == "ZERO_TRUST_CONTEXT_DENIED"
    assert "risk_score" in list(caught.value.context.get("reasons", []))


def test_hunt004_auth_age_from_session_created_at(tmp_path: Path) -> None:
    runtime = EnterpriseServerRuntime(_IdentityStub(), SimpleNamespace(), tmp_path)
    runtime.set_network_policy(
        ZeroTrustPolicy(
            enabled=True,
            max_risk_score=100,
            max_auth_age_seconds=1,
            allowed_network_trust=("private", "trusted", "unknown"),
        )
    )
    token = _authed_session(runtime, "w-age")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with runtime._lock:
        runtime._sessions[digest]["created_at"] = PROCESS_CLOCK.stable_epoch() - 120.0

    # Caller still claims age 0 (old HTTP bug); must deny from real session age.
    with pytest.raises(ArenyxaError) as caught:
        runtime.authorize_worker_session_context(
            token,
            {
                "source_ip": "10.0.0.5",
                "transport": "tls13",
                "via_server_relay": True,
                "peer_to_peer": False,
                "network_trust": "private",
                "risk_score": 0,
                "auth_age_seconds": 0,
            },
        )
    assert caught.value.code == "ZERO_TRUST_CONTEXT_DENIED"
    assert "auth_age" in list(caught.value.context.get("reasons", []))


def test_hunt004_fresh_session_allows_under_default_risk_ceiling(tmp_path: Path) -> None:
    runtime = EnterpriseServerRuntime(_IdentityStub(), SimpleNamespace(), tmp_path)
    runtime.set_network_policy(
        ZeroTrustPolicy(
            enabled=True,
            max_risk_score=100,
            max_auth_age_seconds=24 * 60 * 60,
            allowed_network_trust=("private", "trusted", "unknown"),
        )
    )
    token = _authed_session(runtime, "w-ok")
    runtime.authorize_worker_session_context(
        token,
        {
            "source_ip": "10.0.0.5",
            "transport": "tls13",
            "via_server_relay": True,
            "peer_to_peer": False,
            "network_trust": "private",
        },
    )


def test_hunt004_adversarial_caller_cannot_lower_risk_or_age(tmp_path: Path) -> None:
    runtime = EnterpriseServerRuntime(_IdentityStub(), SimpleNamespace(), tmp_path)
    # Authenticate under a policy that permits fail-closed risk=100, then tighten.
    runtime.set_network_policy(
        ZeroTrustPolicy(
            enabled=True,
            max_risk_score=100,
            max_auth_age_seconds=24 * 60 * 60,
            allowed_network_trust=("private", "trusted", "unknown"),
        )
    )
    token = _authed_session(runtime, "w-adv")
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    with runtime._lock:
        runtime._sessions[digest]["created_at"] = PROCESS_CLOCK.stable_epoch() - 90.0
    runtime.set_network_policy(
        ZeroTrustPolicy(
            enabled=True,
            max_risk_score=50,
            max_auth_age_seconds=30,
            allowed_network_trust=("private", "trusted", "unknown"),
        )
    )

    with pytest.raises(ArenyxaError) as caught:
        runtime.authorize_worker_session_context(
            token,
            {
                "source_ip": "10.0.0.5",
                "via_server_relay": True,
                "network_trust": "private",
                "risk_score": 0,
                "auth_age_seconds": 0,
            },
        )
    reasons = set(caught.value.context.get("reasons", []))
    assert {"risk_score", "auth_age"}.issubset(reasons)
