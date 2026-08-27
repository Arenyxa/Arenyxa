from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from arenyxa.application.dependency_health_history import DependencyHealthHistoryStore
from arenyxa.application.resilience_scheduler import ResilienceDrillScheduler
from arenyxa.enterprise import EnterpriseGovernanceService, LocalEnterpriseIdentityService
from arenyxa.enterprise.distributed import EnterpriseServerRuntime
from arenyxa.enterprise.distributed_queue import DurableDistributedQueue
from arenyxa.security import SecurityKernel
from arenyxa.security.confidential_compute import (
    CallbackConfidentialComputeProvider,
    ConfidentialComputeManager,
    ConfidentialComputePolicy,
)
from arenyxa.security.worker_identity import ECDSA_P256_SHA256, b64u, verify_signature

ADMIN_PASSWORD = "Stage2-Admin-Password!"
VAULT_PASSWORD = "Stage2-Vault-Passphrase!"


def _stack(tmp_path: Path):
    identity = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    identity.create_enterprise("Arenyxa Stage2", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    identity.login("root", ADMIN_PASSWORD)
    identity.step_up(ADMIN_PASSWORD)
    governance = EnterpriseGovernanceService(identity)
    return identity, EnterpriseServerRuntime(identity, governance, tmp_path)


def _p256_identity() -> tuple[ec.EllipticCurvePrivateKey, str]:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return private, b64u(public)


def _p1363_signature(private: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    der = private.sign(bytes(message), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return b64u(raw)


def test_worker_identity_profile_v2_verifies_p256_and_persists(tmp_path: Path) -> None:
    private, public = _p256_identity()
    message = b"arenyxa-worker-proof"
    signature = _p1363_signature(private, message)
    verify_signature(ECDSA_P256_SHA256, public, signature, message)

    queue = DurableDistributedQueue(tmp_path / "queue.sqlite")
    worker = queue.register_worker(
        "tpm-worker", public, {"permissions": ["dataset.read"]},
        identity_algorithm=ECDSA_P256_SHA256,
        identity_metadata={"provider": "windows-tpm-cng", "non_exportable": True},
    )
    assert worker["identity_algorithm"] == ECDSA_P256_SHA256
    assert worker["identity_metadata"]["non_exportable"] is True


def test_enterprise_worker_p256_challenge_v2_authenticates(tmp_path: Path) -> None:
    identity, runtime = _stack(tmp_path)
    private, public = _p256_identity()
    runtime.register_worker(
        "worker-p256", public, {"permissions": ["dataset.read"]}, identity_algorithm=ECDSA_P256_SHA256
    )
    challenge = runtime.create_worker_challenge("worker-p256")
    assert challenge["schema"] == "arenyxa.enterprise-worker-challenge/v2"
    assert challenge["identity_algorithm"] == ECDSA_P256_SHA256
    signature = _p1363_signature(private, runtime._challenge_message(challenge))
    session = runtime.authenticate_worker(challenge, signature)
    assert runtime._worker_session(session["session_token"])["worker_id"] == "worker-p256"
    identity.close()


def test_zero_trust_policy_is_root_signed_hot_reload_and_tamper_fails_closed(tmp_path: Path) -> None:
    identity, runtime = _stack(tmp_path)
    stored = runtime.set_network_policy({"enabled": True, "allowed_source_cidrs": ["10.10.0.0/16"]})
    assert stored["enabled"] is True

    second = EnterpriseServerRuntime(identity, EnterpriseGovernanceService(identity), tmp_path)
    second._refresh_network_policy(force=True)
    assert second.network_policy().allowed_source_cidrs == ("10.10.0.0/16",)

    db = tmp_path / "enterprise" / "distributed.sqlite"
    connection = sqlite3.connect(db)
    try:
        raw = connection.execute(
            "SELECT value FROM distributed_meta WHERE key='zero_trust_network_policy_v1'"
        ).fetchone()[0]
        connection.execute(
            "UPDATE distributed_meta SET value=? WHERE key='zero_trust_network_policy_v1'",
            (str(raw).replace("10.10.0.0/16", "0.0.0.0/0"),),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(Exception) as caught:
        second._refresh_network_policy(force=True)
    assert getattr(caught.value, "code", "") == "ZERO_TRUST_POLICY_INTEGRITY"
    with pytest.raises(Exception) as sticky:
        second.network_policy()
    assert getattr(sticky.value, "code", "") == "ZERO_TRUST_POLICY_INTEGRITY"
    identity.close()


def test_confidential_attestation_policy_rejects_debug_and_stale_attestation() -> None:
    now = __import__("time").time()
    provider = CallbackConfidentialComputeProvider(
        "test-vbs",
        executor=lambda _operation, payload: payload,
        attestation=lambda: {"verified": True, "measurement": "m1", "debug_enabled": True, "attested_at_epoch": now},
        hardware_backed=False,
        isolation="vbs",
    )
    manager = ConfidentialComputeManager(
        (provider,),
        ConfidentialComputePolicy(mode="require", operations=("enterprise.worker.verify",), allowed_measurements=("m1",)),
    )
    assert manager.statuses()[0].ready is False
    with pytest.raises(Exception) as caught:
        manager.execute("enterprise.worker.verify", b"proof", fallback=lambda raw: raw)
    assert getattr(caught.value, "code", "") == "CONFIDENTIAL_COMPUTE_REQUIRED"

    stale = CallbackConfidentialComputeProvider(
        "test-vbs-stale",
        executor=lambda _operation, payload: payload,
        attestation=lambda: {"verified": True, "measurement": "m1", "debug_enabled": False, "attested_at_epoch": now - 9999},
        hardware_backed=False,
        isolation="vbs",
    )
    stale_manager = ConfidentialComputeManager(
        (stale,),
        ConfidentialComputePolicy(mode="require", operations=("enterprise.worker.verify",), max_attestation_age_seconds=60),
    )
    assert stale_manager.statuses()[0].reason == "attestation is stale"


def test_dependency_history_emits_degrading_forecast(tmp_path: Path) -> None:
    store = DependencyHealthHistoryStore(tmp_path)
    for index, latency in enumerate((20.0, 30.0, 55.0, 110.0)):
        store.record(
            {
                "generated_at": str(index),
                "overall": "healthy",
                "probes": [{"component": "PostgreSQL", "state": "healthy", "latency_ms": latency, "metrics": {}}],
            }
        )
    trend = store.trend("PostgreSQL")
    assert trend["direction"] == "degrading"
    assert trend["forecast"] == "warning"


def test_periodic_resilience_scheduler_is_capability_gated_and_persistent(store, tmp_path: Path) -> None:
    class _Access:
        def status(self):
            return SimpleNamespace(capabilities=("fault_injection",))

    context = SimpleNamespace(store=store, paths=SimpleNamespace(root=tmp_path), developer_access=_Access())
    scheduler = ResilienceDrillScheduler(context)
    snapshot = scheduler.run_once()
    assert snapshot["last_state"] == "healthy"
    assert snapshot["history"][-1]["passed"] == 4
    scheduler.enable(interval_seconds=15 * 60)
    assert scheduler.snapshot()["enabled"] is True
    scheduler.disable()
    assert scheduler.snapshot()["enabled"] is False
