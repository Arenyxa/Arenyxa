from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa import __release_channel__
from arenyxa.application.runner_support import _AdaptiveRequestController, _DynamicRequestGate
from arenyxa.enterprise import EnrollmentService, LocalEnterpriseIdentityService
from arenyxa.enterprise.coordinator import CoordinatorClient, OfficeCoordinatorService
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.security import SecurityKernel
from arenyxa.security.key_protection import TPMKeyProtectionAdapter

ADMIN_PASSWORD = "Beta11-Admin-Password!"
VAULT_PASSWORD = "Beta11-Vault-Passphrase!"


def _worker_public() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _coordinator_stack(tmp_path: Path):
    identity = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    identity.create_enterprise("Arenyxa Beta11", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    identity.login("root", ADMIN_PASSWORD)
    identity.step_up(ADMIN_PASSWORD)
    enrollment = EnrollmentService(identity, tmp_path)
    return identity, OfficeCoordinatorService(identity, enrollment, tmp_path)


def test_beta12_release_channel_identity() -> None:
    assert __release_channel__ == "stable"


def test_adaptive_controller_does_not_treat_storage_pressure_as_cpu_pressure() -> None:
    gate = _DynamicRequestGate(8)
    controller = _AdaptiveRequestController(gate, 8, enabled=True)
    for _ in range(24):
        controller.observe(1.0, saturated=True)
    grown = gate.limit()
    assert grown >= 5
    controller.observe(
        900.0,
        saturated=True,
        storage_write_p95_ms=800.0,
        storage_wal_pages=12000,
        storage_backpressured=True,
    )
    snapshot = controller.snapshot()
    assert gate.limit() == grown
    assert snapshot["last_decision"] == "storage-backpressure"


def test_distributed_storage_circuit_distinguishes_backpressure_from_empty_queue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    queue = DurableDistributedQueue(tmp_path / "queue.sqlite")
    queue.register_worker("worker-a", _worker_public(), {"slots": 1})

    def busy(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(queue, "_lease_next_storage", busy)
    codes = []
    for _ in range(3):
        with pytest.raises(Exception) as caught:
            queue.lease_next("worker-a")
        codes.append(getattr(caught.value, "code", ""))
    assert codes[:2] == ["DISTRIBUTED_STORAGE_BACKPRESSURE", "DISTRIBUTED_STORAGE_BACKPRESSURE"]
    assert codes[2] == "DISTRIBUTED_STORAGE_CIRCUIT_OPEN"
    assert queue.storage_circuit_snapshot()["state"] == "open"
    with pytest.raises(Exception) as open_circuit:
        queue.lease_next("worker-a")
    assert getattr(open_circuit.value, "code", "") == "DISTRIBUTED_STORAGE_CIRCUIT_OPEN"


def test_stale_worker_heartbeat_recovers_phantom_lease_before_expiry(tmp_path: Path) -> None:
    db = tmp_path / "queue.sqlite"
    queue = DurableDistributedQueue(db)
    queue.register_worker("worker-stale", _worker_public(), {"slots": 1})
    job = queue.enqueue(
        "task.run", {"task": {"name": "heartbeat"}}, resource_id="heartbeat",
        permission="workflow.execute", idempotency_key="heartbeat-beta12", side_effect_mode="idempotent",
    )
    lease = queue.lease_next("worker-stale", lease_seconds=60)
    assert lease is not None
    now = queue._clock.stable_epoch()
    with sqlite3.connect(db) as connection:
        connection.execute(
            "UPDATE distributed_workers SET heartbeat_at=? WHERE worker_id=?",
            (now - queue._worker_heartbeat_timeout_seconds - 1.0, "worker-stale"),
        )
        connection.commit()
    assert queue.recover_stale_worker_leases(now=now) == 1
    state = queue.job(job)
    assert state["state"] == "queued"
    assert state["error_code"] == "WORKER_HEARTBEAT_LOST_REQUEUED"


def test_non_idempotent_stale_worker_enters_review_required(tmp_path: Path) -> None:
    db = tmp_path / "queue.sqlite"
    queue = DurableDistributedQueue(db)
    queue.register_worker("worker-side-effect", _worker_public(), {"slots": 1})
    job = queue.enqueue(
        "task.run", {"task": {"name": "side-effect"}}, resource_id="side-effect",
        permission="workflow.execute", idempotency_key="side-effect-beta12", side_effect_mode="non_idempotent",
    )
    lease = queue.lease_next("worker-side-effect", lease_seconds=60)
    assert lease is not None
    queue.start_job(job, "worker-side-effect", lease.lease_token)
    queue.mark_side_effect_started(job, "worker-side-effect", lease.lease_token)
    now = queue._clock.stable_epoch()
    with sqlite3.connect(db) as connection:
        connection.execute(
            "UPDATE distributed_workers SET heartbeat_at=? WHERE worker_id=?",
            (now - queue._worker_heartbeat_timeout_seconds - 1.0, "worker-side-effect"),
        )
        connection.commit()
    assert queue.recover_stale_worker_leases(now=now) == 1
    state = queue.job(job)
    assert state["state"] == "review_required"
    assert state["error_code"] == "WORKER_HEARTBEAT_LOST_AFTER_SIDE_EFFECT_START"


def test_coordinator_tls_context_can_hot_rotate_and_new_connections_verify(tmp_path: Path) -> None:
    identity, coordinator = _coordinator_stack(tmp_path)
    root = identity.root_public_identity()
    host, port = coordinator.start_tls("127.0.0.1", 0)
    try:
        before = CoordinatorClient(host, port, root["fingerprint"]).verify_peer()
        assert before["tls_rotation_count"] == 0
        assert coordinator._rotate_tls_context() is True
        after = CoordinatorClient(host, port, root["fingerprint"]).verify_peer()
        assert after["tls_rotation_count"] == 1
        assert after["tls_rotation_status"] == "ok"
    finally:
        coordinator.stop()


def test_tpm_probe_never_claims_protection_without_real_seal_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = TPMKeyProtectionAdapter()
    monkeypatch.setattr(TPMKeyProtectionAdapter, "hardware_present", classmethod(lambda cls: True))
    status = adapter.capability_status()
    assert status["hardware_present"] is True
    assert status["sealing_provider_configured"] is False
    assert adapter.available() is False
