from __future__ import annotations

import base64
import hashlib
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from arenyxa.enterprise import EnterpriseGovernanceService, LocalEnterpriseIdentityService
from arenyxa.enterprise.distributed import (
    CURRENT_PROTOCOL, MIN_COMPATIBLE_PROTOCOL, DurableDistributedQueue, EnterpriseServerRuntime,
    negotiate_protocol, verify_enterprise_server_identity,
)
from arenyxa.enterprise.migration import EnterpriseAuthorityMigrationService
from arenyxa.enterprise.server_api import create_enterprise_server_app
from arenyxa.security import SecurityKernel

ADMIN_PASSWORD = "Phase11-Admin-Password!"
VAULT_PASSWORD = "Phase11-Vault-Passphrase!"


def stack(tmp_path: Path):
    identity = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(tmp_path), tmp_path)
    identity.create_enterprise("Arenyxa Distributed Test", "root", "Root", ADMIN_PASSWORD, VAULT_PASSWORD)
    identity.login("root", ADMIN_PASSWORD)
    identity.step_up(ADMIN_PASSWORD)
    governance = EnterpriseGovernanceService(identity)
    runtime = EnterpriseServerRuntime(identity, governance, tmp_path)
    return identity, governance, runtime


def worker_key():
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_protocol_negotiation_is_explicit_n_n_minus_1() -> None:
    assert CURRENT_PROTOCOL == 2
    assert MIN_COMPATIBLE_PROTOCOL == 1
    assert negotiate_protocol(1, 2) == 2
    assert negotiate_protocol(1, 1) == 1
    with pytest.raises(Exception) as incompatible:
        negotiate_protocol(3, 4)
    assert getattr(incompatible.value, "code", "") == "PROTOCOL_INCOMPATIBLE"


def test_queue_idempotency_lease_digest_and_worker_revoke_recovery(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "queue.sqlite")
    private, public = worker_key()
    registered = queue.register_worker("worker-a", public, {"cpu": 8, "ram_mb": 16384}, max_slots=2)
    assert registered["negotiated_protocol"] == 2
    job_id = queue.enqueue(
        "task.run", {"task": {"name": "placeholder"}}, resource_id="resource-a", permission="workflow.execute",
        idempotency_key="idem-a", side_effect_mode="idempotent",
    )
    assert queue.enqueue(
        "task.run", {"task": {"name": "placeholder"}}, resource_id="resource-a", permission="workflow.execute",
        idempotency_key="idem-a", side_effect_mode="idempotent",
    ) == job_id
    with pytest.raises(Exception) as collision:
        queue.enqueue(
            "task.run", {"task": {"name": "different"}}, resource_id="resource-a", permission="workflow.execute",
            idempotency_key="idem-a", side_effect_mode="idempotent",
        )
    assert getattr(collision.value, "code", "") == "DISTRIBUTED_IDEMPOTENCY_COLLISION"
    lease = queue.lease_next("worker-a")
    assert lease is not None and lease.job_id == job_id
    raw_db = (tmp_path / "queue.sqlite").read_bytes()
    assert lease.lease_token.encode("utf-8") not in raw_db
    import sqlite3
    connection = sqlite3.connect(tmp_path / "queue.sqlite")
    try:
        stored_digest = str(connection.execute("SELECT lease_token_sha256 FROM distributed_jobs WHERE job_id=?", (job_id,)).fetchone()[0])
    finally:
        connection.close()
    assert stored_digest == hashlib.sha256(lease.lease_token.encode("utf-8")).hexdigest()
    assert queue.revoke_worker("worker-a") == 1
    assert queue.job(job_id)["state"] == "queued"


def test_non_idempotent_lease_loss_never_auto_repeats_side_effect(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "queue.sqlite")
    _private, public = worker_key()
    queue.register_worker("worker-b", public, {"slots": 1})
    job = queue.enqueue(
        "task.run", {"task": {"name": "non-idempotent"}}, resource_id="resource-b", permission="workflow.execute",
        idempotency_key="idem-non-idempotent", side_effect_mode="non_idempotent",
    )
    lease = queue.lease_next("worker-b")
    assert lease is not None
    queue.start_job(job, "worker-b", lease.lease_token)
    queue.mark_side_effect_started(job, "worker-b", lease.lease_token)
    assert queue.recover_expired_leases(now=lease.lease_expires_at + 1) == 1
    state = queue.job(job)
    assert state["state"] == "review_required"
    assert state["error_code"] == "LEASE_LOST_AFTER_SIDE_EFFECT_START"
    assert queue.lease_next("worker-b") is None


def test_worker_challenge_is_one_shot_and_exactly_bound(tmp_path: Path) -> None:
    identity, _governance, runtime = stack(tmp_path)
    private, public = worker_key()
    runtime.register_worker("worker-proof", public, {"slots": 1})
    challenge = runtime.create_worker_challenge("worker-proof")
    tampered = dict(challenge)
    tampered["protocol"] = 1
    signature = private.sign(runtime._challenge_message(tampered))
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    with pytest.raises(Exception) as invalid:
        runtime.authenticate_worker(tampered, encoded)
    assert getattr(invalid.value, "code", "") == "WORKER_CHALLENGE_INVALID"
                                                                            
    signature = private.sign(runtime._challenge_message(challenge))
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    with pytest.raises(Exception):
        runtime.authenticate_worker(challenge, encoded)

    challenge2 = runtime.create_worker_challenge("worker-proof")
    signature2 = private.sign(runtime._challenge_message(challenge2))
    session = runtime.authenticate_worker(challenge2, base64.urlsafe_b64encode(signature2).decode("ascii").rstrip("="))
    assert runtime._worker_session(session["session_token"])["worker_id"] == "worker-proof"


def _certificate_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Arenyxa Enterprise Server Test")])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_server_identity_is_enterprise_root_signed_tls_bound_and_api_exposes_worker_plane(tmp_path: Path) -> None:
    identity, _governance, runtime = stack(tmp_path)
    cert_der = _certificate_der()
    artifact = runtime.build_server_identity(cert_der, server_id="server-test")
    root = identity.root_public_identity()
    assert verify_enterprise_server_identity(artifact, root["fingerprint"], cert_der)["server_id"] == "server-test"
    with pytest.raises(Exception) as wrong_tls:
        verify_enterprise_server_identity(artifact, root["fingerprint"], cert_der + b"tamper")
    assert getattr(wrong_tls.value, "code", "") == "SERVER_TLS_BINDING_INVALID"
    app = create_enterprise_server_app(runtime, artifact)
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/enterprise/v1/identity" in paths
    assert "/enterprise/v1/worker/lease" in paths
    assert "/enterprise/v1/worker/job/checkpoint" in paths
    assert not any("admin/password" in path for path in paths)


def test_worker_drain_blocks_new_leases_and_undrain_recovers(tmp_path: Path) -> None:
    _identity, _governance, runtime = stack(tmp_path)
    _private, public = worker_key()
    runtime.register_worker("worker-drain", public, {"slots": 1})
    runtime.queue.enqueue(
        "task.run", {"task": {"name": "x"}}, resource_id="x", permission="workflow.execute",
        idempotency_key="drain-job", side_effect_mode="idempotent",
    )
    runtime.set_worker_drain("worker-drain", True)
    assert runtime.queue.lease_next("worker-drain") is None
    runtime.set_worker_drain("worker-drain", False)
    assert runtime.queue.lease_next("worker-drain") is not None


def test_enterprise_authority_migration_bundle_is_signed_encrypted_and_root_bound(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    target_root = tmp_path / "target"
    identity, _governance, _runtime = stack(source_root)
    root = identity.root_public_identity()
    migration = EnterpriseAuthorityMigrationService(identity)
    bundle = migration.export_bundle(tmp_path / "authority.aryxmigrate", VAULT_PASSWORD)
    raw = bundle.read_bytes()
    assert b"Phase11-Admin-Password" not in raw
    verified = migration.verify_bundle(bundle, root["fingerprint"])
    assert verified["enterprise_id"] == root["enterprise_id"]

    target = LocalEnterpriseIdentityService(SecurityKernel.local_foundation(target_root), target_root)
    EnterpriseAuthorityMigrationService(target).import_bundle(bundle, VAULT_PASSWORD, expected_root_fingerprint=root["fingerprint"])
    target.unlock(VAULT_PASSWORD)
    assert target.root_public_identity()["fingerprint"] == root["fingerprint"]

    import zipfile, json
    tampered = tmp_path / "tampered.aryxmigrate"
    with zipfile.ZipFile(bundle, "r") as archive:
        manifest_raw = archive.read("manifest.json")
        backup_raw = bytearray(archive.read("enterprise.aryxbak"))
    backup_raw[len(backup_raw) // 2] ^= 1
    with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", manifest_raw)
        archive.writestr("enterprise.aryxbak", bytes(backup_raw))
    with pytest.raises(Exception) as tamper_error:
        migration.verify_bundle(tampered, root["fingerprint"])
    assert getattr(tamper_error.value, "code", "") == "MIGRATION_BACKUP_TAMPERED"


def test_worker_executes_leased_task_through_shared_run_orchestrator(tmp_path: Path) -> None:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from arenyxa.application.runner import RunOrchestrator
    from arenyxa.domain.models import RequestSpec, Task
    from arenyxa.enterprise.distributed import EnterpriseWorkerRuntime
    from arenyxa.infrastructure.database import SQLiteStore

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body>shared-core-ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    store = SQLiteStore(tmp_path / "worker.sqlite")
    store.initialize()
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite")
    _private, public = worker_key()
    queue.register_worker("shared-core-worker", public, {"slots": 1})
    task = Task(name="Shared Core", requests=[RequestSpec(url=f"http://127.0.0.1:{server.server_port}/")])
    job = queue.enqueue(
        "task.run", {"task": task.to_dict(), "task_snapshot_sha256": task.snapshot_hash()},
        resource_id="capture:shared-core", permission="enterprise.capture.run",
        idempotency_key="shared-core-execution", side_effect_mode="idempotent",
    )
    lease = queue.lease_next("shared-core-worker")
    assert lease is not None and lease.job_id == job
    try:
        result = EnterpriseWorkerRuntime(runner, "shared-core-worker").execute_lease(queue, lease)
        assert result["status"] == "completed"
        assert queue.job(job)["state"] == "completed"
        persisted = store.get_run(result["run_id"])
        assert persisted is not None and persisted["status"] == "completed"
    finally:
        runner.shutdown(wait=True)
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_server_service_identity_can_refresh_after_human_logout(tmp_path: Path) -> None:
    identity, _governance, runtime = stack(tmp_path)
    cert_der = _certificate_der()
    initial = runtime.build_server_identity(cert_der, server_id="server-longrun", ttl_seconds=600)
    lease = runtime.activate_service(ttl_seconds=600)
    assert lease
    identity.logout()
    refreshed = runtime.build_service_server_identity(cert_der, server_id="server-longrun", ttl_seconds=600)
    root = identity.root_public_identity()
    assert refreshed["server_id"] == initial["server_id"] == "server-longrun"
    assert verify_enterprise_server_identity(refreshed, root["fingerprint"], cert_der)["enterprise_id"] == root["enterprise_id"]
    runtime.deactivate_service()


def test_server_app_identity_provider_is_dynamic(tmp_path: Path) -> None:
    _identity, _governance, runtime = stack(tmp_path)
    cert_der = _certificate_der()
    first = runtime.build_server_identity(cert_der, server_id="server-dynamic-a")
    second = dict(first)
    second["server_id"] = "server-dynamic-b"
    calls = [0]

    def provider():
        calls[0] += 1
        return first if calls[0] == 1 else second

    app = create_enterprise_server_app(runtime, provider)
    endpoint = next(route.endpoint for route in app.routes if getattr(route, "path", "") == "/enterprise/v1/identity")
    assert endpoint()["server_id"] == "server-dynamic-a"
    assert endpoint()["server_id"] == "server-dynamic-b"


def test_worker_renews_lease_independently_during_quiet_execution(tmp_path: Path) -> None:
    import threading
    from dataclasses import asdict
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from arenyxa.application.runner import RunOrchestrator
    from arenyxa.domain.models import RequestSpec, Task
    from arenyxa.enterprise.distributed import DistributedLease, EnterpriseWorkerRuntime
    from arenyxa.infrastructure.database import SQLiteStore

    class SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(1.8)
            body = b"<html><body>quiet-long-step</body></html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    store = SQLiteStore(tmp_path / "worker-keepalive.sqlite"); store.initialize()
    runner = RunOrchestrator(store, max_workers=1, request_workers=1, per_host_workers=1)
    queue = DurableDistributedQueue(tmp_path / "queue-keepalive.sqlite")
    _private, public = worker_key(); queue.register_worker("keepalive-worker", public, {"slots": 1})
    task = Task(name="Quiet lease", requests=[RequestSpec(url=f"http://127.0.0.1:{server.server_port}/")])
    job = queue.enqueue(
        "task.run", {"task": task.to_dict(), "task_snapshot_sha256": task.snapshot_hash()},
        resource_id="capture:quiet", permission="enterprise.capture.run", idempotency_key="quiet-keepalive",
    )
    original = queue.lease_next("keepalive-worker")
    assert original is not None
    lease_data = asdict(original); lease_data["lease_expires_at"] = time.time() + 1.2
    lease = DistributedLease(**lease_data)
    renewals = [0]
    actual_renew = queue.renew_lease

    def counted_renew(*args, **kwargs):
        renewals[0] += 1
        return actual_renew(*args, **kwargs)

    queue.renew_lease = counted_renew                               
    try:
        result = EnterpriseWorkerRuntime(runner, "keepalive-worker").execute_lease(queue, lease)
        assert result["status"] == "completed"
        assert renewals[0] >= 1
        assert queue.job(job)["state"] == "completed"
    finally:
        runner.shutdown(wait=True)
        server.shutdown(); server.server_close(); thread.join(timeout=2)
