from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.application.data_lineage import DataLineageService
from arenyxa.application.dependency_health import DependencyHealthService
from arenyxa.application.resilience_drills import ResilienceDrillService
from arenyxa.application.workflow_runtime import WorkflowDatasetService
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import DatasetRevision, Workflow, WorkflowNode
from arenyxa.enterprise.distributed_runtime import EnterpriseServerRuntime
from arenyxa.infrastructure.http_client import CancellationToken
from arenyxa.security.confidential_compute import (
    CallbackConfidentialComputeProvider,
    ConfidentialComputeManager,
    ConfidentialComputePolicy,
)
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider
from arenyxa.security.zero_trust import ZeroTrustEvaluator, ZeroTrustPolicy


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


class _CancelAfter(CancellationToken):
    def __init__(self, limit: int) -> None:
        super().__init__()
        self.limit = limit
        self.calls = 0

    def checkpoint(self) -> None:
        self.calls += 1
        if self.calls >= self.limit:
            self.cancel()
        super().checkpoint()


def _workflow() -> Workflow:
    return Workflow(
        "resume-safe",
        [
            WorkflowNode("source", {}, id="source", next_ids=["map"]),
            WorkflowNode("map", {"constants": {"verified": True}}, id="map", next_ids=["sink"]),
            WorkflowNode("sink", {}, id="sink"),
        ],
        id="workflow_resume_safe",
        version="1.0.0",
    )


def _source(store) -> DatasetRevision:
    revision = DatasetRevision("source", [], {str(i): {"id": i} for i in range(8)})
    store.save_revision(revision)
    store.upsert_dataset("source", "Source", current_revision_id=revision.id)
    return revision


def test_zero_trust_microsegmentation_is_fail_closed() -> None:
    policy = ZeroTrustPolicy.from_mapping(
        {
            "enabled": True,
            "allowed_source_cidrs": ["10.20.0.0/16"],
            "required_permissions": ["dataset.read"],
            "allowed_worker_ids": ["worker-a"],
            "allowed_server_ids": ["server-primary"],
            "require_server_relay": True,
            "deny_peer_to_peer": True,
            "required_transport": "tls13",
            "max_risk_score": 25,
            "max_auth_age_seconds": 300,
        }
    )
    allowed = ZeroTrustEvaluator.evaluate(
        policy,
        {
            "source_ip": "10.20.4.18",
            "permissions": ["dataset.read", "worker.execute"],
            "worker_id": "worker-a",
            "server_id": "server-primary",
            "via_server_relay": True,
            "peer_to_peer": False,
            "transport": "tls13",
            "network_trust": "trusted",
            "risk_score": 10,
            "auth_age_seconds": 20,
        },
    )
    assert allowed.allowed is True

    denied = ZeroTrustEvaluator.evaluate(
        policy,
        {
            "source_ip": "203.0.113.20",
            "permissions": [],
            "worker_id": "worker-x",
            "server_id": "server-primary",
            "via_server_relay": False,
            "peer_to_peer": True,
            "transport": "tls12",
            "network_trust": "untrusted",
            "risk_score": 90,
            "auth_age_seconds": 900,
        },
    )
    assert denied.allowed is False
    assert {"source_ip", "permissions", "worker_id", "server_relay", "peer_to_peer", "transport"}.issubset(denied.reasons)


def test_enterprise_server_network_policy_engine(tmp_path) -> None:
    runtime = EnterpriseServerRuntime(_IdentityStub(), SimpleNamespace(), tmp_path)
    stored = runtime.set_network_policy(
        ZeroTrustPolicy(enabled=True, allowed_source_cidrs=("10.0.0.0/8",), require_server_relay=True)
    )
    assert stored["enabled"] is True
    runtime.evaluate_network_context(
        {"source_ip": "10.1.2.3", "via_server_relay": True, "network_trust": "trusted", "risk_score": 0, "auth_age_seconds": 0}
    )
    with pytest.raises(ArenyxaError) as caught:
        runtime.evaluate_network_context(
            {"source_ip": "192.0.2.9", "via_server_relay": False, "network_trust": "trusted", "risk_score": 0, "auth_age_seconds": 0}
        )
    assert caught.value.code == "ZERO_TRUST_CONTEXT_DENIED"


def test_confidential_compute_require_mode_is_attestation_gated() -> None:
    provider = CallbackConfidentialComputeProvider(
        "test-enclave",
        executor=lambda operation, payload: operation.encode("utf-8") + b":" + payload[::-1],
        attestation=lambda: {"verified": True, "measurement": "test"},
        hardware_backed=True,
        isolation="test",
    )
    manager = ConfidentialComputeManager(
        (provider,),
        ConfidentialComputePolicy(mode="require", operations=("enterprise.vault.decrypt",)),
    )
    result = manager.execute("enterprise.vault.decrypt", b"secret", fallback=lambda raw: raw)
    assert result == b"enterprise.vault.decrypt:terces"

    unavailable = ConfidentialComputeManager(
        (), ConfidentialComputePolicy(mode="require", operations=("enterprise.vault.decrypt",))
    )
    unavailable.providers = ()
    with pytest.raises(ArenyxaError) as caught:
        unavailable.execute("enterprise.vault.decrypt", b"secret", fallback=lambda raw: raw)
    assert caught.value.code == "CONFIDENTIAL_COMPUTE_REQUIRED"


def test_tpm_provider_never_claims_ed25519_support() -> None:
    status = WindowsTPMEcdsaP256Provider().status()
    assert "ECDSA_P256_SHA256" in status.algorithms
    assert all("Ed25519" not in item for item in status.algorithms)


def test_workflow_resume_preflight_replays_checkpoint(store) -> None:
    source = _source(store)
    runtime = WorkflowDatasetService(store, WorkflowEngine(), DataLineageService(store), checkpoint_every=1)
    with pytest.raises(ArenyxaError) as caught:
        runtime.execute_revision(_workflow(), source.id, "derived", token=_CancelAfter(9))
    assert caught.value.code == "RUN_CANCELLED"
    execution = store.list_workflow_executions("workflow_resume_safe", limit=1)[0]
    validation = runtime.validate_resume_checkpoint(str(execution["id"]), _workflow())
    assert validation.valid is True
    assert validation.replayed is True
    resumed = runtime.resume_execution(str(execution["id"]), _workflow())
    assert resumed.state == "completed"
    assert resumed.processed_inputs == 8


def test_dependency_health_and_resilience_drills_are_non_destructive(store, tmp_path) -> None:
    context = SimpleNamespace(
        store=store,
        paths=SimpleNamespace(root=tmp_path),
        enterprise_server=None,
        nextgen=SimpleNamespace(workers=SimpleNamespace(list=lambda: [])),
    )
    health = DependencyHealthService(context).snapshot(include_network=False)
    names = {probe.component for probe in health.probes}
    assert {"SQLite", "Disk I/O", "System Memory", "Distributed Runtime", "Confidential Compute", "TPM / HSM Signing"}.issubset(names)

    drills = ResilienceDrillService(context).run_all()
    assert len(drills) == 4
    assert all(result.passed for result in drills)
