from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
from contextlib import contextmanager
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping
from arenyxa import __compat_version__
from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.timebase import PROCESS_CLOCK
from arenyxa.domain.models import Task, new_id, utc_now
from arenyxa.enterprise.governance import EnterpriseGovernanceService
from arenyxa.enterprise.runtime_storage import DistributedRuntimeStorageBackend, storage_backend_for
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.application.runner import RunOrchestrator
from arenyxa.security.zero_trust import ZeroTrustEvaluator, ZeroTrustPolicy
from arenyxa.security.confidential_compute import ConfidentialComputeManager, ConfidentialComputePolicy
from arenyxa.security.worker_identity import ED25519, normalize_algorithm, verify_signature
from arenyxa.enterprise.security_policy_store import persist_signed_zero_trust_policy, load_signed_zero_trust_policy
from arenyxa.observability.trace_context import TraceContext
from arenyxa.observability.otel_bridge import internal_span

LOGGER = logging.getLogger(__name__)

from arenyxa.enterprise.distributed_protocol import (
    DISTRIBUTED_SCHEMA,
    CURRENT_PROTOCOL,
    MIN_COMPATIBLE_PROTOCOL,
    MAX_JOB_PAYLOAD_BYTES,
    MAX_RESULT_BYTES,
    MAX_CHECKPOINT_BYTES,
    MAX_RESOURCE_DECLARATION_BYTES,
    MAX_JOBS,
    MAX_WORKERS,
    MAX_CHALLENGES,
    MAX_WORKER_SESSIONS,
    MAX_WORKER_SLOTS,
    MAX_JOB_EVENTS_PER_JOB,
    MAX_EVENT_DETAILS_BYTES,
    DEFAULT_LEASE_SECONDS,
    MAX_LEASE_SECONDS,
    WORKER_SESSION_TTL_SECONDS,
    CHALLENGE_TTL_SECONDS,
    _JOB_STATES,
    _ALLOWED_JOB_TRANSITIONS,
    _fail,
    _canonical,
    _bounded_json,
    _load_json,
    _clean_token,
    _b64u_decode,
    negotiate_protocol,
    verify_enterprise_server_identity,
    DistributedLease,
    _NoopLock,
)

from arenyxa.enterprise.distributed_queue import DurableDistributedQueue

class EnterpriseServerRuntime:
    





    def __init__(
        self,
        identity: LocalEnterpriseIdentityService,
        governance: EnterpriseGovernanceService,
        data_root: Path,
        *,
        distributed_storage_target: Path | str | None = None,
        confidential_compute: ConfidentialComputeManager | None = None,
    ) -> None:
        self.identity = identity
        self.governance = governance
        target = distributed_storage_target or (Path(data_root) / "enterprise" / "distributed.sqlite")
        self.queue = DurableDistributedQueue(target)
        self._lock = threading.Lock()
        self._challenges: dict[str, dict[str, Any]] = {}
        self._sessions: dict[str, dict[str, Any]] = {}
        self._service_lock = threading.Lock()
        self._service_lease = ""
        self._service_stop = threading.Event()
        self._service_thread = None
        self._service_ttl_seconds = 24 * 60 * 60
        self._network_policy = ZeroTrustPolicy()
        self._network_policy_revision = 0
        self._network_policy_checked_mono = 0.0
        self._network_policy_integrity_error: ArenyxaError | None = None
        self._confidential_compute = confidential_compute or ConfidentialComputeManager()

    def set_network_policy(self, policy: Mapping[str, Any] | ZeroTrustPolicy) -> dict[str, Any]:
        self.identity.require("enterprise.policy.modify", "enterprise:network")
        self.identity.require_recent_step_up()
        normalized = policy if isinstance(policy, ZeroTrustPolicy) else ZeroTrustPolicy.from_mapping(policy)
        artifact = persist_signed_zero_trust_policy(self.queue, self.identity, normalized)
        with self._service_lock:
            self._network_policy = normalized
            self._network_policy_revision = int(artifact["revision"])
            self._network_policy_checked_mono = time.monotonic()
            self._network_policy_integrity_error = None
        return normalized.as_dict()

    def _refresh_network_policy(self, *, force: bool = False) -> None:
        now = time.monotonic()
        with self._service_lock:
            if not force and now - self._network_policy_checked_mono < 2.0:
                return
            self._network_policy_checked_mono = now
        try:
            loaded = load_signed_zero_trust_policy(self.queue, self.identity)
        except ArenyxaError as exc:
            with self._service_lock:
                self._network_policy_integrity_error = exc
            raise
        if loaded is None:
            with self._service_lock:
                self._network_policy_integrity_error = None
            return
        policy, revision = loaded
        with self._service_lock:
            if revision >= self._network_policy_revision:
                self._network_policy = policy
                self._network_policy_revision = revision
            self._network_policy_integrity_error = None

    def network_policy(self) -> ZeroTrustPolicy:
        # The persisted artifact is Root-signed. Any parse/signature failure is
        # sticky and fail-closed; subsequent requests cannot reuse a cached policy
        # until a valid signed artifact is observed again.
        with self._service_lock:
            integrity_error = self._network_policy_integrity_error
        if integrity_error is not None:
            raise integrity_error
        self._refresh_network_policy()
        with self._service_lock:
            if self._network_policy_integrity_error is not None:
                raise self._network_policy_integrity_error
            return self._network_policy

    def set_confidential_compute_policy(self, policy: ConfidentialComputePolicy) -> dict[str, Any]:
        """Apply the fail-closed TEE policy without claiming an enclave is active until attested."""
        self.identity.require("enterprise.policy.modify", "enterprise:confidential-compute")
        self.identity.require_recent_step_up()
        self._confidential_compute.policy = policy
        return {
            "mode": policy.normalized_mode(),
            "operations": list(policy.operations),
            "providers": [item.to_dict() for item in self._confidential_compute.statuses()],
        }

    def confidential_compute_status(self) -> dict[str, Any]:
        policy = self._confidential_compute.policy
        return {
            "mode": policy.normalized_mode(),
            "operations": list(policy.operations),
            "providers": [item.to_dict() for item in self._confidential_compute.statuses()],
        }

    def evaluate_network_context(self, context: Mapping[str, Any] | None) -> None:
        policy = self.network_policy()
        decision = ZeroTrustEvaluator.evaluate(policy, context)
        if not decision.allowed:
            raise _fail(
                decision.code,
                "Enterprise network micro-segmentation policy denied this connection",
                reasons=list(decision.reasons),
                risk_score=decision.risk_score,
            )

    def build_server_identity(self, tls_certificate_der: bytes, *, server_id: str = "", ttl_seconds: int = 24 * 60 * 60) -> dict[str, Any]:
        
        self.identity.require("enterprise.server.manage", "enterprise:server")
        self.identity.require_recent_step_up()
        cert = bytes(tls_certificate_der)
        if not cert or len(cert) > 256 * 1024:
            raise _fail("SERVER_TLS_CERT_INVALID", "Enterprise Server TLS certificate is empty or oversized")
        root = self.identity.root_public_identity()
        now = datetime.now(timezone.utc)
        payload = {
            "schema": "arenyxa.enterprise-server-identity/v1",
            "enterprise_id": str(root["enterprise_id"]),
            "server_id": _clean_token(server_id or new_id("server"), "server id"),
            "tls_certificate_sha256": hashlib.sha256(cert).hexdigest(),
            "protocol_min": MIN_COMPATIBLE_PROTOCOL,
            "protocol_max": CURRENT_PROTOCOL,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=max(300, min(7 * 24 * 60 * 60, int(ttl_seconds))))).isoformat(),
        }
        proof = self.identity.sign_enterprise_artifact(
            _canonical(payload), capability="enterprise.server.manage", resource="enterprise:server", step_up=False,
        )
        return {**payload, "root_public_key": proof["root_public_key"], "root_fingerprint": proof["root_fingerprint"], "signature": proof["signature"]}

    def activate_service(self, ttl_seconds: int = 24 * 60 * 60) -> str:
        
        ttl = max(300, min(24 * 60 * 60, int(ttl_seconds)))
        with self._service_lock:
            if self._service_lease:
                return self._service_lease
            lease = self.identity.issue_service_lease(
                "enterprise-server",
                ("governance", "enrollment", "server"),
                (
                    ("enterprise.server.manage", "enterprise:server"),
                    ("enterprise.worker.manage", "enterprise:workers"),
                    ("enterprise.remote_ops", "enterprise:distributed"),
                ),
                ttl_seconds=ttl,
            )
            self._service_lease = lease
            self._service_ttl_seconds = ttl
            self._service_stop.clear()
            thread = threading.Thread(
                target=self._service_lease_maintenance,
                name="arenyxa-enterprise-server-authority", daemon=True,
            )
            self._service_thread = thread
            thread.start()
            return lease

    def _service_lease_maintenance(self) -> None:
        while not self._service_stop.wait(max(60.0, min(3600.0, self._service_ttl_seconds / 3.0))):
            with self._service_lock:
                token = self._service_lease
                ttl = self._service_ttl_seconds
            if not token:
                return
            try:
                self.identity.renew_service_lease(token, "server", ttl_seconds=ttl)
            except Exception:
                                                                                                
                                                                                                    
                                                                                   
                LOGGER.exception("Enterprise Server service-lease renewal failed")

    def deactivate_service(self, reason: str = "SERVER_STOP") -> None:
        with self._service_lock:
            token = self._service_lease
            thread = self._service_thread
            self._service_lease = ""
            self._service_thread = None
            self._service_stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3.0)
        if token:
            self.identity.revoke_service_lease(token, reason=reason)

    def close(self, reason: str = "SERVER_STOP") -> None:
        """Stop service authority and release the durable queue backend."""
        self.deactivate_service(reason=reason)
        self.queue.close()

    def build_service_server_identity(
        self, tls_certificate_der: bytes, *, server_id: str, ttl_seconds: int = 6 * 60 * 60,
    ) -> dict[str, Any]:
        
        with self._service_lock:
            lease = self._service_lease
        if not lease:
            raise _fail("SERVER_SERVICE_INACTIVE", "Enterprise Server service authority is not active")
        cert = bytes(tls_certificate_der)
        if not cert or len(cert) > 256 * 1024:
            raise _fail("SERVER_TLS_CERT_INVALID", "Enterprise Server TLS certificate is empty or oversized")
        now = datetime.now(timezone.utc)
        payload = {
            "schema": "arenyxa.enterprise-server-identity/v1",
            "enterprise_id": "",
            "server_id": _clean_token(server_id, "server id"),
            "tls_certificate_sha256": hashlib.sha256(cert).hexdigest(),
            "protocol_min": MIN_COMPATIBLE_PROTOCOL,
            "protocol_max": CURRENT_PROTOCOL,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=max(300, min(7 * 24 * 60 * 60, int(ttl_seconds))))).isoformat(),
        }
                                                                                                    
                                                                  
        root = self.identity.root_public_identity()
        payload["enterprise_id"] = str(root["enterprise_id"])
        proof = self.identity.service_sign_enterprise_artifact(lease, "server", _canonical(payload))
        return {**payload, "root_public_key": proof["root_public_key"], "root_fingerprint": proof["root_fingerprint"], "signature": proof["signature"]}

    def register_worker(
        self, worker_id: str, public_key: str, resources: Mapping[str, Any], *, display_name: str = "",
        protocol_min: int = MIN_COMPATIBLE_PROTOCOL, protocol_max: int = CURRENT_PROTOCOL,
        app_compat_version: str = __compat_version__, max_slots: int = 1,
        identity_algorithm: str = ED25519, identity_metadata: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.identity.require("enterprise.worker.manage", "enterprise:workers")
        self.identity.require_recent_step_up()                                                                                  
        return self.queue.register_worker(
            worker_id, public_key, resources, display_name=display_name, protocol_min=protocol_min,
            protocol_max=protocol_max, app_compat_version=app_compat_version, max_slots=max_slots,
            identity_algorithm=identity_algorithm, identity_metadata=identity_metadata, enforce_capacity=True,
        )

    def submit_task(
        self,
        task: Task,
        *,
        resource_id: str,
        permission: str,
        idempotency_key: str,
        approval_id: str = "",
        quota_metric: str = "",
        quota_amount: int = 0,
        side_effect_mode: str = "idempotent",
        max_attempts: int = 3,
        priority: int = 0,
        traceparent: str = "",
        tracestate: str = "",
    ) -> str:
        errors = task.validate()
        if errors:
            raise _fail("DISTRIBUTED_TASK_INVALID", "; ".join(errors[:8]))
        idem = _clean_token(idempotency_key, "idempotency key", 192)
        existing = self.queue.job_for_idempotency(idem)
        payload = {"task": task.to_dict(), "task_snapshot_sha256": task.snapshot_hash()}
        payload_json, payload_sha = _bounded_json(payload, MAX_JOB_PAYLOAD_BYTES, "job payload")
        if existing is not None:
            if (
                existing["kind"] != "task.run"
                or existing["resource_id"] != resource_id
                or existing["permission"] != permission
                or existing["side_effect_mode"] != str(side_effect_mode).strip().casefold()
            ):
                raise _fail("DISTRIBUTED_IDEMPOTENCY_COLLISION", "Idempotency key is already bound to another operation")
            if not hmac.compare_digest(str(existing["payload_sha256"]), payload_sha):
                raise _fail("DISTRIBUTED_IDEMPOTENCY_COLLISION", "Idempotency key payload does not match the original job")
            return str(existing["job_id"])
        decision = self.governance.authorize_operation(
            permission, resource_id, approval_id=approval_id, quota_metric=quota_metric, quota_amount=quota_amount,
        )
        try:
            return self.queue.enqueue(
                "task.run", json.loads(payload_json), resource_id=resource_id, permission=permission,
                idempotency_key=idem, side_effect_mode=side_effect_mode, max_attempts=max_attempts,
                priority=priority, protocol_version=CURRENT_PROTOCOL, traceparent=traceparent, tracestate=tracestate,
            )
        except (ArenyxaError, OSError, sqlite3.Error, ValueError, TypeError, RuntimeError):
            reserved = int(decision.get("quota_reserved", 0))
            if quota_metric and quota_amount > 0 and reserved:
                try:
                    self.governance.release_for_operation(resource_id, permission, quota_metric, quota_amount)
                except (ArenyxaError, OSError, sqlite3.Error, ValueError, TypeError, RuntimeError):
                    LOGGER.exception("Enterprise distributed enqueue failed and quota compensation also failed")
            raise

    def create_worker_challenge(self, worker_id: str) -> dict[str, Any]:
        worker = self.queue.worker(worker_id)
        if worker is None:
            raise _fail("WORKER_UNKNOWN", "Worker is not registered")
        if worker["state"] == "revoked":
            raise _fail("WORKER_REVOKED", "Worker is revoked")
        challenge_id = new_id("worker-challenge")
        nonce = secrets.token_bytes(32)
        expires = PROCESS_CLOCK.stable_epoch() + CHALLENGE_TTL_SECONDS
        with self._lock:
            self._cleanup_auth_locked()
            if len(self._challenges) >= MAX_CHALLENGES:
                oldest = min(self._challenges.items(), key=lambda item: float(item[1]["created_at"]))[0]
                self._challenges.pop(oldest, None)
            identity_algorithm = normalize_algorithm(str(worker.get("identity_algorithm", ED25519)))
            schema = "arenyxa.enterprise-worker-challenge/v1" if identity_algorithm == ED25519 else "arenyxa.enterprise-worker-challenge/v2"
            self._challenges[challenge_id] = {
                "worker_id": str(worker_id), "nonce": nonce, "expires_at": expires, "created_at": PROCESS_CLOCK.stable_epoch(),
                "protocol": int(worker["negotiated_protocol"]), "identity_algorithm": identity_algorithm, "schema": schema,
            }
        challenge = {
            "schema": schema,
            "challenge_id": challenge_id,
            "worker_id": str(worker_id),
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("="),
            "expires_at": expires,
            "protocol": int(worker["negotiated_protocol"]),
        }
        if schema.endswith("/v2"):
            challenge["identity_algorithm"] = identity_algorithm
        return challenge

    @staticmethod
    def _challenge_message(challenge: Mapping[str, Any]) -> bytes:
        schema = str(challenge.get("schema", ""))
        payload = {
            "schema": schema,
            "challenge_id": str(challenge["challenge_id"]),
            "worker_id": str(challenge["worker_id"]),
            "nonce": str(challenge["nonce"]),
            "expires_at": float(challenge["expires_at"]),
            "protocol": int(challenge["protocol"]),
        }
        if schema == "arenyxa.enterprise-worker-challenge/v2":
            payload["identity_algorithm"] = normalize_algorithm(str(challenge.get("identity_algorithm", "")))
        return _canonical(payload)

    def authenticate_worker(
        self, challenge: Mapping[str, Any], signature_b64: str, *, access_context: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        challenge_id = str(challenge.get("challenge_id", ""))
        with self._lock:
            self._cleanup_auth_locked()
            state = self._challenges.pop(challenge_id, None)
        if state is None:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge is missing, expired, or already consumed")
        if float(state["expires_at"]) <= PROCESS_CLOCK.stable_epoch() or str(state["worker_id"]) != str(challenge.get("worker_id", "")):
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge binding is invalid")
        expected_schema = str(state.get("schema", "arenyxa.enterprise-worker-challenge/v1"))
        if str(challenge.get("schema", "")) != expected_schema:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge schema is invalid")
        expected_algorithm = normalize_algorithm(str(state.get("identity_algorithm", ED25519)))
        if expected_schema.endswith("/v2") and normalize_algorithm(str(challenge.get("identity_algorithm", ""))) != expected_algorithm:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge identity algorithm binding does not match")
        expected_nonce = base64.urlsafe_b64encode(bytes(state["nonce"])).decode("ascii").rstrip("=")
        if not hmac.compare_digest(expected_nonce, str(challenge.get("nonce", ""))):
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge nonce does not match")
        if int(challenge.get("protocol", -1)) != int(state["protocol"]):
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge protocol binding does not match")
        try:
            presented_expiry = float(challenge.get("expires_at", 0.0))
        except (TypeError, ValueError) as exc:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge expiry is invalid") from exc
        if abs(presented_expiry - float(state["expires_at"])) > 1e-6:
            raise _fail("WORKER_CHALLENGE_INVALID", "Worker challenge expiry binding does not match")
        worker = self.queue.worker(str(state["worker_id"]))
        if worker is None or worker["state"] == "revoked":
            raise _fail("WORKER_REVOKED", "Worker identity is unavailable")
        context = dict(access_context or {})
        context.setdefault("worker_id", str(worker["worker_id"]))
        context.setdefault("permissions", tuple(str(item) for item in dict(worker.get("resources") or {}).get("permissions", ()) if str(item)))
        context.setdefault("via_server_relay", True)
        context.setdefault("peer_to_peer", False)
        self.evaluate_network_context(context)
        algorithm = normalize_algorithm(str(worker.get("identity_algorithm", expected_algorithm)))
        if algorithm != expected_algorithm:
            raise _fail("WORKER_IDENTITY_MISMATCH", "Registered Worker identity algorithm changed during authentication")
        message = self._challenge_message(challenge)

        def verify_in_process(_payload: bytes) -> bytes:
            verify_signature(algorithm, str(worker["public_key"]), str(signature_b64), message)
            return b"verified"

        verification_payload = _canonical({
            "schema": "arenyxa.confidential-operation/worker-verify/v2",
            "identity_algorithm": algorithm,
            "public_key": str(worker["public_key"]),
            "signature": str(signature_b64),
            "challenge": dict(challenge),
        })
        verdict = self._confidential_compute.execute(
            "enterprise.worker.verify", verification_payload, fallback=verify_in_process
        )
        if not hmac.compare_digest(bytes(verdict), b"verified"):
            raise _fail("WORKER_PROOF_INVALID", "Confidential worker verification returned an invalid verdict")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        created_at = PROCESS_CLOCK.stable_epoch()
        expires_at = created_at + WORKER_SESSION_TTL_SECONDS
        with self._lock:
            self._cleanup_auth_locked()
            if len(self._sessions) >= MAX_WORKER_SESSIONS:
                oldest = min(self._sessions.items(), key=lambda item: float(item[1]["created_at"]))[0]
                self._sessions.pop(oldest, None)
            self._sessions[digest] = {
                "worker_id": str(worker["worker_id"]), "protocol": int(worker["negotiated_protocol"]),
                "created_at": created_at, "expires_at": expires_at,
            }
        return {
            "schema": "arenyxa.enterprise-worker-session/v1", "session_token": token,
            "worker_id": str(worker["worker_id"]), "protocol": int(worker["negotiated_protocol"]),
            "expires_at": expires_at,
        }

    def _cleanup_auth_locked(self) -> None:
        now = PROCESS_CLOCK.stable_epoch()
        self._challenges = {key: value for key, value in self._challenges.items() if float(value["expires_at"]) > now}
        self._sessions = {key: value for key, value in self._sessions.items() if float(value["expires_at"]) > now}

    def _worker_session(self, token: str) -> dict[str, Any]:
        digest = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
        with self._lock:
            self._cleanup_auth_locked()
            session = self._sessions.get(digest)
            if session is None:
                raise _fail("WORKER_SESSION_INVALID", "Worker session is invalid or expired")
            return dict(session)

    def authorize_worker_session_context(self, token: str, context: Mapping[str, Any] | None) -> None:
        session = self._worker_session(token)
        worker = self.queue.worker(str(session["worker_id"]))
        if worker is None or str(worker.get("state", "")) == "revoked":
            raise _fail("WORKER_REVOKED", "Worker identity is unavailable")
        actual = dict(context or {})
        actual.setdefault("worker_id", str(worker["worker_id"]))
        actual.setdefault("permissions", tuple(str(item) for item in dict(worker.get("resources") or {}).get("permissions", ()) if str(item)))
        actual.setdefault("via_server_relay", True)
        actual.setdefault("peer_to_peer", False)
        self.evaluate_network_context(actual)

    def lease(self, session_token: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> DistributedLease | None:
        session = self._worker_session(session_token)
        return self.queue.lease_next(str(session["worker_id"]), lease_seconds=lease_seconds)

    def lease_batch(
        self, session_token: str, *, max_items: int = 8, lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> list[DistributedLease]:
        session = self._worker_session(session_token)
        return self.queue.lease_many(
            str(session["worker_id"]), max_items=max_items, lease_seconds=lease_seconds,
        )

    def heartbeat_worker(self, session_token: str, resources: Mapping[str, Any] | None = None) -> None:
        session = self._worker_session(session_token)
        self.queue.heartbeat(str(session["worker_id"]), resources=resources)

    def handover_worker_lease(
        self, session_token: str, job_id: str, lease_token: str, reason: str = "WORKER_HANDOVER"
    ) -> str:
        session = self._worker_session(session_token)
        return self.queue.handover_lease(job_id, str(session["worker_id"]), lease_token, reason=reason)

    def checkpoint_worker(self, session_token: str, job_id: str, lease_token: str, checkpoint: Mapping[str, Any]) -> int:
        session = self._worker_session(session_token)
        return self.queue.checkpoint(job_id, str(session["worker_id"]), lease_token, checkpoint)

    def start_worker_job(self, session_token: str, job_id: str, lease_token: str) -> None:
        session = self._worker_session(session_token)
        self.queue.start_job(job_id, str(session["worker_id"]), lease_token)

    def renew_worker_lease(self, session_token: str, job_id: str, lease_token: str, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> float:
        session = self._worker_session(session_token)
        return self.queue.renew_lease(job_id, str(session["worker_id"]), lease_token, lease_seconds=lease_seconds)

    def mark_worker_side_effect_started(self, session_token: str, job_id: str, lease_token: str) -> None:
        session = self._worker_session(session_token)
        self.queue.mark_side_effect_started(job_id, str(session["worker_id"]), lease_token)

    def complete_worker_job(self, session_token: str, job_id: str, lease_token: str, result: Mapping[str, Any]) -> None:
        session = self._worker_session(session_token)
        self.queue.complete(job_id, str(session["worker_id"]), lease_token, result)

    def fail_worker_job(self, session_token: str, job_id: str, lease_token: str, error_code: str, retryable: bool = True) -> str:
        session = self._worker_session(session_token)
        return self.queue.fail(job_id, str(session["worker_id"]), lease_token, error_code, retryable=retryable)

    def set_worker_drain(self, worker_id: str, drain: bool = True) -> None:
        self.identity.require("enterprise.worker.manage", "enterprise:workers")
        self.queue.set_worker_drain(worker_id, drain)

    def revoke_worker(self, worker_id: str) -> int:
        self.identity.require("enterprise.worker.manage", "enterprise:workers")
        self.identity.require_recent_step_up()
        return self.queue.revoke_worker(worker_id)

    def retry_review_required(self, job_id: str) -> None:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        self.identity.require_recent_step_up()
        self.queue.retry_review_required(job_id)

    def remote_ops_snapshot(self) -> dict[str, Any]:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        return {
            "queue": self.queue.health(),
            "workers": self.queue.list_workers(limit=1000),
            "jobs": self.queue.list_jobs(limit=1000),
        }

NETWORK_PARTITION_LEASE_GRACE_SECONDS = 5.0

def _lease_execution_callbacks(
    queue: DurableDistributedQueue,
    lease: DistributedLease,
    worker_id: str,
    stop_keepalive: threading.Event,
    lease_lost: threading.Event,
    handle_ref: list[Any],
) -> tuple[Any, Any]:
    expiry_lock = threading.Lock()
    confirmed_deadline_mono = [time.monotonic() + DEFAULT_LEASE_SECONDS + NETWORK_PARTITION_LEASE_GRACE_SECONDS]

    def cancel_for_lease_loss() -> None:
        lease_lost.set()
        if handle_ref:
            try:
                handle_ref[0].cancel()
            except (RuntimeError, OSError, ValueError):
                LOGGER.exception("Distributed lease was lost and local Run cancellation failed")

    def keepalive() -> None:
        wait_for = 0.0
        while not stop_keepalive.wait(wait_for):
            try:
                queue.renew_lease(lease.job_id, worker_id, lease.lease_token)
                with expiry_lock:
                    confirmed_deadline_mono[0] = time.monotonic() + DEFAULT_LEASE_SECONDS + NETWORK_PARTITION_LEASE_GRACE_SECONDS
                wait_for = max(2.0, min(20.0, DEFAULT_LEASE_SECONDS / 3.0))
                continue
            except ArenyxaError as exc:
                if exc.code in {"DISTRIBUTED_LEASE_STALE", "DISTRIBUTED_LEASE_EXPIRED"}:
                    cancel_for_lease_loss()
                    return
                LOGGER.warning("Distributed lease keepalive failed: %s", exc)
            except (OSError, TimeoutError, sqlite3.Error) as exc:
                text = str(exc)
                if "DISTRIBUTED_LEASE_STALE" in text or "DISTRIBUTED_LEASE_EXPIRED" in text:
                    cancel_for_lease_loss()
                    return
                LOGGER.warning("Distributed lease keepalive transport failure: %s", exc)
            with expiry_lock:
                expired = time.monotonic() >= confirmed_deadline_mono[0]
            if expired:
                cancel_for_lease_loss()
                return
            wait_for = 2.0

    def progress(run: Any) -> None:
        if lease_lost.is_set():
            return
        try:
            queue.checkpoint(lease.job_id, worker_id, lease.lease_token, {
                "run_id": str(run.id), "stage": str(run.stage), "completed_units": int(run.completed_units),
                "total_units": run.total_units, "status": str(run.status.value),
            })
        except ArenyxaError as exc:
            if exc.code in {"DISTRIBUTED_LEASE_STALE", "DISTRIBUTED_LEASE_EXPIRED"}:
                cancel_for_lease_loss()
                return
            raise

    return keepalive, progress


class EnterpriseWorkerRuntime:
    

    def __init__(
        self, runner: RunOrchestrator, worker_id: str, *,
        job_handlers: Mapping[str, Any] | None = None,
    ) -> None:
        self.runner = runner
        self.worker_id = _clean_token(worker_id, "worker id")
        self._job_handlers: dict[str, Any] = {}
        for kind, handler in dict(job_handlers or {}).items():
            self.register_job_handler(str(kind), handler)

    def register_job_handler(self, kind: str, handler: Any) -> None:
        """Register an explicit non-task distributed job handler.

        Handlers own their job-kind lifecycle (start/checkpoint/complete/fail) and
        receive ``(queue, lease)``.  The default ``task.run`` path remains unchanged.
        """
        kind_id = _clean_token(kind, "job kind")
        if kind_id == "task.run":
            raise ValueError("task.run is reserved for the built-in RunOrchestrator path")
        if not callable(handler):
            raise TypeError("distributed job handler must be callable")
        self._job_handlers[kind_id] = handler

    @staticmethod
    def task_from_payload(payload: Mapping[str, Any]) -> Task:
        raw = payload.get("task")
        if not isinstance(raw, dict):
            raise _fail("DISTRIBUTED_TASK_INVALID", "Distributed task payload is missing")
                                                                                               
                                                        
        from arenyxa.infrastructure.database import SQLiteStore
        task = SQLiteStore._task_from_dict(dict(raw))
        expected = str(payload.get("task_snapshot_sha256", ""))
        if not expected or not hmac.compare_digest(expected, task.snapshot_hash()):
            raise _fail("DISTRIBUTED_TASK_INTEGRITY", "Distributed task snapshot hash does not match")
        return task

    def execute_lease(self, queue: DurableDistributedQueue, lease: DistributedLease) -> dict[str, Any]:
        parent = TraceContext.parse(lease.traceparent, tracestate=lease.tracestate)
        attributes = {
            "arenyxa.job_id": lease.job_id,
            "arenyxa.worker_id": self.worker_id,
            "arenyxa.job_kind": lease.kind,
            "arenyxa.resource_id": lease.resource_id,
            "arenyxa.attempt": lease.attempt,
        }
        with internal_span("arenyxa.distributed.job.execute", parent, attributes):
            return self._execute_lease_inner(queue, lease)

    def _execute_lease_inner(self, queue: DurableDistributedQueue, lease: DistributedLease) -> dict[str, Any]:
        if lease.worker_id != self.worker_id:
            raise _fail("DISTRIBUTED_LEASE_STALE", "Lease belongs to another worker")
        if lease.kind != "task.run":
            handler = self._job_handlers.get(lease.kind)
            if handler is None:
                raise _fail("DISTRIBUTED_JOB_KIND_UNSUPPORTED", "Worker cannot execute this distributed job kind")
            value = handler(queue, lease)
            if not isinstance(value, Mapping):
                raise _fail("DISTRIBUTED_JOB_RESULT_INVALID", "Distributed job handler must return a mapping result")
            return dict(value)
        task = self.task_from_payload(lease.payload)
                                                                                              
                                                                                               
                                                                                              
                                                                             
        try:
            self.runner.store.save_task(task)
        except (ArenyxaError, OSError, sqlite3.Error, ValueError) as exc:
            try:
                queue.fail(lease.job_id, self.worker_id, lease.lease_token, "WORKER_TASK_PERSIST_FAILED", retryable=True)
            except ArenyxaError:
                LOGGER.exception("Worker Task snapshot persistence failed and distributed lease failure could not be recorded")
            raise _fail("WORKER_TASK_PERSIST_FAILED", "Worker could not persist the distributed Task snapshot") from exc
        queue.start_job(lease.job_id, self.worker_id, lease.lease_token)
        if lease.side_effect_mode == "non_idempotent":
                                                                                                   
                                                                                                 
            queue.mark_side_effect_started(lease.job_id, self.worker_id, lease.lease_token)

        stop_keepalive = threading.Event()
        lease_lost = threading.Event()
        handle_ref: list[Any] = []
        keepalive, progress = _lease_execution_callbacks(
            queue, lease, self.worker_id, stop_keepalive, lease_lost, handle_ref,
        )

        handle = None
        keepalive_thread = threading.Thread(
            target=keepalive, name=f"arenyxa-lease-keepalive-{lease.job_id[-16:]}", daemon=True,
        )
        try:
            handle = self.runner.submit(task, on_progress=progress)
            handle_ref.append(handle)
            keepalive_thread.start()
            run = handle.future.result()
            if lease_lost.is_set():
                raise _fail("DISTRIBUTED_LEASE_LOST", "Distributed lease was lost while the local Run was executing")
            result = {
                "run_id": run.id, "status": run.status.value, "stage": run.stage,
                "success_count": run.success_count, "failure_count": run.failure_count,
                "result_count": run.result_count, "error_code": run.error_code or "",
            }
            if run.status.value == "completed":
                queue.complete(lease.job_id, self.worker_id, lease.lease_token, result)
                return result
            state = queue.fail(
                lease.job_id, self.worker_id, lease.lease_token,
                run.error_code or "RUN_FAILED", retryable=lease.side_effect_mode == "idempotent",
            )
            result["distributed_state"] = state
            return result
        except ArenyxaError:
            raise
        except Exception as exc:
            if lease_lost.is_set():
                raise _fail("DISTRIBUTED_LEASE_LOST", "Distributed lease was lost while the local Run was executing") from exc
            try:
                queue.fail(
                    lease.job_id, self.worker_id, lease.lease_token,
                    "WORKER_EXECUTION_EXCEPTION", retryable=lease.side_effect_mode == "idempotent",
                )
            except ArenyxaError:
                LOGGER.exception("Distributed worker execution failed and job failure persistence also failed")
            raise _fail("WORKER_EXECUTION_EXCEPTION", "Distributed worker execution failed") from exc
        finally:
            stop_keepalive.set()
            if keepalive_thread.is_alive():
                keepalive_thread.join(timeout=3.0)
