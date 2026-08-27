from __future__ import annotations

from arenyxa.infrastructure.process_safety import validated_argv
import base64
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.enterprise.distributed import DurableDistributedQueue

PRODUCTION_VALIDATION_SCHEMA = "arenyxa.production-validation/v1"
MULTI_NODE_EVIDENCE_SCHEMA = "arenyxa.production-multinode-evidence/v1"
REQUIRED_EXTERNAL_SCENARIOS = (
    "server_process_crash",
    "worker_process_crash",
    "network_partition",
    "duplicate_delivery",
    "delayed_delivery",
    "disk_pressure",
    "clock_discontinuity",
    "tls_identity_rotation",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _worker_public_key() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class ProductionValidationItem:
    name: str
    status: str
    duration_ms: float
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 2),
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ProductionValidationReport:
    started_at: str
    duration_seconds: float
    local_items: List[ProductionValidationItem]
    external_evidence: Dict[str, Any]

    @property
    def local_gate_passed(self) -> bool:
        return bool(self.local_items) and all(item.status == "passed" for item in self.local_items)

    @property
    def production_evidence_complete(self) -> bool:
        return bool(self.external_evidence.get("valid", False))

    @property
    def production_ready(self) -> bool:
        return self.local_gate_passed and self.production_evidence_complete

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": PRODUCTION_VALIDATION_SCHEMA,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "local_gate_passed": self.local_gate_passed,
            "production_evidence_complete": self.production_evidence_complete,
            "production_ready": self.production_ready,
            "local_items": [item.to_dict() for item in self.local_items],
            "external_evidence": dict(self.external_evidence),
        }


class ProductionValidationSuite:
    







    def __init__(self, soak_jobs: int = 256) -> None:
        self.soak_jobs = max(32, min(int(soak_jobs), 10000))

    def run(self, evidence_path: Optional[Path] = None, progress: Optional[Callable[[str], None]] = None) -> ProductionValidationReport:
        started = time.monotonic()
        started_at = _utc_now()
        cases = (
            ("hard-crash-idempotent-recovery", self._hard_crash_idempotent_recovery),
            ("hard-crash-non-idempotent-fence", self._hard_crash_non_idempotent_fence),
            ("lost-terminal-response-replay", self._lost_terminal_response_replay),
            ("concurrent-lease-exclusivity", self._concurrent_lease_exclusivity),
            ("checkpoint-restart-durability", self._checkpoint_restart_durability),
            ("clock-corruption-fail-closed", self._clock_corruption_fail_closed),
            ("bounded-soak-consistency", self._bounded_soak_consistency),
        )
        items: List[ProductionValidationItem] = []
        with tempfile.TemporaryDirectory(prefix="arenyxa-production-validation-") as raw:
            root = Path(raw)
            for index, (name, case) in enumerate(cases, start=1):
                if progress:
                    progress("[%d/%d] %s" % (index, len(cases), name))
                began = time.perf_counter()
                try:
                    detail = case(root / name)
                except Exception as exc:                                                      
                    items.append(ProductionValidationItem(name, "failed", (time.perf_counter() - began) * 1000.0, "%s: %s" % (type(exc).__name__, exc)))
                else:
                    items.append(ProductionValidationItem(name, "passed", (time.perf_counter() - began) * 1000.0, detail))
        evidence = validate_multi_node_evidence(evidence_path) if evidence_path else {
            "provided": False,
            "valid": False,
            "status": "not_provided",
            "detail": "Local chaos gate passed independently; true Server + 2 Worker evidence is still required.",
            "required_scenarios": list(REQUIRED_EXTERNAL_SCENARIOS),
        }
        return ProductionValidationReport(started_at, time.monotonic() - started, items, evidence)

    @staticmethod
    def _run_crash_child(root: Path, non_idempotent: bool) -> Dict[str, Any]:
        root.mkdir(parents=True, exist_ok=True)
        state_path = root / "child-state.json"
        db_path = root / "distributed.sqlite"
        child = r'''
import base64, json, os, sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from arenyxa.enterprise.distributed import DurableDistributedQueue
root = Path(sys.argv[1]); mode = sys.argv[2]
q = DurableDistributedQueue(root / "distributed.sqlite")
private = Ed25519PrivateKey.generate()
raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
public = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
worker = "crash-worker"
q.register_worker(worker, public, {"slots": 1}, max_slots=1)
job = q.enqueue("task.run", {"task": {"name": "crash-proof"}}, resource_id="production-validation", permission="workflow.execute", idempotency_key="crash-" + mode, side_effect_mode=("non_idempotent" if mode == "non" else "idempotent"))
lease = q.lease_next(worker, lease_seconds=1)
if lease is None: raise RuntimeError("lease missing")
q.start_job(job, worker, lease.lease_token)
if mode == "non": q.mark_side_effect_started(job, worker, lease.lease_token)
(root / "child-state.json").write_text(json.dumps({"job_id": job, "lease_expires_at": lease.lease_expires_at}), encoding="utf-8")
os._exit(91)
'''
        env = dict(os.environ)
        source_root = str(Path(__file__).resolve().parents[2])
        env["PYTHONPATH"] = source_root + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            validated_argv([sys.executable, "-c", child, str(root), "non" if non_idempotent else "idem"]),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if proc.returncode != 91:
            raise RuntimeError("crash child did not terminate at the injected hard-crash point: rc=%s stderr=%s" % (proc.returncode, proc.stderr.decode("utf-8", "replace")[-1000:]))
        state = json.loads(state_path.read_text(encoding="utf-8"))
        reopened = DurableDistributedQueue(db_path)
                                                                                             
                                                                                                  
        reopened.recover_expired_leases(now=float(state["lease_expires_at"]) + 1.0)
        result = reopened.job(str(state["job_id"]))
        if result is None:
            raise RuntimeError("job disappeared after crash/restart")
        return result

    def _hard_crash_idempotent_recovery(self, root: Path) -> str:
        state = self._run_crash_child(root, False)
        if state["state"] != "queued" or state["error_code"] != "LEASE_EXPIRED_REQUEUED":
            raise RuntimeError("idempotent crash did not requeue safely: %r" % state)
        return "os._exit hard crash recovered expired idempotent work to queued state"

    def _hard_crash_non_idempotent_fence(self, root: Path) -> str:
        state = self._run_crash_child(root, True)
        if state["state"] != "review_required" or state["error_code"] != "LEASE_LOST_AFTER_SIDE_EFFECT_START":
            raise RuntimeError("non-idempotent crash was not fenced: %r" % state)
        return "side-effect-started work was fenced to review_required after hard crash"

    @staticmethod
    def _leased_queue(root: Path, worker: str = "worker-a", side_effect_mode: str = "idempotent"):
        root.mkdir(parents=True, exist_ok=True)
        queue = DurableDistributedQueue(root / "distributed.sqlite")
        queue.register_worker(worker, _worker_public_key(), {"slots": 1}, max_slots=1)
        job = queue.enqueue("task.run", {"task": {"name": "production-validation"}}, resource_id="production-validation", permission="workflow.execute", idempotency_key="job-" + root.name, side_effect_mode=side_effect_mode)
        lease = queue.lease_next(worker)
        if lease is None:
            raise RuntimeError("lease missing")
        queue.start_job(job, worker, lease.lease_token)
        return queue, job, lease

    def _lost_terminal_response_replay(self, root: Path) -> str:
        queue, job, lease = self._leased_queue(root)
        result = {"status": "completed", "receipt": "same-result"}
        queue.complete(job, "worker-a", lease.lease_token, result)
        queue.complete(job, "worker-a", lease.lease_token, result)
        events = queue.job_events(job)
        if sum(1 for item in events if item["event_type"] == "completed") != 1:
            raise RuntimeError("terminal replay duplicated completion event")
        try:
            queue.complete(job, "worker-a", lease.lease_token, {"status": "completed", "receipt": "changed"})
        except Exception as exc:
            if getattr(exc, "code", "") != "DISTRIBUTED_TERMINAL_CONFLICT":
                raise
        else:
            raise RuntimeError("conflicting terminal replay was accepted")
        return "exact terminal ACK replay is idempotent; conflicting replay fails closed"

    def _concurrent_lease_exclusivity(self, root: Path) -> str:
        root.mkdir(parents=True, exist_ok=True)
        queue = DurableDistributedQueue(root / "distributed.sqlite")
        workers = ("worker-a", "worker-b")
        for worker in workers:
            queue.register_worker(worker, _worker_public_key(), {"slots": 1}, max_slots=1)
        job = queue.enqueue("task.run", {"task": {"name": "lease-race"}}, resource_id="production-validation", permission="workflow.execute", idempotency_key="lease-race", side_effect_mode="idempotent")
        barrier = threading.Barrier(2)
        leased: List[Any] = []
        errors: List[BaseException] = []

        def contender(worker: str) -> None:
            try:
                barrier.wait(timeout=5)
                lease = queue.lease_next(worker)
                if lease is not None:
                    leased.append(lease)
            except BaseException as exc:                          
                errors.append(exc)

        threads = [threading.Thread(target=contender, args=(worker,)) for worker in workers]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        if errors:
            raise RuntimeError("lease race error: %r" % errors[0])
        if len(leased) != 1 or leased[0].job_id != job:
            raise RuntimeError("expected exactly one lease winner, got %d" % len(leased))
        return "two simultaneous Workers produced exactly one durable lease winner"

    def _checkpoint_restart_durability(self, root: Path) -> str:
        queue, job, lease = self._leased_queue(root)
        seq = queue.checkpoint(job, "worker-a", lease.lease_token, {"offset": 73, "digest": "checkpoint-proof"})
        reopened = DurableDistributedQueue(root / "distributed.sqlite")
        state = reopened.job(job)
        if state is None or state["checkpoint"] != {"offset": 73, "digest": "checkpoint-proof"} or state["checkpoint_seq"] != seq:
            raise RuntimeError("checkpoint did not survive restart: %r" % state)
        return "checkpoint payload and sequence survived queue reconstruction"

    def _clock_corruption_fail_closed(self, root: Path) -> str:
        queue, job, lease = self._leased_queue(root, side_effect_mode="non_idempotent")
        queue.mark_side_effect_started(job, "worker-a", lease.lease_token)
        db = root / "distributed.sqlite"
        with sqlite3.connect(str(db)) as connection:
            connection.execute("UPDATE distributed_jobs SET lease_expires_at=lease_expires_at+864000 WHERE job_id=?", (job,))
            connection.commit()
        reopened = DurableDistributedQueue(db)
        state = reopened.job(job)
        if state is None or state["state"] != "review_required" or state["error_code"] != "LEASE_STATE_LOST_AFTER_SIDE_EFFECT_START":
            raise RuntimeError("implausible future lease did not fail closed: %r" % state)
        return "impossible future lease was treated as state/clock corruption and fenced"

    def _bounded_soak_consistency(self, root: Path) -> str:
        root.mkdir(parents=True, exist_ok=True)
        queue = DurableDistributedQueue(root / "distributed.sqlite")
        workers = tuple("soak-worker-%d" % index for index in range(4))
        for worker in workers:
            queue.register_worker(worker, _worker_public_key(), {"slots": 1}, max_slots=1)
        job_ids = []
        for index in range(self.soak_jobs):
            job_ids.append(queue.enqueue("task.run", {"task": {"index": index}}, resource_id="production-validation", permission="workflow.execute", idempotency_key="soak-%d" % index, side_effect_mode="idempotent"))
        completed = 0
        cursor = 0
        while completed < self.soak_jobs:
            worker = workers[cursor % len(workers)]
            cursor += 1
            lease = queue.lease_next(worker)
            if lease is None:
                if cursor > self.soak_jobs * 8:
                    raise RuntimeError("soak queue stopped yielding leases")
                continue
            queue.start_job(lease.job_id, worker, lease.lease_token)
            if completed % 7 == 0:
                queue.checkpoint(lease.job_id, worker, lease.lease_token, {"completed_before": completed})
            result = {"status": "completed", "index": completed}
            queue.complete(lease.job_id, worker, lease.lease_token, result)
            if completed % 11 == 0:
                queue.complete(lease.job_id, worker, lease.lease_token, result)
            completed += 1
        reopened = DurableDistributedQueue(root / "distributed.sqlite")
        health = reopened.health()
        states = [reopened.job(job_id)["state"] for job_id in job_ids]
        if any(state != "completed" for state in states):
            raise RuntimeError("soak left non-terminal jobs")
        invariants = health.get("state_invariants", {})
        if int(invariants.get("inconsistent_lease_rows", 0)) != 0 or int(invariants.get("unreceipted_completed_jobs", 0)) != 0:
            raise RuntimeError("state invariants failed after soak: %r" % invariants)
        return "%d jobs completed across 4 Workers; restart health/invariants remained clean" % self.soak_jobs


def validate_multi_node_evidence(path: Path) -> Dict[str, Any]:
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("evidence file exceeds 2 MiB")
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        return {"provided": True, "valid": False, "status": "invalid", "detail": "%s: %s" % (type(exc).__name__, exc)}
    if not isinstance(payload, dict) or payload.get("schema") != MULTI_NODE_EVIDENCE_SCHEMA:
        return {"provided": True, "valid": False, "status": "invalid_schema", "detail": "multi-node evidence schema is invalid"}
    nodes = payload.get("nodes")
    scenarios = payload.get("scenarios")
    soak = payload.get("soak")
    if not isinstance(nodes, list) or len(nodes) < 3:
        return {"provided": True, "valid": False, "status": "insufficient_nodes", "detail": "at least 3 independent nodes are required (1 Server + 2 Workers)"}
    roles = [str(node.get("role", "")) for node in nodes if isinstance(node, dict)]
    hosts = [str(node.get("host_id", "")) for node in nodes if isinstance(node, dict)]
    if roles.count("server") < 1 or roles.count("worker") < 2 or len(set(host for host in hosts if host)) < 3:
        return {"provided": True, "valid": False, "status": "insufficient_topology", "detail": "evidence must identify one Server and two Workers on three distinct hosts"}
    if not isinstance(scenarios, dict):
        return {"provided": True, "valid": False, "status": "missing_scenarios", "detail": "scenario results are missing"}
    failed = [name for name in REQUIRED_EXTERNAL_SCENARIOS if scenarios.get(name) != "passed"]
    if failed:
        return {"provided": True, "valid": False, "status": "scenario_failure", "detail": "required scenarios not passed: " + ", ".join(failed)}
    if not isinstance(soak, dict) or float(soak.get("duration_hours", 0.0)) < 24.0 or int(soak.get("uncaught_errors", 1)) != 0:
        return {"provided": True, "valid": False, "status": "soak_incomplete", "detail": "production evidence requires >=24h soak and zero uncaught errors"}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {
        "provided": True,
        "valid": True,
        "status": "passed",
        "detail": "multi-node topology, required chaos scenarios, and >=24h zero-uncaught-error soak are evidenced",
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "nodes": len(nodes),
        "soak_hours": float(soak.get("duration_hours", 0.0)),
    }
