from __future__ import annotations

from arenyxa.infrastructure.process_safety import validated_argv

import base64
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed import DistributedLease, DurableDistributedQueue

PRODUCTION_VALIDATION_SCHEMA = "arenyxa.production-validation/v1"
MULTI_NODE_EVIDENCE_SCHEMA = "arenyxa.production-multinode-evidence/v2"
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


def _remove_validation_root(root: Path, *, timeout_seconds: float = 3.0) -> None:
    """Remove a generated validation workspace with bounded Windows lock retries."""
    deadline = time.monotonic() + max(0.0, float(timeout_seconds))
    delay = 0.025
    while True:
        try:
            shutil.rmtree(root)
            return
        except FileNotFoundError:
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(0.25, delay * 2.0)


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
    







    def __init__(self, soak_jobs: int = 256, *, parallel_workers: int = 8, batch_size: int = 4) -> None:
        self.soak_jobs = max(32, min(int(soak_jobs), 10000))
        self.parallel_workers = max(1, min(int(parallel_workers), 64))
        self.batch_size = max(1, min(int(batch_size), 64))

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
            ("concurrent-batch-soak-consistency", self._concurrent_batch_soak_consistency),
        )
        items: List[ProductionValidationItem] = []
        root = Path(tempfile.mkdtemp(prefix="arenyxa-production-validation-"))
        try:
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
        finally:
            _remove_validation_root(root)
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
from arenyxa.domain.errors import ArenyxaError
from arenyxa.enterprise.distributed import DistributedLease, DurableDistributedQueue
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
    def _leased_queue(root: Path, worker: str = "worker-a", side_effect_mode: str = "idempotent") -> tuple[DurableDistributedQueue, str, DistributedLease]:
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
        except ArenyxaError as exc:
            if exc.code != "DISTRIBUTED_TERMINAL_CONFLICT":
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
            except (ArenyxaError, OSError, RuntimeError, TimeoutError, ValueError, sqlite3.Error) as exc:
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
        with closing(sqlite3.connect(str(db))) as connection:
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


    def _concurrent_batch_soak_consistency(self, root: Path) -> str:
        root.mkdir(parents=True, exist_ok=True)
        queue = DurableDistributedQueue(root / "distributed.sqlite")
        worker_count = self.parallel_workers
        batch_size = self.batch_size
        workers = tuple("parallel-worker-%d" % index for index in range(worker_count))
        for worker in workers:
            queue.register_worker(worker, _worker_public_key(), {"slots": batch_size}, max_slots=batch_size)
        total_jobs = max(64, min(self.soak_jobs, 1024))
        job_ids = [
            queue.enqueue(
                "task.run", {"task": {"index": index}}, resource_id="production-validation",
                permission="workflow.execute", idempotency_key="parallel-soak-%d" % index,
                side_effect_mode="idempotent",
            )
            for index in range(total_jobs)
        ]
        completed: set[str] = set()
        errors: List[str] = []
        state_lock = threading.Lock()
        start_barrier = threading.Barrier(worker_count)

        def consume(worker: str) -> None:
            try:
                start_barrier.wait(timeout=10)
                idle = 0
                while True:
                    with state_lock:
                        if len(completed) >= total_jobs:
                            return
                    leases = queue.lease_many(worker, max_items=batch_size, lease_seconds=60)
                    if not leases:
                        idle += 1
                        if idle > 2000:
                            raise RuntimeError("parallel soak made no leasing progress")
                        time.sleep(0.001)
                        continue
                    idle = 0
                    for lease in leases:
                        queue.start_job(lease.job_id, worker, lease.lease_token)
                        if int(lease.attempt) % 5 == 0:
                            queue.checkpoint(lease.job_id, worker, lease.lease_token, {"worker": worker})
                        queue.complete(lease.job_id, worker, lease.lease_token, {"status": "completed", "worker": worker})
                        with state_lock:
                            if lease.job_id in completed:
                                raise RuntimeError("parallel soak observed duplicate completion")
                            completed.add(lease.job_id)
            except (ArenyxaError, OSError, RuntimeError, TimeoutError, ValueError, sqlite3.Error) as exc:
                with state_lock:
                    errors.append("%s: %s" % (type(exc).__name__, exc))

        threads = [threading.Thread(target=consume, args=(worker,), name="arenyxa-parallel-soak-%d" % index) for index, worker in enumerate(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        if any(thread.is_alive() for thread in threads):
            raise RuntimeError("parallel soak worker thread did not stop")
        if errors:
            raise RuntimeError(errors[0])
        if len(completed) != total_jobs:
            raise RuntimeError("parallel soak completed %d/%d jobs" % (len(completed), total_jobs))
        reopened = DurableDistributedQueue(root / "distributed.sqlite")
        health = reopened.health()
        invariants = dict(health.get("state_invariants") or {})
        if any(int(invariants.get(key, 0)) != 0 for key in ("inconsistent_lease_rows", "unreceipted_completed_jobs", "implausible_future_leases")):
            raise RuntimeError("parallel soak state invariants failed: %r" % invariants)
        if any(reopened.job(job_id)["state"] != "completed" for job_id in job_ids):
            raise RuntimeError("parallel soak left non-completed jobs")
        return "%d jobs completed with %d concurrent Worker threads using batch leases; restart invariants remained clean" % (total_jobs, worker_count)



class _EvidenceValidationError(ValueError):
    def __init__(self, status: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _evidence_require(condition: bool, status: str, detail: str) -> None:
    if not condition:
        raise _EvidenceValidationError(status, detail)


def _is_hex64(value: str) -> bool:
    text = str(value).casefold()
    return len(text) == 64 and all(ch in "0123456789abcdef" for ch in text)


def _validate_evidence_topology(payload: Mapping[str, Any]) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    nodes = payload.get("nodes")
    _evidence_require(
        isinstance(nodes, list) and len(nodes) >= 3 and all(isinstance(node, dict) for node in nodes),
        "insufficient_nodes",
        "at least 3 independent nodes are required (1 Server + 2 Workers)",
    )
    typed_nodes = list(nodes)
    roles = [str(node.get("role", "")).casefold() for node in typed_nodes]
    hosts = [str(node.get("host_id", "")) for node in typed_nodes]
    targets = [str(node.get("target_id", "")).casefold() for node in typed_nodes]
    _evidence_require(
        roles.count("server") >= 1 and roles.count("worker") >= 2 and len(set(host for host in hosts if host)) >= 3,
        "insufficient_topology",
        "evidence must identify one Server and two Workers on three distinct hosts",
    )
    _evidence_require(
        len(hosts) == len(set(hosts)) and all(host.strip() for host in hosts),
        "duplicate_or_empty_host",
        "every evidence node must have a unique non-empty host_id",
    )
    _evidence_require(
        all(_is_hex64(target) for target in targets),
        "missing_target_identity",
        "every evidence node must include a 64-hex target_id",
    )
    _evidence_require(
        len(targets) == len(set(targets)),
        "aliased_targets",
        "declared multi-node evidence contains duplicated SSH target identities",
    )
    return typed_nodes, dict(zip(hosts, roles)), dict(zip(hosts, targets))


def _validate_evidence_deployment(payload: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
    deployment = payload.get("deployment")
    _evidence_require(isinstance(deployment, dict), "missing_deployment", "deployment evidence is missing")
    typed = dict(deployment)
    backend = str(typed.get("storage_backend") or "").casefold()
    _evidence_require(
        "postgres" in backend,
        "non_production_storage",
        "multi-host production evidence requires PostgreSQL distributed storage",
    )
    tls_minimum = str(typed.get("tls_minimum") or "").upper().replace(" ", "")
    _evidence_require(
        tls_minimum in {"TLS1.3", "TLSV1.3"},
        "tls_policy_incomplete",
        "multi-host production evidence requires TLS 1.3 minimum",
    )
    try:
        protocol_version = int(typed.get("protocol_version") or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise _EvidenceValidationError("protocol_evidence_incomplete", "production evidence protocol_version is invalid") from exc
    _evidence_require(
        protocol_version >= 2,
        "protocol_evidence_incomplete",
        "production evidence must identify Enterprise protocol v2 or newer",
    )
    return typed, protocol_version


def _validate_scenario_verification_row(
    name: str,
    row: Mapping[str, Any],
    role_by_host: Mapping[str, str],
    target_by_host: Mapping[str, str],
    protocol_version: int,
) -> tuple[str, str]:
    host = str(row.get("node_id") or "")
    role = str(row.get("role") or "").casefold()
    target_id = str(row.get("target_id") or "").casefold()
    _evidence_require(
        host in role_by_host and role == role_by_host[host] and target_id == target_by_host[host],
        "scenario_verification_identity_mismatch",
        f"scenario verification identity mismatch: {name}",
    )
    _evidence_require(
        row.get("healthy") is True,
        "scenario_verification_unhealthy",
        f"scenario post-cleanup verification is unhealthy: {name}/{host}",
    )
    _evidence_require(
        "postgres" in str(row.get("storage_backend") or "").casefold(),
        "scenario_verification_storage",
        f"scenario verification is not PostgreSQL-backed: {name}/{host}",
    )
    _evidence_require(
        str(row.get("tls_minimum") or "").upper().replace(" ", "") in {"TLS1.3", "TLSV1.3"},
        "scenario_verification_tls",
        f"scenario verification is below TLS 1.3: {name}/{host}",
    )
    try:
        row_protocol = int(row.get("protocol_version") or 0)
        duplicates = int(row.get("duplicate_terminal_receipts", 1))
        uncaught = int(row.get("uncaught_errors", 1))
    except (TypeError, ValueError, OverflowError) as exc:
        raise _EvidenceValidationError(
            "scenario_verification_counter", f"scenario verification counters are invalid: {name}/{host}"
        ) from exc
    _evidence_require(
        row_protocol >= protocol_version and duplicates == 0 and uncaught == 0,
        "scenario_verification_consistency",
        f"scenario verification reported protocol/counter failure: {name}/{host}",
    )
    invariants = row.get("state_invariants")
    _evidence_require(
        isinstance(invariants, dict),
        "scenario_verification_invariants",
        f"scenario verification lacks state invariants: {name}/{host}",
    )
    try:
        invariant_values = [
            int(invariants.get(key, 1))
            for key in ("inconsistent_lease_rows", "unreceipted_completed_jobs", "implausible_future_leases")
        ]
    except (TypeError, ValueError, OverflowError) as exc:
        raise _EvidenceValidationError(
            "scenario_verification_invariants", f"scenario verification invariant counters are invalid: {name}/{host}"
        ) from exc
    _evidence_require(
        not any(invariant_values),
        "scenario_verification_invariants",
        f"scenario verification found state invariant violations: {name}/{host}",
    )
    return host, role


def _validate_evidence_scenarios(
    payload: Mapping[str, Any],
    role_by_host: Mapping[str, str],
    target_by_host: Mapping[str, str],
    protocol_version: int,
) -> None:
    scenarios = payload.get("scenarios")
    _evidence_require(isinstance(scenarios, dict), "missing_scenarios", "scenario results are missing")
    for name in REQUIRED_EXTERNAL_SCENARIOS:
        scenario = scenarios.get(name)
        _evidence_require(
            isinstance(scenario, dict) and scenario.get("status") == "passed",
            "scenario_failure",
            f"required scenario not passed: {name}",
        )
        operations = scenario.get("operations")
        verification = scenario.get("verification")
        _evidence_require(
            isinstance(operations, list) and bool(operations),
            "scenario_evidence_incomplete",
            f"scenario has no recorded operations: {name}",
        )
        _evidence_require(
            isinstance(verification, list) and len(verification) >= 3,
            "scenario_verification_incomplete",
            f"scenario lacks 3-node post-cleanup verification: {name}",
        )
        covered: set[str] = set()
        covered_roles: list[str] = []
        for row in verification:
            _evidence_require(
                isinstance(row, dict),
                "scenario_verification_invalid",
                f"scenario verification row is invalid: {name}",
            )
            host, role = _validate_scenario_verification_row(name, row, role_by_host, target_by_host, protocol_version)
            covered.add(host)
            covered_roles.append(role)
        _evidence_require(
            len(covered) >= 3 and covered_roles.count("server") >= 1 and covered_roles.count("worker") >= 2,
            "scenario_verification_topology",
            f"scenario verification does not cover one Server and two Workers: {name}",
        )
        canonical = json.dumps(
            {"operations": operations, "verification": verification},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        _evidence_require(
            str(scenario.get("evidence_id") or "").casefold() == hashlib.sha256(canonical).hexdigest(),
            "scenario_evidence_digest_mismatch",
            f"scenario evidence digest mismatch: {name}",
        )


def _validate_evidence_soak(payload: Mapping[str, Any], role_by_host: Mapping[str, str]) -> tuple[float, int]:
    soak = payload.get("soak")
    _evidence_require(isinstance(soak, dict), "soak_incomplete", "production evidence requires a real multi-node soak summary")
    try:
        duration_hours = float(soak.get("duration_hours", 0.0))
        uncaught = int(soak.get("uncaught_errors", 1))
        invariant_violations = int(soak.get("invariant_violations", 1))
        duplicates = int(soak.get("duplicate_terminal_receipts", 1))
        probe_failures = int(soak.get("probe_failures", 1))
        sample_count = int(soak.get("sample_count", 0))
    except (TypeError, ValueError, OverflowError) as exc:
        raise _EvidenceValidationError("soak_incomplete", "production soak summary contains invalid counters") from exc
    _evidence_require(
        duration_hours >= 24.0 and uncaught == 0 and probe_failures == 0 and sample_count >= 96,
        "soak_incomplete",
        "production evidence requires >=24h soak, >=96 samples, zero probe failures, and zero uncaught errors",
    )
    _evidence_require(
        invariant_violations == 0 and duplicates == 0,
        "soak_consistency_failure",
        "production soak requires zero state invariant violations and zero duplicate terminal receipts",
    )
    sampled_nodes = soak.get("sampled_nodes")
    _evidence_require(
        isinstance(sampled_nodes, list) and len(set(str(item) for item in sampled_nodes)) >= 3,
        "soak_topology_incomplete",
        "production soak must continuously sample at least three distinct nodes",
    )
    sampled_roles = [role_by_host.get(str(item), "") for item in sampled_nodes]
    _evidence_require(
        sampled_roles.count("server") >= 1 and sampled_roles.count("worker") >= 2,
        "soak_topology_incomplete",
        "production soak must cover one Server and two Workers",
    )
    _evidence_require(
        _is_hex64(str(soak.get("evidence_id") or "")),
        "soak_evidence_identity_missing",
        "production soak requires a 64-hex evidence_id",
    )
    return duration_hours, sample_count


def validate_multi_node_evidence(path: Path) -> Dict[str, Any]:
    """Validate strict real multi-node chaos + soak evidence for production promotion."""
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("evidence file exceeds 4 MiB")
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        return {"provided": True, "valid": False, "status": "invalid", "detail": "%s: %s" % (type(exc).__name__, exc)}
    if not isinstance(payload, dict) or payload.get("schema") != MULTI_NODE_EVIDENCE_SCHEMA:
        return {"provided": True, "valid": False, "status": "invalid_schema", "detail": "multi-node evidence schema is invalid"}
    try:
        campaign_id = str(payload.get("campaign_id") or "").casefold()
        _evidence_require(_is_hex64(campaign_id), "missing_campaign_identity", "multi-node evidence requires a 64-hex campaign_id")
        _evidence_require(
            bool(str(payload.get("started_at") or "").strip()) and bool(str(payload.get("finished_at") or "").strip()),
            "missing_campaign_timestamps",
            "multi-node evidence requires started_at and finished_at",
        )
        nodes, role_by_host, target_by_host = _validate_evidence_topology(payload)
        deployment, protocol_version = _validate_evidence_deployment(payload)
        _validate_evidence_scenarios(payload, role_by_host, target_by_host, protocol_version)
        duration_hours, sample_count = _validate_evidence_soak(payload, role_by_host)
    except _EvidenceValidationError as exc:
        return {"provided": True, "valid": False, "status": exc.status, "detail": exc.detail}
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {
        "provided": True,
        "valid": True,
        "status": "passed",
        "detail": "strict 3-node PostgreSQL/TLS1.3 chaos verification and >=24h zero-error soak are evidenced",
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "campaign_id": campaign_id,
        "nodes": len(nodes),
        "soak_hours": duration_hours,
        "sample_count": sample_count,
        "storage_backend": str(deployment.get("storage_backend") or ""),
        "tls_minimum": str(deployment.get("tls_minimum") or ""),
        "protocol_version": protocol_version,
    }

