from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from arenyxa.compat import dataclass
from arenyxa.enterprise.production_validation import MULTI_NODE_EVIDENCE_SCHEMA, REQUIRED_EXTERNAL_SCENARIOS
from arenyxa.infrastructure.process_safety import validated_argv

_NODE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_INVARIANTS = (
    "inconsistent_lease_rows",
    "unreceipted_completed_jobs",
    "implausible_future_leases",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class ChaosNode:
    host_id: str
    role: str
    ssh_target: str

    @property
    def target_id(self) -> str:
        # Do not persist operator SSH targets in release evidence. A stable digest is
        # enough to prove that three declared host IDs did not secretly alias one target.
        return hashlib.sha256(self.ssh_target.encode("utf-8", errors="strict")).hexdigest()


@dataclass(frozen=True, slots=True)
class ChaosOperation:
    node_id: str
    argv: tuple[str, ...]
    timeout_seconds: float = 120.0
    cleanup_argv: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ChaosProbe:
    node_id: str
    argv: tuple[str, ...]
    timeout_seconds: float = 60.0


@dataclass(frozen=True, slots=True)
class ChaosScenario:
    name: str
    operations: tuple[ChaosOperation, ...]
    verification: tuple[ChaosProbe, ...]


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float


class SSHCommandExecutor:
    """Bounded SSH executor for explicitly configured operator-owned chaos scripts."""

    def __init__(self, *, ssh_executable: str | None = None) -> None:
        self.ssh = ssh_executable or shutil.which("ssh") or ""
        if not self.ssh:
            raise RuntimeError("OpenSSH client is required for external multi-node chaos validation")

    def run(self, node: ChaosNode, argv: Sequence[str], timeout_seconds: float) -> CommandResult:
        args = _validated_remote_argv(argv)
        command = validated_argv([
            self.ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "--", node.ssh_target, "--", *args,
        ])
        began = time.monotonic()
        completed = subprocess.run(
            validated_argv(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(1.0, min(900.0, float(timeout_seconds))),
            check=False,
        )
        return CommandResult(
            completed.returncode,
            completed.stdout[-64 * 1024:],
            completed.stderr[-64 * 1024:],
            time.monotonic() - began,
        )


def _validated_remote_argv(argv: Sequence[str]) -> list[str]:
    values = [str(item) for item in argv]
    if not values or len(values) > 64:
        raise ValueError("external chaos command must contain 1..64 argv items")
    total = 0
    for item in values:
        encoded = item.encode("utf-8", errors="strict")
        total += len(encoded)
        if not item or len(encoded) > 2048 or any(ch in item for ch in ("\x00", "\r", "\n")):
            raise ValueError("external chaos argv contains an unsafe item")
    if total > 16 * 1024:
        raise ValueError("external chaos command exceeds the argv byte budget")
    return values


def _parse_probe(raw: Mapping[str, Any], nodes: Mapping[str, ChaosNode]) -> ChaosProbe:
    node_id = str(raw.get("node_id") or "")
    if node_id not in nodes:
        raise ValueError(f"unknown chaos verification node: {node_id}")
    argv_raw = raw.get("argv")
    argv = tuple(_validated_remote_argv(argv_raw if isinstance(argv_raw, list) else []))
    timeout = max(1.0, min(300.0, float(raw.get("timeout_seconds") or 60.0)))
    return ChaosProbe(node_id=node_id, argv=argv, timeout_seconds=timeout)


def _validate_verification_coverage(probes: Sequence[ChaosProbe], nodes: Mapping[str, ChaosNode]) -> None:
    covered = {probe.node_id for probe in probes}
    roles = [nodes[node_id].role for node_id in covered]
    if len(covered) < 3 or roles.count("server") < 1 or roles.count("worker") < 2:
        raise ValueError("every chaos scenario requires post-cleanup verification on one Server and two Workers")


def parse_chaos_plan(payload: Mapping[str, Any]) -> tuple[dict[str, ChaosNode], list[ChaosScenario], dict[str, Any]]:
    nodes_raw = payload.get("nodes")
    scenarios_raw = payload.get("scenarios")
    deployment = payload.get("deployment")
    if not isinstance(nodes_raw, list) or not isinstance(scenarios_raw, dict) or not isinstance(deployment, dict):
        raise ValueError("chaos plan requires nodes, scenarios, and deployment")

    backend = str(deployment.get("storage_backend") or "").casefold()
    tls_minimum = str(deployment.get("tls_minimum") or "").upper().replace(" ", "")
    try:
        protocol_version = int(deployment.get("protocol_version") or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("invalid chaos deployment protocol_version") from exc
    if "postgres" not in backend:
        raise ValueError("multi-node chaos requires PostgreSQL distributed storage")
    if tls_minimum not in {"TLS1.3", "TLSV1.3"}:
        raise ValueError("multi-node chaos requires TLS 1.3 minimum")
    if protocol_version < 2:
        raise ValueError("multi-node chaos requires Enterprise protocol v2 or newer")

    nodes: dict[str, ChaosNode] = {}
    targets: set[str] = set()
    for raw in nodes_raw:
        if not isinstance(raw, dict):
            raise ValueError("chaos node must be an object")
        host_id = str(raw.get("host_id") or "")
        role = str(raw.get("role") or "").casefold()
        ssh_target = str(raw.get("ssh_target") or "").strip()
        if not _NODE_ID.fullmatch(host_id) or role not in {"server", "worker"} or not ssh_target or any(ch in ssh_target for ch in ("\x00", "\r", "\n")):
            raise ValueError("invalid chaos node")
        if host_id in nodes:
            raise ValueError("duplicate chaos node id")
        target_id = hashlib.sha256(ssh_target.encode("utf-8", errors="strict")).hexdigest()
        if target_id in targets:
            raise ValueError("chaos nodes must map to distinct SSH targets")
        targets.add(target_id)
        nodes[host_id] = ChaosNode(host_id, role, ssh_target)
    if len(nodes) < 3 or sum(node.role == "server" for node in nodes.values()) < 1 or sum(node.role == "worker" for node in nodes.values()) < 2:
        raise ValueError("external chaos requires at least one Server and two Workers")

    global_verify_raw = payload.get("verification_probes")
    global_verify: tuple[ChaosProbe, ...] = ()
    if isinstance(global_verify_raw, list) and global_verify_raw:
        global_verify = tuple(_parse_probe(raw, nodes) for raw in global_verify_raw if isinstance(raw, Mapping))
        if len(global_verify) != len(global_verify_raw):
            raise ValueError("invalid global chaos verification probe")
        _validate_verification_coverage(global_verify, nodes)

    scenarios: list[ChaosScenario] = []
    for name in REQUIRED_EXTERNAL_SCENARIOS:
        raw_scenario = scenarios_raw.get(name)
        if isinstance(raw_scenario, list):
            raw_ops = raw_scenario
            raw_verify = None
        elif isinstance(raw_scenario, dict):
            raw_ops = raw_scenario.get("operations")
            raw_verify = raw_scenario.get("verify")
        else:
            raise ValueError(f"chaos scenario is missing operations: {name}")
        if not isinstance(raw_ops, list) or not raw_ops:
            raise ValueError(f"chaos scenario is missing operations: {name}")
        operations: list[ChaosOperation] = []
        for raw in raw_ops:
            if not isinstance(raw, dict):
                raise ValueError(f"invalid operation in chaos scenario: {name}")
            node_id = str(raw.get("node_id") or "")
            if node_id not in nodes:
                raise ValueError(f"unknown chaos node: {node_id}")
            argv = tuple(_validated_remote_argv(raw.get("argv") if isinstance(raw.get("argv"), list) else []))
            cleanup_raw = raw.get("cleanup_argv")
            cleanup = tuple(_validated_remote_argv(cleanup_raw)) if isinstance(cleanup_raw, list) and cleanup_raw else ()
            timeout = max(1.0, min(900.0, float(raw.get("timeout_seconds") or 120.0)))
            operations.append(ChaosOperation(node_id, argv, timeout, cleanup))

        if isinstance(raw_verify, list) and raw_verify:
            verification = tuple(_parse_probe(raw, nodes) for raw in raw_verify if isinstance(raw, Mapping))
            if len(verification) != len(raw_verify):
                raise ValueError(f"invalid verification probe in chaos scenario: {name}")
        else:
            verification = global_verify
        if not verification:
            raise ValueError(f"chaos scenario requires post-cleanup verification probes: {name}")
        _validate_verification_coverage(verification, nodes)
        scenarios.append(ChaosScenario(name, tuple(operations), verification))
    return nodes, scenarios, dict(deployment)


def _counter(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"invalid chaos verification counter: {name}") from exc
    if parsed < 0 or parsed > 1_000_000_000:
        raise ValueError(f"chaos verification counter outside bounds: {name}")
    return parsed


def _normalize_tls(value: Any) -> str:
    return str(value or "").upper().replace(" ", "")


def _verification_payload(result: CommandResult, node: ChaosNode, deployment: Mapping[str, Any]) -> dict[str, Any]:
    if result.returncode != 0:
        raise RuntimeError(f"verification probe returned {result.returncode}")
    encoded = result.stdout.encode("utf-8", errors="replace")
    if len(encoded) > 256 * 1024:
        raise ValueError("verification probe output exceeds 256 KiB")
    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("verification probe must emit one JSON object") from exc
    if not isinstance(raw, Mapping):
        raise ValueError("verification probe output must be a JSON object")
    host_id = str(raw.get("host_id") or "")
    role = str(raw.get("role") or "").casefold()
    if host_id != node.host_id or role != node.role:
        raise ValueError("verification probe identity does not match the configured node")
    if raw.get("healthy") is not True:
        raise ValueError("verification probe reported unhealthy runtime")
    backend = str(raw.get("storage_backend") or "").casefold()
    if "postgres" not in backend:
        raise ValueError("verification probe is not using PostgreSQL distributed storage")
    if _normalize_tls(raw.get("tls_minimum")) not in {"TLS1.3", "TLSV1.3"}:
        raise ValueError("verification probe does not enforce TLS 1.3 minimum")
    try:
        protocol_version = int(raw.get("protocol_version") or 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("verification probe protocol_version is invalid") from exc
    if protocol_version < int(deployment.get("protocol_version") or 2):
        raise ValueError("verification probe protocol version regressed below the campaign deployment")
    invariants = raw.get("state_invariants")
    if not isinstance(invariants, Mapping):
        raise ValueError("verification probe is missing state_invariants")
    normalized_invariants = {name: _counter(invariants.get(name, 1), name) for name in _REQUIRED_INVARIANTS}
    if any(normalized_invariants.values()):
        raise ValueError("verification probe reported distributed state invariant violations")
    duplicates = _counter(raw.get("duplicate_terminal_receipts", 0), "duplicate_terminal_receipts")
    uncaught = _counter(raw.get("uncaught_errors", 0), "uncaught_errors")
    if duplicates or uncaught:
        raise ValueError("verification probe reported duplicate terminal receipts or uncaught errors")
    return {
        "node_id": node.host_id,
        "role": node.role,
        "target_id": node.target_id,
        "healthy": True,
        "storage_backend": backend,
        "tls_minimum": str(raw.get("tls_minimum") or ""),
        "protocol_version": protocol_version,
        "state_invariants": normalized_invariants,
        "duplicate_terminal_receipts": duplicates,
        "uncaught_errors": uncaught,
        "output_sha256": hashlib.sha256((result.stdout + "\x00" + result.stderr).encode("utf-8", errors="replace")).hexdigest(),
    }


class ExternalChaosRunner:
    def __init__(self, executor: SSHCommandExecutor | Any) -> None:
        self.executor = executor

    def run(
        self,
        plan: Mapping[str, Any],
        *,
        allow_disruptive: bool,
        progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        if not allow_disruptive:
            raise PermissionError("external chaos requires explicit disruptive-operation confirmation")
        nodes, scenarios, deployment = parse_chaos_plan(plan)
        started_at = _utc_now()
        campaign_seed = {
            "started_at": started_at,
            "deployment": deployment,
            "nodes": sorted((node.host_id, node.role, node.target_id) for node in nodes.values()),
        }
        campaign_id = hashlib.sha256(json.dumps(campaign_seed, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        evidence: dict[str, Any] = {
            "schema": MULTI_NODE_EVIDENCE_SCHEMA,
            "campaign_id": campaign_id,
            "started_at": started_at,
            "deployment": deployment,
            "nodes": [
                {"host_id": node.host_id, "role": node.role, "target_id": node.target_id}
                for node in nodes.values()
            ],
            "scenarios": {},
            "soak": {
                "duration_hours": 0.0,
                "uncaught_errors": 0,
                "invariant_violations": 0,
                "duplicate_terminal_receipts": 0,
                "probe_failures": 0,
                "sample_count": 0,
                "sampled_nodes": [],
                "evidence_id": "",
            },
        }
        for scenario in scenarios:
            if progress:
                progress(f"external-chaos:{scenario.name}")
            details: list[dict[str, Any]] = []
            verification_rows: list[dict[str, Any]] = []
            passed = True
            for operation in scenario.operations:
                node = nodes[operation.node_id]
                try:
                    result = self.executor.run(node, operation.argv, operation.timeout_seconds)
                    passed = passed and result.returncode == 0
                    details.append(_result_row(node, operation.argv, result, "operation"))
                except (OSError, subprocess.SubprocessError, TimeoutError, ValueError, RuntimeError) as exc:
                    passed = False
                    details.append({"node_id": node.host_id, "phase": "operation", "error": f"{type(exc).__name__}: {exc}"[:2048]})
                finally:
                    if operation.cleanup_argv:
                        try:
                            cleanup = self.executor.run(node, operation.cleanup_argv, operation.timeout_seconds)
                            passed = passed and cleanup.returncode == 0
                            details.append(_result_row(node, operation.cleanup_argv, cleanup, "cleanup"))
                        except (OSError, subprocess.SubprocessError, TimeoutError, ValueError, RuntimeError) as exc:
                            passed = False
                            details.append({"node_id": node.host_id, "phase": "cleanup", "error": f"{type(exc).__name__}: {exc}"[:2048]})
            for probe in scenario.verification:
                node = nodes[probe.node_id]
                try:
                    result = self.executor.run(node, probe.argv, probe.timeout_seconds)
                    verification_rows.append(_verification_payload(result, node, deployment))
                except (OSError, subprocess.SubprocessError, TimeoutError, ValueError, RuntimeError) as exc:
                    passed = False
                    verification_rows.append({
                        "node_id": node.host_id,
                        "role": node.role,
                        "target_id": node.target_id,
                        "healthy": False,
                        "error": f"{type(exc).__name__}: {exc}"[:2048],
                    })
            canonical = json.dumps(
                {"operations": details, "verification": verification_rows},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
            evidence["scenarios"][scenario.name] = {
                "status": "passed" if passed else "failed",
                "evidence_id": hashlib.sha256(canonical).hexdigest(),
                "operations": details,
                "verification": verification_rows,
            }
        evidence["finished_at"] = _utc_now()
        return evidence


def _result_row(node: ChaosNode, argv: Sequence[str], result: CommandResult, phase: str) -> dict[str, Any]:
    digest = hashlib.sha256((result.stdout + "\x00" + result.stderr).encode("utf-8", errors="replace")).hexdigest()
    return {
        "node_id": node.host_id,
        "target_id": node.target_id,
        "phase": phase,
        "argv_sha256": hashlib.sha256("\x00".join(argv).encode("utf-8")).hexdigest(),
        "returncode": result.returncode,
        "duration_seconds": round(result.duration_seconds, 3),
        "output_sha256": digest,
    }
