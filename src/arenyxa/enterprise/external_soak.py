from __future__ import annotations

import hashlib
import json
import subprocess
import time
from typing import Any, Callable, Mapping, Sequence

from arenyxa.compat import dataclass
from arenyxa.enterprise.external_chaos import ChaosNode, CommandResult, SSHCommandExecutor, _validated_remote_argv

MIN_PRODUCTION_SOAK_HOURS = 24.0
MIN_SAMPLE_INTERVAL_SECONDS = 30.0
MAX_SAMPLE_INTERVAL_SECONDS = 15 * 60.0


@dataclass(frozen=True, slots=True)
class SoakProbe:
    node_id: str
    argv: tuple[str, ...]
    timeout_seconds: float = 60.0


def parse_soak_probes(plan: Mapping[str, Any], nodes: Mapping[str, ChaosNode]) -> list[SoakProbe]:
    raw_probes = plan.get("soak_probes")
    if not isinstance(raw_probes, list) or not raw_probes:
        raise ValueError("external production soak requires soak_probes")
    probes: list[SoakProbe] = []
    for raw in raw_probes:
        if not isinstance(raw, dict):
            raise ValueError("soak probe must be an object")
        node_id = str(raw.get("node_id") or "")
        if node_id not in nodes:
            raise ValueError("soak probe references an unknown node")
        argv_raw = raw.get("argv")
        argv = tuple(_validated_remote_argv(argv_raw if isinstance(argv_raw, list) else []))
        timeout = max(1.0, min(300.0, float(raw.get("timeout_seconds") or 60.0)))
        probes.append(SoakProbe(node_id=node_id, argv=argv, timeout_seconds=timeout))
    covered = {probe.node_id for probe in probes}
    roles = [nodes[node_id].role for node_id in covered]
    if len(covered) < 3 or roles.count("server") < 1 or roles.count("worker") < 2:
        raise ValueError("production soak probes must cover one Server and two Workers")
    return probes


def _probe_payload(result: CommandResult) -> dict[str, Any]:
    if result.returncode != 0:
        raise RuntimeError(f"soak probe returned {result.returncode}")
    if len(result.stdout.encode("utf-8", errors="replace")) > 256 * 1024:
        raise ValueError("soak probe output exceeds 256 KiB")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("soak probe must emit one JSON object") from exc
    if not isinstance(payload, dict):
        raise ValueError("soak probe output must be a JSON object")
    return payload


def _counter(payload: Mapping[str, Any], name: str) -> int:
    value = payload.get(name, 0)
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"invalid soak counter: {name}") from exc
    if parsed < 0 or parsed > 1_000_000_000:
        raise ValueError(f"soak counter outside safety bounds: {name}")
    return parsed


def summarize_soak_samples(samples: Sequence[Mapping[str, Any]], *, duration_seconds: float) -> dict[str, Any]:
    """Build the strict evidence counters expected by the production validator."""
    uncaught = 0
    invariants = 0
    duplicates = 0
    probe_failures = 0
    for raw in samples:
        if not bool(raw.get("probe_ok", False)):
            probe_failures += 1
            uncaught += 1
            continue
        payload = raw.get("payload")
        if not isinstance(payload, Mapping):
            probe_failures += 1
            uncaught += 1
            continue
        uncaught = max(uncaught, _counter(payload, "uncaught_errors"))
        invariants = max(invariants, _counter(payload, "invariant_violations"))
        duplicates = max(duplicates, _counter(payload, "duplicate_terminal_receipts"))
        if payload.get("healthy") is False:
            invariants = max(invariants, 1)
    digest = hashlib.sha256(
        json.dumps(list(samples), sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()
    sampled_nodes = sorted({str(raw.get("node_id") or "") for raw in samples if str(raw.get("node_id") or "")})
    return {
        "duration_hours": round(max(0.0, float(duration_seconds)) / 3600.0, 6),
        "uncaught_errors": uncaught,
        "invariant_violations": invariants,
        "duplicate_terminal_receipts": duplicates,
        "probe_failures": probe_failures,
        "sample_count": len(samples),
        "sampled_nodes": sampled_nodes,
        "evidence_id": digest,
    }


class ExternalSoakRunner:
    """Collect real multi-node health evidence for at least 24 wall-clock hours."""

    def __init__(
        self,
        executor: SSHCommandExecutor | Any,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.executor = executor
        self.monotonic = monotonic
        self.sleeper = sleeper

    def run(
        self,
        plan: Mapping[str, Any],
        nodes: Mapping[str, ChaosNode],
        *,
        duration_hours: float,
        sample_interval_seconds: float = 60.0,
        progress: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        duration = float(duration_hours)
        if duration < MIN_PRODUCTION_SOAK_HOURS:
            raise ValueError("production soak evidence requires at least 24 wall-clock hours")
        interval = max(MIN_SAMPLE_INTERVAL_SECONDS, min(MAX_SAMPLE_INTERVAL_SECONDS, float(sample_interval_seconds)))
        probes = parse_soak_probes(plan, nodes)
        started = self.monotonic()
        deadline = started + duration * 3600.0
        samples: list[dict[str, Any]] = []
        cycle = 0
        while True:
            now = self.monotonic()
            if now >= deadline:
                break
            cycle += 1
            if progress:
                progress(f"production-soak cycle={cycle} elapsed_hours={(now - started) / 3600.0:.3f}")
            for probe in probes:
                node = nodes[probe.node_id]
                row: dict[str, Any] = {"node_id": node.host_id, "cycle": cycle, "probe_ok": False}
                try:
                    result = self.executor.run(node, probe.argv, probe.timeout_seconds)
                    payload = _probe_payload(result)
                    row.update({
                        "probe_ok": True,
                        "payload": payload,
                        "returncode": result.returncode,
                        "duration_seconds": round(result.duration_seconds, 3),
                        "output_sha256": hashlib.sha256(
                            (result.stdout + "\x00" + result.stderr).encode("utf-8", errors="replace")
                        ).hexdigest(),
                    })
                except (OSError, subprocess.SubprocessError, TimeoutError, ValueError, RuntimeError) as exc:
                    row["error"] = f"{type(exc).__name__}: {exc}"[:2048]
                samples.append(row)
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                break
            self.sleeper(min(interval, remaining))
        elapsed = self.monotonic() - started
        summary = summarize_soak_samples(samples, duration_seconds=elapsed)
        # A scheduler waking early or a host clock discontinuity cannot manufacture
        # a 24h result: actual monotonic elapsed time must meet the requested floor.
        if elapsed + 1.0 < duration * 3600.0:
            summary["uncaught_errors"] = max(1, int(summary["uncaught_errors"]))
            summary["premature_termination"] = True
        return summary
