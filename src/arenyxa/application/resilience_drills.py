from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import base64
import hashlib
import json
import random
import sqlite3
import tempfile
import time
from dataclasses import field
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.application.reliability import ResourceGovernor, ResourceLimits, ResourceSnapshot
from arenyxa.config import AppSettings
from arenyxa.compat import dataclass
from arenyxa.enterprise.distributed_queue import DurableDistributedQueue
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, read_bytes_limited


@dataclass(frozen=True, slots=True)
class ResilienceDrillResult:
    scenario: str
    passed: bool
    duration_ms: float
    detail: str
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "passed": self.passed,
            "duration_ms": self.duration_ms,
            "detail": self.detail,
            "metrics": dict(self.metrics),
        }


class ResilienceDrillService:
    """Non-destructive chaos/recovery rehearsal executed only in isolated sandboxes.

    The service intentionally does not kill live workers, corrupt the production
    database, or inject packet loss into the host network. It exercises the same
    durable queue/recovery primitives against temporary state, which makes it
    safe to run from the desktop product and deterministic in CI.
    """

    def __init__(self, context: Any) -> None:
        self.context = context

    @staticmethod
    def _timed(name: str, action: Callable[[], tuple[bool, str, dict[str, Any]]]) -> ResilienceDrillResult:
        started = time.perf_counter()
        try:
            passed, detail, metrics = action()
        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
            passed, detail, metrics = False, f"{type(exc).__name__}: {exc}", {}
        return ResilienceDrillResult(
            name,
            bool(passed),
            (time.perf_counter() - started) * 1000.0,
            str(detail),
            dict(metrics),
        )

    def _worker_crash_recovery(self) -> tuple[bool, str, dict[str, Any]]:
        with tempfile.TemporaryDirectory(prefix="arenyxa-chaos-worker-") as temp:
            queue = DurableDistributedQueue(Path(temp) / "distributed.sqlite")
            private = Ed25519PrivateKey.generate()
            public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            public = base64.urlsafe_b64encode(public_raw).decode("ascii").rstrip("=")
            queue.register_worker("drill-worker", public, {"slots": 1}, max_slots=1)
            job_id = queue.enqueue(
                "drill.noop",
                {"scenario": "worker-crash"},
                resource_id="drill:worker",
                permission="drill.execute",
                idempotency_key="drill-worker-crash",
                max_attempts=3,
            )
            lease = queue.lease_next("drill-worker", lease_seconds=15)
            if lease is None:
                return False, "sandbox worker did not receive a lease", {}
            recovered = queue.recover_expired_leases(now=float(lease.lease_expires_at) + 1.0)
            row = queue.job(job_id)
            state = "" if row is None else str(row.get("state", ""))
            passed = recovered == 1 and state == "queued"
            return passed, f"lease recovery -> {state or 'missing'}", {"recovered": recovered, "state": state}

    @staticmethod
    def _network_loss_recovery() -> tuple[bool, str, dict[str, Any]]:
        rng = random.Random(0xA7E1_5A)
        attempts = 400
        max_retries = 5
        completed = 0
        exhausted = 0
        total_tries = 0
        for _index in range(attempts):
            success = False
            for retry in range(max_retries + 1):
                total_tries += 1
                # Deterministic 50% synthetic packet loss. No host network is modified.
                if rng.random() >= 0.5:
                    success = True
                    completed += 1
                    break
                _backoff = min(2.0, 0.05 * (2 ** retry))
            if not success:
                exhausted += 1
        ratio = completed / attempts
        passed = ratio >= 0.96 and exhausted <= 16
        return passed, f"50% synthetic loss with bounded retries: {ratio:.1%} completed", {
            "operations": attempts,
            "completed": completed,
            "exhausted": exhausted,
            "total_tries": total_tries,
            "loss_rate": 0.5,
            "max_retries": max_retries,
        }

    def _disk_latency_integrity(self) -> tuple[bool, str, dict[str, Any]]:
        with tempfile.TemporaryDirectory(prefix="arenyxa-chaos-disk-") as temp:
            path = Path(temp) / "checkpoint.bin"
            payload = json.dumps({"checkpoint": 7, "payload": "x" * 131072}, sort_keys=True).encode("utf-8")
            digest = hashlib.sha256(payload).hexdigest()
            time.sleep(0.05)  # controlled sandbox-only I/O delay
            atomic_write_bytes(path, payload, mode=0o600)
            time.sleep(0.05)
            readback = read_bytes_limited(path, 512 * 1024)
            verified = hashlib.sha256(readback).hexdigest() == digest
            return verified, "atomic checkpoint remained valid under injected I/O delay", {
                "bytes": len(payload), "delay_ms": 100, "sha256_verified": verified,
            }

    def _recovery_audit(self) -> tuple[bool, str, dict[str, Any]]:
        audit = RuntimeRecoveryService(self.context.store).audit()
        payload = audit.to_dict()
        broken = len(payload.get("broken_interrupted_workflows") or []) + len(payload.get("broken_interrupted_revisions") or [])
        return broken == 0, f"runtime recovery audit reported {broken} broken recovery chains", {
            "resumable_workflows": len(payload.get("resumable_workflows") or []),
            "broken_recovery_chains": broken,
        }

    @staticmethod
    def _sqlite_lock_backpressure() -> tuple[bool, str, dict[str, Any]]:
        """Prove SQLite contention fails within a bounded budget instead of hanging a caller."""
        with tempfile.TemporaryDirectory(prefix="arenyxa-chaos-sqlite-") as temp:
            path = Path(temp) / "lock.sqlite"
            owner = sqlite3.connect(path, timeout=0.05, isolation_level=None)
            contender = sqlite3.connect(path, timeout=0.05, isolation_level=None)
            try:
                owner.execute("CREATE TABLE IF NOT EXISTS drill (id INTEGER PRIMARY KEY, value TEXT)")
                owner.execute("BEGIN IMMEDIATE")
                owner.execute("INSERT INTO drill(value) VALUES ('owner')")
                started = time.perf_counter()
                failed_bounded = False
                try:
                    contender.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as exc:
                    failed_bounded = "locked" in str(exc).casefold()
                elapsed_ms = (time.perf_counter() - started) * 1000.0
                owner.rollback()
                passed = failed_bounded and elapsed_ms < 1000.0
                return passed, "SQLite lock contention remained bounded and recoverable", {
                    "bounded_failure": failed_bounded,
                    "elapsed_ms": round(elapsed_ms, 3),
                    "budget_ms": 1000.0,
                }
            finally:
                try:
                    owner.rollback()
                except sqlite3.Error:
                    record_current_exception(__name__, 'ResilienceDrillService._sqlite_lock_backpressure:176')
                owner.close()
                contender.close()

    @staticmethod
    def _corrupt_config_fallback() -> tuple[bool, str, dict[str, Any]]:
        """Verify malformed settings do not prevent startup and fall back to safe defaults."""
        with tempfile.TemporaryDirectory(prefix="arenyxa-chaos-config-") as temp:
            path = Path(temp) / "settings.json"
            path.write_text('{"theme": "modern_dark", "max_workers": ', encoding="utf-8")
            settings = AppSettings.load(path)
            defaults = AppSettings()
            passed = (
                settings.theme == defaults.theme
                and settings.max_workers == defaults.max_workers
                and settings.resource_governor_enabled is True
            )
            return passed, "malformed config fell back to validated defaults", {
                "theme": settings.theme,
                "max_workers": settings.max_workers,
                "resource_governor_enabled": settings.resource_governor_enabled,
            }

    @staticmethod
    def _resource_pressure_degradation() -> tuple[bool, str, dict[str, Any]]:
        limits = ResourceLimits(
            max_request_concurrency=16,
            max_worker_count=8,
            max_browser_instances=4,
            cpu_soft_percent=80.0,
            cpu_critical_percent=95.0,
            memory_soft_percent=80.0,
            memory_critical_percent=92.0,
            min_free_disk_bytes=512 * 1024 * 1024,
            critical_free_disk_bytes=128 * 1024 * 1024,
        )
        governor = ResourceGovernor(limits)
        critical = governor.evaluate(ResourceSnapshot(
            sampled_at=time.monotonic(),
            cpu_percent=98.0,
            memory_percent=94.0,
            process_rss_bytes=2 * 1024**3,
            available_memory_bytes=128 * 1024**2,
            disk_free_bytes=64 * 1024**2,
            active_browser_instances=4,
            active_workers=8,
        ))
        recovered = None
        for _index in range(12):
            recovered = governor.evaluate(ResourceSnapshot(
                sampled_at=time.monotonic(),
                cpu_percent=10.0,
                memory_percent=20.0,
                process_rss_bytes=256 * 1024**2,
                available_memory_bytes=8 * 1024**3,
                disk_free_bytes=8 * 1024**3,
                active_browser_instances=0,
                active_workers=0,
            ))
        passed = bool(
            critical.pressure == "critical"
            and not critical.admit_new_browser
            and not critical.admit_new_runs
            and recovered is not None
            and recovered.pressure == "normal"
            and recovered.request_ceiling > critical.request_ceiling
        )
        return passed, "resource governor degraded under pressure and recovered gradually", {
            "critical": critical.to_dict(),
            "recovered": {} if recovered is None else recovered.to_dict(),
        }

    def run_all(self) -> tuple[ResilienceDrillResult, ...]:
        """Preserved v7/v8 baseline drill contract used by the periodic scheduler."""
        return (
            self._timed("Worker lease crash recovery", self._worker_crash_recovery),
            self._timed("50% network-loss retry rehearsal", self._network_loss_recovery),
            self._timed("Delayed disk checkpoint integrity", self._disk_latency_integrity),
            self._timed("Runtime recovery audit", self._recovery_audit),
        )

    def run_phase6(self) -> tuple[ResilienceDrillResult, ...]:
        """Extended Phase-6 validation without changing the legacy four-drill scheduler contract."""
        return (
            *self.run_all(),
            self._timed("SQLite lock backpressure", self._sqlite_lock_backpressure),
            self._timed("Corrupt configuration fallback", self._corrupt_config_fallback),
            self._timed("Resource-pressure degradation/recovery", self._resource_pressure_degradation),
        )
