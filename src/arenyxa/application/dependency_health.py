from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import os
import socket
import ssl
import time
from dataclasses import field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from arenyxa.compat import dataclass
from arenyxa.infrastructure.atomic_io import atomic_write_bytes
from arenyxa.security.confidential_compute import ConfidentialComputeManager
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider
from arenyxa.application.dependency_health_history import DependencyHealthHistoryStore


@dataclass(frozen=True, slots=True)
class DependencyProbe:
    component: str
    state: str
    latency_ms: float | None = None
    detail: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "state": self.state,
            "latency_ms": self.latency_ms,
            "detail": self.detail,
            "metrics": dict(self.metrics),
        }


@dataclass(frozen=True, slots=True)
class DependencyHealthSnapshot:
    generated_at: str
    overall: str
    probes: tuple[DependencyProbe, ...]
    trends: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "overall": self.overall,
            "probes": [probe.to_dict() for probe in self.probes],
            "trends": {str(key): dict(value) for key, value in self.trends.items()},
        }


class DependencyHealthService:
    """Read-only/preflight dependency health with bounded active probes."""

    def __init__(self, context: Any, *, network_timeout: float = 2.0) -> None:
        self.context = context
        self.network_timeout = max(0.5, min(5.0, float(network_timeout)))

    @staticmethod
    def _state_for_latency(value_ms: float, warning_ms: float, critical_ms: float) -> str:
        if value_ms >= critical_ms:
            return "critical"
        if value_ms >= warning_ms:
            return "warning"
        return "healthy"

    def _probe_sqlite(self) -> DependencyProbe:
        started = time.perf_counter()
        try:
            result = str(self.context.store.quick_check())
            latency = (time.perf_counter() - started) * 1000.0
            state = "healthy" if result.casefold() == "ok" else "critical"
            return DependencyProbe("SQLite", state, latency, f"quick_check={result or 'missing'}")
        except (OSError, RuntimeError, ValueError) as exc:
            return DependencyProbe("SQLite", "critical", None, f"{type(exc).__name__}: {exc}")

    def _probe_disk(self) -> DependencyProbe:
        root = Path(self.context.paths.root) / "health"
        root.mkdir(parents=True, exist_ok=True)
        probe = root / f".dependency-health-{os.getpid()}.bin"
        payload = os.urandom(64 * 1024)
        started = time.perf_counter()
        try:
            atomic_write_bytes(probe, payload, mode=0o600)
            with probe.open("rb") as handle:
                readback = handle.read()
            latency = (time.perf_counter() - started) * 1000.0
            state = self._state_for_latency(latency, 150.0, 750.0)
            if readback != payload:
                state = "critical"
            return DependencyProbe(
                "Disk I/O", state, latency,
                "atomic 64 KiB write/read probe",
                {"bytes": len(payload), "verified": readback == payload},
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return DependencyProbe("Disk I/O", "critical", None, f"{type(exc).__name__}: {exc}")
        finally:
            try:
                probe.unlink(missing_ok=True)
            except OSError:
                record_current_exception(__name__, 'DependencyHealthService._probe_disk:103')

    @staticmethod
    def _probe_memory() -> DependencyProbe:
        try:
            import psutil

            memory = psutil.virtual_memory()
            percent = float(memory.percent)
            state = "critical" if percent >= 92.0 else "warning" if percent >= 82.0 else "healthy"
            return DependencyProbe(
                "System Memory", state, None, f"{percent:.1f}% used",
                {"percent": percent, "available": int(memory.available), "total": int(memory.total)},
            )
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            return DependencyProbe("System Memory", "warning", None, f"probe unavailable: {type(exc).__name__}")

    def _probe_distributed_runtime(self) -> DependencyProbe:
        runtime = getattr(self.context, "enterprise_server", None)
        if runtime is None:
            return DependencyProbe("Distributed Runtime", "healthy", None, "not configured")
        started = time.perf_counter()
        try:
            health = dict(runtime.queue.health())
            latency = (time.perf_counter() - started) * 1000.0
            healthy = bool(health.get("healthy", True))
            invariants = dict(health.get("state_invariants") or {})
            broken = {key: value for key, value in invariants.items() if isinstance(value, (int, float)) and int(value) != 0}
            state = "healthy" if healthy and not broken else "critical"
            return DependencyProbe(
                "Distributed Runtime", state, latency,
                str(health.get("storage") or health.get("deployment_profile") or "queue"),
                {"invariant_failures": broken, "storage_capabilities": health.get("storage_capabilities")},
            )
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            return DependencyProbe("Distributed Runtime", "critical", None, f"{type(exc).__name__}: {exc}")

    @staticmethod
    def _probe_confidential_compute() -> DependencyProbe:
        statuses = ConfidentialComputeManager().statuses()
        ready = [status for status in statuses if status.ready]
        supported = [status for status in statuses if status.supported]
        state = "healthy" if ready else "warning" if supported else "healthy"
        detail = "active: " + ", ".join(item.provider for item in ready) if ready else (
            "supported but inactive: " + ", ".join(item.provider for item in supported) if supported else "optional provider not available"
        )
        return DependencyProbe(
            "Confidential Compute", state, None, detail,
            {"providers": [status.to_dict() for status in statuses]},
        )

    @staticmethod
    def _probe_tpm() -> DependencyProbe:
        status = WindowsTPMEcdsaP256Provider().status()
        state = "healthy" if status.available else "warning" if os.name == "nt" else "healthy"
        return DependencyProbe("TPM / HSM Signing", state, None, status.reason or "hardware-backed signer available", status.to_dict())

    def _worker_tls_targets(self) -> list[tuple[str, int, str]]:
        targets: list[tuple[str, int, str]] = []
        try:
            workers = self.context.nextgen.workers.list()
        except (AttributeError, OSError, RuntimeError, ValueError, TypeError):
            return targets
        for worker in workers[:8]:
            parts = urlsplit(str(worker.base_url))
            if parts.scheme.casefold() != "https" or not parts.hostname:
                continue
            targets.append((parts.hostname, int(parts.port or 443), str(worker.name or worker.id)))
        return targets

    def _probe_tls(self, host: str, port: int, label: str) -> DependencyProbe:
        started = time.perf_counter()
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, int(port)), timeout=self.network_timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    version = str(tls.version() or "unknown")
            latency = (time.perf_counter() - started) * 1000.0
            expires_text = str(cert.get("notAfter", ""))
            if not expires_text:
                return DependencyProbe(f"TLS · {label}", "warning", latency, "certificate expiry unavailable")
            expires_epoch = ssl.cert_time_to_seconds(expires_text)
            days = (expires_epoch - time.time()) / 86400.0
            state = "critical" if days <= 7 else "warning" if days <= 30 else "healthy"
            return DependencyProbe(
                f"TLS · {label}", state, latency,
                f"{version} · certificate expires in {days:.1f} days",
                {"host": host, "port": int(port), "days_remaining": round(days, 2), "tls_version": version},
            )
        except (OSError, ssl.SSLError, ValueError) as exc:
            return DependencyProbe(f"TLS · {label}", "critical", None, f"{type(exc).__name__}: {exc}")

    def snapshot(self, *, include_network: bool = True) -> DependencyHealthSnapshot:
        probes = [
            self._probe_sqlite(),
            self._probe_disk(),
            self._probe_memory(),
            self._probe_distributed_runtime(),
            self._probe_confidential_compute(),
            self._probe_tpm(),
        ]
        if include_network:
            probes.extend(self._probe_tls(host, port, label) for host, port, label in self._worker_tls_targets())
        overall = "critical" if any(item.state == "critical" for item in probes) else (
            "warning" if any(item.state == "warning" for item in probes) else "healthy"
        )
        generated_at = datetime.now(timezone.utc).isoformat()
        trends: dict[str, dict[str, Any]] = {}
        try:
            history = DependencyHealthHistoryStore(Path(self.context.paths.root))
            provisional = {
                "generated_at": generated_at, "overall": overall,
                "probes": [probe.to_dict() for probe in probes],
            }
            history.record(provisional)
            trends = history.trends_for([probe.component for probe in probes])
        except (AttributeError, OSError, RuntimeError, ValueError, TypeError):
            trends = {}
        return DependencyHealthSnapshot(generated_at, overall, tuple(probes), trends)
