from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import hashlib
import json
import os
import platform
import re
import shutil
import tempfile
import time
import zipfile
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from arenyxa import __package_version__, __version__
from arenyxa.application.job_system import JobExecutionContext, JobSystem
from arenyxa.application.resilience_drills import ResilienceDrillService
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.streaming_io import sha256_file
from arenyxa.security import PolicyEffect, PolicyRule, SecurityKernel, Session, TrustDomain

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+"),
    re.compile(r"(?i)((?:token|password|passphrase|secret|api[_-]?key)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
)


def create_local_control_session(security: SecurityKernel) -> Session:
    """Mint the process-local personal session used by the unified application control plane."""
    identity = security.state.create_identity(
        TrustDomain.PERSONAL,
        principal_id="local-interactive-runtime",
        display_name="Local Arenyxa Runtime",
        kind="local-runtime",
    )
    grants = {
        "project.read": ("health:*", "diagnostics:*", "job:*", "resilience:*", "performance:*"),
        "logs.read": ("health:*", "diagnostics:*", "job:*", "enterprise:*", "windows:*", "resilience:*", "performance:*"),
        "system.configure": ("health:*", "diagnostics:*", "job:*", "enterprise:*", "windows:*", "resilience:*", "performance:*"),
        "data.read": ("network:*", "capture:*", "capture-file:*", "protocol:*", "proxy:*", "mitm:*"),
        "data.export": ("proxy:export:*", "capture:export:*", "protocol:export:*"),
        "capture.run": ("capture:*", "proxy:*", "mitm:*"),
        "replay.run": ("proxy:*", "mitm:*"),
    }
    for capability, resources in grants.items():
        security.catalog.require(capability)
        security.add_policy(
            PolicyRule(
                id=f"v8-local-control-{capability.replace('.', '-')}",
                trust_domain=TrustDomain.PERSONAL,
                capabilities=(capability,),
                resources=resources,
                effect=PolicyEffect.ALLOW,
                conditions={"surface": "application-control-plane"},
                priority=100,
            )
        )
    capabilities = tuple(grants)
    return security.issue_session(
        identity.id,
        capabilities=list(capabilities),
        ttl_seconds=24 * 60 * 60,
        metadata={"surface": "local-runtime", "scope": "v8-control-plane"},
    )


class PlatformControlPlane:
    """Single v8 application service shared by GUI, CLI, Server, and Worker surfaces."""

    def __init__(
        self,
        *,
        paths: Any,
        store: Any,
        security: SecurityKernel,
        jobs: JobSystem,
        runner: Any = None,
        capture: Any = None,
        proxy: Any = None,
        mitm: Any = None,
        plugins: Any = None,
        runtime_supervisor: Any = None,
        runtime_recovery: Any = None,
        enterprise_server: Any = None,
        enterprise_control: Any = None,
        windows_runtime: Any = None,
        survivability: Any = None,
        performance_telemetry: Any = None,
        resilience_drills: Any = None,
    ) -> None:
        self.paths = paths
        self.store = store
        self.security = security
        self.jobs = jobs
        self.runner = runner
        self.capture = capture
        self.proxy = proxy
        self.mitm = mitm
        self.plugins = plugins
        self.runtime_supervisor = runtime_supervisor
        self.runtime_recovery = runtime_recovery
        self.enterprise_server = enterprise_server
        self.enterprise_control = enterprise_control
        self.windows_runtime = windows_runtime
        self.survivability = survivability
        self.performance_telemetry = performance_telemetry
        self.resilience_drills = resilience_drills

    def health(self, *, deep: bool = False) -> dict[str, Any]:
        started = time.monotonic()
        components: dict[str, dict[str, Any]] = {}

        def probe(name: str, operation: Any) -> None:
            probe_started = time.monotonic()
            try:
                value = operation()
                payload = self._normalize(value)
                healthy = not (isinstance(payload, dict) and payload.get("healthy") is False)
                latency_ms = round((time.monotonic() - probe_started) * 1000.0, 3)
                components[name] = {
                    "status": "healthy" if healthy else "unhealthy",
                    "latency_ms": latency_ms,
                    "details": payload,
                }
            except (OSError, RuntimeError, ValueError, TypeError, LookupError) as exc:
                latency_ms = round((time.monotonic() - probe_started) * 1000.0, 3)
                components[name] = {
                    "status": "unhealthy",
                    "latency_ms": latency_ms,
                    "error_code": f"{name.upper()}_HEALTH_FAILED",
                    "error": f"{type(exc).__name__}: {exc}"[:512],
                }
            if self.performance_telemetry is not None:
                self.performance_telemetry.record_latency(f"health.{name}", latency_ms)

        probe("storage", self._deep_storage_health if deep else self._storage_health)
        probe("audit", self._audit_health)
        probe("jobs", self.jobs.health)
        probe("resources", self._resource_health)
        if self.runner is not None:
            probe("runner", self._runner_health)
        if self.capture is not None:
            probe("capture", self._capture_health)
        if self.proxy is not None:
            probe("proxy", lambda: self.proxy.status())
        if self.mitm is not None:
            probe("mitm", lambda: self.mitm.status())
        if self.plugins is not None:
            probe("plugins", self._plugin_health)
        if self.runtime_supervisor is not None:
            probe("runtime_supervisor", self.runtime_supervisor.snapshot)
        if self.enterprise_server is not None:
            probe("enterprise_server", self._enterprise_health)
        if self.enterprise_control is not None:
            probe("enterprise_control", lambda: self.enterprise_control.status(include_fleet=False))
        if self.windows_runtime is not None:
            probe("windows_runtime", lambda: self.windows_runtime.status(deep=deep))
        if self.survivability is not None:
            probe("survivability", self.survivability.snapshot)

        statuses = [str(item.get("status")) for item in components.values()]
        overall = "unhealthy" if "unhealthy" in statuses else "healthy"
        if overall == "healthy":
            resource_details = components.get("resources", {}).get("details", {})
            if isinstance(resource_details, dict) and resource_details.get("pressure") in {"soft", "critical"}:
                overall = "degraded"
            survivability_details = components.get("survivability", {}).get("details", {})
            if isinstance(survivability_details, dict) and survivability_details.get("state") not in {None, "normal"}:
                overall = "degraded"
        return {
            "schema": "arenyxa.platform-health/v1",
            "product": "Arenyxa",
            "version": __version__,
            "package_version": __package_version__,
            "status": overall,
            "mode": "deep" if deep else "standard",
            "checked_at": utc_now(),
            "latency_ms": round((time.monotonic() - started) * 1000.0, 3),
            "components": components,
        }

    def submit_diagnostics_export(
        self,
        *,
        destination: Path | str | None,
        session: Session | None,
        surface: str,
        timeout_seconds: float = 120.0,
    ) -> dict[str, Any]:
        target = self._diagnostic_destination(destination)

        def operation(execution: JobExecutionContext) -> dict[str, Any]:
            return self._build_diagnostic_bundle(target, execution)

        return self.jobs.submit(
            "diagnostics-export",
            operation,
            session=session,
            capability="logs.read",
            resource="diagnostics:bundle",
            surface=surface,
            timeout_seconds=timeout_seconds,
            workload="diagnostics",
        )

    def list_jobs(
        self,
        *,
        session: Session | None,
        surface: str,
        limit: int = 100,
        state: str = "",
    ) -> list[dict[str, Any]]:
        self._require_read(session, "job:list", surface)
        return self.store.list_platform_jobs(limit=limit, state=state)

    def get_job(self, job_id: str, *, session: Session | None, surface: str) -> dict[str, Any]:
        self._require_read(session, f"job:{job_id!s}", surface)
        row = self.store.get_platform_job(job_id)
        if row is None:
            from arenyxa.domain.errors import ArenyxaError

            raise ArenyxaError("JOB_NOT_FOUND", "platform job was not found", domain="JOB")
        return row

    def cancel_job(self, job_id: str, *, session: Session | None, surface: str) -> dict[str, Any]:
        return self.jobs.cancel(job_id, session=session, surface=surface)

    def wait_job(
        self,
        job_id: str,
        *,
        session: Session | None,
        surface: str,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        self._require_read(session, f"job:{job_id!s}", surface)
        return self.jobs.wait(job_id, timeout_seconds)

    def _require_capability(
        self, session: Session | None, capability: str, resource: str, surface: str
    ) -> None:
        self.security.require(
            session,
            capability,
            resource,
            context={"surface": "application-control-plane", "entry_surface": str(surface)},
        )

    def _require_read(self, session: Session | None, resource: str, surface: str) -> None:
        self._require_capability(session, "logs.read", resource, surface)

    def survivability_status(
        self, *, session: Session | None, surface: str, refresh: bool = False
    ) -> dict[str, Any]:
        self._require_read(session, "resilience:status", surface)
        if self.survivability is None:
            return {"available": False, "reason": "Survivability Manager is unavailable"}
        return self.survivability.refresh() if refresh else self.survivability.snapshot()

    def performance_status(
        self, *, session: Session | None, surface: str
    ) -> dict[str, Any]:
        self._require_read(session, "performance:status", surface)
        if self.performance_telemetry is None:
            return {"available": False, "reason": "Performance Telemetry is unavailable"}
        snapshot = self.performance_telemetry.snapshot()
        runtime: dict[str, Any] = {"jobs": self.jobs.health()}
        if self.survivability is not None:
            runtime["survivability"] = self.survivability.snapshot()
        proxy = self.proxy
        if proxy is not None and hasattr(proxy, "persistence_status"):
            runtime["proxy_persistence"] = proxy.persistence_status()
        governor = None if self.survivability is None else getattr(self.survivability, "resource_governor", None)
        if governor is not None:
            runtime["resources"] = self._normalize(governor.snapshot())
        snapshot["runtime"] = runtime
        return snapshot

    def submit_resilience_drills(
        self,
        *,
        session: Session | None,
        surface: str,
        timeout_seconds: float = 120.0,
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", "resilience:drills", surface)
        service = self.resilience_drills
        if service is None:
            raise RuntimeError("Resilience Drill Service is unavailable")

        def operation(execution: JobExecutionContext) -> dict[str, Any]:
            execution.report_progress(0.05, "Starting isolated survivability drills")
            results = []
            drills = service.run_phase6()
            total = max(1, len(drills))
            for index, result in enumerate(drills, start=1):
                execution.check_cancelled()
                results.append(result.to_dict())
                execution.report_progress(min(0.98, index / total), result.scenario)
            passed = all(bool(item.get("passed")) for item in results)
            if self.performance_telemetry is not None:
                self.performance_telemetry.increment("resilience.drill_runs")
                self.performance_telemetry.increment("resilience.drill_failures", sum(not bool(item.get("passed")) for item in results))
            return {
                "schema": "arenyxa.resilience-drill-run/v1",
                "passed": passed,
                "count": len(results),
                "results": results,
            }

        return self.jobs.submit(
            "resilience-drills",
            operation,
            session=session,
            capability="system.configure",
            resource="resilience:drills",
            surface=surface,
            timeout_seconds=max(10.0, min(3600.0, float(timeout_seconds))),
            workload="heavy",
        )

    def enterprise_status(
        self, *, session: Session | None, surface: str, include_fleet: bool = True
    ) -> dict[str, Any]:
        self._require_read(session, "enterprise:status", surface)
        if self.enterprise_control is None:
            return {"available": False, "reason": "Enterprise Control Plane is unavailable"}
        return self.enterprise_control.status(include_fleet=include_fleet)

    def enterprise_governance(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        self._require_read(session, "enterprise:governance", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.governance_snapshot()

    def enterprise_enrollment(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        self._require_read(session, "enterprise:enrollment", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.enrollment_snapshot()

    def enterprise_storage(self, *, session: Session | None, surface: str) -> dict[str, Any]:
        self._require_read(session, "enterprise:storage", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.storage_health()

    def enterprise_workers(
        self, *, session: Session | None, surface: str, limit: int = 1000, state: str = ""
    ) -> list[dict[str, Any]]:
        self._require_read(session, "enterprise:workers", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.workers(limit=limit, state=state)

    def enterprise_jobs(
        self, *, session: Session | None, surface: str, limit: int = 1000, state: str = ""
    ) -> list[dict[str, Any]]:
        self._require_read(session, "enterprise:jobs", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.jobs(limit=limit, state=state)

    def enterprise_worker_drain(
        self, worker_id: str, *, drain: bool, session: Session | None, surface: str
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", f"enterprise:worker:{worker_id}", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.worker_drain(worker_id, drain=drain)

    def enterprise_worker_revoke(
        self, worker_id: str, *, session: Session | None, surface: str
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", f"enterprise:worker:{worker_id}", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.worker_revoke(worker_id)

    def enterprise_retry_job(
        self, job_id: str, *, session: Session | None, surface: str
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", f"enterprise:job:{job_id}", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.retry_review_required(job_id)

    def enterprise_recover_leases(
        self, *, session: Session | None, surface: str
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", "enterprise:leases", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return self.enterprise_control.recover_expired_leases()

    def enterprise_server_authority(
        self, action: str, *, session: Session | None, surface: str, ttl_seconds: int = 86400
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", "enterprise:server", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        normalized = str(action).casefold()
        if normalized == "start":
            return self.enterprise_control.server_authority_start(ttl_seconds=ttl_seconds)
        if normalized == "stop":
            return self.enterprise_control.server_authority_stop()
        raise ValueError("server authority action must be start or stop")

    def enterprise_audit(
        self, *, session: Session | None, surface: str, limit: int = 100
    ) -> dict[str, Any]:
        self._require_read(session, "enterprise:audit", surface)
        if self.enterprise_control is None:
            raise RuntimeError("Enterprise Control Plane is unavailable")
        return {
            "integrity": self.enterprise_control.audit_integrity(),
            "events": self.enterprise_control.audit_tail(limit=limit),
        }

    def windows_status(
        self, *, session: Session | None, surface: str, deep: bool = False
    ) -> dict[str, Any]:
        self._require_read(session, "windows:status", surface)
        if self.windows_runtime is None:
            return {"available": False, "reason": "Windows Runtime Control is unavailable"}
        return self.windows_runtime.status(deep=deep)

    def windows_service_status(
        self, *, session: Session | None, surface: str, service_name: str = "Arenyxa"
    ) -> dict[str, Any]:
        self._require_read(session, f"windows:service:{service_name}", surface)
        if self.windows_runtime is None:
            return {"state": "not_available", "service": service_name, "reason": "Windows Runtime Control is unavailable"}
        return self.windows_runtime.service_status(service_name=service_name)

    def windows_service_control(
        self, action: str, *, session: Session | None, surface: str, service_name: str = "Arenyxa"
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", f"windows:service:{service_name}", surface)
        if self.windows_runtime is None:
            raise RuntimeError("Windows Runtime Control is unavailable")
        return self.windows_runtime.service_control(action, service_name=service_name)

    def windows_service_install(
        self, *, session: Session | None, surface: str, service_name: str = "Arenyxa", start: str = "auto"
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", f"windows:service:{service_name}", surface)
        if self.windows_runtime is None:
            raise RuntimeError("Windows Runtime Control is unavailable")
        return self.windows_runtime.service_install(self.paths.root, service_name=service_name, start=start)

    def windows_service_remove(
        self, *, session: Session | None, surface: str, service_name: str = "Arenyxa"
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", f"windows:service:{service_name}", surface)
        if self.windows_runtime is None:
            raise RuntimeError("Windows Runtime Control is unavailable")
        return self.windows_runtime.service_remove(service_name=service_name)

    def windows_event(
        self, message: str, *, session: Session | None, surface: str, level: str = "INFORMATION"
    ) -> dict[str, Any]:
        self._require_capability(session, "system.configure", "windows:event-log", surface)
        if self.windows_runtime is None:
            raise RuntimeError("Windows Runtime Control is unavailable")
        return self.windows_runtime.write_event(message, level=level)

    def _storage_health(self) -> dict[str, Any]:
        return {"healthy": bool(self.store.ping()), "check": "ping"}

    def _deep_storage_health(self) -> dict[str, Any]:
        integrity = str(self.store.quick_check())
        with self.store.connect() as connection:
            migration = connection.execute("SELECT max(version),count(*) FROM schema_migrations").fetchone()
            job_table = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='platform_jobs'"
            ).fetchone()
        healthy = integrity.casefold() == "ok" and job_table is not None
        return {
            "healthy": healthy,
            "check": "quick_check",
            "integrity": integrity,
            "migration_current": 0 if migration is None else int(migration[0] or 0),
            "migration_count": 0 if migration is None else int(migration[1] or 0),
            "platform_jobs_schema": job_table is not None,
        }

    def _audit_health(self) -> dict[str, Any]:
        valid, reason = self.security.audit.verify()
        return {"healthy": bool(valid), "integrity": "valid" if valid else "broken", "reason": reason}

    def _resource_health(self) -> dict[str, Any]:
        usage = shutil.disk_usage(Path(self.paths.root))
        free_mb = usage.free // (1024 * 1024)
        pressure = "normal"
        if free_mb < 64:
            pressure = "critical"
        elif free_mb < 256:
            pressure = "soft"
        payload: dict[str, Any] = {
            "healthy": pressure != "critical",
            "pressure": pressure,
            "disk_total_bytes": int(usage.total),
            "disk_free_bytes": int(usage.free),
        }
        try:
            import psutil

            memory = psutil.virtual_memory()
            payload.update(
                {
                    "memory_total_bytes": int(memory.total),
                    "memory_available_bytes": int(memory.available),
                    "memory_percent": float(memory.percent),
                }
            )
            if float(memory.percent) >= 97.0:
                payload["healthy"] = False
                payload["pressure"] = "critical"
            elif float(memory.percent) >= 90.0 and payload["pressure"] == "normal":
                payload["pressure"] = "soft"
        except (ImportError, OSError, ValueError):
            payload["memory_probe"] = "unavailable"
        return payload

    def _runner_health(self) -> dict[str, Any]:
        handles = tuple(self.runner.active_handles())
        snapshot = self.runner.resource_snapshot()
        return {
            "healthy": True,
            "active_runs": sum(not handle.future.done() for handle in handles),
            "resources": self._normalize(snapshot),
        }

    def _capture_health(self) -> dict[str, Any]:
        session = self.capture.session
        return {
            "healthy": True,
            "state": "idle" if session is None else session.state.value,
            "session_id": "" if session is None else session.id,
            "dropped_events": 0 if session is None else int(session.dropped_events),
        }

    def _plugin_health(self) -> dict[str, Any]:
        snapshot = getattr(self.plugins, "health_snapshot", None)
        if callable(snapshot):
            rows = snapshot()
            return {"healthy": True, "count": len(rows), "items": self._normalize(rows)}
        listed = self.plugins.discover() if hasattr(self.plugins, "discover") else []
        return {"healthy": True, "count": len(listed)}

    def _enterprise_health(self) -> dict[str, Any]:
        for name in ("health_snapshot", "fleet_snapshot", "status"):
            operation = getattr(self.enterprise_server, name, None)
            if callable(operation):
                return {"healthy": True, "snapshot": self._normalize(operation())}
        return {"healthy": True, "runtime": type(self.enterprise_server).__name__}

    def _diagnostic_destination(self, destination: Path | str | None) -> Path:
        exports = Path(self.paths.exports).resolve()
        exports.mkdir(parents=True, exist_ok=True)
        if destination is None or not str(destination).strip():
            stamp = utc_now().replace(":", "").replace("-", "").replace("+", "_")
            target = exports / f"Arenyxa-v8-Diagnostics-{stamp}.zip"
        else:
            candidate = Path(destination)
            target = candidate if candidate.is_absolute() else exports / candidate
            target = target.expanduser().resolve()
        try:
            target.relative_to(exports)
        except ValueError as exc:
            raise ValueError("diagnostic exports must remain inside the configured exports directory") from exc
        if target.suffix.casefold() != ".zip":
            raise ValueError("diagnostic export destination must use the .zip extension")
        return target

    def _build_diagnostic_bundle(
        self, target: Path, execution: JobExecutionContext
    ) -> dict[str, Any]:
        execution.report_progress(0.05, "Collecting deep platform health")
        entries: dict[str, bytes] = {}
        health = self.health(deep=True)
        entries["platform-health.json"] = self._json_bytes(health)
        execution.report_progress(0.25, "Collecting bounded job history")
        entries["jobs.json"] = self._json_bytes(self.store.list_platform_jobs(limit=200))
        audit_valid, audit_reason = self.security.audit.verify()
        runtime = {
            "schema": "arenyxa.diagnostics-runtime/v1",
            "version": __version__,
            "package_version": __package_version__,
            "generated_at": utc_now(),
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "audit": {"valid": bool(audit_valid), "reason": str(audit_reason)},
            "recovery": self._normalize(self.runtime_recovery),
        }
        entries["runtime.json"] = self._json_bytes(runtime)
        if self.survivability is not None:
            entries["survivability.json"] = self._json_bytes(self.survivability.snapshot())
        if self.performance_telemetry is not None:
            entries["performance-telemetry.json"] = self._json_bytes(self.performance_telemetry.snapshot())
        execution.report_progress(0.45, "Collecting redacted bounded logs")
        log_root = Path(self.paths.logs)
        if log_root.is_dir():
            logs = sorted(
                (path for path in log_root.rglob("*.log") if path.is_file()),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )[:5]
            for index, path in enumerate(logs, start=1):
                execution.check_cancelled()
                raw = self._tail_bytes(path, 256 * 1024)
                redacted = self._redact(raw.decode("utf-8", "replace"))
                entries[f"logs/{index:02d}-{path.name}"] = redacted.encode("utf-8")

        manifest = {
            "schema": "arenyxa.diagnostics-bundle/v1",
            "version": __version__,
            "package_version": __package_version__,
            "generated_at": utc_now(),
            "redaction": "secrets-and-private-keys-v1",
            "files": {
                name: {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
                for name, payload in sorted(entries.items())
            },
        }
        entries["manifest.json"] = self._json_bytes(manifest)
        execution.report_progress(0.7, "Writing atomic diagnostic archive")
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for name, payload in sorted(entries.items()):
                    execution.check_cancelled()
                    archive.writestr(name, payload)
            with temporary.open("rb+") as stream:
                stream.flush()
                os.fsync(stream.fileno())
            execution.report_progress(0.9, "Committing diagnostic archive")
            os.replace(temporary, target)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                record_current_exception(__name__, 'PlatformControlPlane._build_diagnostic_bundle:652')
        digest = sha256_file(target)
        execution.report_progress(0.99, "Verifying diagnostic archive")
        with zipfile.ZipFile(target, "r") as archive:
            bad_entry = archive.testzip()
            names = set(archive.namelist())
        if bad_entry is not None or names != set(entries):
            raise RuntimeError(f"diagnostic archive verification failed: {bad_entry or 'inventory mismatch'}")
        return {
            "path": str(target),
            "sha256": digest,
            "bytes": target.stat().st_size,
            "entries": len(entries),
        }

    @staticmethod
    def _tail_bytes(path: Path, limit: int) -> bytes:
        size = path.stat().st_size
        with path.open("rb") as stream:
            if size > limit:
                stream.seek(size - limit)
            return stream.read(limit)

    @staticmethod
    def _redact(text: str) -> str:
        redacted = str(text)
        for pattern in _SECRET_PATTERNS:
            redacted = pattern.sub(lambda match: (match.group(1) if match.lastindex else "") + "[REDACTED]", redacted)
        return redacted

    @staticmethod
    def _json_bytes(value: Any) -> bytes:
        return (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n"
        ).encode("utf-8")

    @classmethod
    def _normalize(cls, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if is_dataclass(value):
            return cls._normalize(asdict(value))
        if isinstance(value, dict):
            return {str(key): cls._normalize(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [cls._normalize(item) for item in value]
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict):
            return cls._normalize(to_dict())
        return str(value)
