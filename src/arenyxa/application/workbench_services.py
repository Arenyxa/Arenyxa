from __future__ import annotations

from dataclasses import asdict, is_dataclass
import sqlite3
from pathlib import Path
from typing import Any

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now


_WORKBENCH_OPERATION_ERRORS = (ArenyxaError, sqlite3.Error, OSError, RuntimeError, ValueError, TypeError, KeyError)


class OperationalWorkbenchService:
    """Read/control facade used by Phase-5 GUI workbenches.

    All operations delegate to the shared application/control planes. QWidget code only
    renders results and dispatches bounded background work.
    """

    def __init__(self, context: Any) -> None:
        self.context = context

    @property
    def control(self) -> Any:
        value = getattr(self.context, "control_plane", None)
        if value is None:
            raise RuntimeError("Application Control Plane is unavailable")
        return value

    @property
    def session(self) -> Any:
        value = getattr(self.context, "local_control_session", None)
        if value is None:
            raise RuntimeError("local Control Plane session is unavailable")
        return value

    def protocol(self) -> dict[str, Any]:
        traffic = getattr(self.context, "traffic_control", None)
        if traffic is None:
            raise RuntimeError("Traffic Control Plane is unavailable")
        catalog = traffic.protocol_catalog(session=self.session, surface="gui", limit=5000)
        fields = traffic.protocol_fields(session=self.session, surface="gui", limit=10000)
        return {
            "schema": "arenyxa.workbench.protocol/v1",
            "checked_at": utc_now(),
            "status": traffic.status(session=self.session, surface="gui"),
            "protocol_count": len(catalog),
            "field_count": len(fields),
            "protocols": catalog,
        }

    def security(self) -> dict[str, Any]:
        security = getattr(self.context, "security", None)
        if security is None:
            raise RuntimeError("Security Kernel is unavailable")
        valid, reason = security.audit.verify()
        developer = getattr(self.context, "developer_access", None)
        try:
            developer_status = None if developer is None else developer.status()
        except (OSError, RuntimeError, ValueError, TypeError):
            developer_status = None
        enterprise = self.control.enterprise_status(session=self.session, surface="gui", include_fleet=False)
        return {
            "schema": "arenyxa.workbench.security/v1",
            "checked_at": utc_now(),
            "audit_integrity": {"valid": bool(valid), "reason": str(reason)},
            "capabilities": [getattr(item, "name", str(item)) for item in security.catalog.snapshot()],
            "developer_authority": self._normalize(developer_status),
            "enterprise": enterprise,
            "root_workstation_registered": bool(getattr(self.context, "root_workstation_registered", False)),
            "active_root_session": bool(getattr(self.context, "root_developer_workstation", False)),
        }

    def server(self) -> dict[str, Any]:
        return {
            "schema": "arenyxa.workbench.server/v1",
            "checked_at": utc_now(),
            "enterprise": self.control.enterprise_status(
                session=self.session, surface="gui", include_fleet=True
            ),
            "windows": self.control.windows_status(
                session=self.session, surface="gui", deep=False
            ),
        }

    def workers(self) -> dict[str, Any]:
        return {
            "schema": "arenyxa.workbench.workers/v1",
            "checked_at": utc_now(),
            "workers": self.control.enterprise_workers(session=self.session, surface="gui", limit=1000),
            "storage": self.control.enterprise_storage(session=self.session, surface="gui"),
        }

    def worker_drain(self, worker_id: str, drain: bool) -> dict[str, Any]:
        return self.control.enterprise_worker_drain(
            worker_id, drain=drain, session=self.session, surface="gui"
        )

    def worker_revoke(self, worker_id: str) -> dict[str, Any]:
        return self.control.enterprise_worker_revoke(worker_id, session=self.session, surface="gui")

    def jobs(self) -> dict[str, Any]:
        return {
            "schema": "arenyxa.workbench.jobs/v1",
            "checked_at": utc_now(),
            "local_jobs": self.control.list_jobs(session=self.session, surface="gui", limit=500),
            "distributed_jobs": self.control.enterprise_jobs(session=self.session, surface="gui", limit=1000),
        }

    def retry_distributed_job(self, job_id: str) -> dict[str, Any]:
        return self.control.enterprise_retry_job(job_id, session=self.session, surface="gui")

    def recover_leases(self) -> dict[str, Any]:
        return self.control.enterprise_recover_leases(session=self.session, surface="gui")

    def storage(self) -> dict[str, Any]:
        store = getattr(self.context, "store", None)
        if store is None:
            raise RuntimeError("Storage service is unavailable")
        database_path = Path(getattr(store, "path", getattr(self.context.paths, "database", "")))
        payload: dict[str, Any] = {
            "schema": "arenyxa.workbench.storage/v1",
            "checked_at": utc_now(),
            "sqlite": {
                "ping": bool(store.ping()),
                "quick_check": str(store.quick_check()),
                "path": str(database_path),
                "bytes": database_path.stat().st_size if database_path.is_file() else 0,
            },
        }
        try:
            payload["enterprise_runtime"] = self.control.enterprise_storage(
                session=self.session, surface="gui"
            )
        except _WORKBENCH_OPERATION_ERRORS as exc:
            payload["enterprise_runtime"] = {
                "state": "locked_or_unavailable",
                "reason": f"{type(exc).__name__}: {exc}"[:512],
            }
        return payload

    def audit(self) -> dict[str, Any]:
        security = getattr(self.context, "security", None)
        valid, reason = security.audit.verify() if security is not None else (False, "security unavailable")
        payload: dict[str, Any] = {
            "schema": "arenyxa.workbench.audit/v1",
            "checked_at": utc_now(),
            "integrity": {"valid": bool(valid), "reason": str(reason)},
            "events": [],
        }
        try:
            enterprise = self.control.enterprise_audit(
                session=self.session, surface="gui", limit=200
            )
            payload["events"] = enterprise.get("events", [])
            payload["enterprise_integrity"] = enterprise.get("integrity", {})
        except _WORKBENCH_OPERATION_ERRORS as exc:
            payload["enterprise_state"] = {
                "state": "locked_or_unavailable",
                "reason": f"{type(exc).__name__}: {exc}"[:512],
            }
        return payload

    def diagnostics(self) -> dict[str, Any]:
        return {
            "schema": "arenyxa.workbench.diagnostics/v2",
            "checked_at": utc_now(),
            "health": self.control.health(deep=True),
            "survivability": self.control.survivability_status(
                session=self.session, surface="gui", refresh=False
            ),
            "performance": self.control.performance_status(session=self.session, surface="gui"),
            "windows": self.control.windows_status(session=self.session, surface="gui", deep=False),
        }

    def performance(self) -> dict[str, Any]:
        performance = getattr(self.context, "performance", None)
        runner = getattr(self.context, "runner", None)
        supervisor = getattr(self.context, "runtime_supervisor", None)
        result = {
            "schema": "arenyxa.workbench.performance/v1",
            "checked_at": utc_now(),
            "policy": self._normalize(performance),
            "job_system": getattr(self.context, "job_system", None).health() if getattr(self.context, "job_system", None) is not None else {},
            "runner_resources": runner.resource_snapshot() if runner is not None else {},
            "runtime_supervisor": supervisor.snapshot() if supervisor is not None else {},
            "survivability": self.control.survivability_status(
                session=self.session, surface="gui", refresh=False
            ),
            "telemetry": self.control.performance_status(session=self.session, surface="gui"),
        }
        try:
            result["fleet"] = self.control.enterprise_storage(session=self.session, surface="gui")
        except _WORKBENCH_OPERATION_ERRORS:
            result["fleet"] = {"state": "locked_or_unavailable"}
        return result

    def developer(self) -> dict[str, Any]:
        runtime = getattr(self.context, "command_runtime", None)
        manager = getattr(self.context, "developer_access", None)
        return {
            "schema": "arenyxa.workbench.developer/v1",
            "checked_at": utc_now(),
            "authorized": bool(runtime.developer_authorized()) if runtime is not None else False,
            "authority": self._normalize(manager.status()) if manager is not None else None,
            "terminal_workspace": bool(getattr(self.context, "terminal_workspace", None) is not None),
            "plugin_sandbox": bool(getattr(self.context, "plugin_sandbox", None) is not None),
        }

    @staticmethod
    def _normalize(value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if is_dataclass(value):
            return asdict(value)
        converter = getattr(value, "to_dict", None)
        if callable(converter):
            return converter()
        if isinstance(value, dict):
            return {str(k): OperationalWorkbenchService._normalize(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [OperationalWorkbenchService._normalize(item) for item in value]
        return str(value)
