from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.enterprise.distributed import EnterpriseServerRuntime
from arenyxa.enterprise.enrollment import EnrollmentService
from arenyxa.enterprise.governance import EnterpriseGovernanceService
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.security import SecurityKernel

_MAX_AUDIT_TAIL_BYTES = 8 * 1024 * 1024
_MAX_AUDIT_ROWS = 500


class EnterpriseControlPlane:
    """Canonical Phase-4 application service for Enterprise/Server/Worker operations.

    The service deliberately delegates identity and authorization to the existing
    Enterprise Identity boundary. It never manufactures an Enterprise session and it
    never bypasses step-up requirements enforced by the underlying runtime.
    """

    def __init__(
        self,
        *,
        identity: LocalEnterpriseIdentityService,
        governance: EnterpriseGovernanceService,
        enrollment: EnrollmentService,
        server: EnterpriseServerRuntime,
        security: SecurityKernel,
        data_root: Path,
    ) -> None:
        self.identity = identity
        self.governance = governance
        self.enrollment = enrollment
        self.server = server
        self.security = security
        self.data_root = Path(data_root)

    @staticmethod
    def _identity_payload(status: Any) -> dict[str, Any]:
        converter = getattr(status, "to_dict", None)
        if callable(converter):
            return dict(converter())
        if hasattr(status, "__dict__"):
            return dict(status.__dict__)
        return {"configured": False, "reason": "identity status unavailable"}

    def status(self, *, include_fleet: bool = True) -> dict[str, Any]:
        identity_status = self.identity.status()
        payload: dict[str, Any] = {
            "schema": "arenyxa.enterprise-control-plane/v1",
            "checked_at": utc_now(),
            "identity": self._identity_payload(identity_status),
            "audit": self.audit_integrity(),
            "fleet": {"state": "locked"},
        }
        if include_fleet and bool(getattr(identity_status, "authenticated", False)):
            permissions = {str(item) for item in getattr(identity_status, "permissions", ())}
            if "enterprise.remote_ops" in permissions:
                payload["fleet"] = self.fleet_snapshot()
            else:
                payload["fleet"] = {"state": "forbidden", "required": "enterprise.remote_ops"}
        return payload

    def governance_snapshot(self) -> dict[str, Any]:
        self.identity.require("enterprise.workspace.manage", "enterprise:governance")
        return dict(self.governance.snapshot())

    def enrollment_snapshot(self) -> dict[str, Any]:
        self.identity.require("enterprise.enrollment.manage", "enterprise:enrollment")
        return {
            "campaigns": list(self.enrollment.list_campaigns()),
            "devices": list(self.enrollment.list_devices()),
            "local_device": dict(self.enrollment.local_device_posture()),
        }

    def fleet_snapshot(self) -> dict[str, Any]:
        snapshot = dict(self.server.remote_ops_snapshot())
        snapshot["checked_at"] = utc_now()
        snapshot["schema"] = "arenyxa.enterprise-fleet-snapshot/v1"
        return snapshot

    def workers(self, *, limit: int = 1000, state: str = "") -> list[dict[str, Any]]:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        rows = list(self.server.queue.list_workers(limit=max(1, min(1000, int(limit)))))
        expected = str(state or "").strip().casefold()
        if expected:
            rows = [row for row in rows if str(row.get("state", "")).casefold() == expected]
        return rows

    def jobs(self, *, limit: int = 1000, state: str = "") -> list[dict[str, Any]]:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        rows = list(self.server.queue.list_jobs(limit=max(1, min(1000, int(limit)))))
        expected = str(state or "").strip().casefold()
        if expected:
            rows = [row for row in rows if str(row.get("state", "")).casefold() == expected]
        return rows

    def worker_drain(self, worker_id: str, *, drain: bool) -> dict[str, Any]:
        worker = str(worker_id or "").strip()
        if not worker:
            raise ArenyxaError("WORKER_ID_REQUIRED", "worker id is required", domain="ENTERPRISE")
        self.server.set_worker_drain(worker, bool(drain))
        row = self.server.queue.worker(worker)
        if row is None:
            raise ArenyxaError("WORKER_UNKNOWN", "worker is not registered", domain="ENTERPRISE")
        return {"worker_id": worker, "state": row.get("state"), "drain": bool(drain)}

    def worker_revoke(self, worker_id: str) -> dict[str, Any]:
        worker = str(worker_id or "").strip()
        if not worker:
            raise ArenyxaError("WORKER_ID_REQUIRED", "worker id is required", domain="ENTERPRISE")
        recovered = int(self.server.revoke_worker(worker))
        return {"worker_id": worker, "revoked": True, "recovered_jobs": recovered}

    def retry_review_required(self, job_id: str) -> dict[str, Any]:
        job = str(job_id or "").strip()
        if not job:
            raise ArenyxaError("JOB_ID_REQUIRED", "distributed job id is required", domain="ENTERPRISE")
        self.server.retry_review_required(job)
        return {"job_id": job, "state": "queued"}

    def recover_expired_leases(self) -> dict[str, Any]:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        self.identity.require_recent_step_up()
        count = int(self.server.queue.recover_expired_leases())
        retention = dict(self.server.queue.retain_terminal_jobs())
        return {
            "recovered_leases": count,
            "retention_maintenance": retention,
            "checked_at": utc_now(),
        }

    def server_authority_start(self, *, ttl_seconds: int = 24 * 60 * 60) -> dict[str, Any]:
        token = str(self.server.activate_service(ttl_seconds=max(300, min(24 * 60 * 60, int(ttl_seconds)))))
        # Service-lease tokens are bearer credentials. Only return a stable fingerprint.
        return {
            "active": True,
            "lease_fingerprint": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "checked_at": utc_now(),
        }

    def server_authority_stop(self, *, reason: str = "OPERATOR_STOP") -> dict[str, Any]:
        self.identity.require("enterprise.server.manage", "enterprise:server")
        self.identity.require_recent_step_up()
        self.server.deactivate_service(reason=str(reason or "OPERATOR_STOP")[:128])
        return {"active": False, "checked_at": utc_now()}

    def storage_health(self) -> dict[str, Any]:
        self.identity.require("enterprise.remote_ops", "enterprise:distributed")
        return dict(self.server.queue.health())

    def audit_integrity(self) -> dict[str, Any]:
        valid, reason = self.security.audit.verify()
        status = self.security.audit.status() if hasattr(self.security.audit, "status") else {}
        return {
            "valid": bool(valid),
            "reason": str(reason),
            "appendable": bool(self.security.audit.appendable),
            "mode": str(status.get("mode", "normal")),
            "failure_policy": str(status.get("failure_policy", "fail_closed")),
            "recovery_valid": bool(status.get("recovery_valid", True)),
            "emergency_memory_events": int(status.get("emergency_memory_events", 0)),
        }

    def audit_tail(self, *, limit: int = 100) -> list[dict[str, Any]]:
        self.identity.require("enterprise.audit.read", "enterprise:audit")
        bounded = max(1, min(_MAX_AUDIT_ROWS, int(limit)))
        path = getattr(self.security.audit, "path", None)
        if path is None:
            rows = list(getattr(self.security.audit, "_memory", ()))
            return [dict(row) for row in rows[-bounded:]]
        audit_path = Path(path)
        if not audit_path.exists():
            return []
        size = audit_path.stat().st_size
        if size > _MAX_AUDIT_TAIL_BYTES:
            with audit_path.open("rb") as stream:
                stream.seek(max(0, size - _MAX_AUDIT_TAIL_BYTES))
                raw = stream.read(_MAX_AUDIT_TAIL_BYTES)
            # The first line can be partial after seeking. Discard it.
            if size > len(raw):
                _discard, _sep, raw = raw.partition(b"\n")
        else:
            raw = audit_path.read_bytes()
        result: list[dict[str, Any]] = []
        for line in raw.splitlines()[-bounded:]:
            if not line.strip():
                continue
            try:
                value = json.loads(line.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise ArenyxaError(
                    "AUDIT_READ_INVALID",
                    "security audit log contains an unreadable row",
                    domain="SECURITY",
                ) from exc
            if isinstance(value, Mapping):
                result.append(dict(value))
        return result
