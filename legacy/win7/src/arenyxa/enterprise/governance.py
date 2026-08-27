from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService

GOVERNANCE_SCHEMA = "arenyxa.enterprise-governance/v1"
MAX_WORKSPACES = 512
MAX_TEAMS = 1024
MAX_RESOURCES = 20000
MAX_APPROVALS = 10000
RESOURCE_KINDS = frozenset({"workspace", "project", "workflow", "dataset", "capture", "schedule", "worker"})
RESOURCE_PERMISSION_MAP = {
    "dataset": frozenset({"dataset.read", "dataset.write", "dataset.export"}),
    "workflow": frozenset({"workflow.execute", "workflow.publish"}),
    "capture": frozenset({"enterprise.capture.run"}),
    "schedule": frozenset({"schedule.manage"}),
    "worker": frozenset({"worker.use"}),
    "workspace": frozenset({"enterprise.workspace.manage"}),
    "project": frozenset({"enterprise.workspace.manage"}),
}
HIGH_RISK_ACTIONS = frozenset({"workflow.publish", "dataset.export", "enterprise.policy.modify"})
LOGGER = logging.getLogger(__name__)


def _fail(code: str, message: str, **context: Any) -> ArenyxaError:
    return ArenyxaError(code, message, domain="ENTERPRISE", context=context)


def _future_iso(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=max(60, int(seconds)))).isoformat()


def _state(state: dict[str, Any]) -> dict[str, Any]:
    if not state:
        state.update({
            "schema": GOVERNANCE_SCHEMA,
            "workspaces": {}, "teams": {}, "resources": {}, "approvals": {},
            "quota_usage": {},
        })
    if state.get("schema") != GOVERNANCE_SCHEMA:
        raise _fail("GOVERNANCE_STATE_INVALID", "Enterprise governance state schema is invalid")
    for key, limit in (("workspaces", MAX_WORKSPACES), ("teams", MAX_TEAMS), ("resources", MAX_RESOURCES), ("approvals", MAX_APPROVALS)):
        value = state.get(key)
        if not isinstance(value, dict) or len(value) > limit:
            raise _fail("GOVERNANCE_STATE_INVALID", f"Enterprise governance {key} exceeds safety bounds")
    if not isinstance(state.get("quota_usage"), dict):
        raise _fail("GOVERNANCE_STATE_INVALID", "Enterprise quota state is invalid")
    return state


def _clean_id(value: str, label: str) -> str:
    text = str(value).strip()
    if not text or len(text) > 160:
        raise _fail("GOVERNANCE_ID_INVALID", f"{label} identifier is invalid")
    return text


class EnterpriseGovernanceService:
    

    def __init__(self, identity: LocalEnterpriseIdentityService, binding_store: object | None = None) -> None:
        self.identity = identity
        self._binding_store = binding_store

    def snapshot(self) -> dict[str, Any]:
        return _state(self.identity.extension_snapshot("governance", "enterprise.workspace.manage", "enterprise:governance"))

    def create_workspace(self, title: str, *, owner_account_id: str | None = None, retention_days: int = 365) -> str:
        status = self.identity.status()
        owner = str(owner_account_id or status.account_id)
        workspace_id = new_id("workspace")
        retention = min(3650, max(1, int(retention_days)))
        def mutate(state: dict[str, Any], vault: dict[str, Any]) -> None:
            state = _state(state)
            if owner not in vault["accounts"]:
                raise _fail("GOVERNANCE_OWNER_INVALID", "Workspace owner account does not exist")
            state["workspaces"][workspace_id] = {
                "id": workspace_id, "title": str(title).strip()[:160] or "Workspace",
                "owner_account_id": owner, "retention_days": retention,
                "created_at": utc_now(), "updated_at": utc_now(),
            }
        self.identity.mutate_extension("governance", "enterprise.workspace.manage", "enterprise:governance", "enterprise.workspace.create", mutate, step_up=False)
        return workspace_id

    def create_team(self, workspace_id: str, title: str, member_account_ids: list[str]) -> str:
        team_id = new_id("team")
        members = sorted(set(str(item) for item in member_account_ids if str(item)))
        def mutate(state: dict[str, Any], vault: dict[str, Any]) -> None:
            state = _state(state)
            if workspace_id not in state["workspaces"]:
                raise _fail("GOVERNANCE_WORKSPACE_MISSING", "Workspace does not exist")
            if any(account_id not in vault["accounts"] for account_id in members):
                raise _fail("GOVERNANCE_MEMBER_INVALID", "Team references an unknown Enterprise account")
            state["teams"][team_id] = {
                "id": team_id, "workspace_id": workspace_id, "title": str(title).strip()[:160] or "Team",
                "members": members, "created_at": utc_now(), "updated_at": utc_now(),
            }
        self.identity.mutate_extension("governance", "enterprise.workspace.manage", "enterprise:governance", "enterprise.team.create", mutate, step_up=False)
        return team_id

    def register_resource(
        self,
        kind: str,
        external_id: str,
        workspace_id: str,
        *,
        owner_account_id: str | None = None,
        team_id: str = "",
        scope: str = "workspace",
        retention_days: int = 365,
        quota: Mapping[str, int] | None = None,
    ) -> str:
        resource_kind = str(kind).strip().casefold()
        if resource_kind not in RESOURCE_KINDS:
            raise _fail("GOVERNANCE_RESOURCE_KIND_INVALID", "Unsupported Enterprise resource kind")
        external = _clean_id(external_id, "resource")
        status = self.identity.status()
        owner = str(owner_account_id or status.account_id)
        resource_id = f"{resource_kind}:{external}"
        scope_id = str(scope).strip().casefold() or "workspace"
        if scope_id not in {"private", "team", "workspace", "enterprise"}:
            raise _fail("GOVERNANCE_SCOPE_INVALID", "Enterprise resource scope is invalid")
        if scope_id == "team" and not str(team_id):
            raise _fail("GOVERNANCE_SCOPE_INVALID", "Team-scoped Enterprise resource requires a team")
        quota_map = {str(k): max(0, int(v)) for k, v in dict(quota or {}).items() if str(k)}
        if len(quota_map) > 16:
            raise _fail("GOVERNANCE_QUOTA_INVALID", "Resource quota contains too many metrics")
        staged_binding = False
        if self._binding_store is not None:
            status = self.identity.status()
            if not status.authenticated or not status.enterprise_id:
                raise _fail("ENTERPRISE_SESSION_INVALID", "Authenticated Enterprise session required for resource registration")
            existing_binding = self._binding_store.enterprise_resource_binding(resource_kind, external)
            if existing_binding is None:
                self._binding_store.bind_enterprise_resource(
                    resource_kind, external, resource_id, status.enterprise_id
                )
                staged_binding = True
            else:
                if (
                    str(existing_binding.get("resource_id", "")) != resource_id
                    or str(existing_binding.get("enterprise_id", "")) != status.enterprise_id
                ):
                    raise _fail(
                        "ENTERPRISE_BINDING_CONFLICT",
                        "Local resource is already bound to a different Enterprise resource",
                        resource_id=resource_id,
                    )
        def mutate(state: dict[str, Any], vault: dict[str, Any]) -> None:
            state = _state(state)
            if workspace_id not in state["workspaces"]:
                raise _fail("GOVERNANCE_WORKSPACE_MISSING", "Workspace does not exist")
            if owner not in vault["accounts"]:
                raise _fail("GOVERNANCE_OWNER_INVALID", "Resource owner account does not exist")
            if team_id and team_id not in state["teams"]:
                raise _fail("GOVERNANCE_TEAM_MISSING", "Resource team does not exist")
            state["resources"][resource_id] = {
                "id": resource_id, "kind": resource_kind, "external_id": external,
                "workspace_id": workspace_id, "owner_account_id": owner, "team_id": str(team_id),
                "scope": scope_id, "retention_days": min(3650, max(1, int(retention_days))),
                "quota": quota_map, "grants": {}, "created_at": utc_now(), "updated_at": utc_now(),
            }
            state["quota_usage"].setdefault(resource_id, {})
        try:
            self.identity.mutate_extension(
                "governance", "enterprise.workspace.manage", "enterprise:governance",
                "enterprise.resource.register", mutate, step_up=False,
            )
        except Exception:
            if staged_binding and self._binding_store is not None:
                try:
                    self._binding_store.unbind_enterprise_resource(
                        resource_kind, external, enterprise_id=self.identity.status().enterprise_id
                    )
                except Exception:
                                                                                              
                                                                                         
                    LOGGER.exception(
                        "Enterprise resource registration failed and local binding compensation failed; "
                        "binding remains fail-closed",
                        extra={"resource_id": resource_id, "enterprise_id": self.identity.status().enterprise_id},
                    )
            raise
        return resource_id

    def grant_role(self, resource_id: str, role_id: str, permissions: list[str]) -> None:
        requested = sorted(set(str(item) for item in permissions if str(item)))
        def mutate(state: dict[str, Any], vault: dict[str, Any]) -> None:
            state = _state(state)
            resource = state["resources"].get(str(resource_id))
            if not isinstance(resource, dict):
                raise _fail("GOVERNANCE_RESOURCE_MISSING", "Enterprise resource does not exist")
            if role_id not in vault["roles"]:
                raise _fail("ENTERPRISE_ROLE_INVALID", "Enterprise role does not exist")
            allowed = RESOURCE_PERMISSION_MAP.get(str(resource.get("kind")), frozenset())
            if any(permission not in allowed for permission in requested):
                raise _fail("GOVERNANCE_PERMISSION_INVALID", "Resource grant contains an unsupported permission")
            resource.setdefault("grants", {})[f"role:{role_id}"] = requested
            resource["updated_at"] = utc_now()
        self.identity.mutate_extension("governance", "enterprise.workspace.manage", "enterprise:governance", "enterprise.resource.grant", mutate, step_up=True)

    def require_resource(self, permission: str, resource_id: str) -> dict[str, Any]:
        self.identity.require(permission, resource_id)
        status = self.identity.status()
        state = _state(self.identity.extension_snapshot("governance", permission, resource_id))
        resource = state["resources"].get(str(resource_id))
        if not isinstance(resource, dict):
            raise _fail("GOVERNANCE_RESOURCE_MISSING", "Enterprise resource is not registered")
        if status.account_id == str(resource.get("owner_account_id")) or "super_admin" in status.roles:
            return dict(resource)
        scope_id = str(resource.get("scope", "workspace"))
        if scope_id == "private":
            raise _fail("GOVERNANCE_SCOPE_DENIED", "Private Enterprise resource is restricted to its owner", permission=permission, resource_id=resource_id)
        if scope_id == "team":
            team = state["teams"].get(str(resource.get("team_id", "")))
            if not isinstance(team, dict) or status.account_id not in set(str(item) for item in team.get("members", [])):
                raise _fail("GOVERNANCE_SCOPE_DENIED", "Enterprise resource is restricted to its assigned team", permission=permission, resource_id=resource_id)
        grants = resource.get("grants", {})
        for role in status.roles:
            if permission in grants.get(f"role:{role}", []):
                return dict(resource)
        raise _fail("GOVERNANCE_SCOPE_DENIED", "Enterprise resource scope denied the requested operation", permission=permission, resource_id=resource_id)

    def authorize_operation(
        self, permission: str, resource_id: str, *, approval_id: str = "",
        quota_metric: str = "", quota_amount: int = 0,
    ) -> dict[str, Any]:
        
        resource = self.require_resource(permission, resource_id)
        status = self.identity.status()
        metric_id = _clean_id(quota_metric, "quota metric") if quota_metric else ""
        delta = int(quota_amount)
        if delta < 0:
            raise _fail("GOVERNANCE_QUOTA_INVALID", "Quota reservation amount cannot be negative")
        requires_approval = permission in HIGH_RISK_ACTIONS
        if requires_approval and not approval_id:
            raise _fail("APPROVAL_REQUIRED", "This Enterprise operation requires an approved change request")
        if not requires_approval and not metric_id:
            return {"resource": resource, "quota_reserved": 0, "approval_consumed": False}

        result = {"quota_reserved": 0, "approval_consumed": False}
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = _state(state)
            current_resource = state["resources"].get(str(resource_id))
            if not isinstance(current_resource, dict):
                raise _fail("GOVERNANCE_RESOURCE_MISSING", "Enterprise resource does not exist")
            if requires_approval:
                item = state["approvals"].get(str(approval_id))
                if not isinstance(item, dict) or item.get("status") != "approved":
                    raise _fail("APPROVAL_REQUIRED", "A matching approved Enterprise change request is required")
                if item.get("action") != permission or item.get("resource_id") != resource_id:
                    raise _fail("APPROVAL_REQUIRED", "Enterprise approval does not match this operation")
                if str(item.get("requester_account_id", "")) != status.account_id:
                    raise _fail("APPROVAL_REQUESTER_MISMATCH", "Enterprise approval belongs to a different requester")
                expires = datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires <= datetime.now(timezone.utc):
                    item["status"] = "expired"
                    raise _fail("APPROVAL_EXPIRED", "Enterprise approval has expired")
            if metric_id and delta > 0:
                limit = int(current_resource.get("quota", {}).get(metric_id, 0))
                usage = state["quota_usage"].setdefault(str(resource_id), {})
                current = int(usage.get(metric_id, 0))
                if limit > 0 and current + delta > limit:
                    raise _fail(
                        "GOVERNANCE_QUOTA_EXCEEDED", "Enterprise resource quota would be exceeded",
                        metric=metric_id, limit=limit, current=current, requested=delta,
                    )
                usage[metric_id] = current + delta
                result["quota_reserved"] = usage[metric_id]
            if requires_approval:
                item = state["approvals"][str(approval_id)]
                item["status"] = "consumed"
                item["consumed_at"] = utc_now()
                result["approval_consumed"] = True

        self.identity.mutate_extension(
            "governance", permission, str(resource_id), "enterprise.operation.authorize", mutate, step_up=False,
        )
        return {"resource": resource, **result}

    def reserve_for_operation(self, resource_id: str, permission: str, metric: str, amount: int) -> int:
        self.require_resource(permission, resource_id)
        metric_id = _clean_id(metric, "quota metric")
        delta = int(amount)
        if delta < 0:
            raise _fail("GOVERNANCE_QUOTA_INVALID", "Quota reservation amount cannot be negative")
        result = {"value": 0}
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = _state(state)
            resource = state["resources"].get(str(resource_id))
            if not isinstance(resource, dict):
                raise _fail("GOVERNANCE_RESOURCE_MISSING", "Enterprise resource does not exist")
            limit = int(resource.get("quota", {}).get(metric_id, 0))
            usage = state["quota_usage"].setdefault(str(resource_id), {})
            current = int(usage.get(metric_id, 0))
            if limit > 0 and current + delta > limit:
                raise _fail(
                    "GOVERNANCE_QUOTA_EXCEEDED", "Enterprise resource quota would be exceeded",
                    metric=metric_id, limit=limit, current=current, requested=delta,
                )
            usage[metric_id] = current + delta
            result["value"] = usage[metric_id]
        self.identity.mutate_extension(
            "governance", permission, str(resource_id), "enterprise.quota.operation.reserve", mutate, step_up=False,
        )
        return int(result["value"])

    def release_for_operation(self, resource_id: str, permission: str, metric: str, amount: int) -> int:
        self.require_resource(permission, resource_id)
        metric_id = _clean_id(metric, "quota metric")
        delta = max(0, int(amount))
        result = {"value": 0}
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = _state(state)
            usage = state["quota_usage"].setdefault(str(resource_id), {})
            usage[metric_id] = max(0, int(usage.get(metric_id, 0)) - delta)
            result["value"] = usage[metric_id]
        self.identity.mutate_extension(
            "governance", permission, str(resource_id), "enterprise.quota.operation.release", mutate, step_up=False,
        )
        return int(result["value"])

    def operations_snapshot(self) -> dict[str, Any]:
        
        state = self.snapshot()
        resources = list(state["resources"].values())
        by_kind: dict[str, int] = {}
        quota_pressure: list[dict[str, Any]] = []
        for resource in resources:
            kind = str(resource.get("kind", "unknown"))
            by_kind[kind] = by_kind.get(kind, 0) + 1
            usage = state["quota_usage"].get(str(resource.get("id", "")), {})
            for metric, limit_value in dict(resource.get("quota", {})).items():
                limit = int(limit_value)
                current = int(usage.get(metric, 0))
                if limit > 0:
                    quota_pressure.append({
                        "resource_id": str(resource.get("id", "")), "metric": str(metric),
                        "current": current, "limit": limit,
                        "ratio": round(current / limit, 4),
                    })
        quota_pressure.sort(key=lambda item: float(item["ratio"]), reverse=True)
        pending = sum(1 for item in state["approvals"].values() if item.get("status") == "pending")
        binding_summary = {"bound_local_resources": 0, "orphaned_local_bindings": 0}
        if self._binding_store is not None:
            status = self.identity.status()
            bindings = self._binding_store.list_enterprise_resource_bindings(
                enterprise_id=status.enterprise_id, limit=MAX_RESOURCES
            ) if status.enterprise_id else []
            binding_summary["bound_local_resources"] = len(bindings)
            resource_ids = {str(item.get("id", "")) for item in resources}
            binding_summary["orphaned_local_bindings"] = sum(
                1 for item in bindings if str(item.get("resource_id", "")) not in resource_ids
            )
        return {
            "workspaces": len(state["workspaces"]), "teams": len(state["teams"]),
            "resources": len(resources), "resources_by_kind": by_kind,
            "pending_approvals": pending, "quota_pressure": quota_pressure[:100],
            **binding_summary,
        }

    def reserve_quota(self, resource_id: str, metric: str, amount: int) -> int:
        metric_id = _clean_id(metric, "quota metric")
        delta = int(amount)
        if delta < 0:
            raise _fail("GOVERNANCE_QUOTA_INVALID", "Quota reservation amount cannot be negative")
        result = {"value": 0}
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = _state(state)
            resource = state["resources"].get(str(resource_id))
            if not isinstance(resource, dict):
                raise _fail("GOVERNANCE_RESOURCE_MISSING", "Enterprise resource does not exist")
            limits = resource.get("quota", {})
            limit = int(limits.get(metric_id, 0))
            usage = state["quota_usage"].setdefault(str(resource_id), {})
            current = int(usage.get(metric_id, 0))
            if limit > 0 and current + delta > limit:
                raise _fail("GOVERNANCE_QUOTA_EXCEEDED", "Enterprise resource quota would be exceeded", metric=metric_id, limit=limit, current=current, requested=delta)
            usage[metric_id] = current + delta
            result["value"] = usage[metric_id]
        self.identity.mutate_extension("governance", "enterprise.quota.manage", "enterprise:governance", "enterprise.quota.reserve", mutate, step_up=False)
        return int(result["value"])

    def release_quota(self, resource_id: str, metric: str, amount: int) -> int:
        metric_id = _clean_id(metric, "quota metric")
        delta = max(0, int(amount))
        result = {"value": 0}
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = _state(state)
            usage = state["quota_usage"].setdefault(str(resource_id), {})
            usage[metric_id] = max(0, int(usage.get(metric_id, 0)) - delta)
            result["value"] = usage[metric_id]
        self.identity.mutate_extension("governance", "enterprise.quota.manage", "enterprise:governance", "enterprise.quota.release", mutate, step_up=False)
        return int(result["value"])

    def request_approval(self, action: str, resource_id: str, *, ttl_seconds: int = 3600, reason: str = "") -> str:
        action_id = str(action)
        if action_id not in HIGH_RISK_ACTIONS:
            raise _fail("APPROVAL_ACTION_INVALID", "Only configured high-risk actions can require Enterprise approval")
                                                                                               
                                                                                    
        self.require_resource(action_id, resource_id)
        status = self.identity.status()
        approval_id = new_id("approval")
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = _state(state)
            state["approvals"][approval_id] = {
                "id": approval_id, "action": action_id, "resource_id": str(resource_id),
                "requester_account_id": status.account_id, "approver_account_id": "",
                "status": "pending", "reason": str(reason)[:512], "created_at": utc_now(),
                "expires_at": _future_iso(min(24 * 3600, max(300, int(ttl_seconds)))), "decided_at": "",
                "consumed_at": "",
            }
        self.identity.mutate_extension(
            "governance", action_id, str(resource_id), "enterprise.approval.request", mutate, step_up=False,
        )
        return approval_id

    def decide_approval(self, approval_id: str, approved: bool) -> None:
        status = self.identity.status()
        def mutate(state: dict[str, Any], _vault: dict[str, Any]) -> None:
            state = _state(state)
            item = state["approvals"].get(str(approval_id))
            if not isinstance(item, dict) or item.get("status") != "pending":
                raise _fail("APPROVAL_INVALID", "Approval request is missing or no longer pending")
            expires = datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= datetime.now(timezone.utc):
                item["status"] = "expired"
                raise _fail("APPROVAL_EXPIRED", "Approval request has expired")
            if status.account_id == str(item.get("requester_account_id")):
                raise _fail("APPROVAL_SELF_REVIEW_DENIED", "Requester cannot approve their own high-risk action")
            item["status"] = "approved" if approved else "rejected"
            item["approver_account_id"] = status.account_id
            item["decided_at"] = utc_now()
        self.identity.mutate_extension("governance", "enterprise.approval.manage", "enterprise:governance", "enterprise.approval.decide", mutate, step_up=True)

    def require_approval(self, approval_id: str, action: str, resource_id: str) -> None:
        state = self.snapshot()
        item = state["approvals"].get(str(approval_id))
        if not isinstance(item, dict) or item.get("status") != "approved" or item.get("action") != action or item.get("resource_id") != resource_id:
            raise _fail("APPROVAL_REQUIRED", "A matching approved Enterprise change request is required")
        expires = datetime.fromisoformat(str(item["expires_at"]).replace("Z", "+00:00"))
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= datetime.now(timezone.utc):
            raise _fail("APPROVAL_EXPIRED", "Enterprise approval has expired")

    def query_audit(self, *, actor: str = "", resource: str = "", action: str = "", decision: str = "", limit: int = 200) -> list[dict[str, Any]]:
        self.identity.require("enterprise.audit.read", "enterprise:audit")
        valid, reason = self.identity.security.audit.verify()
        if not valid:
            raise _fail("AUDIT_INTEGRITY_BROKEN", "Security audit integrity verification failed", reason=reason)
        path = self.identity.security.audit.path
        if path is None or not path.exists():
            return []
        cap = min(1000, max(1, int(limit)))
        rows: list[dict[str, Any]] = []
        with Path(path).open("rb") as stream:
            for raw in stream:
                if len(raw) > self.identity.security.audit.MAX_LINE_BYTES:
                    raise _fail("AUDIT_INTEGRITY_BROKEN", "Security audit row exceeds safety bound")
                try:
                    row = json.loads(raw.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise _fail("AUDIT_INTEGRITY_BROKEN", "Security audit row cannot be decoded") from exc
                if actor and actor not in str(row.get("actor", "")):
                    continue
                if resource and resource not in str(row.get("resource", "")):
                    continue
                if action and action not in str(row.get("action", "")):
                    continue
                if decision and decision != str(row.get("decision", "")):
                    continue
                rows.append(row)
                if len(rows) > cap:
                    rows.pop(0)
        return rows
