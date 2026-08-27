from __future__ import annotations

import logging
from typing import Any

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id
from arenyxa.enterprise.governance import EnterpriseGovernanceService, RESOURCE_PERMISSION_MAP
from arenyxa.enterprise.identity import LocalEnterpriseIdentityService
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.security.models import TrustDomain

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class EnterpriseOperationDecision:
    governed: bool
    resource_id: str = ""
    enterprise_id: str = ""
    correlation_id: str = ""
    permission: str = ""
    quota_reserved: int = 0
    approval_consumed: bool = False


class EnterpriseOperationGuard:
    







    def __init__(
        self,
        store: SQLiteStore,
        identity: LocalEnterpriseIdentityService,
        governance: EnterpriseGovernanceService,
    ) -> None:
        self.store = store
        self.identity = identity
        self.governance = governance

    @staticmethod
    def _normalize(kind: str, external_id: str) -> tuple[str, str]:
        resource_kind = str(kind).strip().casefold()
        local_id = str(external_id).strip()
        if resource_kind not in RESOURCE_PERMISSION_MAP:
            raise ArenyxaError(
                "ENTERPRISE_RESOURCE_KIND_INVALID",
                "Unsupported Enterprise resource kind for operation convergence.",
                domain="ENTERPRISE",
                context={"kind": resource_kind},
            )
        if not local_id or len(local_id) > 160:
            raise ArenyxaError(
                "ENTERPRISE_RESOURCE_ID_INVALID",
                "Enterprise-bound local resource identifier is invalid.",
                domain="ENTERPRISE",
            )
        return resource_kind, local_id

    def register_and_bind_resource(
        self,
        kind: str,
        external_id: str,
        workspace_id: str,
        **kwargs: Any,
    ) -> str:
        






        resource_kind, local_id = self._normalize(kind, external_id)
        status = self.identity.status()
        if not status.authenticated or not status.enterprise_id:
            raise ArenyxaError(
                "ENTERPRISE_SESSION_INVALID",
                "An authenticated Enterprise session is required to register a governed resource.",
                domain="ENTERPRISE",
            )
        resource_id = f"{resource_kind}:{local_id}"
        self.store.bind_enterprise_resource(
            resource_kind, local_id, resource_id, status.enterprise_id
        )
        try:
            created = self.governance.register_resource(
                resource_kind, local_id, workspace_id, **kwargs
            )
            if str(created) != resource_id:
                raise ArenyxaError(
                    "ENTERPRISE_BINDING_MISMATCH",
                    "Governance returned an unexpected Enterprise resource identity.",
                    domain="ENTERPRISE",
                    context={"expected": resource_id, "actual": str(created)},
                )
        except Exception:
            try:
                self.store.unbind_enterprise_resource(
                    resource_kind, local_id, enterprise_id=status.enterprise_id
                )
            except Exception:
                LOGGER.exception(
                    "Enterprise registration failed and staged ownership binding could not be compensated; "
                    "binding remains fail-closed"
                )
            raise
        self.identity.security.audit.emit(
            actor=f"enterprise:{status.enterprise_id}:{status.account_id}",
            action="enterprise.resource.bind_local",
            resource=resource_id,
            decision="allow",
            trust_domain=TrustDomain.ENTERPRISE,
            reason=f"{resource_kind}:{local_id}",
        )
        return resource_id

    def bind_registered_resource(self, kind: str, external_id: str, resource_id: str) -> dict[str, Any]:
        resource_kind, local_id = self._normalize(kind, external_id)
        governed_id = str(resource_id).strip()
        expected_id = f"{resource_kind}:{local_id}"
        if governed_id != expected_id:
            raise ArenyxaError(
                "ENTERPRISE_BINDING_MISMATCH",
                "Enterprise resource binding does not match the local resource identity.",
                domain="ENTERPRISE",
                context={"expected": expected_id, "resource_id": governed_id},
            )
                                                                                               
                                                                                           
        state = self.governance.snapshot()
        resource = state.get("resources", {}).get(governed_id)
        if not isinstance(resource, dict):
            raise ArenyxaError(
                "GOVERNANCE_RESOURCE_MISSING",
                "Enterprise resource must be registered before it can be bound locally.",
                domain="ENTERPRISE",
                context={"resource_id": governed_id},
            )
        if str(resource.get("kind")) != resource_kind or str(resource.get("external_id")) != local_id:
            raise ArenyxaError(
                "ENTERPRISE_BINDING_MISMATCH",
                "Enterprise resource metadata does not match the requested local binding.",
                domain="ENTERPRISE",
                context={"resource_id": governed_id},
            )
        status = self.identity.status()
        if not status.authenticated or not status.enterprise_id:
            raise ArenyxaError(
                "ENTERPRISE_SESSION_INVALID",
                "An authenticated Enterprise session is required to bind a local resource.",
                domain="ENTERPRISE",
            )
        self.store.bind_enterprise_resource(resource_kind, local_id, governed_id, status.enterprise_id)
        self.identity.security.audit.emit(
            actor=f"enterprise:{status.enterprise_id}:{status.account_id}",
            action="enterprise.resource.bind_local",
            resource=governed_id,
            decision="allow",
            trust_domain=TrustDomain.ENTERPRISE,
            reason=f"{resource_kind}:{local_id}",
        )
        return dict(resource)

    def binding(self, kind: str, external_id: str) -> dict[str, Any] | None:
        resource_kind, local_id = self._normalize(kind, external_id)
        return self.store.enterprise_resource_binding(resource_kind, local_id)

    def authorize_if_bound(
        self,
        kind: str,
        external_id: str,
        permission: str,
        *,
        approval_id: str = "",
        quota_metric: str = "",
        quota_amount: int = 0,
        correlation_id: str = "",
    ) -> EnterpriseOperationDecision:
        resource_kind, local_id = self._normalize(kind, external_id)
        permission_id = str(permission).strip()
        allowed = RESOURCE_PERMISSION_MAP.get(resource_kind, frozenset())
        if permission_id not in allowed:
            raise ArenyxaError(
                "ENTERPRISE_OPERATION_PERMISSION_INVALID",
                "Permission does not belong to this Enterprise resource kind.",
                domain="ENTERPRISE",
                context={"kind": resource_kind, "permission": permission_id},
            )
        binding = self.store.enterprise_resource_binding(resource_kind, local_id)
        operation_correlation = str(correlation_id).strip() or new_id("enterprise-op")
        if binding is None:
            return EnterpriseOperationDecision(
                governed=False,
                correlation_id=operation_correlation,
                permission=permission_id,
            )

        resource_id = str(binding.get("resource_id", ""))
        enterprise_id = str(binding.get("enterprise_id", ""))
        expected_resource = f"{resource_kind}:{local_id}"
        if resource_id != expected_resource or not enterprise_id:
            raise ArenyxaError(
                "ENTERPRISE_BINDING_CORRUPT",
                "Enterprise local-resource binding is inconsistent; refusing local execution.",
                domain="ENTERPRISE",
                context={"kind": resource_kind, "external_id": local_id},
            )

        status = self.identity.status()
                                                                                             
                                                                                              
        if not status.unlocked or not status.authenticated:
            raise ArenyxaError(
                "ENTERPRISE_BOUND_RESOURCE_LOCKED",
                "This local resource belongs to an Enterprise and requires an active Enterprise session.",
                domain="ENTERPRISE",
                context={"resource_id": resource_id, "enterprise_id": enterprise_id},
            )
        if status.enterprise_id != enterprise_id:
            raise ArenyxaError(
                "ENTERPRISE_DOMAIN_MISMATCH",
                "This local resource is bound to a different Enterprise domain.",
                domain="ENTERPRISE",
                context={"resource_id": resource_id, "expected_enterprise_id": enterprise_id},
            )

        try:
            decision = self.governance.authorize_operation(
                permission_id,
                resource_id,
                approval_id=approval_id,
                quota_metric=quota_metric,
                quota_amount=quota_amount,
            )
        except Exception:
                                                                                            
                                                                                                  
            try:
                self.identity.security.audit.emit(
                    actor=f"enterprise:{status.enterprise_id}:{status.account_id}",
                    action="enterprise.local_operation.gate",
                    resource=resource_id,
                    decision="deny",
                    trust_domain=TrustDomain.ENTERPRISE,
                    correlation_id=operation_correlation,
                    reason=permission_id,
                )
            except Exception:
                LOGGER.exception("Unable to append Enterprise local-operation deny audit")
            raise

        self.identity.security.audit.emit(
            actor=f"enterprise:{status.enterprise_id}:{status.account_id}",
            action="enterprise.local_operation.gate",
            resource=resource_id,
            decision="allow",
            trust_domain=TrustDomain.ENTERPRISE,
            correlation_id=operation_correlation,
            reason=permission_id,
        )
        return EnterpriseOperationDecision(
            governed=True,
            resource_id=resource_id,
            enterprise_id=enterprise_id,
            correlation_id=operation_correlation,
            permission=permission_id,
            quota_reserved=int(decision.get("quota_reserved", 0)),
            approval_consumed=bool(decision.get("approval_consumed", False)),
        )
