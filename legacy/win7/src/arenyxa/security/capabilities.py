from __future__ import annotations

import fnmatch
import threading
from dataclasses import field
from typing import Any, Mapping, Sequence

from arenyxa.compat import StrEnum, dataclass
from arenyxa.security.models import Session, TrustDomain


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    name: str
    trust_domain: TrustDomain
    description: str = ""


class CapabilityCatalog:
    def __init__(self, definitions: Sequence[CapabilityDefinition] | None = None) -> None:
        self._definitions: dict[str, CapabilityDefinition] = {}
        for item in definitions or DEFAULT_CAPABILITIES:
            self.register(item)

    def register(self, definition: CapabilityDefinition) -> None:
        name = str(definition.name).strip()
        if not name or " " in name:
            raise ValueError("capability name must be a non-empty token")
        existing = self._definitions.get(name)
        if existing is not None and existing != definition:
            raise ValueError(f"capability already registered with another definition: {name}")
        self._definitions[name] = definition

    def get(self, name: str) -> CapabilityDefinition | None:
        return self._definitions.get(str(name))

    def require(self, name: str) -> CapabilityDefinition:
        item = self.get(name)
        if item is None:
            raise KeyError(name)
        return item

    def snapshot(self) -> tuple[CapabilityDefinition, ...]:
        return tuple(self._definitions[key] for key in sorted(self._definitions))


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    trust_domain: TrustDomain
    capabilities: tuple[str, ...]
    resources: tuple[str, ...] = ("*",)
    effect: PolicyEffect = PolicyEffect.DENY
    conditions: Mapping[str, Any] = field(default_factory=dict)
    priority: int = 0


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    allowed: bool
    code: str
    reason: str
    matched_rules: tuple[str, ...] = field(default_factory=tuple)


class PolicyEvaluator:
    

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rules: list[PolicyRule] = []

    def add(self, rule: PolicyRule) -> None:
        if not rule.capabilities or not rule.resources:
            raise ValueError("policy must name at least one capability and resource pattern")
        with self._lock:
            if any(existing.id == rule.id for existing in self._rules):
                raise ValueError(f"duplicate policy id: {rule.id}")
            self._rules.append(rule)
            self._rules.sort(key=lambda item: (-int(item.priority), item.id))

    def clear(self) -> None:
        with self._lock:
            self._rules.clear()

    @staticmethod
    def _conditions_match(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
        for key, wanted in expected.items():
            if isinstance(wanted, (tuple, list, set, frozenset)):
                if actual.get(key) not in wanted:
                    return False
            elif actual.get(key) != wanted:
                return False
        return True

    def evaluate(
        self,
        session: Session,
        capability: str,
        resource: str,
        context: Mapping[str, Any] | None = None,
    ) -> AuthorizationDecision:
        context = dict(context or {})
        if capability not in session.granted_capabilities:
            return AuthorizationDecision(False, "CAPABILITY_NOT_GRANTED", "session does not carry the requested capability")
        matched_allow: list[str] = []
        matched_deny: list[str] = []
        with self._lock:
            rules = tuple(self._rules)
        for rule in rules:
            if rule.trust_domain != session.trust_domain:
                continue
            if not any(fnmatch.fnmatchcase(capability, pattern) for pattern in rule.capabilities):
                continue
            if not any(fnmatch.fnmatchcase(resource, pattern) for pattern in rule.resources):
                continue
            if not self._conditions_match(rule.conditions, context):
                continue
            if rule.effect == PolicyEffect.DENY:
                matched_deny.append(rule.id)
            else:
                matched_allow.append(rule.id)
        if matched_deny:
            return AuthorizationDecision(False, "POLICY_DENY", "an explicit deny policy matched", tuple(matched_deny + matched_allow))
        if matched_allow:
            return AuthorizationDecision(True, "ALLOW", "capability and allow policy matched", tuple(matched_allow))
        return AuthorizationDecision(False, "POLICY_DEFAULT_DENY", "no allow policy matched")


DEFAULT_CAPABILITIES: tuple[CapabilityDefinition, ...] = (
    CapabilityDefinition("project.read", TrustDomain.PERSONAL),
    CapabilityDefinition("project.write", TrustDomain.PERSONAL),
    CapabilityDefinition("task.run", TrustDomain.PERSONAL),
    CapabilityDefinition("data.read", TrustDomain.PERSONAL),
    CapabilityDefinition("data.write", TrustDomain.PERSONAL),
    CapabilityDefinition("data.export", TrustDomain.PERSONAL),
    CapabilityDefinition("capture.run", TrustDomain.PERSONAL),
    CapabilityDefinition("replay.run", TrustDomain.PERSONAL),
    CapabilityDefinition("secrets.use", TrustDomain.PERSONAL),
    CapabilityDefinition("plugin.install", TrustDomain.PERSONAL),
    CapabilityDefinition("plugin.run", TrustDomain.PERSONAL),
    CapabilityDefinition("workspace.manage", TrustDomain.PERSONAL),
    CapabilityDefinition("system.configure", TrustDomain.PERSONAL),
    CapabilityDefinition("logs.read", TrustDomain.PERSONAL),
    CapabilityDefinition("runtime.debug", TrustDomain.DEVELOPER),
    CapabilityDefinition("profiler", TrustDomain.DEVELOPER),
    CapabilityDefinition("stress_test", TrustDomain.DEVELOPER),
    CapabilityDefinition("fault_injection", TrustDomain.DEVELOPER),
    CapabilityDefinition("internal_logs", TrustDomain.DEVELOPER),
    CapabilityDefinition("release.verify", TrustDomain.DEVELOPER),
                                                                                       
                                                                                                 
    CapabilityDefinition("platform.root", TrustDomain.DEVELOPER),
    CapabilityDefinition("enterprise.account.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.policy.modify", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.audit.read", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.enrollment.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.device.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.coordinator.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.workspace.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.approval.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.quota.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("dataset.read", TrustDomain.ENTERPRISE),
    CapabilityDefinition("dataset.write", TrustDomain.ENTERPRISE),
    CapabilityDefinition("dataset.export", TrustDomain.ENTERPRISE),
    CapabilityDefinition("workflow.execute", TrustDomain.ENTERPRISE),
    CapabilityDefinition("workflow.publish", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.capture.run", TrustDomain.ENTERPRISE),
    CapabilityDefinition("schedule.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("worker.use", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.worker.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.server.manage", TrustDomain.ENTERPRISE),
    CapabilityDefinition("enterprise.remote_ops", TrustDomain.ENTERPRISE),
)
