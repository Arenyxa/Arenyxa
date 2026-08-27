from __future__ import annotations

import ipaddress
from dataclasses import field
from typing import Any, Mapping

from arenyxa.compat import dataclass


_DEFAULT_NETWORK_TRUST = ("trusted", "private", "unknown")


def _tuple_values(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [item.strip() for item in value.split(",")]
    if not isinstance(value, (list, tuple, set, frozenset)):
        return ()
    return tuple(sorted({str(item).strip() for item in value if str(item).strip()}))


def _valid_cidrs(value: object) -> tuple[str, ...]:
    result: list[str] = []
    for item in _tuple_values(value):
        try:
            result.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            continue
    return tuple(sorted(set(result)))


@dataclass(frozen=True, slots=True)
class ZeroTrustPolicy:
    """Define identity, posture and network micro-segmentation requirements."""

    enabled: bool = False
    require_managed_device: bool = False
    require_compliant_device: bool = False
    require_mfa: bool = False
    allowed_network_trust: tuple[str, ...] = _DEFAULT_NETWORK_TRUST
    max_risk_score: int = 100
    max_auth_age_seconds: int = 24 * 60 * 60
    allowed_source_cidrs: tuple[str, ...] = ()
    required_permissions: tuple[str, ...] = ()
    allowed_worker_ids: tuple[str, ...] = ()
    allowed_server_ids: tuple[str, ...] = ()
    require_server_relay: bool = False
    deny_peer_to_peer: bool = False
    required_transport: str = ""

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "ZeroTrustPolicy":
        raw = dict(value or {})
        allowed = raw.get("allowed_network_trust", _DEFAULT_NETWORK_TRUST)
        normalized = tuple(item.casefold() for item in _tuple_values(allowed)) or _DEFAULT_NETWORK_TRUST
        transport = str(raw.get("required_transport", "")).strip().casefold()
        if transport not in {"", "tls13", "tls12", "local"}:
            transport = ""
        return cls(
            enabled=bool(raw.get("enabled", False)),
            require_managed_device=bool(raw.get("require_managed_device", False)),
            require_compliant_device=bool(raw.get("require_compliant_device", False)),
            require_mfa=bool(raw.get("require_mfa", False)),
            allowed_network_trust=tuple(sorted(set(normalized))),
            max_risk_score=max(0, min(100, int(raw.get("max_risk_score", 100)))),
            max_auth_age_seconds=max(0, min(7 * 24 * 60 * 60, int(raw.get("max_auth_age_seconds", 24 * 60 * 60)))),
            allowed_source_cidrs=_valid_cidrs(raw.get("allowed_source_cidrs", ())),
            required_permissions=_tuple_values(raw.get("required_permissions", ())),
            allowed_worker_ids=_tuple_values(raw.get("allowed_worker_ids", ())),
            allowed_server_ids=_tuple_values(raw.get("allowed_server_ids", ())),
            require_server_relay=bool(raw.get("require_server_relay", False)),
            deny_peer_to_peer=bool(raw.get("deny_peer_to_peer", False)),
            required_transport=transport,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "require_managed_device": self.require_managed_device,
            "require_compliant_device": self.require_compliant_device,
            "require_mfa": self.require_mfa,
            "allowed_network_trust": list(self.allowed_network_trust),
            "max_risk_score": self.max_risk_score,
            "max_auth_age_seconds": self.max_auth_age_seconds,
            "allowed_source_cidrs": list(self.allowed_source_cidrs),
            "required_permissions": list(self.required_permissions),
            "allowed_worker_ids": list(self.allowed_worker_ids),
            "allowed_server_ids": list(self.allowed_server_ids),
            "require_server_relay": self.require_server_relay,
            "deny_peer_to_peer": self.deny_peer_to_peer,
            "required_transport": self.required_transport,
        }


@dataclass(frozen=True, slots=True)
class ZeroTrustDecision:
    """Represent the fail-closed result of evaluating runtime access context."""

    allowed: bool
    code: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    risk_score: int = 0


class ZeroTrustEvaluator:
    """Evaluate real-time access context using fail-closed resource policy."""

    @staticmethod
    def _source_allowed(source_ip: str, networks: tuple[str, ...]) -> bool:
        if not networks:
            return True
        try:
            address = ipaddress.ip_address(str(source_ip).strip())
        except ValueError:
            return False
        for cidr in networks:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def evaluate(policy: ZeroTrustPolicy, context: Mapping[str, Any] | None) -> ZeroTrustDecision:
        if not policy.enabled:
            return ZeroTrustDecision(True, "ZERO_TRUST_DISABLED")

        actual = dict(context or {})
        reasons: list[str] = []
        try:
            risk = max(0, min(100, int(actual.get("risk_score", 100))))
        except (TypeError, ValueError, OverflowError):
            risk = 100
        if risk > policy.max_risk_score:
            reasons.append("risk_score")

        if policy.require_managed_device and actual.get("managed_device") is not True:
            reasons.append("managed_device")
        if policy.require_compliant_device and actual.get("device_compliant") is not True:
            reasons.append("device_compliant")
        if policy.require_mfa and actual.get("mfa_verified") is not True:
            reasons.append("mfa_verified")

        network_trust = str(actual.get("network_trust", "unknown")).strip().casefold() or "unknown"
        if network_trust not in policy.allowed_network_trust:
            reasons.append("network_trust")

        try:
            auth_age = max(0, int(actual.get("auth_age_seconds", policy.max_auth_age_seconds + 1)))
        except (TypeError, ValueError, OverflowError):
            auth_age = policy.max_auth_age_seconds + 1
        if auth_age > policy.max_auth_age_seconds:
            reasons.append("auth_age")

        if policy.allowed_source_cidrs and not ZeroTrustEvaluator._source_allowed(
            str(actual.get("source_ip", "")), policy.allowed_source_cidrs
        ):
            reasons.append("source_ip")

        supplied_permissions = {str(item) for item in actual.get("permissions", ()) if str(item)}
        if any(permission not in supplied_permissions for permission in policy.required_permissions):
            reasons.append("permissions")

        worker_id = str(actual.get("worker_id", ""))
        if policy.allowed_worker_ids and worker_id not in set(policy.allowed_worker_ids):
            reasons.append("worker_id")

        server_id = str(actual.get("server_id", ""))
        if policy.allowed_server_ids and server_id not in set(policy.allowed_server_ids):
            reasons.append("server_id")

        if policy.require_server_relay and actual.get("via_server_relay") is not True:
            reasons.append("server_relay")
        if policy.deny_peer_to_peer and actual.get("peer_to_peer") is True:
            reasons.append("peer_to_peer")

        transport = str(actual.get("transport", "")).strip().casefold()
        if policy.required_transport and transport != policy.required_transport:
            reasons.append("transport")

        if reasons:
            return ZeroTrustDecision(False, "ZERO_TRUST_CONTEXT_DENIED", tuple(sorted(set(reasons))), risk)
        return ZeroTrustDecision(True, "ZERO_TRUST_ALLOW", (), risk)
