from __future__ import annotations

import re
import threading
import urllib.parse
from dataclasses import field
from typing import Any, Mapping

from arenyxa.compat import StrEnum, dataclass


class DlpMode(StrEnum):
    """Select monitor-only or enforcing data-loss-prevention behavior."""
    OFF = "off"
    MONITOR = "monitor"
    ENFORCE = "enforce"


@dataclass(frozen=True, slots=True)
class DlpFinding:
    """Describe one redacted DLP signal without retaining the matched secret value."""
    kind: str
    location: str
    severity: str


@dataclass(frozen=True, slots=True)
class DlpDecision:
    """Return the bounded DLP decision and finding metadata for one outbound payload."""
    allowed: bool
    code: str
    findings: tuple[DlpFinding, ...] = field(default_factory=tuple)
    destination_host: str = ""


@dataclass(frozen=True, slots=True)
class DlpPolicy:
    """Configure trusted destinations, scan budgets, and blocking rules for DLP."""
    mode: DlpMode = DlpMode.MONITOR
    trusted_domains: tuple[str, ...] = ()
    block_plaintext_secrets: bool = True
    block_private_keys: bool = True
    max_scan_chars: int = 256 * 1024


_SECRET_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-access-token",
})
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization)\s*[:=]\s*[^\s,;&]{6,}"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")


class DataLossPreventionEngine:
    """Central outbound DLP classifier with monitor and enforce modes.

    It never records secret values. Findings contain only category, location and
    severity. Enforcement is intentionally policy-driven because authorized
    security tooling frequently needs to transmit credentials to expected hosts.
    """

    def __init__(self, policy: DlpPolicy | None = None) -> None:
        self._lock = threading.RLock()
        self._policy = policy or DlpPolicy()
        self._last_decision = DlpDecision(True, "DLP_NO_FINDINGS")

    def policy(self) -> DlpPolicy:
        with self._lock:
            return self._policy

    def configure(self, policy: DlpPolicy) -> None:
        if not isinstance(policy, DlpPolicy):
            raise TypeError("policy must be a DlpPolicy")
        with self._lock:
            self._policy = policy

    def last_decision(self) -> DlpDecision:
        with self._lock:
            return self._last_decision

    @staticmethod
    def _host(url: str) -> str:
        try:
            return str(urllib.parse.urlsplit(str(url)).hostname or "").strip().casefold()
        except ValueError:
            return ""

    @staticmethod
    def _trusted(host: str, trusted_domains: tuple[str, ...]) -> bool:
        normalized = host.casefold().rstrip(".")
        for item in trusted_domains:
            domain = str(item).strip().casefold().lstrip(".").rstrip(".")
            if domain and (normalized == domain or normalized.endswith("." + domain)):
                return True
        return False

    def inspect_http(
        self,
        *,
        url: str,
        headers: Mapping[str, Any] | None = None,
        cookies: Mapping[str, Any] | None = None,
        body: str | bytes | None = None,
    ) -> DlpDecision:
        with self._lock:
            policy = self._policy
        host = self._host(url)
        if policy.mode == DlpMode.OFF:
            decision = DlpDecision(True, "DLP_DISABLED", destination_host=host)
            with self._lock:
                self._last_decision = decision
            return decision

        findings: list[DlpFinding] = []
        for name in (headers or {}):
            if str(name).strip().casefold() in _SECRET_HEADER_NAMES:
                findings.append(DlpFinding("credential", "header", "high"))
        if cookies:
            findings.append(DlpFinding("session-cookie", "cookie", "high"))

        if isinstance(body, bytes):
            sample = body[: policy.max_scan_chars].decode("utf-8", errors="replace")
        else:
            sample = str(body or "")[: policy.max_scan_chars]
        if sample:
            if _PRIVATE_KEY.search(sample):
                findings.append(DlpFinding("private-key", "body", "critical"))
            if _SECRET_ASSIGNMENT.search(sample):
                findings.append(DlpFinding("credential", "body", "high"))

        if not findings:
            decision = DlpDecision(True, "DLP_NO_FINDINGS", destination_host=host)
        else:
            trusted = self._trusted(host, policy.trusted_domains)
            scheme = urllib.parse.urlsplit(str(url)).scheme.casefold()
            critical = any(item.severity == "critical" for item in findings)
            secret = any(item.kind in {"credential", "session-cookie"} for item in findings)
            should_block = (
                policy.mode == DlpMode.ENFORCE
                and not trusted
                and ((critical and policy.block_private_keys) or (secret and policy.block_plaintext_secrets and scheme != "https"))
            )
            decision = DlpDecision(
                not should_block,
                "DLP_EGRESS_BLOCKED" if should_block else "DLP_FINDINGS_MONITORED",
                tuple(findings),
                destination_host=host,
            )
        with self._lock:
            self._last_decision = decision
        return decision


GLOBAL_DLP_ENGINE = DataLossPreventionEngine()
