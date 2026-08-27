"""Policy-safe anti-bot diagnostics for authorized Arenyxa crawler jobs.

This module classifies blocking/rate-limit/session/browser requirements and recommends
safe recovery actions.  It deliberately does not solve CAPTCHAs, forge identities,
or bypass access controls.
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Mapping

from arenyxa.domain.models import FetchResponse


class BlockKind(str, Enum):
    NONE = "NONE"
    RATE_LIMITED = "RATE_LIMITED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    PROXY_AUTH_REQUIRED = "PROXY_AUTH_REQUIRED"
    REQUEST_REJECTED = "REQUEST_REJECTED"
    JS_REQUIRED = "JS_REQUIRED"
    CAPTCHA_PRESENT = "CAPTCHA_PRESENT"
    BOT_CHALLENGE_PRESENT = "BOT_CHALLENGE_PRESENT"
    ROBOTS_DISALLOWED = "ROBOTS_DISALLOWED"
    TLS_INCOMPATIBLE = "TLS_INCOMPATIBLE"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    REDIRECT_LOOP = "REDIRECT_LOOP"
    UNEXPECTED_HTML = "UNEXPECTED_HTML"
    UNKNOWN_BLOCK = "UNKNOWN_BLOCK"


class SafeAction(str, Enum):
    CONTINUE = "continue"
    THROTTLE = "throttle"
    BACKOFF = "backoff"
    REFRESH_SESSION = "refresh-session"
    REQUIRE_AUTH = "require-auth"
    REEVALUATE_PROXY = "reevaluate-proxy"
    BROWSER_RENDER = "browser-render"
    OPERATOR_INTERVENTION = "operator-intervention"
    STOP = "stop"


@dataclass(slots=True)
class BlockAssessment:
    kind: BlockKind
    confidence: float
    actions: list[SafeAction] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    retry_after_seconds: float | None = None
    status: int = 0

    @property
    def blocked(self) -> bool:
        return self.kind is not BlockKind.NONE

    def snapshot(self) -> dict[str, object]:
        value = asdict(self)
        value["kind"] = self.kind.value
        value["actions"] = [x.value for x in self.actions]
        return value


@dataclass(slots=True)
class ClientProfile:
    """Internally-consistent, explicit client metadata; no fingerprint spoofing."""
    name: str = "arenyxa-default"
    user_agent: str = ""
    accept: str = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"
    accept_language: str = "en-US,en;q=0.8"
    extra_headers: dict[str, str] = field(default_factory=dict)

    def headers(self) -> dict[str, str]:
        out = {"Accept": self.accept, "Accept-Language": self.accept_language}
        if self.user_agent:
            out["User-Agent"] = self.user_agent
        reserved = {"accept", "accept-language", "user-agent"}
        for k, v in list(self.extra_headers.items())[:64]:
            name, content = str(k), str(v)
            if "\r" in name + content or "\n" in name + content:
                raise ValueError("Client profile headers cannot contain CR/LF")
            if name.casefold() in reserved:
                raise ValueError(f"Client profile reserved header must use its dedicated field: {name}")
            out[name] = content
        return out

    def browser_settings(self) -> dict[str, str]:
        locale = str(self.accept_language or "en-US").split(",", 1)[0].split(";", 1)[0].strip() or "en-US"
        return {"user_agent": str(self.user_agent or ""), "locale": locale[:64]}


class AntiBotIntelligenceEngine:
    _CAPTCHA = re.compile(r"\b(captcha|hcaptcha|recaptcha|turnstile)\b", re.I)
    _BOT_CHALLENGE = re.compile(
        r"(checking your browser|verify (?:that )?you are human|challenge-platform|cf-chl-|bot (?:check|challenge|detection)|automated traffic)",
        re.I,
    )
    _JS = re.compile(r"(enable javascript|javascript (?:is )?required|requires javascript)", re.I)
    _SESSION = re.compile(r"(session (?:has )?expired|invalid session|cookie(?:s)? required)", re.I)
    _BLOCK = re.compile(r"(access denied|request blocked|forbidden|temporarily blocked)", re.I)

    def __init__(self, *, body_scan_bytes: int = 256 * 1024, max_redirects: int = 20) -> None:
        self.body_scan_bytes = max(4096, min(1024 * 1024, int(body_scan_bytes)))
        self.max_redirects = max(3, min(100, int(max_redirects)))

    @staticmethod
    def _retry_after(headers: Mapping[str, str]) -> float | None:
        raw = next((v for k, v in headers.items() if k.casefold() == "retry-after"), "").strip()
        try:
            return max(0.0, min(86400.0, float(raw))) if raw else None
        except ValueError:
            return None

    def assess(self, response: FetchResponse, *, expected_content: str = "") -> BlockAssessment:
        status = int(response.status or 0)
        retry_after = self._retry_after(response.headers)
        sample = response.body[: self.body_scan_bytes].decode(response.encoding or "utf-8", errors="replace") if response.body else ""
        lower_ct = (response.content_type or "").casefold()
        evidence: list[str] = []

        if len(response.redirect_chain) > self.max_redirects or len(set(response.redirect_chain)) < len(response.redirect_chain):
            return BlockAssessment(BlockKind.REDIRECT_LOOP, .98, [SafeAction.STOP], ["redirect chain repeats/exceeds bound"], status=status)
        if status == 429:
            evidence.append("HTTP 429")
            if retry_after is not None: evidence.append(f"Retry-After={retry_after:g}s")
            return BlockAssessment(BlockKind.RATE_LIMITED, .99, [SafeAction.THROTTLE, SafeAction.BACKOFF], evidence, retry_after, status)
        if status == 407:
            return BlockAssessment(BlockKind.PROXY_AUTH_REQUIRED, .99, [SafeAction.REEVALUATE_PROXY, SafeAction.STOP], ["HTTP 407"], status=status)
        if status == 401:
            return BlockAssessment(BlockKind.AUTH_REQUIRED, .99, [SafeAction.REQUIRE_AUTH, SafeAction.STOP], ["HTTP 401"], status=status)
        if self._CAPTCHA.search(sample):
            return BlockAssessment(BlockKind.CAPTCHA_PRESENT, .98, [SafeAction.OPERATOR_INTERVENTION, SafeAction.STOP], ["human-verification marker detected"], status=status)
        if self._BOT_CHALLENGE.search(sample):
            return BlockAssessment(
                BlockKind.BOT_CHALLENGE_PRESENT,
                .96,
                [SafeAction.BACKOFF, SafeAction.OPERATOR_INTERVENTION, SafeAction.STOP],
                ["anti-bot challenge marker detected"],
                status=status,
            )
        if self._SESSION.search(sample) and status in {200, 401, 403, 409, 423}:
            return BlockAssessment(BlockKind.SESSION_EXPIRED, .90, [SafeAction.REFRESH_SESSION, SafeAction.OPERATOR_INTERVENTION], ["session/cookie rejection marker"], status=status)
        if self._JS.search(sample) and status in {200, 403, 503}:
            return BlockAssessment(BlockKind.JS_REQUIRED, .91, [SafeAction.BROWSER_RENDER], ["JavaScript-required marker"], status=status)
        if status == 403:
            return BlockAssessment(BlockKind.REQUEST_REJECTED, .94, [SafeAction.BACKOFF, SafeAction.OPERATOR_INTERVENTION], ["HTTP 403"], status=status)
        if status in {423}:
            return BlockAssessment(BlockKind.REQUEST_REJECTED, .90, [SafeAction.BACKOFF, SafeAction.OPERATOR_INTERVENTION], [f"HTTP {status}"], status=status)
        if status == 503:
            return BlockAssessment(BlockKind.SERVICE_UNAVAILABLE, .88, [SafeAction.BACKOFF], ["HTTP 503"], retry_after, status)
        if self._BLOCK.search(sample) and status >= 400:
            return BlockAssessment(BlockKind.UNKNOWN_BLOCK, .80, [SafeAction.BACKOFF, SafeAction.OPERATOR_INTERVENTION], ["blocking response marker"], status=status)
        if expected_content and "json" in expected_content.casefold() and "html" in lower_ct:
            return BlockAssessment(BlockKind.UNEXPECTED_HTML, .78, [SafeAction.OPERATOR_INTERVENTION], [f"expected {expected_content}, received {response.content_type}"], status=status)
        return BlockAssessment(BlockKind.NONE, 1.0, [SafeAction.CONTINUE], status=status)

    def assess_exception(self, exc: BaseException) -> BlockAssessment:
        text = f"{type(exc).__name__}: {exc}".casefold()
        if any(x in text for x in ("ssl", "tls", "certificate", "handshake")):
            return BlockAssessment(BlockKind.TLS_INCOMPATIBLE, .85, [SafeAction.STOP, SafeAction.OPERATOR_INTERVENTION], [type(exc).__name__])
        if "proxy" in text:
            return BlockAssessment(BlockKind.UNKNOWN_BLOCK, .70, [SafeAction.REEVALUATE_PROXY], [type(exc).__name__])
        return BlockAssessment(BlockKind.UNKNOWN_BLOCK, .45, [SafeAction.BACKOFF], [type(exc).__name__])

@dataclass(slots=True)
class HumanVerificationTicket:
    """Opaque operator-intervention ticket for an encountered human challenge.

    The ticket records the challenge and operator decision only; Arenyxa does not
    solve or bypass the challenge itself.
    """
    ticket_id: str
    target_sha256: str
    kind: BlockKind
    created_at: float
    expires_at: float
    state: str = "pending"
    operator_id: str = ""

    def snapshot(self) -> dict[str, object]:
        return {
            "ticket_id": self.ticket_id,
            "target_sha256": self.target_sha256,
            "kind": self.kind.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "state": self.state,
            "operator_id": self.operator_id,
        }


class HumanVerificationCoordinator:
    """Bounded manual-verification queue used when CAPTCHA/challenges are detected."""

    def __init__(self, *, ttl_seconds: float = 900.0, max_pending: int = 1024) -> None:
        self.ttl_seconds = max(30.0, min(float(ttl_seconds), 86400.0))
        self.max_pending = max(1, min(int(max_pending), 100_000))
        self._tickets: dict[str, HumanVerificationTicket] = {}
        self._lock = threading.RLock()

    def issue(self, target_url: str, assessment: BlockAssessment) -> HumanVerificationTicket:
        if assessment.kind not in {BlockKind.CAPTCHA_PRESENT, BlockKind.BOT_CHALLENGE_PRESENT}:
            raise ValueError("Human verification tickets are only issued for detected CAPTCHA/anti-bot challenge responses")
        now = time.time()
        with self._lock:
            self._expire_locked(now)
            if len(self._tickets) >= self.max_pending:
                raise RuntimeError("Human verification queue is full")
            ticket = HumanVerificationTicket(
                ticket_id=f"human_{uuid.uuid4().hex}",
                target_sha256=hashlib.sha256(str(target_url).encode("utf-8")).hexdigest(),
                kind=assessment.kind,
                created_at=now,
                expires_at=now + self.ttl_seconds,
            )
            self._tickets[ticket.ticket_id] = ticket
            return ticket

    def resolve(self, ticket_id: str, *, operator_id: str, approved: bool) -> HumanVerificationTicket:
        now = time.time()
        with self._lock:
            self._expire_locked(now)
            ticket = self._tickets.get(str(ticket_id))
            if ticket is None:
                raise KeyError("Unknown or expired human verification ticket")
            if ticket.state != "pending":
                raise RuntimeError("Human verification ticket is already terminal")
            actor = str(operator_id).strip()[:256]
            if not actor:
                raise ValueError("operator_id is required")
            ticket.operator_id = actor
            ticket.state = "approved" if bool(approved) else "rejected"
            return ticket

    def pending(self) -> list[HumanVerificationTicket]:
        now = time.time()
        with self._lock:
            self._expire_locked(now)
            return [ticket for ticket in self._tickets.values() if ticket.state == "pending"]

    def _expire_locked(self, now: float) -> None:
        for ticket in self._tickets.values():
            if ticket.state == "pending" and ticket.expires_at <= now:
                ticket.state = "expired"

@dataclass(slots=True)
class _HostPenalty:
    failures: int = 0
    retry_at: float = 0.0
    last_kind: BlockKind = BlockKind.NONE


class AntiBotHostGovernor:
    """Conservative per-host backoff state driven by AntiBot assessments.

    It never changes identity/fingerprints or attempts to defeat a challenge. Its
    only automated behavior is slowing down or pausing future requests.
    """

    def __init__(self, *, max_hosts: int = 4096, max_backoff_seconds: float = 60.0) -> None:
        self.max_hosts = max(16, min(int(max_hosts), 100_000))
        self.max_backoff_seconds = max(1.0, min(float(max_backoff_seconds), 3600.0))
        self._hosts: dict[str, _HostPenalty] = {}
        self._lock = threading.RLock()

    def observe(self, host: str, assessment: BlockAssessment) -> None:
        key = str(host or "").strip().casefold().rstrip(".")
        if not key:
            return
        now = time.monotonic()
        with self._lock:
            if key not in self._hosts and len(self._hosts) >= self.max_hosts:
                oldest = min(self._hosts.items(), key=lambda item: item[1].retry_at)[0]
                self._hosts.pop(oldest, None)
            state = self._hosts.setdefault(key, _HostPenalty())
            state.last_kind = assessment.kind
            if assessment.kind is BlockKind.NONE:
                state.failures = max(0, state.failures - 1)
                if state.failures == 0:
                    state.retry_at = 0.0
                return
            if assessment.kind is BlockKind.RATE_LIMITED:
                state.failures = min(16, state.failures + 1)
                requested = float(assessment.retry_after_seconds or 0.0)
                delay = requested if requested > 0 else min(self.max_backoff_seconds, 0.75 * (2 ** (state.failures - 1)))
                state.retry_at = max(state.retry_at, now + min(self.max_backoff_seconds, delay))
            elif assessment.kind in {BlockKind.SERVICE_UNAVAILABLE, BlockKind.REQUEST_REJECTED}:
                state.failures = min(16, state.failures + 1)
                delay = min(self.max_backoff_seconds, 0.5 * (2 ** (state.failures - 1)))
                state.retry_at = max(state.retry_at, now + delay)

    def wait_seconds(self, host: str) -> float:
        key = str(host or "").strip().casefold().rstrip(".")
        with self._lock:
            state = self._hosts.get(key)
            if state is None:
                return 0.0
            return max(0.0, state.retry_at - time.monotonic())

    def snapshot(self) -> dict[str, dict[str, object]]:
        now = time.monotonic()
        with self._lock:
            return {
                host: {
                    "failures": state.failures,
                    "retry_in_seconds": round(max(0.0, state.retry_at - now), 3),
                    "last_kind": state.last_kind.value,
                }
                for host, state in self._hosts.items()
            }

