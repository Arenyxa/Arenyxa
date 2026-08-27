from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import ipaddress
import socket
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from arenyxa.domain.errors import ArenyxaError


@dataclass(slots=True)
class NetworkGuardPolicy:
    enabled: bool = True
    max_concurrent_connections: int = 128
    max_global_connects_per_minute: int = 1200
    max_target_connects_per_minute: int = 240
    max_distinct_targets_per_minute: int = 512
    max_tracked_targets: int = 2048
    max_resolved_addresses: int = 16
    block_cloud_metadata: bool = True
    block_unspecified_or_multicast: bool = True
    block_private_or_loopback: bool = False
    protected_hosts: tuple[str, ...] = (
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
        "metadata.google.internal",
        "metadata.google.internal.",
    )

    def validate(self) -> None:
        if self.max_concurrent_connections < 1 or self.max_concurrent_connections > 4096:
            raise ValueError("max_concurrent_connections is outside the safe range")
        if self.max_global_connects_per_minute < 1 or self.max_global_connects_per_minute > 1_000_000:
            raise ValueError("max_global_connects_per_minute is outside the safe range")
        if self.max_target_connects_per_minute < 1 or self.max_target_connects_per_minute > 100_000:
            raise ValueError("max_target_connects_per_minute is outside the safe range")
        if self.max_distinct_targets_per_minute < 1 or self.max_distinct_targets_per_minute > 100_000:
            raise ValueError("max_distinct_targets_per_minute is outside the safe range")
        if self.max_tracked_targets < self.max_distinct_targets_per_minute or self.max_tracked_targets > 1_000_000:
            raise ValueError("max_tracked_targets must cover the distinct-target window and remain bounded")
        if self.max_resolved_addresses < 1 or self.max_resolved_addresses > 256:
            raise ValueError("max_resolved_addresses is outside the safe range")


@dataclass(slots=True)
class _Window:
    started: float
    count: int = 0
    last_seen: float = 0.0


class NetworkUseGuard:
    def __init__(self, policy: NetworkGuardPolicy | None = None) -> None:
        self.policy = policy or NetworkGuardPolicy()
        self.policy.validate()
        self._lock = threading.RLock()
        now = time.monotonic()
        self._active = 0
        self._global = _Window(now, last_seen=now)
        self._fanout = _Window(now, last_seen=now)
        self._targets: dict[str, _Window] = {}

    def _fail(self, code: str, message: str, **context: object) -> ArenyxaError:
        return ArenyxaError(code, message, domain="NETWORK_GOVERNANCE", context=dict(context))

    @staticmethod
    def _normalized_host(host: str) -> str:
        normalized = str(host).strip().rstrip(".").casefold()
        if not normalized or len(normalized) > 253:
            return ""
        if any(ord(ch) < 33 or ord(ch) == 127 for ch in normalized):
            return ""
        return normalized

    @staticmethod
    def _roll(window: _Window, now: float) -> bool:
        if now - window.started >= 60.0:
            window.started = now
            window.count = 0
            window.last_seen = now
            return True
        window.last_seen = now
        return False

    def _cleanup_targets(self, now: float) -> None:
        stale = [key for key, window in self._targets.items() if now - max(window.last_seen, window.started) >= 120.0]
        for key in stale:
            self._targets.pop(key, None)
        if len(self._targets) <= self.policy.max_tracked_targets:
            return
        ordered = sorted(self._targets.items(), key=lambda item: max(item[1].last_seen, item[1].started))
        remove_count = len(self._targets) - self.policy.max_tracked_targets
        for key, _window in ordered[:remove_count]:
            self._targets.pop(key, None)

    def _protected(self, normalized: str, address: ipaddress._BaseAddress | None = None) -> bool:
        protected = {self._normalized_host(item) for item in self.policy.protected_hosts}
        if normalized in protected:
            return True
        if address is None:
            return False
        return str(address).casefold() in protected

    def _resolve(self, host: str) -> list[ipaddress._BaseAddress]:
        normalized = self._normalized_host(host)
        if not normalized:
            raise self._fail("NETWORK_TARGET_INVALID", "Network target host is empty or malformed")
        if self.policy.block_cloud_metadata and self._protected(normalized):
            raise self._fail(
                "NETWORK_PROTECTED_TARGET",
                "Protected metadata endpoint is blocked by the network governance policy",
                host=host,
            )
        try:
            return [ipaddress.ip_address(normalized)]
        except ValueError:
            record_current_exception(__name__, 'NetworkUseGuard._resolve:120')
        try:
            rows = socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise self._fail("NETWORK_TARGET_RESOLUTION_FAILED", "Network target could not be resolved", host=host) from exc
        addresses: list[ipaddress._BaseAddress] = []
        for row in rows:
            try:
                address = ipaddress.ip_address(row[4][0])
            except (ValueError, IndexError, TypeError):
                continue
            if address not in addresses:
                addresses.append(address)
                if len(addresses) >= self.policy.max_resolved_addresses:
                    break
        if not addresses:
            raise self._fail("NETWORK_TARGET_RESOLUTION_FAILED", "Network target did not resolve to a usable address", host=host)
        return addresses

    def _validate_addresses(self, host: str, normalized: str, addresses: list[ipaddress._BaseAddress]) -> None:
        for address in addresses:
            if self.policy.block_cloud_metadata and self._protected(normalized, address):
                raise self._fail(
                    "NETWORK_PROTECTED_TARGET",
                    "Cloud metadata endpoint is blocked by the network governance policy",
                    host=host,
                    address=str(address),
                )
            if self.policy.block_unspecified_or_multicast and (address.is_unspecified or address.is_multicast):
                raise self._fail(
                    "NETWORK_SPECIAL_TARGET_BLOCKED",
                    "Unspecified or multicast targets are blocked by the network governance policy",
                    host=host,
                    address=str(address),
                )
            if self.policy.block_private_or_loopback and (address.is_private or address.is_loopback or address.is_link_local):
                raise self._fail(
                    "NETWORK_PRIVATE_TARGET_BLOCKED",
                    "Private, loopback, or link-local targets are blocked for this network exposure mode",
                    host=host,
                    address=str(address),
                )

    def check_target(self, host: str, *, resolve_dns: bool = True) -> None:
        if not self.policy.enabled:
            return
        normalized = self._normalized_host(host)
        if not normalized:
            raise self._fail("NETWORK_TARGET_INVALID", "Network target host is empty or malformed")
        if self.policy.block_cloud_metadata and self._protected(normalized):
            raise self._fail(
                "NETWORK_PROTECTED_TARGET",
                "Protected metadata endpoint is blocked by the network governance policy",
                host=host,
            )
        if not resolve_dns:
            try:
                addresses = [ipaddress.ip_address(normalized)]
            except ValueError:
                return
        else:
            addresses = self._resolve(host)
        self._validate_addresses(host, normalized, addresses)

    @contextmanager
    def connection_candidates(self, host: str) -> Iterator[tuple[str, ...]]:
        if not self.policy.enabled:
            yield (str(host),)
            return
        key = self._normalized_host(host)
        addresses = self._resolve(host)
        self._validate_addresses(host, key, addresses)
        candidates = tuple(str(address) for address in addresses)
        now = time.monotonic()
        with self._lock:
            global_rolled = self._roll(self._global, now)
            fanout_rolled = self._roll(self._fanout, now)
            if global_rolled or fanout_rolled:
                self._cleanup_targets(now)
            target = self._targets.get(key)
            if target is None:
                if self._fanout.count >= self.policy.max_distinct_targets_per_minute:
                    raise self._fail(
                        "NETWORK_TARGET_FANOUT_LIMIT",
                        "Distinct-target network budget reached",
                        tracked_targets=len(self._targets),
                    )
                if len(self._targets) >= self.policy.max_tracked_targets:
                    self._cleanup_targets(now)
                if len(self._targets) >= self.policy.max_tracked_targets:
                    raise self._fail(
                        "NETWORK_TARGET_TRACKING_LIMIT",
                        "Network target tracking capacity reached",
                        tracked_targets=len(self._targets),
                    )
                target = _Window(now, last_seen=now)
                self._targets[key] = target
                self._fanout.count += 1
            self._roll(target, now)
            if self._active >= self.policy.max_concurrent_connections:
                raise self._fail("NETWORK_CONCURRENCY_LIMIT", "Network concurrency safety limit reached", active=self._active)
            if self._global.count >= self.policy.max_global_connects_per_minute:
                raise self._fail("NETWORK_GLOBAL_RATE_LIMIT", "Global network connection budget reached")
            if target.count >= self.policy.max_target_connects_per_minute:
                raise self._fail("NETWORK_TARGET_RATE_LIMIT", "Per-target network connection budget reached", host=host)
            self._active += 1
            self._global.count += 1
            target.count += 1
            target.last_seen = now
        try:
            yield candidates
        finally:
            with self._lock:
                self._active = max(0, self._active - 1)

    @contextmanager
    def connection(self, host: str) -> Iterator[str]:
        with self.connection_candidates(host) as candidates:
            yield candidates[0]

    def snapshot(self) -> dict[str, int | bool]:
        with self._lock:
            now = time.monotonic()
            self._roll(self._global, now)
            self._roll(self._fanout, now)
            self._cleanup_targets(now)
            return {
                "enabled": self.policy.enabled,
                "active_connections": self._active,
                "global_connects_current_window": self._global.count,
                "distinct_targets_current_window": self._fanout.count,
                "tracked_targets": len(self._targets),
                "max_tracked_targets": self.policy.max_tracked_targets,
                "max_concurrent_connections": self.policy.max_concurrent_connections,
                "max_global_connects_per_minute": self.policy.max_global_connects_per_minute,
                "max_target_connects_per_minute": self.policy.max_target_connects_per_minute,
                "max_distinct_targets_per_minute": self.policy.max_distinct_targets_per_minute,
                "max_resolved_addresses": self.policy.max_resolved_addresses,
                "block_cloud_metadata": self.policy.block_cloud_metadata,
                "block_private_or_loopback": self.policy.block_private_or_loopback,
            }
