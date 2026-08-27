"""RFC 8484 DNS-over-HTTPS resolver for crawler diagnostics and policy use."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from arenyxa.domain.errors import ArenyxaError
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


@dataclass(slots=True)
class DoHConfig:
    endpoint: str = "https://cloudflare-dns.com/dns-query"
    timeout_seconds: float = 8.0
    max_addresses: int = 16

    def normalized(self) -> "DoHConfig":
        parsed = urlsplit(str(self.endpoint).strip())
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("DoH endpoint must be an https URL")
        return DoHConfig(
            endpoint=str(self.endpoint).strip(),
            timeout_seconds=max(0.5, min(float(self.timeout_seconds), 60.0)),
            max_addresses=max(1, min(int(self.max_addresses), 64)),
        )


class DoHResolver:
    """Resolve A/AAAA records over HTTPS without changing global OS DNS state."""

    def __init__(self, config: DoHConfig | None = None, *, network_policy: NetworkGuardPolicy | None = None) -> None:
        self.config = (config or DoHConfig()).normalized()
        self.guard = NetworkUseGuard(network_policy or NetworkGuardPolicy())

    def resolve(self, host: str) -> tuple[str, ...]:
        value = str(host).strip().rstrip(".").casefold()
        if not value:
            raise ValueError("DoH host is empty")
        try:
            direct = str(ipaddress.ip_address(value))
        except ValueError:
            direct = ""
        if direct:
            return (direct,)
        endpoint = urlsplit(self.config.endpoint)
        assert endpoint.hostname is not None
        self.guard.check_target(endpoint.hostname, resolve_dns=True)
        try:
            import dns.exception
            import dns.message
            import dns.query
            import dns.rdatatype
        except ImportError as exc:
            raise ArenyxaError(
                "DOH_RUNTIME_UNAVAILABLE", "DNS-over-HTTPS requires the analysis extra (dnspython)", domain="CRAWLER"
            ) from exc
        addresses: list[str] = []
        for rdtype in ("A", "AAAA"):
            query = dns.message.make_query(value, rdtype)
            try:
                response = dns.query.https(query, self.config.endpoint, timeout=self.config.timeout_seconds)
            except (dns.exception.DNSException, OSError, RuntimeError, TimeoutError, ValueError) as exc:
                if addresses:
                    break
                raise ArenyxaError("DOH_RESOLUTION_FAILED", f"DoH resolution failed: {type(exc).__name__}", domain="CRAWLER", retryable=True) from exc
            for answer in response.answer:
                for item in answer:
                    text = str(item).strip()
                    try:
                        address = str(ipaddress.ip_address(text))
                    except ValueError:
                        continue
                    if address not in addresses:
                        addresses.append(address)
                        if len(addresses) >= self.config.max_addresses:
                            break
                if len(addresses) >= self.config.max_addresses:
                    break
        if not addresses:
            raise ArenyxaError("DOH_NO_ADDRESS", "DoH response contained no usable A/AAAA addresses", domain="CRAWLER")
        # Reuse Arenyxa governance semantics for special/private destinations.
        self.guard._validate_addresses(value, value, [ipaddress.ip_address(v) for v in addresses])
        return tuple(addresses)
