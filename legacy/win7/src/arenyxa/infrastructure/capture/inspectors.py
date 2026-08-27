from __future__ import annotations

import socket
import ssl
import time
from dataclasses import field
from arenyxa.compat import dataclass
from typing import Any, Dict, cast


@dataclass(slots=True)
class TlsReport:
    host: str
    port: int
    tls_version: str
    cipher: str
    bits: int
    handshake_ms: float
    subject: dict[str, str]
    issuer: dict[str, str]
    serial_number: str
    not_before: str
    not_after: str
    san: list[str]


class TlsInspector:
    @staticmethod
    def inspect(host: str, port: int = 443, timeout: float = 10.0) -> TlsReport:
        context = ssl.create_default_context()
        started = time.perf_counter()
                                                                                          
                                                                                          
                                                    
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                certificate = cast(Dict[str, Any], secure.getpeercert() or {})
                cipher = secure.cipher() or ("unknown", "", 0)
                version = secure.version() or "unknown"
        elapsed = (time.perf_counter() - started) * 1000
        subject = {key: value for group in certificate.get("subject", []) for key, value in group}
        issuer = {key: value for group in certificate.get("issuer", []) for key, value in group}
        san = [value for name, value in certificate.get("subjectAltName", []) if name == "DNS"]
        return TlsReport(
            host=host,
            port=port,
            tls_version=version,
            cipher=str(cipher[0]),
            bits=int(cipher[2] or 0),
            handshake_ms=elapsed,
            subject=subject,
            issuer=issuer,
            serial_number=str(certificate.get("serialNumber", "")),
            not_before=str(certificate.get("notBefore", "")),
            not_after=str(certificate.get("notAfter", "")),
            san=san,
        )


@dataclass(slots=True)
class DnsReport:
    host: str
    elapsed_ms: float
    addresses: list[dict[str, Any]] = field(default_factory=list)
    canonical_name: str = ""
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


class DnsAnalyzer:
    @staticmethod
    def resolve(host: str, port: int = 443) -> DnsReport:
        started = time.perf_counter()
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        elapsed = (time.perf_counter() - started) * 1000
        addresses = []
        seen = set()
        canonical = ""
        for family, socktype, proto, canonname, sockaddr in records:
            address = sockaddr[0]
            key = (family, address)
            if key in seen:
                continue
            seen.add(key)
            canonical = canonical or canonname
            addresses.append(
                {
                    "type": "AAAA" if family == socket.AF_INET6 else "A",
                    "address": address,
                    "port": sockaddr[1],
                }
            )
        report = DnsReport(host=host, elapsed_ms=elapsed, addresses=addresses, canonical_name=canonical)
        try:
            import dns.resolver

            resolver = dns.resolver.Resolver()
            resolver.timeout = 2.5
            resolver.lifetime = 5.0
            for record_type in ("A", "AAAA", "CNAME", "MX", "TXT", "NS"):
                try:
                    answer = resolver.resolve(host, record_type, raise_on_no_answer=False)
                    report.records[record_type] = [item.to_text() for item in answer]
                except Exception as exc:                                                                 
                    report.errors[record_type] = type(exc).__name__
        except ImportError:
            report.errors["extended"] = "dnspython_not_installed"
        return report
