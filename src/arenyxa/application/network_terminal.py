from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import asdict
from typing import Any

from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class NetworkProbeResult:
    host: str
    port: int
    connected: bool
    elapsed_ms: float
    peer: str = ""
    local: str = ""
    error: str = ""
    tls: dict[str, Any] | None = None


class NetworkTerminalToolkit:
    """Bounded, local-first network diagnostics for Arenyxa Terminal.

    The toolkit deliberately exposes single-target diagnostics rather than bulk
    scanning primitives. Every network operation is time-bounded and result
    sets are capped so the terminal cannot accidentally become an unbounded
    resource consumer.
    """

    MAX_RESULTS = 128
    MAX_HOST_CHARS = 253
    MIN_TIMEOUT = 0.1
    MAX_TIMEOUT = 30.0

    @classmethod
    def capabilities(cls) -> dict[str, Any]:
        """Return the bounded diagnostics supported by the developer terminal."""
        try:
            import psutil  # type: ignore
        except ImportError:
            psutil_available = False
        else:
            psutil_available = True
        return {
            "resolver": True,
            "reverse_dns": True,
            "tcp_probe": True,
            "tls_probe": True,
            "service_database": True,
            "protocol_database": True,
            "interface_inventory": True,
            "socket_inventory": psutil_available,
            "max_results": cls.MAX_RESULTS,
            "max_timeout_seconds": cls.MAX_TIMEOUT,
        }

    @classmethod
    def resolve(
        cls,
        host: str,
        *,
        port: int = 0,
        family: str = "any",
        socktype: str = "stream",
        limit: int = 64,
    ) -> dict[str, Any]:
        """Resolve one host with explicit family, socket type, and result bounds."""
        target = cls._host(host)
        port_value = cls._port(port, allow_zero=True)
        family_map = {
            "any": socket.AF_UNSPEC,
            "ipv4": socket.AF_INET,
            "ipv6": socket.AF_INET6,
        }
        type_map = {
            "any": 0,
            "stream": socket.SOCK_STREAM,
            "datagram": socket.SOCK_DGRAM,
        }
        family_value = family_map.get(str(family).casefold())
        type_value = type_map.get(str(socktype).casefold())
        if family_value is None:
            raise ValueError("family must be any, ipv4, or ipv6")
        if type_value is None:
            raise ValueError("socktype must be any, stream, or datagram")
        bounded = max(1, min(int(limit), cls.MAX_RESULTS))
        started = time.perf_counter()
        rows = socket.getaddrinfo(target, port_value, family_value, type_value)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        result: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        for family_id, socket_type, protocol, canonname, sockaddr in rows:
            key = (family_id, socket_type, protocol, sockaddr)
            if key in seen:
                continue
            seen.add(key)
            address = str(sockaddr[0]) if sockaddr else ""
            resolved_port = int(sockaddr[1]) if sockaddr and len(sockaddr) > 1 else port_value
            result.append(
                {
                    "family": cls._family_name(family_id),
                    "socket_type": cls._socket_type_name(socket_type),
                    "protocol": int(protocol),
                    "canonical_name": str(canonname or ""),
                    "address": address,
                    "port": resolved_port,
                }
            )
            if len(result) >= bounded:
                break
        return {
            "host": target,
            "port": port_value,
            "elapsed_ms": round(elapsed_ms, 3),
            "result_count": len(result),
            "results": result,
            "truncated": len(seen) > len(result),
        }

    @classmethod
    def reverse(cls, address: str) -> dict[str, Any]:
        """Perform one bounded reverse lookup for an IP address."""
        text = str(address).strip()
        ipaddress.ip_address(text)
        started = time.perf_counter()
        host, aliases, addresses = socket.gethostbyaddr(text)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return {
            "address": text,
            "hostname": host,
            "aliases": list(aliases)[: cls.MAX_RESULTS],
            "addresses": list(addresses)[: cls.MAX_RESULTS],
            "elapsed_ms": round(elapsed_ms, 3),
        }

    @classmethod
    def tcp_probe(cls, host: str, port: int, *, timeout: float = 3.0) -> dict[str, Any]:
        """Probe one TCP endpoint with a bounded connection timeout."""
        target = cls._host(host)
        port_value = cls._port(port)
        timeout_value = cls._timeout(timeout)
        started = time.perf_counter()
        try:
            with socket.create_connection((target, port_value), timeout=timeout_value) as connection:
                peer = cls._endpoint(connection.getpeername())
                local = cls._endpoint(connection.getsockname())
        except OSError as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return asdict(
                NetworkProbeResult(
                    host=target,
                    port=port_value,
                    connected=False,
                    elapsed_ms=round(elapsed_ms, 3),
                    error=cls._safe_error(exc),
                )
            )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return asdict(
            NetworkProbeResult(
                host=target,
                port=port_value,
                connected=True,
                elapsed_ms=round(elapsed_ms, 3),
                peer=peer,
                local=local,
            )
        )

    @classmethod
    def tls_probe(
        cls,
        host: str,
        port: int = 443,
        *,
        timeout: float = 5.0,
        alpn: tuple[str, ...] = ("h2", "http/1.1"),
    ) -> dict[str, Any]:
        """Probe one TLS endpoint with certificate and hostname verification enabled."""
        target = cls._host(host)
        port_value = cls._port(port)
        timeout_value = cls._timeout(timeout)
        context = ssl.create_default_context()
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        requested_alpn = [str(item).strip() for item in alpn if str(item).strip()][:16]
        if requested_alpn:
            context.set_alpn_protocols(requested_alpn)
        started = time.perf_counter()
        try:
            with socket.create_connection((target, port_value), timeout=timeout_value) as raw:
                with context.wrap_socket(raw, server_hostname=target) as connection:
                    certificate = connection.getpeercert() or {}
                    cipher = connection.cipher()
                    tls = {
                        "verified": True,
                        "version": str(connection.version() or ""),
                        "cipher": str(cipher[0]) if cipher else "",
                        "cipher_protocol": str(cipher[1]) if cipher and len(cipher) > 1 else "",
                        "cipher_bits": int(cipher[2]) if cipher and len(cipher) > 2 else 0,
                        "alpn": str(connection.selected_alpn_protocol() or ""),
                        "subject": cls._certificate_name(certificate.get("subject")),
                        "issuer": cls._certificate_name(certificate.get("issuer")),
                        "serial_number": str(certificate.get("serialNumber") or ""),
                        "not_before": str(certificate.get("notBefore") or ""),
                        "not_after": str(certificate.get("notAfter") or ""),
                        "subject_alt_names": [
                            str(value)
                            for kind, value in certificate.get("subjectAltName", ())
                            if str(kind).casefold() in {"dns", "ip address"}
                        ][:64],
                    }
                    peer = cls._endpoint(connection.getpeername())
                    local = cls._endpoint(connection.getsockname())
        except (OSError, ssl.SSLError) as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            return asdict(
                NetworkProbeResult(
                    host=target,
                    port=port_value,
                    connected=False,
                    elapsed_ms=round(elapsed_ms, 3),
                    error=cls._safe_error(exc),
                )
            )
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        return asdict(
            NetworkProbeResult(
                host=target,
                port=port_value,
                connected=True,
                elapsed_ms=round(elapsed_ms, 3),
                peer=peer,
                local=local,
                tls=tls,
            )
        )

    @classmethod
    def interfaces(cls) -> dict[str, Any]:
        """Return a bounded snapshot of local network interfaces."""
        try:
            import psutil  # type: ignore
        except ImportError:
            hostname = socket.gethostname()
            resolved = cls.resolve(hostname, socktype="any", limit=cls.MAX_RESULTS)
            return {"backend": "socket", "interfaces": [{"name": hostname, "addresses": resolved["results"]}]}

        stats = psutil.net_if_stats()
        rows: list[dict[str, Any]] = []
        for name, addresses in psutil.net_if_addrs().items():
            address_rows: list[dict[str, Any]] = []
            for item in addresses[:32]:
                address_rows.append(
                    {
                        "family": cls._family_name(item.family),
                        "address": str(item.address or ""),
                        "netmask": str(item.netmask or ""),
                        "broadcast": str(item.broadcast or ""),
                        "ptp": str(item.ptp or ""),
                    }
                )
            state = stats.get(name)
            rows.append(
                {
                    "name": str(name),
                    "up": bool(state.isup) if state is not None else None,
                    "duplex": int(state.duplex) if state is not None else None,
                    "speed_mbps": int(state.speed) if state is not None else None,
                    "mtu": int(state.mtu) if state is not None else None,
                    "addresses": address_rows,
                }
            )
            if len(rows) >= cls.MAX_RESULTS:
                break
        return {"backend": "psutil", "interface_count": len(rows), "interfaces": rows}

    @classmethod
    def sockets(cls, *, kind: str = "inet", limit: int = 500) -> dict[str, Any]:
        """Return a bounded snapshot of local socket state."""
        try:
            import psutil  # type: ignore
        except ImportError as exc:
            raise RuntimeError("socket inventory requires the optional system process dependency") from exc
        allowed = {"inet", "inet4", "inet6", "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6"}
        kind_value = str(kind).casefold()
        if kind_value not in allowed:
            raise ValueError(f"unsupported socket kind: {kind}")
        bounded = max(1, min(int(limit), 5000))
        rows: list[dict[str, Any]] = []
        for item in psutil.net_connections(kind=kind_value):
            rows.append(
                {
                    "family": cls._family_name(item.family),
                    "type": cls._socket_type_name(item.type),
                    "local": cls._endpoint(item.laddr),
                    "remote": cls._endpoint(item.raddr),
                    "status": str(item.status or ""),
                    "pid": item.pid,
                }
            )
            if len(rows) >= bounded:
                break
        return {"kind": kind_value, "socket_count": len(rows), "truncated": len(rows) >= bounded, "sockets": rows}

    @staticmethod
    def service(port: int, *, protocol: str = "tcp") -> dict[str, Any]:
        """Resolve a local service name for one port and transport protocol."""
        port_value = NetworkTerminalToolkit._port(port)
        proto = str(protocol).casefold()
        if proto not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        try:
            name = socket.getservbyport(port_value, proto)
        except OSError:
            name = ""
        return {"port": port_value, "protocol": proto, "service": name}

    @staticmethod
    def protocol(name: str) -> dict[str, Any]:
        """Resolve one local protocol database entry by name."""
        value = str(name).strip().casefold()
        if not value or len(value) > 64 or not value.replace("-", "").isalnum():
            raise ValueError("invalid protocol name")
        try:
            number = socket.getprotobyname(value)
        except OSError:
            number = None
        return {"name": value, "number": number}

    @classmethod
    def _host(cls, value: str) -> str:
        host = str(value).strip().rstrip(".")
        if not host or len(host) > cls.MAX_HOST_CHARS or any(character.isspace() for character in host):
            raise ValueError("invalid host")
        return host

    @staticmethod
    def _port(value: int, *, allow_zero: bool = False) -> int:
        port = int(value)
        minimum = 0 if allow_zero else 1
        if not minimum <= port <= 65535:
            raise ValueError("port is outside the valid range")
        return port

    @classmethod
    def _timeout(cls, value: float) -> float:
        timeout = float(value)
        if not cls.MIN_TIMEOUT <= timeout <= cls.MAX_TIMEOUT:
            raise ValueError(f"timeout must be between {cls.MIN_TIMEOUT} and {cls.MAX_TIMEOUT} seconds")
        return timeout

    @staticmethod
    def _family_name(value: int) -> str:
        mapping = {
            socket.AF_INET: "ipv4",
            socket.AF_INET6: "ipv6",
            getattr(socket, "AF_LINK", -10000): "link",
            getattr(socket, "AF_PACKET", -10001): "packet",
            socket.AF_UNSPEC: "unspecified",
        }
        return mapping.get(value, str(value))

    @staticmethod
    def _socket_type_name(value: int) -> str:
        masked = int(value) & 0xF
        mapping = {socket.SOCK_STREAM: "stream", socket.SOCK_DGRAM: "datagram", socket.SOCK_RAW: "raw"}
        return mapping.get(masked, str(value))

    @staticmethod
    def _endpoint(value: Any) -> str:
        if not value:
            return ""
        if hasattr(value, "ip"):
            address = str(value.ip)
            port = int(value.port) if getattr(value, "port", None) is not None else None
        elif isinstance(value, (tuple, list)) and value:
            address = str(value[0])
            port = int(value[1]) if len(value) > 1 and value[1] is not None else None
        else:
            return str(value)
        if port is None:
            return address
        return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"

    @staticmethod
    def _safe_error(exc: BaseException) -> str:
        text = str(exc).replace("\r", " ").replace("\n", " ").strip()
        return text[:512] or type(exc).__name__

    @staticmethod
    def _certificate_name(value: Any) -> str:
        if not isinstance(value, (tuple, list)):
            return ""
        parts: list[str] = []
        for group in value:
            if not isinstance(group, (tuple, list)):
                continue
            for pair in group:
                if isinstance(pair, (tuple, list)) and len(pair) >= 2:
                    parts.append(f"{pair[0]}={pair[1]}")
        return ", ".join(parts)[:2048]
