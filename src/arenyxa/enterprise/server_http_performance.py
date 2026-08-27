from __future__ import annotations

import http.client
import json
import math
import socket
import ssl
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from arenyxa.enterprise.server_api import MAX_SERVER_INFLIGHT_REQUESTS, create_enterprise_server_app


@dataclass(slots=True)
class ServerHTTPConcurrencyLevel:
    clients: int
    requests: int
    duration_seconds: float
    throughput_requests_per_second: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    errors: int
    status_counts: dict[str, int]
    tls_versions: dict[str, int]
    stable: bool


@dataclass(slots=True)
class ServerHTTPPerformanceReport:
    schema: str
    stable: bool
    tls_minimum: str
    requests_per_level: int
    recommended_clients: int
    peak_throughput_requests_per_second: float
    server_thread_stopped: bool
    levels: list[ServerHTTPConcurrencyLevel]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "stable": self.stable,
            "tls_minimum": self.tls_minimum,
            "requests_per_level": self.requests_per_level,
            "recommended_clients": self.recommended_clients,
            "peak_throughput_requests_per_second": self.peak_throughput_requests_per_second,
            "server_thread_stopped": self.server_thread_stopped,
            "levels": [asdict(level) for level in self.levels],
        }


class _HealthQueue:
    @staticmethod
    def health() -> dict[str, Any]:
        return {
            "healthy": True,
            "state_invariants": {
                "inconsistent_lease_rows": 0,
                "unreceipted_completed_jobs": 0,
                "implausible_future_leases": 0,
            },
        }


class _HealthRuntime:
    queue = _HealthQueue()


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return ordered[position]


def _certificate(directory: Path) -> tuple[Path, Path]:
    private = Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Arenyxa Server Validation")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(private, algorithm=None)
    )
    cert_path = directory / "server-cert.pem"
    key_path = directory / "server-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class ServerHTTPConcurrencyValidator:
    def __init__(self, *, requests_per_level: int = 80, client_levels: tuple[int, ...] = (1, 4, 8, 16, 32)) -> None:
        self.requests_per_level = max(16, min(96, int(requests_per_level)))
        levels = tuple(sorted({max(1, min(64, int(value))) for value in client_levels}))
        self.client_levels = levels or (1,)

    def run(self) -> ServerHTTPPerformanceReport:
        try:
            import uvicorn
        except ImportError as exc:
            raise RuntimeError("server HTTP performance validation requires uvicorn") from exc
        with tempfile.TemporaryDirectory(prefix="arenyxa-server-http-") as raw:
            directory = Path(raw)
            cert_path, key_path = _certificate(directory)
            app = create_enterprise_server_app(_HealthRuntime(), {"schema": "arenyxa.server-performance-identity/v1"})
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(1024)
            port = int(listener.getsockname()[1])

            def tls_context_factory(_config: Any, default_factory: Any) -> ssl.SSLContext:
                context = default_factory()
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                if hasattr(ssl, "OP_NO_COMPRESSION"):
                    context.options |= ssl.OP_NO_COMPRESSION
                return context

            config = uvicorn.Config(
                app,
                host="127.0.0.1",
                port=port,
                ssl_certfile=str(cert_path),
                ssl_keyfile=str(key_path),
                ssl_context_factory=tls_context_factory,
                proxy_headers=False,
                server_header=False,
                access_log=False,
                log_level="error",
                limit_concurrency=MAX_SERVER_INFLIGHT_REQUESTS,
                backlog=1024,
                timeout_keep_alive=5,
                timeout_graceful_shutdown=10,
            )
            server = uvicorn.Server(config)
            server_thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, name="arenyxa-http-validation", daemon=True)
            server_thread.start()
            deadline = time.monotonic() + 8.0
            while not server.started and server_thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not server.started:
                server.should_exit = True
                server_thread.join(timeout=3.0)
                listener.close()
                raise RuntimeError("validation server failed to start")

            levels: list[ServerHTTPConcurrencyLevel] = []
            try:
                for clients in self.client_levels:
                    levels.append(self._run_level(port, clients))
            finally:
                server.should_exit = True
                server_thread.join(timeout=10.0)
                listener.close()
            stopped = not server_thread.is_alive()
            stable = stopped and all(level.stable for level in levels)
            peak = max((level.throughput_requests_per_second for level in levels), default=0.0)
            baseline_p95 = levels[0].p95_ms if levels else 0.0
            efficient = [
                level for level in levels
                if level.stable and (baseline_p95 <= 0.0 or level.p95_ms <= max(25.0, baseline_p95 * 3.0))
            ]
            recommendation = max(efficient or levels, key=lambda item: item.throughput_requests_per_second).clients if levels else 1
            return ServerHTTPPerformanceReport(
                schema="arenyxa.enterprise-server-http-performance/v1",
                stable=stable,
                tls_minimum="TLSv1.3",
                requests_per_level=self.requests_per_level,
                recommended_clients=recommendation,
                peak_throughput_requests_per_second=peak,
                server_thread_stopped=stopped,
                levels=levels,
            )

    def _run_level(self, port: int, clients: int) -> ServerHTTPConcurrencyLevel:
        latencies: list[float] = []
        statuses: Counter[str] = Counter()
        tls_versions: Counter[str] = Counter()
        errors: list[str] = []
        lock = threading.Lock()
        base = self.requests_per_level // clients
        remainder = self.requests_per_level % clients

        def client_unit(index: int) -> None:
            count = base + (1 if index < remainder else 0)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=5.0, context=context)
            try:
                for _ in range(count):
                    started = time.perf_counter()
                    connection.request("GET", "/enterprise/v1/health", headers={"Connection": "keep-alive"})
                    response = connection.getresponse()
                    raw = response.read()
                    elapsed_ms = (time.perf_counter() - started) * 1000.0
                    if response.status == 200:
                        json.loads(raw.decode("utf-8"))
                    with lock:
                        latencies.append(elapsed_ms)
                        statuses[str(response.status)] += 1
                        if connection.sock is not None:
                            tls_versions[str(connection.sock.version())] += 1
            except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, json.JSONDecodeError) as exc:
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                connection.close()

        started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=clients, thread_name_prefix="arenyxa-http-client") as executor:
            futures = [executor.submit(client_unit, index) for index in range(clients)]
            for future in as_completed(futures):
                future.result()
        duration = max(0.000001, time.perf_counter() - started)
        completed = sum(statuses.values())
        stable = (
            not errors
            and completed == self.requests_per_level
            and statuses == Counter({"200": self.requests_per_level})
            and set(tls_versions).issubset({"TLSv1.3"})
            and sum(tls_versions.values()) == self.requests_per_level
        )
        return ServerHTTPConcurrencyLevel(
            clients=clients,
            requests=self.requests_per_level,
            duration_seconds=duration,
            throughput_requests_per_second=self.requests_per_level / duration,
            p95_ms=_percentile(latencies, 0.95),
            p99_ms=_percentile(latencies, 0.99),
            max_ms=max(latencies, default=0.0),
            errors=len(errors),
            status_counts=dict(statuses),
            tls_versions=dict(tls_versions),
            stable=stable,
        )
