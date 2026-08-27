from __future__ import annotations

import ipaddress
from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True, slots=True)
class StorageDeploymentDecision:
    backend: str
    runtime_mode: str
    distributed: bool
    bind_host: str | None
    worker_concurrency: int
    safe: bool
    warnings: tuple[str, ...] = ()

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


def is_loopback_bind(host: str | None) -> bool:
    """Return True only when *host* is unambiguously loopback/local-only."""

    value = str(host or "").strip().casefold()
    if value in {"localhost", "ip6-localhost"}:
        return True
    if not value or value in {"0.0.0.0", "::", "*", "+"}:
        return False
    # Bracketed IPv6 is accepted for command-line friendliness.
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def validate_storage_deployment(
    database_backend: str,
    runtime_mode: str,
    distributed: bool = False,
    *,
    bind_host: str | None = None,
    worker_concurrency: int = 1,
) -> StorageDeploymentDecision:
    """Fail closed when SQLite is selected for a distributed/multi-host runtime.

    SQLite remains a supported, high-reliability local desktop/single-host backend.
    Enterprise Server/Worker deployments that can be reached by another host must use
    PostgreSQL so queue leases, job ownership, and failover semantics are not silently
    weakened by a file-local database.
    """

    backend = str(database_backend or "").strip().casefold()
    mode = str(runtime_mode or "").strip().casefold()
    concurrency = max(1, int(worker_concurrency))
    aliases = {
        "postgres": "postgresql",
        "postgresql+psycopg": "postgresql",
        "sqlite3": "sqlite",
    }
    backend = aliases.get(backend, backend)
    if backend not in {"sqlite", "postgresql"}:
        raise ValueError(f"unsupported database backend: {database_backend!r}")
    if mode not in {"desktop", "server", "worker", "cluster", "cli"}:
        raise ValueError(f"unsupported runtime mode: {runtime_mode!r}")

    network_exposed = bind_host is not None and not is_loopback_bind(bind_host)
    distributed_effective = bool(distributed or mode in {"cluster", "worker"} or (mode == "server" and network_exposed))

    if backend == "sqlite" and distributed_effective:
        raise RuntimeError(
            "SQLite is restricted to local/single-host Arenyxa runtimes. "
            "Use PostgreSQL for Enterprise Server, Worker, cluster, or non-loopback deployment."
        )

    warnings: list[str] = []
    if backend == "sqlite" and concurrency >= 16:
        raise RuntimeError(
            "SQLite worker concurrency at or above 16 is outside Arenyxa's durable single-host envelope. "
            "Use PostgreSQL before enabling this concurrency level."
        )
    if backend == "sqlite" and concurrency > 8:
        warnings.append(
            "SQLite worker concurrency above 8 enters the serialized-WAL pressure zone; "
            "use PostgreSQL before scaling further."
        )

    return StorageDeploymentDecision(
        backend=backend,
        runtime_mode=mode,
        distributed=distributed_effective,
        bind_host=bind_host,
        worker_concurrency=concurrency,
        safe=True,
        warnings=tuple(warnings),
    )
