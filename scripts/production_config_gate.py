"""Release-blocking production configuration safety checks."""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - modern lane is Python 3.11+
    tomllib = None

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa.infrastructure.deployment_guard import is_loopback_bind, validate_storage_deployment


def _record(checks: list[dict[str, object]], name: str, ok: bool, detail: str) -> None:
    checks.append({"name": name, "ok": bool(ok), "detail": detail})


def main() -> int:
    checks: list[dict[str, object]] = []

    if tomllib is None:
        _record(checks, "pyproject_parse", False, "tomllib unavailable")
    else:
        with (ROOT / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)
        version = str(project.get("project", {}).get("version", ""))
        _record(checks, "release_version", version == "8.1.0", f"version={version}")

    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8") if (ROOT / "Dockerfile").is_file() else ""
    docker_nonroot = any(
        line.strip().startswith("USER ") and line.strip().split(maxsplit=1)[1].casefold() not in {"root", "0"}
        for line in dockerfile.splitlines()
    )
    _record(checks, "docker_non_root", docker_nonroot, "Dockerfile must switch to a non-root runtime user")

    compose_path = ROOT / "docker-compose.yml"
    compose = compose_path.read_text(encoding="utf-8") if compose_path.is_file() else ""
    loopback_port = '"127.0.0.1:8787:8787"' in compose or "'127.0.0.1:8787:8787'" in compose
    _record(checks, "compose_secure_default_bind", loopback_port, "published desktop/server UI port defaults to loopback")

    try:
        validate_storage_deployment("sqlite", "desktop", distributed=False, bind_host="127.0.0.1")
        local_sqlite_ok = True
    except (RuntimeError, ValueError):
        local_sqlite_ok = False
    _record(checks, "sqlite_local_allowed", local_sqlite_ok, "SQLite remains supported for local/single-host runtime")

    try:
        pressure = validate_storage_deployment("sqlite", "desktop", worker_concurrency=9)
        sqlite_pressure_warns = bool(pressure.warnings)
    except (RuntimeError, ValueError):
        sqlite_pressure_warns = False
    _record(checks, "sqlite_pressure_warning", sqlite_pressure_warns, "SQLite 9-worker local mode must surface serialized-WAL pressure")

    sqlite_cutover_rejected = False
    try:
        validate_storage_deployment("sqlite", "desktop", worker_concurrency=16)
    except RuntimeError:
        sqlite_cutover_rejected = True
    _record(checks, "sqlite_high_concurrency_fail_closed", sqlite_cutover_rejected, "SQLite 16+ worker concurrency must require PostgreSQL")

    sqlite_distributed_rejected = False
    try:
        validate_storage_deployment("sqlite", "server", distributed=True, bind_host="0.0.0.0")
    except RuntimeError:
        sqlite_distributed_rejected = True
    _record(checks, "sqlite_distributed_fail_closed", sqlite_distributed_rejected, "distributed SQLite must be rejected")

    try:
        postgres = validate_storage_deployment("postgresql", "server", distributed=True, bind_host="0.0.0.0")
        postgres_ok = postgres.safe
    except (RuntimeError, ValueError):
        postgres_ok = False
    _record(checks, "postgres_distributed_allowed", postgres_ok, "PostgreSQL is the supported distributed backend")

    _record(checks, "loopback_detection", is_loopback_bind("127.0.0.1") and is_loopback_bind("::1") and not is_loopback_bind("0.0.0.0"), "bind classification is fail-closed")

    server_source = (ROOT / "scripts" / "enterprise_server.py").read_text(encoding="utf-8")
    server_guarded = "validate_storage_deployment(" in server_source and 'bind_host = args.host if args.command == "serve" else None' in server_source
    _record(checks, "enterprise_server_storage_guard", server_guarded, "Enterprise serve path invokes storage deployment guard before bootstrap")

    passed = all(bool(item["ok"]) for item in checks)
    payload = {
        "schema": "arenyxa.production-config-gate/v2",
        "production_config": "validated" if passed else "rejected",
        "passed": passed,
        "checks": checks,
    }
    report = ROOT / "PRODUCTION_CONFIG_GATE.json"
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
