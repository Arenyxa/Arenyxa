from __future__ import annotations

import argparse
import hashlib
import hmac
import logging
import secrets
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from arenyxa import __display_version__, __version__
from arenyxa.application.async_runner import AsyncRunOrchestrator
from arenyxa.application.control_plane import PlatformControlPlane
from arenyxa.application.job_system import JobSystem
from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.application.windows_runtime import WindowsRuntimeControl
from arenyxa.config import AppPaths
from arenyxa.console_io import console_write
from arenyxa.domain.enums import WorkspaceRole
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.permissions import ROLE_PERMISSIONS
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.repair import repair_worker_active
from arenyxa.security import PolicyEffect, PolicyRule, SecurityKernel, Session, TrustDomain

LOGGER = logging.getLogger(__name__)


def _build_server_services(
    data_dir: Path,
    api_tokens: dict[str, tuple[str, WorkspaceRole]],
) -> tuple[Any, ...]:
    paths = AppPaths.discover(data_dir)
    paths.initialize()
    lease = DataRootLease(paths.root)
    if not lease.acquire():
        raise RuntimeError(
            f"Arenyxa data directory is already in use by another Desktop/Server runtime: {paths.root}"
        )
    try:
        if repair_worker_active(paths.root):
            raise RuntimeError(f"Arenyxa data directory is currently owned by Repair Center: {paths.root}")
        store = SQLiteStore(paths.database)
        store.initialize()

        RuntimeRecoveryService(store).recover()
        runner = AsyncRunOrchestrator(store)

        security = SecurityKernel.local_foundation(paths.root)
        token_identities: dict[str, tuple[str, tuple[str, ...], WorkspaceRole]] = {}
        for digest, (principal_id, role) in api_tokens.items():
            capabilities = tuple(sorted(ROLE_PERMISSIONS[role]))
            identity = security.state.create_identity(
                TrustDomain.PERSONAL,
                principal_id=str(principal_id),
                display_name=str(principal_id),
                kind="api-token",
            )
            token_identities[str(digest)] = (identity.id, capabilities, role)
            for capability in capabilities:
                security.catalog.require(capability)
                security.add_policy(
                    PolicyRule(
                        id=f"headless-{identity.id}-{capability}",
                        trust_domain=TrustDomain.PERSONAL,
                        capabilities=(capability,),
                        resources=("*",),
                        effect=PolicyEffect.ALLOW,
                        conditions={"surface": "headless-api"},
                    )
                )
                if capability in {"logs.read", "system.configure"}:
                    security.add_policy(
                        PolicyRule(
                            id=f"headless-control-{identity.id}-{capability}",
                            trust_domain=TrustDomain.PERSONAL,
                            capabilities=(capability,),
                            resources=("health:*", "diagnostics:*", "job:*", "windows:*"),
                            effect=PolicyEffect.ALLOW,
                            conditions={"surface": "application-control-plane"},
                        )
                    )
        jobs = JobSystem(store, security, max_workers=4, queue_capacity=64)
        windows_runtime = WindowsRuntimeControl()
        control_plane = PlatformControlPlane(
            paths=paths,
            store=store,
            security=security,
            jobs=jobs,
            runner=runner,
            runtime_recovery=None,
            windows_runtime=windows_runtime,
        )
    except Exception:
        lease.release()
        raise
    return paths, lease, store, runner, security, token_identities, jobs, control_plane


def _register_server_routes(
    app: Any,
    *,
    authenticated_session: Any,
    require_capability: Any,
    control_plane: PlatformControlPlane,
    store: SQLiteStore,
    runner: AsyncRunOrchestrator,
    http_exception: Any,
) -> None:
    @app.get("/health")
    def health() -> dict[str, Any]:
        snapshot = control_plane.health(deep=False)
        return {
            "status": "ok" if snapshot["status"] == "healthy" else snapshot["status"],
            "version": __version__,
            "database": ("ok" if snapshot["components"]["storage"]["status"] == "healthy" else "unavailable"),
            "platform": snapshot,
        }

    @app.get("/api/v1/platform/health")
    def platform_health(session: Session = authenticated_session) -> dict[str, Any]:
        require_capability(session, "logs.read", "health:deep")
        return control_plane.health(deep=True)

    @app.get("/api/v1/platform/windows")
    def platform_windows(deep: bool = False, session: Session = authenticated_session) -> dict[str, Any]:
        require_capability(session, "logs.read", "windows:status")
        return control_plane.windows_status(session=session, surface="server", deep=bool(deep))

    @app.get("/api/v1/platform/jobs")
    def platform_jobs(
        limit: int = 100,
        state: str = "",
        session: Session = authenticated_session,
    ) -> list[dict[str, Any]]:
        require_capability(session, "logs.read", "job:list")
        return control_plane.list_jobs(
            session=session,
            surface="server",
            limit=max(1, min(1000, int(limit))),
            state=state,
        )

    @app.get("/api/v1/platform/jobs/{job_id}")
    def platform_job(job_id: str, session: Session = authenticated_session) -> dict[str, Any]:
        require_capability(session, "logs.read", f"job:{job_id}")
        return control_plane.get_job(job_id, session=session, surface="server")

    @app.post("/api/v1/platform/jobs/{job_id}/cancel")
    def cancel_platform_job(job_id: str, session: Session = authenticated_session) -> dict[str, Any]:
        require_capability(session, "system.configure", f"job:{job_id}")
        return control_plane.cancel_job(job_id, session=session, surface="server")

    @app.post("/api/v1/platform/diagnostics", status_code=202)
    def export_platform_diagnostics(session: Session = authenticated_session) -> dict[str, Any]:
        require_capability(session, "logs.read", "diagnostics:bundle")
        return control_plane.submit_diagnostics_export(
            destination=None,
            session=session,
            surface="server",
            timeout_seconds=120.0,
        )

    @app.get("/api/v1/tasks")
    def tasks(session: Session = authenticated_session) -> list[dict[str, Any]]:
        require_capability(session, "project.read", "tasks:list")
        return [task.to_dict() for task in store.list_tasks(include_archived=True)]

    @app.post("/api/v1/tasks/{task_id}/runs", status_code=202)
    def run_task(task_id: str, session: Session = authenticated_session) -> dict[str, Any]:
        require_capability(session, "task.run", f"task:{task_id}")
        task = store.get_task(task_id)
        if not task:
            raise http_exception(status_code=404, detail="task not found")
        handle = runner.submit(task)
        return {"run_id": handle.run.id, "status": handle.run.status.value}

    @app.get("/api/v1/runs")
    def runs(session: Session = authenticated_session) -> list[dict[str, Any]]:
        require_capability(session, "project.read", "runs:list")
        return store.list_runs()


def create_app(data_dir: Path, api_tokens: dict[str, tuple[str, WorkspaceRole]]) -> Any:
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
    except ImportError as exc:
        raise RuntimeError("Server mode requires: pip install -e .[server]") from exc
    (
        _paths,
        lease,
        store,
        runner,
        security,
        token_identities,
        jobs,
        control_plane,
    ) = _build_server_services(data_dir, api_tokens)

    @asynccontextmanager
    async def lifespan(_app: Any) -> AsyncIterator[None]:
        try:
            yield
        finally:
            try:
                jobs.shutdown(wait=True)
                runner.shutdown(wait_for_runs=True)
                try:
                    store.checkpoint("PASSIVE")
                    store.optimize()
                except (sqlite3.Error, OSError, RuntimeError) as exc:
                    LOGGER.error("Headless server database maintenance during shutdown failed: %s", exc)
            finally:
                lease.release()

    app = FastAPI(title="Arenyxa Headless Server", version=__version__, lifespan=lifespan)
    app.state.data_root_lease = lease
    app.state.security_kernel = security
    app.state.job_system = jobs
    app.state.control_plane = control_plane

    authorization_header = Header(default="")

    def authenticate(authorization: str = authorization_header) -> Session:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="authentication required")
        supplied = authorization.removeprefix("Bearer ")
        supplied_digest = hashlib.sha256(supplied.encode()).hexdigest()
        matched: tuple[str, tuple[str, ...], WorkspaceRole] | None = None
        for digest, identity in token_identities.items():
            if hmac.compare_digest(supplied_digest, digest):
                matched = identity
        if matched is None:
            raise HTTPException(status_code=403, detail="invalid token")
        identity_id, capabilities, role = matched
        return security.issue_session(
            identity_id,
            capabilities=list(capabilities),
            ttl_seconds=300,
            metadata={"surface": "headless-api", "workspace_role": role.value},
        )

    def require_capability(session: Session, capability: str, resource: str) -> None:
        try:
            security.require(session, capability, resource, context={"surface": "headless-api"})
        except ArenyxaError as exc:
            if exc.code == "AUDIT_INTEGRITY_BROKEN":
                raise HTTPException(status_code=503, detail="security audit unavailable") from exc
            raise HTTPException(status_code=403, detail="forbidden") from exc

    _register_server_routes(
        app,
        authenticated_session=Depends(authenticate),
        require_capability=require_capability,
        control_plane=control_plane,
        store=store,
        runner=runner,
        http_exception=HTTPException,
    )

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Arenyxa V{__display_version__} headless server")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--token", help="Initial admin token. A random token is generated when omitted.")
    parser.add_argument("--allow-lan", action="store_true")
    arguments = parser.parse_args()
    if arguments.host not in {"127.0.0.1", "::1", "localhost"} and not arguments.allow_lan:
        parser.error(
            "non-loopback binding requires --allow-lan and should be protected with TLS/reverse proxy"
        )
    token = arguments.token or secrets.token_urlsafe(32)
    if not arguments.token:
        console_write(f"Generated one-time admin token: {token}")
    digest = hashlib.sha256(token.encode()).hexdigest()
    app = create_app(arguments.data_dir, {digest: ("admin", WorkspaceRole.ADMIN)})
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("Server mode requires: pip install -e .[server]") from exc
    uvicorn.run(app, host=arguments.host, port=arguments.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
