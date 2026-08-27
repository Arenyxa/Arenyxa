from __future__ import annotations

from arenyxa.console_io import console_write
import argparse
from contextlib import asynccontextmanager
import hashlib
import hmac
import logging
import secrets
from pathlib import Path
from typing import Any

from arenyxa import __version__
from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.runtime_recovery import RuntimeRecoveryService
from arenyxa.config import AppPaths
from arenyxa.domain.enums import WorkspaceRole
from arenyxa.domain.permissions import ROLE_PERMISSIONS
from arenyxa.domain.errors import ArenyxaError
from arenyxa.security import PolicyEffect, PolicyRule, SecurityKernel, Session, TrustDomain
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.repair import repair_worker_active

LOGGER = logging.getLogger(__name__)


def create_app(data_dir: Path, api_tokens: dict[str, tuple[str, WorkspaceRole]]) -> Any:
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
    except ImportError as exc:
        raise RuntimeError("Server mode requires: pip install -e .[server]") from exc
    paths = AppPaths.discover(data_dir)
    paths.initialize()
    lease = DataRootLease(paths.root)
    if not lease.acquire():
        raise RuntimeError(
            f"Arenyxa data directory is already in use by another Desktop/Server runtime: {paths.root}"
        )
    try:
        if repair_worker_active(paths.root):
            raise RuntimeError(
                f"Arenyxa data directory is currently owned by Repair Center: {paths.root}"
            )
        store = SQLiteStore(paths.database)
        store.initialize()
                                                                                     
                                                                                          
                                                                                            
        RuntimeRecoveryService(store).recover()
        runner = RunOrchestrator(store)
                                                                                              
                                                                                     
        security = SecurityKernel.local_foundation(paths.root)
        token_identities: dict[str, tuple[str, tuple[str, ...], WorkspaceRole]] = {}
        for digest, (principal_id, role) in api_tokens.items():
            capabilities = tuple(sorted(ROLE_PERMISSIONS[role]))
            identity = security.state.create_identity(
                TrustDomain.PERSONAL, principal_id=str(principal_id),
                display_name=str(principal_id), kind="api-token",
            )
            token_identities[str(digest)] = (identity.id, capabilities, role)
            for capability in capabilities:
                                                                                                   
                security.catalog.require(capability)
                security.add_policy(PolicyRule(
                    id=f"headless-{identity.id}-{capability}",
                    trust_domain=TrustDomain.PERSONAL, capabilities=(capability,),
                    resources=("*",), effect=PolicyEffect.ALLOW,
                    conditions={"surface": "headless-api"},
                ))
    except Exception:
        lease.release()
        raise

    @asynccontextmanager
    async def lifespan(_app: Any):
        try:
            yield
        finally:
            try:
                runner.shutdown(wait_for_runs=True)
                try:
                    store.checkpoint("PASSIVE")
                    store.optimize()
                except Exception:
                    LOGGER.exception("Headless server database maintenance during shutdown failed")
            finally:
                lease.release()

    app = FastAPI(title="Arenyxa Headless Server", version=__version__, lifespan=lifespan)
    app.state.data_root_lease = lease
    app.state.security_kernel = security

    def authenticate(authorization: str = Header(default="")) -> Session:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="authentication required")
        supplied = authorization[len("Bearer "):] if authorization.startswith("Bearer ") else authorization
        supplied_digest = hashlib.sha256(supplied.encode()).hexdigest()
        matched: tuple[str, tuple[str, ...], WorkspaceRole] | None = None
        for digest, identity in token_identities.items():
            if hmac.compare_digest(supplied_digest, digest):
                matched = identity
        if matched is None:
            raise HTTPException(status_code=403, detail="invalid token")
        identity_id, capabilities, role = matched
        return security.issue_session(
            identity_id, capabilities=list(capabilities), ttl_seconds=300,
            metadata={"surface": "headless-api", "workspace_role": role.value},
        )

    def require_capability(session: Session, capability: str, resource: str) -> None:
        try:
            security.require(session, capability, resource, context={"surface": "headless-api"})
        except ArenyxaError as exc:
            if exc.code == "AUDIT_INTEGRITY_BROKEN":
                raise HTTPException(status_code=503, detail="security audit unavailable") from exc
            raise HTTPException(status_code=403, detail="forbidden") from exc

    @app.get("/health")
    def health() -> dict[str, Any]:
                                                                                           
                                                                                         
        return {"status": "ok", "version": __version__, "database": "ok" if store.ping() else "unavailable"}

    @app.get("/api/v1/tasks")
    def tasks(session: Session = Depends(authenticate)) -> list[dict[str, Any]]:
        require_capability(session, "project.read", "tasks:list")
        return [task.to_dict() for task in store.list_tasks(include_archived=True)]

    @app.post("/api/v1/tasks/{task_id}/runs", status_code=202)
    def run_task(task_id: str, session: Session = Depends(authenticate)) -> dict[str, Any]:
        require_capability(session, "task.run", f"task:{task_id}")
        task = store.get_task(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="task not found")
        handle = runner.submit(task)
        return {"run_id": handle.run.id, "status": handle.run.status.value}

    @app.get("/api/v1/runs")
    def runs(session: Session = Depends(authenticate)) -> list[dict[str, Any]]:
        require_capability(session, "project.read", "runs:list")
        return store.list_runs()

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Arenyxa V{__version__} headless server")
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
