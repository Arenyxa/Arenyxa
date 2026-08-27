from __future__ import annotations

import argparse
import getpass
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from arenyxa.bootstrap import bootstrap
from arenyxa.config import AppPaths
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.deployment_guard import validate_storage_deployment
from arenyxa.repair import repair_worker_active
from arenyxa.enterprise.server_api import MAX_SERVER_INFLIGHT_REQUESTS, create_enterprise_server_app


def _authenticate(context, username: str) -> None:
    identity = context.enterprise_identity
    if identity is None or context.enterprise_server is None:
        raise RuntimeError("Enterprise services are unavailable")
    vault_passphrase = getpass.getpass("Enterprise Vault passphrase: ")
    identity.unlock(vault_passphrase)
    password = getpass.getpass(f"Enterprise administrator password ({username}): ")
    identity.login(username, password)
    identity.step_up(password)


def main() -> int:
    parser = argparse.ArgumentParser(description="Arenyxa Phase-11 Enterprise Server / Worker control utility")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--username", default="root")
    parser.add_argument(
        "--runtime-database-dsn-file", type=Path, default=None,
        help="UTF-8 file containing a postgresql:// DSN for Enterprise distributed runtime; SQLite is local-only",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the TLS-only Enterprise Worker Service")
    serve.add_argument("--host", default="0.0.0.0")
    serve.add_argument("--port", type=int, default=9444)
    serve.add_argument("--tls-cert", type=Path, required=True)
    serve.add_argument("--tls-key", type=Path, required=True)
    serve.add_argument("--server-id", default="")
    serve.add_argument("--allow-tls12", action="store_true", help="Allow TLS 1.2 compatibility; modern default is TLS 1.3")

    register = sub.add_parser("register-worker")
    register.add_argument("--worker-id", required=True)
    register.add_argument("--public-key", required=True, help="Canonical base64url Ed25519 public key")
    register.add_argument("--display-name", default="")
    register.add_argument("--max-slots", type=int, default=1)

    drain = sub.add_parser("drain-worker")
    drain.add_argument("--worker-id", required=True)
    drain.add_argument("--undo", action="store_true")

    revoke = sub.add_parser("revoke-worker")
    revoke.add_argument("--worker-id", required=True)

    sub.add_parser("status")
    args = parser.parse_args()
    paths = AppPaths.discover(args.data_dir)
    paths.initialize()
    if repair_worker_active(paths.root):
        raise RuntimeError(f"Arenyxa data directory is currently owned by Repair Center: {paths.root}")
    root_lease = DataRootLease(paths.root)
    if not root_lease.acquire():
        raise RuntimeError(f"Arenyxa data directory is already in use by another runtime: {paths.root}")
    context = None
    try:
        runtime_database = None
        if args.runtime_database_dsn_file is not None:
            runtime_database = args.runtime_database_dsn_file.read_text(encoding="utf-8").strip()
            if not runtime_database.casefold().startswith(("postgresql://", "postgres://")):
                raise RuntimeError("runtime database DSN file must contain a postgresql:// or postgres:// DSN")
        backend = "postgresql" if runtime_database else "sqlite"
        bind_host = args.host if args.command == "serve" else None
        validate_storage_deployment(
            backend,
            "server" if args.command == "serve" else "cli",
            distributed=args.command == "serve" and backend == "postgresql",
            bind_host=bind_host,
        )
        context = bootstrap(
            args.data_dir, start_scheduler=False, enterprise_runtime_database=runtime_database
        )
        _authenticate(context, args.username)
        runtime = context.enterprise_server
        assert runtime is not None
        if args.command == "register-worker":
            result = runtime.register_worker(
                args.worker_id, args.public_key, {"source": "operator-registration"},
                display_name=args.display_name, max_slots=args.max_slots,
            )
            print(result)
            return 0
        if args.command == "drain-worker":
            runtime.set_worker_drain(args.worker_id, not args.undo)
            print("worker drain state updated")
            return 0
        if args.command == "revoke-worker":
            affected = runtime.revoke_worker(args.worker_id)
            print(f"worker revoked; recovered/review jobs={affected}")
            return 0
        if args.command == "status":
            print(runtime.remote_ops_snapshot())
            return 0
        cert_pem = args.tls_cert.read_bytes()
        certificate = x509.load_pem_x509_certificate(cert_pem)
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
                                                                                               
                                                                                         
        initial_identity = runtime.build_server_identity(cert_der, server_id=args.server_id, ttl_seconds=6 * 60 * 60)
        server_id = str(initial_identity["server_id"])
        runtime.activate_service()
        identity_lock = threading.Lock()
        identity_cache = [initial_identity]

        def identity_provider():
            with identity_lock:
                artifact = identity_cache[0]
                try:
                    expires = datetime.fromisoformat(str(artifact["expires_at"]).replace("Z", "+00:00"))
                    if expires.tzinfo is None:
                        expires = expires.replace(tzinfo=timezone.utc)
                except (KeyError, TypeError, ValueError, OverflowError):
                    expires = datetime.now(timezone.utc)
                if expires <= datetime.now(timezone.utc) + timedelta(hours=1):
                    artifact = runtime.build_service_server_identity(cert_der, server_id=server_id, ttl_seconds=6 * 60 * 60)
                    identity_cache[0] = artifact
                return dict(artifact)

                                                                                              
        context.enterprise_identity.logout()
        app = create_enterprise_server_app(runtime, identity_provider)
        try:
            import uvicorn
        except ImportError as exc:
            raise RuntimeError("Enterprise Server mode requires: pip install -e .[server]") from exc
        def tls_context_factory(_config, default_factory):
            context = default_factory()
            context.minimum_version = ssl.TLSVersion.TLSv1_2 if args.allow_tls12 else ssl.TLSVersion.TLSv1_3
            if hasattr(ssl, "OP_NO_COMPRESSION"):
                context.options |= ssl.OP_NO_COMPRESSION
            return context

        uvicorn.run(
            app, host=args.host, port=args.port,
            ssl_certfile=str(args.tls_cert), ssl_keyfile=str(args.tls_key),
            ssl_context_factory=tls_context_factory,
            proxy_headers=False, server_header=False, access_log=False,
            limit_concurrency=MAX_SERVER_INFLIGHT_REQUESTS, backlog=1024,
            timeout_keep_alive=5, timeout_graceful_shutdown=30,
        )
        return 0
    finally:
        if context is not None:
            context.shutdown()
        root_lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
