from __future__ import annotations

import argparse
import base64
import getpass
import logging
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa import __package_version__
from arenyxa.bootstrap import bootstrap
from arenyxa.config import AppPaths
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.repair import repair_worker_active
from arenyxa.enterprise.server_api import EnterpriseWorkerHTTPClient
from arenyxa.enterprise.worker_agent import EnterpriseWorkerAgent


LOGGER = logging.getLogger(__name__)


def _load_or_create(path: Path, passphrase: str) -> Ed25519PrivateKey:
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError("Worker private-key path cannot be a symbolic link")
    if path.exists():
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            raise RuntimeError("Worker private-key file is invalid or oversized")
        return serialization.load_pem_private_key(path.read_bytes(), password=passphrase.encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    payload = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    created = True
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("Worker private-key write made no progress")
            view = view[written:]
        os.fsync(fd)
    except Exception:
        try:
            os.close(fd)
        finally:
            fd = -1
            if created:
                try:
                    path.unlink(missing_ok=True)
                except OSError as cleanup_exc:
                    LOGGER.warning("Failed to remove incomplete Worker private-key file %s: %s", path, cleanup_exc)
        raise
    finally:
        if fd >= 0:
            os.close(fd)
    return private


def _new_authenticated_client(args, private: Ed25519PrivateKey) -> EnterpriseWorkerHTTPClient:
    client = EnterpriseWorkerHTTPClient(
        args.endpoint,
        args.enterprise_root_fingerprint,
        ca_file=args.ca_file,
        allow_tls12=bool(args.allow_tls12_server),
    )
    client.verify_peer()
    return client


def _run_worker_loop(args, private: Ed25519PrivateKey | None, worker=None, control_plane=None) -> None:
    """Compatibility entry point delegating the bounded Worker loop to EnterpriseWorkerAgent."""
    client = _new_authenticated_client(args, private)
    resources = {"version": __package_version__}
    if control_plane is not None:
        health = control_plane.health(deep=False)
        resources.update({
            "platform_health": health.get("status", "unknown"),
            "job_system": health.get("components", {}).get("jobs", {}).get("details", {}),
        })
    signer = (private.sign if private is not None else (lambda _message: b""))
    agent = EnterpriseWorkerAgent(
        client=client,
        runner=None if worker is not None else getattr(control_plane, "runner", None),
        worker_id=args.worker_id,
        signer=signer,
        max_slots=max(1, min(64, int(args.concurrency))),
        worker_runtime=worker,
        preauthenticated=private is None,
        resources=resources,
        heartbeat_seconds=args.heartbeat_seconds,
        idle_seconds=args.poll_seconds,
    )
    try:
        if args.once:
            agent.run_once()
        else:
            agent.run_forever()
    finally:
        agent.stop(timeout=15.0, cancel_running=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Arenyxa Phase-11 Enterprise Worker")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--endpoint", required=True, help="https://server:port")
    parser.add_argument("--enterprise-root-fingerprint", required=True)
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--allow-tls12-server", action="store_true", help="Allow explicit TLS 1.2 compatibility with a legacy Enterprise Server")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--heartbeat-seconds", type=float, default=10.0)
    parser.add_argument("--concurrency", type=int, default=min(4, max(1, os.cpu_count() or 1)), help="Maximum concurrent leased jobs on this Worker; server-side max_slots remains authoritative")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    passphrase = getpass.getpass("Worker private-key passphrase: ")
    private = _load_or_create(args.key_file, passphrase)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print("Worker public key (register this on the Enterprise Server):")
    print(base64.urlsafe_b64encode(public).decode("ascii").rstrip("="))

    paths = AppPaths.discover(args.data_dir)
    paths.initialize()
    if repair_worker_active(paths.root):
        raise RuntimeError(f"Arenyxa data directory is currently owned by Repair Center: {paths.root}")
    root_lease = DataRootLease(paths.root)
    if not root_lease.acquire():
        raise RuntimeError(f"Arenyxa data directory is already in use by another runtime: {paths.root}")
    context = None
    try:
        context = bootstrap(args.data_dir, start_scheduler=False)
        if context.control_plane is None:
            raise RuntimeError("Arenyxa v8 Application Control Plane is unavailable on this Worker")
        try:
            _run_worker_loop(args, private, None, context.control_plane)
        except KeyboardInterrupt:
            LOGGER.info("Enterprise Worker shutdown requested")
        return 0
    finally:
        if context is not None:
            context.shutdown()
        root_lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
