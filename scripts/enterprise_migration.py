from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from arenyxa.bootstrap import bootstrap
from arenyxa.config import AppPaths
from arenyxa.enterprise.migration import EnterpriseAuthorityMigrationService
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.repair import repair_worker_active


def _lease(data_dir: Path):
    paths = AppPaths.discover(data_dir); paths.initialize()
    if repair_worker_active(paths.root):
        raise RuntimeError(f"Arenyxa data directory is currently owned by Repair Center: {paths.root}")
    lease = DataRootLease(paths.root)
    if not lease.acquire():
        raise RuntimeError(f"Arenyxa data directory is already in use by another runtime: {paths.root}")
    return lease


def main() -> int:
    parser = argparse.ArgumentParser(description="Arenyxa Enterprise Authority migration tool")
    parser.add_argument("--data-dir", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    export = sub.add_parser("export")
    export.add_argument("--username", default="root")
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--source-mode", default="office", choices=("standalone", "office"))
    imp = sub.add_parser("import")
    imp.add_argument("--input", type=Path, required=True)
    imp.add_argument("--expected-root-fingerprint", required=True)
    args = parser.parse_args()

    lease = _lease(args.data_dir)
    context = None
    try:
        context = bootstrap(args.data_dir, start_scheduler=False)
        identity = context.enterprise_identity
        if identity is None:
            raise RuntimeError("Enterprise identity service is unavailable")
        service = EnterpriseAuthorityMigrationService(identity)
        if args.command == "export":
            vault_passphrase = getpass.getpass("Enterprise Vault passphrase: ")
            identity.unlock(vault_passphrase)
            password = getpass.getpass(f"Enterprise administrator password ({args.username}): ")
            identity.login(args.username, password); identity.step_up(password)
            path = service.export_bundle(args.output, vault_passphrase, source_mode=args.source_mode)
            print(f"Verified encrypted authority migration bundle: {path}")
            print("Enterprise Root fingerprint:", identity.root_public_identity()["fingerprint"])
            return 0
        backup_passphrase = getpass.getpass("Migration backup/Vault passphrase: ")
        service.import_bundle(
            args.input, backup_passphrase,
            expected_root_fingerprint=args.expected_root_fingerprint,
        )
        print("Enterprise Authority migration bundle restored. Unlock and validate the Root fingerprint before serving traffic.")
        return 0
    finally:
        if context is not None:
            context.shutdown()
        lease.release()


if __name__ == "__main__":
    raise SystemExit(main())
