from __future__ import annotations

import argparse
import json
from pathlib import Path

from arenyxa.release_hardening import UpgradeTransaction, default_migration_registry


def _paths(values: list[str]) -> list[Path]:
    return [Path(item) for item in values]


def main() -> int:
    parser = argparse.ArgumentParser(description="Arenyxa Phase-12 backup-first upgrade/migration manager")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--file", action="append", default=[])
    preflight.add_argument("--database", type=Path)

    backup = sub.add_parser("backup")
    backup.add_argument("--file", action="append", default=[])
    backup.add_argument("--database", action="append", default=[])

    migrate = sub.add_parser("migrate-json")
    migrate.add_argument("--path", type=Path, required=True)
    migrate.add_argument("--artifact", required=True, choices=("settings", "workflow_definition", "plugin_api", "enterprise_vault", "distributed_queue"))
    migrate.add_argument("--from-version", type=int, required=True)
    migrate.add_argument("--to-version", type=int)

    sub.add_parser("verify-backup")
    sub.add_parser("restore")
    args = parser.parse_args()
    transaction = UpgradeTransaction(args.data_dir, args.backup_dir)

    if args.command == "preflight":
        result = transaction.preflight(_paths(args.file), args.database)
        print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True, indent=2))
        return 0 if result.allowed else 2
    if args.command == "backup":
        manifest = transaction.backup(_paths(args.file), database_paths=_paths(args.database))
        transaction.verify_backup()
        print(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2))
        return 0
    if args.command == "verify-backup":
        transaction.verify_backup(); print("Upgrade backup verification: PASS"); return 0
    if args.command == "restore":
        transaction.restore(); print("Verified upgrade rollback restored."); return 0
    registry = default_migration_registry()
    migrated = transaction.execute(lambda: transaction.apply_json_migration(
        args.path, registry, args.artifact, args.from_version, args.to_version,
    ))
    print(json.dumps(migrated, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
