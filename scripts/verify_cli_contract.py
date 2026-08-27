from __future__ import annotations

import json
import logging
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from arenyxa.application.command_runtime import ArenyxaCommandRuntime
from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION
from arenyxa.bootstrap import bootstrap

REQUIRED_COMMANDS: dict[str, tuple[str, ...]] = {
    "task": ("list", "show", "run"),
    "run": ("list", "show", "cancel"),
    "capture": ("start", "stop", "status"),
    "packet": ("sessions", "analytics", "protocols"),
    "proxy": ("start", "stop", "sessions", "replay"),
    "mitm": ("start", "stop", "status"),
    "fleet": ("status", "workers", "jobs"),
    "plugin": ("list", "health"),
    "health-check": (),
    "diagnostics": ("export",),
    "job": ("list", "show", "wait", "cancel"),
}


def main() -> int:
    evidence: dict[str, object] = {"schema": "arenyxa.cli-contract-gate/v2"}
    missing: list[str] = []
    for group, actions in REQUIRED_COMMANDS.items():
        actual = ArenyxaCommandRuntime.COMMAND_TREE.get(group)
        if actual is None:
            missing.append(group)
            continue
        for action in actions:
            if action not in actual:
                missing.append(f"{group} {action}")
    evidence["static_surface"] = {
        "required": {name: list(actions) for name, actions in REQUIRED_COMMANDS.items()},
        "missing": missing,
    }
    if missing:
        evidence["healthy"] = False
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
        return 1

    try:
        with tempfile.TemporaryDirectory(prefix="arenyxa-v8-cli-gate-") as raw:
            context = bootstrap(Path(raw) / "runtime", start_scheduler=False)
            try:
                context.settings.developer_mode = True
                context.settings.developer_terms_version = DEVELOPER_TERMS_VERSION
                context.settings.developer_terms_accepted_at = "2026-08-22T12:00:00+00:00"
                runtime = context.command_runtime
                version = runtime.execute("version")["data"]
                help_payload = runtime.execute("help")["data"]
                health = runtime.execute("health-check --deep")["data"]
                diagnostic_job = runtime.execute(
                    "diagnostics export --output cli-contract-diagnostics.zip --timeout 30"
                )["data"]
                bundle = Path(diagnostic_job["result"]["path"])
                with zipfile.ZipFile(bundle, "r") as archive:
                    archive_error = archive.testzip()
                    archive_names = sorted(archive.namelist())
                audit_valid, audit_reason = context.security.audit.verify()
                runtime_evidence = {
                    "version": version,
                    "help_groups": sorted(help_payload["groups"]),
                    "health_status": health["status"],
                    "storage_integrity": health["components"]["storage"]["details"]["integrity"],
                    "job_state": diagnostic_job["state"],
                    "diagnostic_archive": str(bundle),
                    "diagnostic_archive_error": archive_error,
                    "diagnostic_archive_entries": archive_names,
                    "audit_valid": audit_valid,
                    "audit_reason": audit_reason,
                }
            finally:
                context.shutdown()
                logging.shutdown()
    except Exception as exc:  # noqa: BLE001 - the release gate must report every bootstrap failure
        evidence["healthy"] = False
        evidence["runtime_error"] = f"{type(exc).__name__}: {exc}"
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
        return 1

    healthy = bool(
        runtime_evidence["health_status"] == "healthy"
        and runtime_evidence["storage_integrity"] == "ok"
        and runtime_evidence["job_state"] == "succeeded"
        and runtime_evidence["diagnostic_archive_error"] is None
        and runtime_evidence["audit_valid"] is True
    )
    evidence["runtime"] = runtime_evidence
    evidence["healthy"] = healthy
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
