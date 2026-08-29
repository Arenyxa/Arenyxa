from __future__ import annotations

import tempfile
from pathlib import Path

from arenyxa.bootstrap import _root_developer_clean_start
from arenyxa.config import AppPaths, AppSettings

ROOT = Path(__file__).resolve().parents[1]


def _check_welcome_state_persistence() -> None:
    with tempfile.TemporaryDirectory(prefix="arenyxa-root-persistence-") as raw:
        paths = AppPaths.discover(Path(raw) / "data")
        paths.initialize()
        settings = AppSettings(
            theme="terminal_green",
            experience_profile="professional",
            experience_setup_completed=True,
        )
        settings.save(paths.root / "settings.json")
        preserved = _root_developer_clean_start(paths, settings)
        if preserved != settings:
            raise SystemExit("Root workstation startup mutated AppSettings")
        reloaded = AppSettings.load(paths.root / "settings.json")
        if not reloaded.experience_setup_completed or reloaded.experience_profile != "professional":
            raise SystemExit("Root workstation startup reset Welcome/Experience state")


def _check_root_binding_contract() -> None:
    access_source = (ROOT / "src/arenyxa/application/developer_access.py").read_text(encoding="utf-8")
    binding_source = (ROOT / "src/arenyxa/application/root_workstation_binding.py").read_text(encoding="utf-8")

    access_required = (
        "ROOT_WORKSTATION_BIND_FAILED",
        "def activate_root_workstation_session",
        "def ensure_root_workstation_session",
        "def root_startup_security_status",
        "def record_root_startup_failure",
        "def record_root_startup_cancel",
    )
    binding_required = (
        "round_trip = self.protector.unprotect",
        "BOUND_VERIFIED",
        "ROOT_OWNER_MAX_STARTUP_FAILURES = 3",
    )
    missing = [needle for needle in access_required if needle not in access_source]
    missing.extend(needle for needle in binding_required if needle not in binding_source)
    if missing:
        raise SystemExit(f"Root persistence contract missing: {missing}")

    bootstrap = (ROOT / "src/arenyxa/bootstrap.py").read_text(encoding="utf-8")
    if "developer_access.activate_root_workstation_session()" in bootstrap:
        raise SystemExit("Bootstrap must not auto-reactivate Root authority from a workstation binding")
    app = (ROOT / "src/arenyxa/app.py").read_text(encoding="utf-8")
    if "enforce_root_owner_startup_gate(context)" not in app:
        raise SystemExit("Desktop startup does not enforce the Root Owner re-authentication gate")
    if "reset application preferences to defaults" in bootstrap:
        raise SystemExit("Legacy Root settings-reset behavior is still present")

    repair_engine = (ROOT / "src/arenyxa/repair_engine.py").read_text(encoding="utf-8")
    repair_scanner = (ROOT / "src/arenyxa/repair_scanner.py").read_text(encoding="utf-8")
    if "experience_setup_completed" not in repair_engine or "experience_setup_completed" not in repair_scanner:
        raise SystemExit("Repair settings contract does not preserve Welcome completion state")


def main() -> int:
    _check_welcome_state_persistence()
    _check_root_binding_contract()
    print("Arenyxa v8.1.1 Root Persistence Contract: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
