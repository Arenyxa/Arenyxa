from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def main() -> int:
    checks: dict[str, dict[str, object]] = {}
    failures: list[str] = []

    try:
        import arenyxa
        checks["package_import"] = {"ok": True, "version": arenyxa.__version__}
        if arenyxa.__version__ != "8.1":
            failures.append("runtime version is not 8.1")
    except (ImportError, AttributeError) as exc:
        checks["package_import"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        failures.append("package import failed")

    try:
        from arenyxa.application.command_runtime import ArenyxaCommandRuntime
        from arenyxa.infrastructure.capture import (
            BoundedEventStream,
            DynamicProtocolRegistry,
            LiveIntelligencePipeline,
            OfflinePacketLab,
            PassiveDetectionEngine,
            ThreatHunter,
        )
        checks["critical_imports"] = {
            "ok": True,
            "symbols": [
                ArenyxaCommandRuntime.__name__, DynamicProtocolRegistry.__name__,
                BoundedEventStream.__name__, LiveIntelligencePipeline.__name__,
                PassiveDetectionEngine.__name__, ThreatHunter.__name__, OfflinePacketLab.__name__,
            ],
        }
    except ImportError as exc:
        checks["critical_imports"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        failures.append("critical runtime imports failed")

    try:
        from arenyxa.infrastructure.database import SQLiteStore
        with tempfile.TemporaryDirectory(prefix="arenyxa-runtime-diagnostic-") as td:
            store = SQLiteStore(Path(td) / "diagnostic.sqlite3")
            store.initialize()
            with store.connect() as connection:
                quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
                journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        ok = quick_check.casefold() == "ok"
        checks["sqlite"] = {
            "ok": ok,
            "quick_check": quick_check,
            "journal_mode": journal_mode,
            "sqlite_version": sqlite3.sqlite_version,
        }
        if not ok:
            failures.append("SQLite quick_check failed")
    except (ImportError, OSError, RuntimeError, sqlite3.Error) as exc:
        checks["sqlite"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        failures.append("SQLite diagnostic failed")

    payload = {
        "schema": "arenyxa.runtime-diagnostic/v2",
        "runtime": "diagnostic",
        "python": sys.version.split()[0],
        "healthy": not failures,
        "checks": checks,
        "failures": failures,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
