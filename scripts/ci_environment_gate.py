from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from typing import Any


def _require_module(name: str) -> None:
    if importlib.util.find_spec(name) is None:
        raise RuntimeError(f"required CI module is unavailable: {name}")


def _qt_probe() -> dict[str, Any]:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import qVersion
    from PySide6.QtWidgets import QApplication, QLabel

    app = QApplication.instance() or QApplication([])
    label = QLabel("Arenyxa CI Qt probe")
    label.resize(200, 40)
    label.show()
    app.processEvents()
    visible = label.isVisible()
    label.close()
    app.processEvents()
    return {"qt": qVersion(), "platform": os.environ.get("QT_QPA_PLATFORM", ""), "widget_visible": visible}


def _process_probe() -> dict[str, Any]:
    code = "import os,sys; print(str(os.getpid()) + ':' + str(sys.version_info[:2]))"
    completed = subprocess.run(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0 or ":" not in completed.stdout:
        raise RuntimeError(f"cross-process Python probe failed: {completed.stderr[-500:]}")
    return {"returncode": completed.returncode, "stdout": completed.stdout.strip()[:200]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail CI early when release-blocking runtime dependencies are absent.")
    parser.add_argument("--require-static", action="store_true")
    parser.add_argument("--require-tshark", action="store_true")
    args = parser.parse_args(argv)
    required = ["PySide6", "pytest", "fastapi", "httpx", "cryptography"]
    if args.require_static:
        required.extend(["ruff", "mypy"])
    for module in required:
        _require_module(module)
    tshark = shutil.which("tshark")
    if args.require_tshark and not tshark:
        raise RuntimeError("required CI protocol parity backend is unavailable: tshark")
    report = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "qt": _qt_probe(),
        "process": _process_probe(),
        "static_tools": {name: importlib.util.find_spec(name) is not None for name in ("ruff", "mypy")},
        "tshark": tshark or "",
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
