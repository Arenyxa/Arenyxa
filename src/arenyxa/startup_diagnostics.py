from __future__ import annotations

import json
import os
import platform
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LOCK = threading.RLock()
_LAST_STAGE = "process-import"
_FAULT_HANDLE = None
_INSTALLED = False


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _log_dir() -> Path:
    override = os.environ.get("ARENYXA_STARTUP_LOG_DIR", "").strip()
    if override:
        return Path(override).expanduser()

    # Default diagnostics are intentionally user-visible on Windows so a startup
    # crash can be inspected without navigating AppData. Resolve the current
    # user's desktop instead of hard-coding an account name.
    user_profile = os.environ.get("USERPROFILE", "").strip()
    if os.name == "nt" and user_profile:
        return Path(user_profile) / "Desktop" / "Arenyxa_Logs"

    # Non-Windows/degraded fallback. Runtime logging remains independent from
    # the product data root so diagnostics never alter normal application data.
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if local:
        return Path(local) / "Arenyxa" / "logs"
    return Path.home() / ".arenyxa" / "logs"


def log_paths() -> dict[str, Path]:
    base = _log_dir()
    return {
        "startup": base / "startup.log",
        "crash": base / "startup_crash.log",
        "native": base / "native_fault.log",
        "deep_exit": base / "exit_trace.log",
    }


def _safe_json(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value[:64]]
    if isinstance(value, dict):
        return {str(key): _safe_json(item) for key, item in list(value.items())[:64]}
    return repr(value)[:2048]


def _append(path: Path, text: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", errors="replace") as handle:
            handle.write(text)
            handle.flush()
    except Exception:
        # Startup diagnostics must never become a new startup failure.
        return


def checkpoint(stage: str, **details: Any) -> None:
    # Keep verbose startup trace emission disabled in the stable runtime.
    # Keep the last stage in memory for crash diagnostics.
    global _LAST_STAGE
    _LAST_STAGE = str(stage)


def record_crash(exc: BaseException, *, source: str = "unhandled") -> None:
    payload = {
        "timestamp_utc": _utc_now(),
        "pid": os.getpid(),
        "source": source,
        "last_stage": _LAST_STAGE,
        "python_executable": sys.executable,
        "python_version": sys.version,
        "argv": list(sys.argv),
        "cwd": os.getcwd(),
        "platform": platform.platform(),
        "exception_type": type(exc).__name__,
        "exception_message": str(exc),
    }
    text = (
        "\n=== ARENYXA STARTUP CRASH ===\n"
        + json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n--- traceback ---\n"
        + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        + "=== END CRASH ===\n"
    )
    with _LOCK:
        _append(log_paths()["crash"], text)
        checkpoint("CRASH_RECORDED", source=source, exception_type=type(exc).__name__)


def _sys_excepthook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
    try:
        if exc.__traceback__ is None:
            exc = exc.with_traceback(tb)
        record_crash(exc, source="sys.excepthook")
    finally:
        sys.__excepthook__(exc_type, exc, tb)


def _thread_excepthook(args: Any) -> None:
    try:
        exc = args.exc_value
        if exc is not None:
            record_crash(exc, source=f"thread:{getattr(args.thread, 'name', 'unknown')}")
    finally:
        original = getattr(threading, "__excepthook__", None)
        if original is not None:
            original(args)


def install_early_diagnostics() -> None:
    """Install diagnostics without creating persistent files during healthy startup.

    Normal application startup must not create Arenyxa_Logs, launcher.log,
    native_fault.log, exit_trace.log, or any other persistent startup trace.
    A crash report is still written lazily by record_crash() only when an
    unhandled Python exception actually occurs.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True
    sys.excepthook = _sys_excepthook
    if hasattr(threading, "excepthook"):
        threading.excepthook = _thread_excepthook
    try:
        import faulthandler

        if not faulthandler.is_enabled():
            # Preserve native traceback support on stderr only; no persistent file.
            faulthandler.enable(all_threads=True)
    except Exception as exc:
        checkpoint("DIAGNOSTICS_FAULTHANDLER_UNAVAILABLE", error=repr(exc))
    checkpoint(
        "BOOT-000-DIAGNOSTICS-INSTALLED",
        python=sys.executable,
        cwd=os.getcwd(),
    )


def install_deep_exit_tracing() -> None:
    """Compatibility no-op: persistent startup/exit tracing is intentionally disabled in the stable runtime."""
    return
