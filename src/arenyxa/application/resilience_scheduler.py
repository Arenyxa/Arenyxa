from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arenyxa.exception_boundary import call_exception_boundary
from arenyxa.application.resilience_drills import ResilienceDrillService
from arenyxa.infrastructure.atomic_io import atomic_write_json, read_text_limited

_MAX_HISTORY = 64
_MAX_FILE_BYTES = 2 * 1024 * 1024
LOGGER = logging.getLogger(__name__)


class ResilienceDrillScheduler:
    """Opt-in periodic sandbox resilience validation with bounded history.

    The scheduler never injects faults into production resources. It runs the
    isolated drills already used by Repair Center, and it only executes while a
    Developer session owns ``fault_injection`` or ``platform.root``.
    """

    def __init__(self, context: Any, *, interval_seconds: int = 6 * 60 * 60) -> None:
        self.context = context
        self.interval_seconds = max(15 * 60, min(7 * 24 * 60 * 60, int(interval_seconds)))
        self.root = Path(context.paths.root) / "health"
        self.root.mkdir(parents=True, exist_ok=True)
        self.config_path = self.root / "resilience_schedule.json"
        self.history_path = self.root / "resilience_history.json"
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._enabled = False
        self._last_run_at = ""
        self._last_state = "never"
        self._failure_count = 0
        self._last_error = ""
        self._load_config()

    def _load_config(self) -> None:
        if not self.config_path.exists():
            return
        try:
            import json
            raw = read_text_limited(self.config_path, 64 * 1024)
            data = json.loads(raw)
            if isinstance(data, dict):
                self._enabled = bool(data.get("enabled", False))
                self.interval_seconds = max(
                    15 * 60,
                    min(7 * 24 * 60 * 60, int(data.get("interval_seconds", self.interval_seconds))),
                )
        except (OSError, ValueError, TypeError):
            self._enabled = False

    def _save_config(self) -> None:
        atomic_write_json(
            self.config_path,
            {"enabled": self._enabled, "interval_seconds": self.interval_seconds},
            mode=0o600,
        )

    def _authorized(self) -> bool:
        access = getattr(self.context, "developer_access", None)
        if access is None:
            return False
        try:
            status = access.status()
        except (OSError, RuntimeError, ValueError, TypeError):
            return False
        capabilities = set(getattr(status, "capabilities", ()) or ())
        return "fault_injection" in capabilities or "platform.root" in capabilities

    def _load_history(self) -> list[dict[str, Any]]:
        if not self.history_path.exists():
            return []
        try:
            import json
            raw = read_text_limited(self.history_path, _MAX_FILE_BYTES)
            rows = json.loads(raw)
        except (OSError, ValueError, TypeError):
            return []
        if not isinstance(rows, list):
            return []
        return [dict(item) for item in rows[-_MAX_HISTORY:] if isinstance(item, dict)]

    def _record(self, state: str, results: list[dict[str, Any]]) -> None:
        row = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "state": str(state),
            "passed": sum(1 for item in results if item.get("passed") is True),
            "total": len(results),
            "results": results,
        }
        with self._lock:
            rows = self._load_history()
            rows.append(row)
            atomic_write_json(self.history_path, rows[-_MAX_HISTORY:], mode=0o600)
            self._last_run_at = str(row["generated_at"])
            self._last_state = str(state)

    def run_once(self) -> dict[str, Any]:
        if not self._authorized():
            self._record("blocked-no-developer-capability", [])
            return self.snapshot()
        results = [item.to_dict() for item in ResilienceDrillService(self.context).run_all()]
        state = "healthy" if results and all(item.get("passed") is True for item in results) else "degraded"
        self._record(state, results)
        return self.snapshot()

    def _loop(self) -> None:
        # Delay the first automatic drill to avoid adding startup load.
        while not self._stop.wait(self.interval_seconds):
            with self._lock:
                enabled = self._enabled
            if not enabled:
                return
            def record_failure(exc: Exception) -> None:
                with self._lock:
                    self._failure_count += 1
                    self._last_error = f"{type(exc).__name__}: {exc}"[:512]
                LOGGER.exception("Scheduled resilience drill failed; scheduler remains active")

            sentinel = object()
            outcome = call_exception_boundary(
                lambda: (self.run_once(), sentinel)[1],
                on_error=record_failure,
            )
            if outcome is sentinel:
                with self._lock:
                    self._last_error = ""

    def start_if_enabled(self) -> None:
        with self._lock:
            if not self._enabled or (self._thread is not None and self._thread.is_alive()):
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="arenyxa-resilience-drills", daemon=True)
            self._thread.start()

    def enable(self, *, interval_seconds: int | None = None) -> None:
        with self._lock:
            if interval_seconds is not None:
                self.interval_seconds = max(15 * 60, min(7 * 24 * 60 * 60, int(interval_seconds)))
            self._enabled = True
            self._save_config()
        self.start_if_enabled()

    def disable(self) -> None:
        with self._lock:
            self._enabled = False
            self._save_config()
            thread = self._thread
            self._thread = None
            self._stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def shutdown(self) -> None:
        with self._lock:
            thread = self._thread
            self._thread = None
            self._stop.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._enabled,
                "interval_seconds": self.interval_seconds,
                "running": bool(self._thread is not None and self._thread.is_alive()),
                "last_run_at": self._last_run_at,
                "last_state": self._last_state,
                "failure_count": self._failure_count,
                "last_error": self._last_error,
                "history": self._load_history()[-10:],
            }
