"""Out-of-process liveness supervision for Arenyxa runtimes.

The in-process runtime supervisor is useful for collecting Python stacks, but it cannot
observe a process whose GIL or interpreter is completely wedged.  This module provides
an independent child process connected by a pipe.  The child owns the stall clock and
incident persistence, so it continues supervising when application threads stop running.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from arenyxa.infrastructure.atomic_io import atomic_write_json
from arenyxa.infrastructure.process_safety import validated_argv

LOGGER = logging.getLogger(__name__)
_SCHEMA = "arenyxa.external-supervisor-heartbeat/v1"
_INCIDENT_SCHEMA = "arenyxa.external-supervisor-incident/v1"
_SENTINEL = object()


def _process_exists(pid: int) -> bool:
    if pid <= 0:
        return False

    if pid == os.getpid():
        return True

    if os.name == "nt":
        try:
            import ctypes

            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                False,
                pid,
            )

            if not handle:
                return False

            ctypes.windll.kernel32.CloseHandle(handle)
            return True

        except Exception:
            return False

    try:
        os.kill(pid, 0)
        return True

    except ProcessLookupError:
        return False

    except PermissionError:
        return True

    except OSError:
        return False    

class ExternalSupervisorClient:
    """Non-blocking parent-side transport to the independent supervisor process."""

    def __init__(
        self,
        diagnostics_dir: Path,
        *,
        stale_seconds: float = 5.0,
        queue_capacity: int = 2048,
    ) -> None:
        self.diagnostics_dir = Path(diagnostics_dir)
        self.stale_seconds = max(1.0, float(stale_seconds))
        self.queue_capacity = max(128, int(queue_capacity))
        self._queue: queue.Queue[object] = queue.Queue(maxsize=self.queue_capacity)
        self._process: subprocess.Popen[str] | None = None
        self._sender_thread: threading.Thread | None = None
        self._ticker_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._dropped = 0
        self._send_failures = 0
        self._sent = 0
        self._started_monotonic = 0.0

    def start(self) -> None:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return
            self.diagnostics_dir.mkdir(parents=True, exist_ok=True)
            child_stderr = self.diagnostics_dir / "external-supervisor.stderr.log"
            stderr_stream = child_stderr.open("a", encoding="utf-8", buffering=1)
            creationflags = 0
            if os.name == "nt":
                creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            command = [
                sys.executable,
                "-m",
                "arenyxa.infrastructure.external_supervisor",
                "--child",
                "--parent-pid",
                str(os.getpid()),
                "--diagnostics-dir",
                str(self.diagnostics_dir),
                "--stale-seconds",
                str(self.stale_seconds),
            ]
            child_env = os.environ.copy()
            source_root = str(Path(__file__).resolve().parents[2])
            existing_pythonpath = child_env.get("PYTHONPATH", "")
            pythonpath_entries = [entry for entry in existing_pythonpath.split(os.pathsep) if entry]
            if source_root not in pythonpath_entries:
                pythonpath_entries.insert(0, source_root)
            child_env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
            child_env["PYTHONUNBUFFERED"] = "1"
            try:
                process = subprocess.Popen(
                    validated_argv(command),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr_stream,
                    text=True,
                    encoding="utf-8",
                    bufsize=1,
                    creationflags=creationflags,
                    env=child_env,
                )
            except (OSError, ValueError):
                stderr_stream.close()
                raise
            self._process = process
            self._stop.clear()
            self._started_monotonic = time.monotonic()
            self._sender_thread = threading.Thread(
                target=self._sender_loop,
                args=(process, stderr_stream),
                name="arenyxa-external-supervisor-ipc",
                daemon=True,
            )
            self._ticker_thread = threading.Thread(
                target=self._ticker_loop,
                name="arenyxa-external-supervisor-process-heartbeat",
                daemon=True,
            )
            self._sender_thread.start()
            self._ticker_thread.start()
        self.heartbeat("process", {"pid": os.getpid(), "executable": sys.executable})

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        self._enqueue(_SENTINEL)
        with self._lock:
            sender = self._sender_thread
            ticker = self._ticker_thread
            process = self._process
            self._sender_thread = None
            self._ticker_thread = None
            self._process = None
        if ticker is not None and ticker is not threading.current_thread():
            ticker.join(max(0.0, min(float(timeout), 1.0)))
        if sender is not None and sender is not threading.current_thread():
            sender.join(max(0.0, min(float(timeout), 1.5)))
        if process is not None:
            try:
                process.wait(timeout=max(0.1, float(timeout)))
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)

    def heartbeat(self, component: str, state: Mapping[str, Any] | None = None) -> None:
        payload = {
            "schema": _SCHEMA,
            "component": str(component),
            "sent_monotonic": time.monotonic(),
            "sent_unix_ns": time.time_ns(),
            "state": dict(state or {}),
        }
        self._enqueue(payload)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            process = self._process
            sender = self._sender_thread
            ticker = self._ticker_thread
            return {
                "running": bool(process is not None and process.poll() is None),
                "pid": int(process.pid) if process is not None else None,
                "ipc_sender_alive": bool(sender and sender.is_alive()),
                "process_ticker_alive": bool(ticker and ticker.is_alive()),
                "queue_depth": self._queue.qsize(),
                "queue_capacity": self.queue_capacity,
                "dropped": self._dropped,
                "sent": self._sent,
                "send_failures": self._send_failures,
                "uptime_seconds": max(0.0, time.monotonic() - self._started_monotonic)
                if self._started_monotonic
                else 0.0,
            }

    def _enqueue(self, item: object) -> None:
        try:
            self._queue.put_nowait(item)
            return
        except queue.Full:
            with self._lock:
                self._dropped += 1
        try:
            self._queue.get_nowait()
        except queue.Empty:
            LOGGER.warning("External supervisor IPC queue reported full but no item was removable")
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._lock:
                self._dropped += 1

    def _ticker_loop(self) -> None:
        while not self._stop.wait(0.5):
            self.heartbeat("process", {"pid": os.getpid()})

    def _sender_loop(self, process: subprocess.Popen[str], stderr_stream: TextIO) -> None:
        try:
            stream = process.stdin
            if stream is None:
                raise RuntimeError("External supervisor child has no IPC stdin")
            while not self._stop.is_set():
                try:
                    item = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if item is _SENTINEL:
                    break
                try:
                    line = json.dumps(item, ensure_ascii=False, separators=(",", ":"), default=str)
                    stream.write(line + "\n")
                    stream.flush()
                    with self._lock:
                        self._sent += 1
                except (BrokenPipeError, OSError, ValueError, TypeError) as exc:
                    with self._lock:
                        self._send_failures += 1
                    LOGGER.error("External supervisor IPC transport failed: %s", exc)
                    break
            try:
                stream.close()
            except OSError as exc:
                LOGGER.warning("External supervisor IPC close failed: %s", exc)
        finally:
            stderr_stream.close()


def _incident_path(diagnostics_dir: Path, component: str, now_ns: int) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in component)[:80]
    return diagnostics_dir / f"external-stall-{safe}-{now_ns}.json"


def _write_child_incident(
    diagnostics_dir: Path,
    *,
    parent_pid: int,
    component: str,
    age_seconds: float,
    state: Mapping[str, Any],
    reason: str,
) -> None:
    now_ns = time.time_ns()
    payload = {
        "schema": _INCIDENT_SCHEMA,
        "parent_pid": parent_pid,
        "component": component,
        "reason": reason,
        "detected_at_unix_ns": now_ns,
        "age_seconds": round(max(0.0, age_seconds), 3),
        "state": json.loads(json.dumps(dict(state), ensure_ascii=False, default=str)),
        "supervisor_pid": os.getpid(),
    }
    atomic_write_json(_incident_path(diagnostics_dir, component, now_ns), payload)


def _child_reader(stream: TextIO, inbox: queue.Queue[dict[str, Any]], eof: threading.Event) -> None:
    try:
        for raw in stream:
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                LOGGER.error("External supervisor rejected malformed IPC heartbeat: %s", exc)
                continue
            if not isinstance(payload, dict) or payload.get("schema") != _SCHEMA:
                LOGGER.error("External supervisor rejected heartbeat with invalid schema")
                continue
            inbox.put(payload)
    finally:
        eof.set()


def run_child(*, parent_pid: int, diagnostics_dir: Path, stale_seconds: float) -> int:
    diagnostics_dir = Path(diagnostics_dir)
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    stale_seconds = max(1.0, float(stale_seconds))
    inbox: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=4096)
    eof = threading.Event()
    reader = threading.Thread(
        target=_child_reader,
        args=(sys.stdin, inbox, eof),
        name="arenyxa-external-supervisor-reader",
        daemon=True,
    )
    reader.start()
    last_seen: dict[str, tuple[float, dict[str, Any]]] = {}
    reported_bucket: dict[str, int] = {}
    last_ipc = time.monotonic()
    required_thresholds = {
        "process": stale_seconds,
        "ui_thread": stale_seconds,
        "database": max(stale_seconds * 2.0, 10.0),
        "worker_progress": max(stale_seconds * 3.0, 15.0),
    }
    while True:
        now = time.monotonic()
        drained = False
        while True:
            try:
                payload = inbox.get_nowait()
            except queue.Empty:
                break
            drained = True
            component = str(payload.get("component", "unknown"))
            state = payload.get("state")
            last_seen[component] = (now, dict(state) if isinstance(state, dict) else {})
            reported_bucket.pop(component, None)
        if drained:
            last_ipc = now
        if not _process_exists(parent_pid):
            _write_child_incident(
                diagnostics_dir,
                parent_pid=parent_pid,
                component="process",
                age_seconds=0.0,
                state={},
                reason="PARENT_PROCESS_EXITED",
            )
            return 0
        if eof.is_set() and not _process_exists(parent_pid):
            return 0
        ipc_age = now - last_ipc
        if ipc_age > stale_seconds:
            bucket = int(ipc_age // stale_seconds)
            if reported_bucket.get("ipc") != bucket:
                _write_child_incident(
                    diagnostics_dir,
                    parent_pid=parent_pid,
                    component="ipc",
                    age_seconds=ipc_age,
                    state={},
                    reason="IPC_HEARTBEAT_STALE",
                )
                reported_bucket["ipc"] = bucket
        for component, threshold in required_thresholds.items():
            seen = last_seen.get(component)
            if seen is None:
                # Give bootstrap a bounded grace window before requiring component heartbeats.
                continue
            seen_at, state = seen
            age = now - seen_at
            if age <= threshold:
                continue
            bucket = int(age // threshold)
            if reported_bucket.get(component) == bucket:
                continue
            reason = {
                "process": "PROCESS_HEARTBEAT_STALE",
                "ui_thread": "EVENT_LOOP_HEARTBEAT_STALE",
                "database": "DATABASE_RESPONSIVENESS_STALE",
                "worker_progress": "WORKER_PROGRESS_STALE",
            }.get(component, "COMPONENT_HEARTBEAT_STALE")
            _write_child_incident(
                diagnostics_dir,
                parent_pid=parent_pid,
                component=component,
                age_seconds=age,
                state=state,
                reason=reason,
            )
            reported_bucket[component] = bucket
        if eof.is_set() and now - last_ipc > 1.0:
            # Graceful shutdown closes stdin while the parent can still be alive for teardown.
            return 0
        time.sleep(0.2)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Arenyxa independent runtime supervisor")
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--parent-pid", type=int, default=0)
    parser.add_argument("--diagnostics-dir", type=Path)
    parser.add_argument("--stale-seconds", type=float, default=5.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.child or args.parent_pid <= 0 or args.diagnostics_dir is None:
        raise SystemExit("external_supervisor is an internal child-process entry point")
    return run_child(
        parent_pid=int(args.parent_pid),
        diagnostics_dir=Path(args.diagnostics_dir),
        stale_seconds=float(args.stale_seconds),
    )


if __name__ == "__main__":
    raise SystemExit(main())
