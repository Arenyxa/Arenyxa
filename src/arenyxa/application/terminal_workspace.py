from __future__ import annotations

import threading
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from arenyxa.application.terminal import TerminalMode, TerminalResult, TerminalSession
from arenyxa.application.windows_conpty import WindowsConPtySession


@dataclass(slots=True)
class TerminalWorkspaceState:
    id: str
    title: str
    mode: str
    pane: str
    cwd: str
    running: bool
    persistent: bool
    backend: str = "persistent-pipes"
    exit_code: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    output_truncated: bool = False


class TerminalWorkspaceManager:
    MAX_SESSIONS = 12
    MAX_OUTPUT_CHARS = 1_000_000

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._sessions: dict[str, Any] = {}
        self._meta: dict[str, dict[str, Any]] = {}
        self._output: dict[str, deque[str]] = {}
        self._output_chars: dict[str, int] = {}
        self._counter = 0

    def create(self, *, title: str = "Terminal", mode: str = "powershell-session", pane: str = "primary") -> dict[str, Any]:
        normalized_mode = TerminalMode(mode)
        if normalized_mode not in {
            TerminalMode.POWERSHELL_SESSION,
            TerminalMode.CMD_SESSION,
            TerminalMode.PYTHON_SESSION,
        }:
            raise ValueError("Workspace sessions require a persistent terminal mode")
        pane_name = str(pane or "primary").strip().casefold()
        if pane_name not in {"primary", "secondary", "bottom"}:
            raise ValueError("pane must be primary, secondary, or bottom")
        with self._lock:
            if len(self._sessions) >= self.MAX_SESSIONS:
                raise RuntimeError(f"Terminal workspace is limited to {self.MAX_SESSIONS} sessions")
            self._counter += 1
            session_id = f"term-{self._counter:03d}"
            use_conpty = normalized_mode in {TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION} and WindowsConPtySession.supported()
            session = WindowsConPtySession(self.root) if use_conpty else TerminalSession(self.root)
            self._sessions[session_id] = session
            self._meta[session_id] = {
                "title": str(title or "Terminal")[:80],
                "mode": normalized_mode,
                "pane": pane_name,
                "backend": "windows-conpty" if use_conpty else "persistent-pipes",
                "result": None,
                "columns": 120,
                "rows": 32,
            }
            self._output[session_id] = deque()
            self._output_chars[session_id] = 0
        return self.snapshot(session_id)

    def start(self, session_id: str) -> dict[str, Any]:
        session, meta = self._require(session_id)
        if session.is_running:
            return self.snapshot(session_id)
        mode = meta["mode"]
        launch = session.build_launch("interactive-session", mode)

        def on_output(text: str) -> None:
            self._append_output(session_id, text)

        def on_exit(result: TerminalResult) -> None:
            with self._lock:
                if session_id in self._meta:
                    self._meta[session_id]["result"] = result

        session.start(launch, on_output, on_exit)
        return self.snapshot(session_id)

    def send(self, session_id: str, text: str, *, newline: bool = True) -> dict[str, Any]:
        session, _meta = self._require(session_id)
        if not session.is_running:
            self.start(session_id)
        payload = str(text)
        if not session.send_input(payload, append_newline=newline):
            raise RuntimeError("Terminal workspace session is not accepting input")
        return self.snapshot(session_id)


    def rename(self, session_id: str, title: str) -> dict[str, Any]:
        self._require(session_id)
        normalized = str(title).strip()[:80]
        if not normalized:
            raise ValueError("Terminal workspace title is empty")
        with self._lock:
            self._meta[session_id]["title"] = normalized
        return self.snapshot(session_id)

    def move(self, session_id: str, pane: str) -> dict[str, Any]:
        self._require(session_id)
        pane_name = str(pane or "").strip().casefold()
        if pane_name not in {"primary", "secondary", "bottom"}:
            raise ValueError("pane must be primary, secondary, or bottom")
        with self._lock:
            self._meta[session_id]["pane"] = pane_name
        return self.snapshot(session_id)

    def resize(self, session_id: str, columns: int, rows: int) -> dict[str, Any]:
        session, _meta = self._require(session_id)
        width = max(20, min(int(columns), 1000))
        height = max(5, min(int(rows), 400))
        resize = getattr(session, "resize", None)
        if callable(resize):
            resize(width, height)
        with self._lock:
            self._meta[session_id]["columns"] = width
            self._meta[session_id]["rows"] = height
        return self.snapshot(session_id)

    def interrupt(self, session_id: str) -> dict[str, Any]:
        session, _meta = self._require(session_id)
        if not session.is_running:
            return self.snapshot(session_id)
        if not session.send_input("\x03", append_newline=False):
            session.stop()
        return self.snapshot(session_id)

    def stop(self, session_id: str) -> dict[str, Any]:
        session, _meta = self._require(session_id)
        if session.is_running:
            session.stop()
            session.wait(5.0)
        return self.snapshot(session_id)

    def close(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            return False
        try:
            session.close()
        finally:
            with self._lock:
                self._sessions.pop(session_id, None)
                self._meta.pop(session_id, None)
                self._output.pop(session_id, None)
                self._output_chars.pop(session_id, None)
        return True

    def close_all(self) -> None:
        with self._lock:
            ids = list(self._sessions)
        for session_id in ids:
            self.close(session_id)

    def output(self, session_id: str, *, tail_chars: int = 200_000) -> str:
        self._require(session_id)
        bounded = max(0, min(int(tail_chars), self.MAX_OUTPUT_CHARS))
        with self._lock:
            text = "".join(self._output[session_id])
        return text[-bounded:] if bounded else ""

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            ids = list(self._sessions)
        return [self.snapshot(session_id) for session_id in ids]

    def snapshot(self, session_id: str) -> dict[str, Any]:
        session, meta = self._require(session_id)
        result = meta.get("result")
        state = TerminalWorkspaceState(
            id=session_id,
            title=str(meta["title"]),
            mode=TerminalMode(meta["mode"]).value,
            pane=str(meta["pane"]),
            cwd=str(session.cwd),
            running=session.is_running,
            persistent=session.active_persistent,
            backend=str(meta.get("backend") or "persistent-pipes"),
            exit_code=None if result is None else int(result.exit_code),
            timed_out=False if result is None else bool(result.timed_out),
            cancelled=False if result is None else bool(result.cancelled),
            output_truncated=False if result is None else bool(result.output_truncated),
        )
        payload = asdict(state)
        payload["output_chars"] = self._output_chars.get(session_id, 0)
        payload["columns"] = int(meta.get("columns") or 120)
        payload["rows"] = int(meta.get("rows") or 32)
        return payload

    def _append_output(self, session_id: str, text: str) -> None:
        chunk = str(text)
        if not chunk:
            return
        with self._lock:
            queue = self._output.get(session_id)
            if queue is None:
                return
            queue.append(chunk)
            total = self._output_chars.get(session_id, 0) + len(chunk)
            while total > self.MAX_OUTPUT_CHARS and queue:
                removed = queue.popleft()
                total -= len(removed)
            self._output_chars[session_id] = max(0, total)

    def _require(self, session_id: str) -> tuple[Any, dict[str, Any]]:
        key = str(session_id).strip()
        with self._lock:
            session = self._sessions.get(key)
            meta = self._meta.get(key)
        if session is None or meta is None:
            raise KeyError(f"Terminal workspace session not found: {key}")
        return session, meta
