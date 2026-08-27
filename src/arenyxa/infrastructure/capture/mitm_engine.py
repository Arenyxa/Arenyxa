from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from arenyxa.infrastructure.process_safety import validated_argv

import json
import os
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from arenyxa.compat import dataclass
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard
from arenyxa.infrastructure.atomic_io import atomic_write_text
from arenyxa.infrastructure.external_tools import ExternalToolProbe
from arenyxa.domain.errors import ArenyxaError


_VALID_MODES = {"regular", "local", "wireguard", "reverse", "upstream", "transparent", "tun", "socks5", "dns"}


@dataclass(slots=True)
class MitmSettings:
    """Configure the local interception engine with bounded capture and filter settings."""
    executable: str = ""
    bind_host: str = "127.0.0.1"
    bind_port: int = 8081
    mode: str = "regular"
    mode_spec: str = ""
    allow_remote_clients: bool = False
    intercept_filter: str = ""
    view_filter: str = ""
    ignore_hosts: list[str] = field(default_factory=list)
    allow_hosts: list[str] = field(default_factory=list)
    map_local: list[str] = field(default_factory=list)
    map_remote: list[str] = field(default_factory=list)
    modify_headers: list[str] = field(default_factory=list)
    modify_body: list[str] = field(default_factory=list)
    block_list: list[str] = field(default_factory=list)
    addon_scripts: list[str] = field(default_factory=list)
    protobuf_definitions: str = ""
    client_certs: str = ""
    upstream_cert: bool = True
    http2: bool = True
    http3: bool = True
    rawtcp: bool = True
    websocket: bool = True
    anticache: bool = False
    anticomp: bool = False
    stream_large_bodies: str = ""
    connection_strategy: str = "eager"
    intercept_timeout_seconds: float = 120.0
    save_filter: str = ""
    network_guard_enabled: bool = True

    def validate(self) -> None:
        """Validate listener, capture, timeout, and filter bounds before startup."""
        if self.mode not in _VALID_MODES:
            raise ValueError("Unsupported MITM mode")
        if not isinstance(self.bind_port, int) or isinstance(self.bind_port, bool) or self.bind_port < 0 or self.bind_port > 65535:
            raise ValueError("MITM listen port must be between 0 and 65535")
        host = self.bind_host.strip()
        if not host:
            raise ValueError("MITM listen host is required")
        if not self.allow_remote_clients and host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("Remote MITM listeners require explicit allow_remote_clients")
        if self.mode in {"reverse", "upstream"} and not self.mode_spec.strip():
            raise ValueError(f"{self.mode} mode requires a target specification")
        if self.mode == "wireguard" and self.mode_spec.strip() and "\x00" in self.mode_spec:
            raise ValueError("Invalid WireGuard key path")
        if self.connection_strategy not in {"lazy", "eager"}:
            raise ValueError("connection_strategy must be lazy or eager")
        if self.intercept_timeout_seconds < 1 or self.intercept_timeout_seconds > 600:
            raise ValueError("intercept timeout must be between 1 and 600 seconds")
        if self.network_guard_enabled and self.mode in {"reverse", "upstream"}:
            parsed = urlsplit(self.mode_spec.strip())
            target_host = parsed.hostname or self.mode_spec.strip().split(":", 1)[0]
            NetworkUseGuard(NetworkGuardPolicy()).check_target(target_host, resolve_dns=False)


@dataclass(slots=True)
class MitmStatus:
    """Expose interception-engine lifecycle and runtime health state."""
    running: bool
    pid: int | None
    executable: str
    version: str
    mode: str
    bind_host: str
    bind_port: int
    events: int
    pending: int
    flow_file: str
    last_error: str


@dataclass(slots=True)
class MitmEvent:
    """Represent one normalized interception event without embedding UI state."""
    sequence: int
    timestamp: float
    event: str
    flow_id: str
    protocol: str
    phase: str
    method: str = ""
    url: str = ""
    host: str = ""
    status: int | None = None
    direction: str = ""
    size: int = 0
    replay: str = ""
    intercepted: bool = False
    payload: dict[str, Any] = field(default_factory=dict)


class MitmEngine:
    """Manage the local interception runtime, event bridge, replay, and lifecycle boundaries."""
    def __init__(self, root: Path, settings: MitmSettings | None = None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(parents=True, exist_ok=True)
        self.pending_dir = self.runtime / "pending"
        self.control_dir = self.runtime / "control"
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.control_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.runtime / "events.jsonl"
        self.flow_path = self.root / "flows.mitm"
        self.settings = settings or MitmSettings()
        self.bridge_path = Path(__file__).with_name("mitm_bridge.py")
        self._process: subprocess.Popen[str] | None = None
        self._events: list[MitmEvent] = []
        self._event_offset = 0
        self._lock = threading.RLock()
        self._last_error = ""
        self._version = ""
        self._log_handle = None
        self.log_path = self.runtime / "mitmdump.log"

    @staticmethod
    def discover(executable: str = "") -> str:
        """Discover the optional local interception executable without invoking a shell."""
        if executable:
            candidate = Path(executable)
            if candidate.is_file():
                return str(candidate)
            located = shutil.which(executable)
            if located:
                return located
            return ""
        for name in ("mitmdump", "mitmdump.exe"):
            located = shutil.which(name)
            if located:
                return located
        return ""

    @staticmethod
    def probe_version(executable: str) -> str:
        """Return the version only when the interception runtime satisfies its contract."""
        capability = ExternalToolProbe.mitmdump(executable=executable or None)
        return capability.version if capability.usable else ""

    def _mode_argument(self) -> str:
        mode = self.settings.mode
        spec = self.settings.mode_spec.strip()
        if mode in {"reverse", "upstream"}:
            return f"{mode}:{spec}"
        if mode in {"local", "wireguard", "tun"} and spec:
            return f"{mode}:{spec}"
        return mode

    def build_command(self, executable: str | None = None) -> list[str]:
        """Build a validated argv vector for the local interception runtime."""
        self.settings.validate()
        binary = executable or self.discover(self.settings.executable)
        if not binary:
            raise FileNotFoundError("mitmdump was not found. Install a compatible interception runtime or configure its executable path.")
        args = [binary, "--mode", self._mode_argument(), "--listen-host", self.settings.bind_host]
        if self.settings.bind_port:
            args += ["--listen-port", str(self.settings.bind_port)]
        args += ["--set", f"http2={'true' if self.settings.http2 else 'false'}"]
        args += ["--set", f"http3={'true' if self.settings.http3 else 'false'}"]
        args += ["--set", f"rawtcp={'true' if self.settings.rawtcp else 'false'}"]
        args += ["--set", f"websocket={'true' if self.settings.websocket else 'false'}"]
        args += ["--set", f"ssl_insecure={'false' if self.settings.upstream_cert else 'true'}"]
        args += ["--set", f"connection_strategy={self.settings.connection_strategy}"]
        args += ["--set", f"anticache={'true' if self.settings.anticache else 'false'}"]
        args += ["--set", f"anticomp={'true' if self.settings.anticomp else 'false'}"]
        args += ["--set", f"save_stream_file={self.flow_path}"]
        if self.settings.save_filter.strip():
            args += ["--set", f"save_stream_filter={self.settings.save_filter.strip()}"]
        if self.settings.stream_large_bodies.strip():
            args += ["--set", f"stream_large_bodies={self.settings.stream_large_bodies.strip()}"]
        if self.settings.protobuf_definitions.strip():
            args += ["--set", f"protobuf_definitions={self.settings.protobuf_definitions.strip()}"]
        if self.settings.client_certs.strip():
            args += ["--set", f"client_certs={self.settings.client_certs.strip()}"]
        for option, values in (
            ("ignore_hosts", self.settings.ignore_hosts),
            ("allow_hosts", self.settings.allow_hosts),
            ("map_local", self.settings.map_local),
            ("map_remote", self.settings.map_remote),
            ("modify_headers", self.settings.modify_headers),
            ("modify_body", self.settings.modify_body),
            ("block_list", self.settings.block_list),
        ):
            for value in values:
                if str(value).strip():
                    args += ["--set", f"{option}={str(value).strip()}"]
        args += ["-s", str(self.bridge_path)]
        for script in self.settings.addon_scripts:
            script_path = Path(script).expanduser()
            if script_path.is_file():
                args += ["-s", str(script_path)]
        return args

    def start(self) -> MitmStatus:
        """Start the interception runtime and event bridge with bounded local resources."""
        with self._lock:
            if self.running:
                return self.status()
            executable = self.discover(self.settings.executable)
            capability = ExternalToolProbe.mitmdump(executable=executable or None)
            if not capability.usable:
                raise ArenyxaError(
                    "MITM_RUNTIME_INCOMPATIBLE",
                    "mitmdump is missing or does not satisfy the Arenyxa compatibility contract.",
                    domain="CAPTURE",
                    context={
                        "version": capability.version,
                        "detail": capability.detail,
                    },
                    suggested_action="Install a compatible mitmproxy/mitmdump runtime or use the built-in proxy/API analysis path.",
                )
            executable = capability.executable
            command = self.build_command(executable)
            self._version = capability.version
            self._last_error = ""
            self._clear_runtime_channels()
            env = os.environ.copy()
            env["ARENYXA_MITM_EVENT_FILE"] = str(self.events_path)
            env["ARENYXA_MITM_PENDING_DIR"] = str(self.pending_dir)
            env["ARENYXA_MITM_CONTROL_DIR"] = str(self.control_dir)
            env["ARENYXA_MITM_INTERCEPT_FILTER"] = self.settings.intercept_filter.strip()
            env["ARENYXA_MITM_VIEW_FILTER"] = self.settings.view_filter.strip()
            env["ARENYXA_MITM_INTERCEPT_TIMEOUT"] = str(float(self.settings.intercept_timeout_seconds))
            flags = 0
            if os.name == "nt":
                flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                self._log_handle = self.log_path.open("a", encoding="utf-8", buffering=1)
                self._process = subprocess.Popen(
                    validated_argv(command),
                    stdin=subprocess.DEVNULL,
                    stdout=self._log_handle,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env=env,
                    creationflags=flags,
                )
            except OSError as exc:
                self._last_error = str(exc)
                self._process = None
                if self._log_handle is not None:
                    self._log_handle.close()
                    self._log_handle = None
                raise
            return self.status()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the interception subprocess and finalize bridge resources."""
        with self._lock:
            process = self._process
            self._process = None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=max(0.1, timeout))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        self.poll_events()
        with self._lock:
            if self._log_handle is not None:
                self._log_handle.close()
                self._log_handle = None

    @property
    def running(self) -> bool:
        """Return whether the interception subprocess is currently alive."""
        process = self._process
        return bool(process is not None and process.poll() is None)

    def status(self) -> MitmStatus:
        """Return runtime discovery, process, listener, and event status."""
        self.poll_events()
        process = self._process
        if process is not None and process.poll() is not None and process.returncode not in (0, None):
            self._last_error = self._last_error or self._read_log_tail()
        return MitmStatus(
            running=self.running,
            pid=process.pid if process is not None and process.poll() is None else None,
            executable=self.discover(self.settings.executable),
            version=self._version,
            mode=self.settings.mode,
            bind_host=self.settings.bind_host,
            bind_port=self.settings.bind_port,
            events=len(self._events),
            pending=len(self.pending()),
            flow_file=str(self.flow_path),
            last_error=self._last_error,
        )

    def poll_events(self) -> list[MitmEvent]:
        """Read newly emitted bridge events within configured size and count budgets."""
        with self._lock:
            if not self.events_path.exists():
                return list(self._events)
            try:
                size = self.events_path.stat().st_size
                if size < self._event_offset:
                    self._event_offset = 0
                    self._events.clear()
                with self.events_path.open("r", encoding="utf-8", errors="replace") as handle:
                    handle.seek(self._event_offset)
                    while True:
                        line = handle.readline()
                        if not line:
                            break
                        self._event_offset = handle.tell()
                        try:
                            payload = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        self._events.append(self._event_from_payload(payload))
                if len(self._events) > 20000:
                    self._events = self._events[-20000:]
            except OSError as exc:
                self._last_error = str(exc)
            return list(self._events)

    def events(self, query: str = "", protocol: str = "") -> list[MitmEvent]:
        """Return bounded recent normalized interception events."""
        rows = self.poll_events()
        query_fold = query.strip().casefold()
        protocol_fold = protocol.strip().casefold()
        if protocol_fold and protocol_fold != "all":
            rows = [row for row in rows if row.protocol.casefold() == protocol_fold]
        if query_fold:
            rows = [
                row
                for row in rows
                if query_fold in row.url.casefold()
                or query_fold in row.host.casefold()
                or query_fold in row.method.casefold()
                or query_fold in row.event.casefold()
                or query_fold in row.flow_id.casefold()
            ]
        return rows

    def pending(self) -> list[dict[str, Any]]:
        """Return bounded pending interception decisions awaiting operator action."""
        rows: list[dict[str, Any]] = []
        for path in sorted(self.pending_dir.glob("*.json"), key=lambda item: item.stat().st_mtime if item.exists() else 0):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            payload["token"] = path.stem
            rows.append(payload)
        return rows

    def resolve(self, token: str, action: str, edited: dict[str, Any] | None = None) -> bool:
        """Resolve one pending interception token with an explicit action."""
        if action not in {"forward", "drop"}:
            raise ValueError("Intercept action must be forward or drop")
        if not token or any(char not in "0123456789abcdef-" for char in token.lower()):
            raise ValueError("Invalid intercept token")
        pending_path = self.pending_dir / f"{token}.json"
        if not pending_path.exists():
            return False
        command = {"action": action, "edited": edited or {}, "resolved_at": time.time()}
        target = self.control_dir / f"{token}.json"
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(json.dumps(command, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, target)
        return True

    def replay_command(self, flow_file: Path, direction: str = "client", keep_serving: bool = False) -> list[str]:
        """Build a validated replay argv vector without executing it."""
        if direction not in {"client", "server"}:
            raise ValueError("Replay direction must be client or server")
        path = Path(flow_file)
        if not path.is_file():
            raise FileNotFoundError(str(path))
        executable = self.discover(self.settings.executable)
        if not executable:
            raise FileNotFoundError("mitmdump was not found")
        option = "client_replay" if direction == "client" else "server_replay"
        command = [executable, "--mode", self._mode_argument(), "--set", f"{option}={path}"]
        if keep_serving:
            command += ["--set", "keepserving=true"]
        return command

    def run_replay(self, flow_file: Path, direction: str = "client", timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
        """Run one bounded replay operation and return structured output."""
        command = self.replay_command(flow_file, direction)
        return subprocess.run(validated_argv(command), capture_output=True, text=True, timeout=timeout, check=False)

    def export_events(self, destination: Path, *, query: str = "", protocol: str = "") -> Path:
        """Export normalized event metadata as bounded JSON Lines without raw message bodies."""
        rows = self.events(query=query, protocol=protocol)[-20000:]
        rendered = []
        for row in rows:
            rendered.append(json.dumps({
                "sequence": row.sequence, "timestamp": row.timestamp, "event": row.event,
                "flow_id": row.flow_id, "protocol": row.protocol, "phase": row.phase,
                "method": row.method, "url": row.url, "host": row.host, "status": row.status,
                "direction": row.direction, "size": row.size, "replay": row.replay,
                "intercepted": row.intercepted,
            }, ensure_ascii=False, sort_keys=True))
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(destination, "\n".join(rendered) + ("\n" if rendered else ""), encoding="utf-8", mode=0o600)
        return destination

    def export_flows(self, destination: Path) -> Path:
        """Export normalized interception events to a bounded artifact."""
        if not self.flow_path.exists():
            raise FileNotFoundError("No MITM flow archive has been created yet")
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(self.flow_path, destination)
        return destination

    def _clear_runtime_channels(self) -> None:
        for directory in (self.pending_dir, self.control_dir):
            for path in directory.glob("*.json"):
                try:
                    path.unlink()
                except OSError:
                    record_current_exception(__name__, 'MitmEngine._clear_runtime_channels:449')
        self.events_path.write_text("", encoding="utf-8")
        self._event_offset = 0
        self._events.clear()

    @staticmethod
    def _event_from_payload(payload: dict[str, Any]) -> MitmEvent:
        return MitmEvent(
            sequence=int(payload.get("sequence") or 0),
            timestamp=float(payload.get("timestamp") or 0.0),
            event=str(payload.get("event") or ""),
            flow_id=str(payload.get("flow_id") or ""),
            protocol=str(payload.get("protocol") or ""),
            phase=str(payload.get("phase") or ""),
            method=str(payload.get("method") or ""),
            url=str(payload.get("url") or ""),
            host=str(payload.get("host") or ""),
            status=int(payload["status"]) if payload.get("status") is not None else None,
            direction=str(payload.get("direction") or ""),
            size=int(payload.get("size") or 0),
            replay=str(payload.get("replay") or ""),
            intercepted=bool(payload.get("intercepted")),
            payload=dict(payload.get("payload") or {}),
        )

    def _read_log_tail(self) -> str:
        try:
            data = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            data = ""
        return data[-4000:].strip()
