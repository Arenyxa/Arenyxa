from __future__ import annotations

from arenyxa.infrastructure.process_safety import validated_argv
import codecs
import locale
import logging
import os
import re
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from arenyxa.compat import dataclass
from arenyxa.compat import StrEnum
from pathlib import Path
from typing import Callable


class TerminalMode(StrEnum):
    





    DIRECT = "direct"
    POWERSHELL = "powershell"
    CMD = "cmd"
    PYTHON = "python"


@dataclass(frozen=True, slots=True)
class TerminalLaunch:
    mode: TerminalMode
    executable: str
    arguments: tuple[str, ...]
    cwd: Path
    display: str
    encoding: str
    risk_reason: str | None = None


@dataclass(frozen=True, slots=True)
class TerminalResult:
    exit_code: int
    duration_seconds: float
    timed_out: bool
    cancelled: bool
    output_truncated: bool


OutputCallback = Callable[[str], None]
ExitCallback = Callable[[TerminalResult], None]


_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_COMMAND_SECRET_PATTERNS = (
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r"(?i)((?:access[_-]?token|refresh[_-]?token|token|secret|api[_-]?key|apikey|password)"
        r"\s*[=:]\s*)[^\s,;&]+"
    ),
    re.compile(
        r"(?i)((?:--?(?:token|secret|password|api[_-]?key)|/password)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)"
    ),
    re.compile(
        r"(?i)(['\"](?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)(.*?)(?=['\"])"
    ),
    re.compile(r"(?i)((?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*)[^\s'\"]+"),
)
_SENSITIVE_ENV_FRAGMENTS = (
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "PRIVATE_KEY",
    "API_KEY",
    "ACCESS_KEY",
    "COOKIE",
    "AUTHORIZATION",
    "AUTH_TOKEN",
    "CREDENTIAL",
    "PROXY",
    "DATABASE_URL",
    "DATABASE_DSN",
    "CONNECTION_STRING",
)

LOGGER = logging.getLogger(__name__)


class TerminalSession:
    






    def __init__(
        self,
        root: Path,
        *,
        default_timeout_seconds: float = 300.0,
        max_output_chars: int = 2_000_000,
        history_limit: int = 200,
    ) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._cwd = self.root
        self._environment = dict(os.environ)
        self._timeout_seconds = self._clamp_timeout(default_timeout_seconds)
        self._max_output_chars = max(32_768, min(int(max_output_chars), 20_000_000))
        self._history_limit = max(20, min(int(history_limit), 2_000))
        self._history: list[str] = []
        self._lock = threading.RLock()
        self._process: subprocess.Popen[bytes] | None = None
        self._process_started_at = 0.0
        self._cancelled = False
        self._timed_out = False
        self._output_truncated = False
        self._output_chars = 0
        self._input_encoding = "utf-8"
        self._finished_event = threading.Event()
        self._finished_event.set()

    @property
    def cwd(self) -> Path:
        with self._lock:
            return self._cwd

    @property
    def timeout_seconds(self) -> float:
        with self._lock:
            return self._timeout_seconds

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._process is not None and self._process.poll() is None

    def set_timeout(self, seconds: float) -> float:
        value = self._clamp_timeout(seconds)
        with self._lock:
            self._timeout_seconds = value
        return value

    @staticmethod
    def _clamp_timeout(seconds: float) -> float:
        value = float(seconds)
        if not 1.0 <= value <= 3600.0:
            raise ValueError("timeout must be between 1 and 3600 seconds")
        return value

    @staticmethod
    def redact_command(command: str) -> str:
        result = command
        for pattern in _COMMAND_SECRET_PATTERNS:
            result = pattern.sub(lambda match: match.group(1) + "<redacted>", result)
        return result

    def remember(self, command: str) -> None:
        normalized = self.redact_command(command.strip())
        if not normalized:
            return
        with self._lock:
            if self._history and self._history[-1] == normalized:
                return
            self._history.append(normalized)
            del self._history[:-self._history_limit]

    def history(self, limit: int | None = None) -> tuple[str, ...]:
        with self._lock:
            rows = tuple(self._history)
        if limit is None:
            return rows
        bounded = max(0, min(int(limit), self._history_limit))
        return rows[-bounded:]

    def set_cwd(self, raw_path: str | Path) -> Path:
        candidate = Path(raw_path).expanduser()
        with self._lock:
            base = self._cwd
        if not candidate.is_absolute():
            candidate = base / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError("working directory must stay inside the Arenyxa Projects root") from exc
        if not resolved.exists():
            raise FileNotFoundError(str(resolved))
        if not resolved.is_dir():
            raise NotADirectoryError(str(resolved))
        with self._lock:
            self._cwd = resolved
        return resolved

    def list_directory(self, raw_path: str | Path = ".", *, limit: int = 500) -> list[dict[str, object]]:
        candidate = Path(raw_path).expanduser()
        with self._lock:
            base = self._cwd
        if not candidate.is_absolute():
            candidate = base / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise PermissionError("directory listing must stay inside the Arenyxa Projects root") from exc
        if not resolved.is_dir():
            raise NotADirectoryError(str(resolved))
        bounded = max(1, min(int(limit), 5_000))
                                                                                            
                                                                                        
        scan_limit = min(5_000, max(bounded, bounded * 4))
        candidates: list[Path] = []
        for item in resolved.iterdir():
            candidates.append(item)
            if len(candidates) >= scan_limit:
                break
        candidates.sort(key=lambda path: (not path.is_dir(), path.name.casefold()))
        rows: list[dict[str, object]] = []
        for item in candidates[:bounded]:
            try:
                is_dir = item.is_dir()
                stat = item.stat()
                size = None if is_dir else int(stat.st_size)
            except OSError:
                is_dir = False
                size = None
            rows.append({"name": item.name, "type": "dir" if is_dir else "file", "size": size})
        return rows

    def set_environment(self, name: str, value: str) -> None:
        if not _ENV_NAME.fullmatch(name):
            raise ValueError("invalid environment variable name")
        if "\x00" in value or len(value) > 8_192:
            raise ValueError("environment variable value is invalid or too large")
        with self._lock:
            self._environment[name] = value

    def unset_environment(self, name: str) -> bool:
        if not _ENV_NAME.fullmatch(name):
            raise ValueError("invalid environment variable name")
        with self._lock:
            return self._environment.pop(name, None) is not None

    def environment_items(self, contains: str = "", *, mask_secrets: bool = True) -> list[tuple[str, str]]:
        needle = contains.casefold().strip()
        with self._lock:
            items = list(self._environment.items())
        rows: list[tuple[str, str]] = []
        for name, value in sorted(items, key=lambda pair: pair[0].casefold()):
            if needle and needle not in name.casefold():
                continue
            if mask_secrets and (
                self.is_sensitive_environment_name(name) or self.is_sensitive_environment_value(value)
            ):
                value = "<redacted>"
            rows.append((name, value))
        return rows

    @staticmethod
    def is_sensitive_environment_name(name: str) -> bool:
        upper = name.upper()
        return any(fragment in upper for fragment in _SENSITIVE_ENV_FRAGMENTS)

    @staticmethod
    def is_sensitive_environment_value(value: str) -> bool:
        if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
            return True
        return re.search(r"://[^/\s:@]+:[^/\s@]+@", value) is not None

    @staticmethod
    def readonly_sql(database: Path, query: str, *, limit: int = 500) -> dict[str, object]:
        statement = query.strip()
        if not statement:
            raise ValueError("SQL query is empty")
        if statement.casefold() == "tables":
            statement = (
                "SELECT type, name FROM sqlite_master "
                "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
            )
        first = statement.lstrip().split(maxsplit=1)[0].casefold()
        if first not in {"select", "pragma", "explain", "with"}:
            raise PermissionError("SQL console is read-only: SELECT / PRAGMA / EXPLAIN / WITH only")
        bounded = max(1, min(int(limit), 500))
        uri = database.expanduser().resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
        connection.row_factory = sqlite3.Row
        try:
            cursor = connection.execute(statement)
            columns = [item[0] for item in cursor.description or ()]
            rows = cursor.fetchmany(bounded + 1)
            truncated = len(rows) > bounded
            result_rows = [dict(row) for row in rows[:bounded]]
            return {
                "columns": columns,
                "rows": result_rows,
                "row_count": len(result_rows),
                "truncated": truncated,
                "read_only": True,
            }
        finally:
            connection.close()

    def which(self, executable: str) -> str | None:
        if not executable.strip():
            return None
        with self._lock:
            path_value = self._environment.get("PATH")
            cwd = self._cwd
        candidate = Path(executable)
        if candidate.parent != Path(".") or candidate.is_absolute():
            if not candidate.is_absolute():
                candidate = cwd / candidate
            try:
                resolved = candidate.resolve()
            except OSError:
                return None
            return str(resolved) if resolved.is_file() else None
        return shutil.which(executable, path=path_value)

    def build_launch(self, command: str, mode: TerminalMode | str) -> TerminalLaunch:
        selected = TerminalMode(mode)
        command = command.strip()
        if not command:
            raise ValueError("command is empty")
        with self._lock:
            cwd = self._cwd
        risk = self.detect_risk(command, selected)
        if selected == TerminalMode.DIRECT:
            arguments = self._split_direct(command)
            executable = self.which(arguments[0])
            if executable is None:
                raise FileNotFoundError(f"executable not found: {arguments[0]}")
            executable_name = Path(executable).name.casefold()
            encoding = (
                "utf-8"
                if executable_name.startswith("python") or Path(executable) == Path(sys.executable)
                else (locale.getpreferredencoding(False) or "utf-8")
            )
            return TerminalLaunch(
                mode=selected,
                executable=executable,
                arguments=tuple(arguments[1:]),
                cwd=cwd,
                display=command,
                encoding=encoding,
                risk_reason=risk,
            )
        if selected == TerminalMode.PYTHON:
            return TerminalLaunch(
                mode=selected,
                executable=sys.executable,
                arguments=("-u", "-c", command),
                cwd=cwd,
                display=command,
                encoding="utf-8",
                risk_reason=risk,
            )
        if selected == TerminalMode.POWERSHELL:
            executable = self._find_powershell()
            if executable is None:
                raise FileNotFoundError("PowerShell/pwsh was not found in PATH")
            prefix = (
                "$OutputEncoding=[Console]::OutputEncoding="
                "[System.Text.UTF8Encoding]::new($false); "
            )
            return TerminalLaunch(
                mode=selected,
                executable=executable,
                arguments=("-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefix + command),
                cwd=cwd,
                display=command,
                encoding="utf-8",
                risk_reason=risk,
            )
        if os.name != "nt":
            raise OSError("CMD mode is only available on Windows")
        with self._lock:
            comspec = self._environment.get("COMSPEC")
            path_value = self._environment.get("PATH")
        executable = comspec or shutil.which("cmd.exe", path=path_value) or "cmd.exe"
        return TerminalLaunch(
            mode=selected,
            executable=executable,
            arguments=("/D", "/S", "/C", "chcp 65001>nul & " + command),
            cwd=cwd,
            display=command,
            encoding="utf-8",
            risk_reason=risk,
        )

    @staticmethod
    def _split_direct(command: str) -> list[str]:
        if os.name == "nt":
                                                                                             
                                                                                   
            arguments = shlex.split(command, posix=False)
            arguments = [
                item[1:-1]
                if len(item) >= 2 and item[0] == item[-1] and item[0] in {"\"", "'"}
                else item
                for item in arguments
            ]
        else:
            arguments = shlex.split(command, posix=True)
        if not arguments:
            raise ValueError("command is empty")
        return arguments

    def _find_powershell(self) -> str | None:
        with self._lock:
            path_value = self._environment.get("PATH")
        for candidate in ("pwsh", "powershell.exe", "powershell"):
            resolved = shutil.which(candidate, path=path_value)
            if resolved:
                return resolved
        return None

    @staticmethod
    def detect_risk(command: str, mode: TerminalMode | str) -> str | None:
        text = " ".join(command.casefold().split())
        destructive_markers = (
            "rm -rf",
            "rm -fr",
            "del /s",
            "erase /s",
            "rmdir /s",
            "rd /s",
            "remove-item -recurse",
            "remove-item -force",
            "format ",
            "diskpart",
            "mkfs",
            "dd if=",
            "bcdedit",
            "reg delete",
            "clear-disk",
            "initialize-disk",
            "shutdown ",
            "stop-computer",
            "restart-computer",
        )
        if any(marker in text for marker in destructive_markers):
            return "命令包含删除、磁盘、启动配置或关机类高风险操作。"
        privilege_markers = ("runas ", "sudo ", "doas ")
        if any(marker in text for marker in privilege_markers) or (
            "start-process" in text and "-verb runas" in text
        ):
            return "命令可能请求提权或启动高权限进程。"
        selected = TerminalMode(mode)
        if selected in {TerminalMode.POWERSHELL, TerminalMode.CMD} and any(
            token in command for token in ("|", ">", "<", "&&", "||")
        ):
            return "完整 Shell 模式将解释管道、重定向或命令连接符。"
        return None

    def start(
        self,
        launch: TerminalLaunch,
        on_output: OutputCallback,
        on_exit: ExitCallback,
    ) -> None:
        with self._lock:
            if self._process is not None:
                if self._process.poll() is None:
                    raise RuntimeError("another terminal process is already running")
                                                                                            
                                                                                              
                                                                                            
                raise RuntimeError("previous terminal process cleanup is still finishing")
            environment = dict(self._environment)
            executable_name = Path(launch.executable).name.casefold()
            if launch.mode == TerminalMode.PYTHON or executable_name.startswith("python"):
                environment.setdefault("PYTHONUTF8", "1")
                environment.setdefault("PYTHONIOENCODING", "utf-8")
            creationflags = 0
            start_new_session = False
            if os.name == "nt":
                creationflags |= int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                creationflags |= int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
            else:
                start_new_session = True
            process = subprocess.Popen(
                validated_argv([launch.executable, *launch.arguments]),
                cwd=launch.cwd,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                creationflags=creationflags,
                start_new_session=start_new_session,
            )
            self._process = process
            started_at = time.monotonic()
            self._process_started_at = started_at
            self._cancelled = False
            self._timed_out = False
            self._output_truncated = False
            self._output_chars = 0
            self._input_encoding = launch.encoding
            self._finished_event.clear()
            timeout = self._timeout_seconds

        threading.Thread(
            target=self._read_process,
            args=(process, launch.encoding, on_output, on_exit, started_at),
            daemon=True,
            name="arenyxa-terminal-reader",
        ).start()
        threading.Thread(
            target=self._watch_timeout,
            args=(process, timeout),
            daemon=True,
            name="arenyxa-terminal-timeout",
        ).start()

    def _read_process(
        self,
        process: subprocess.Popen[bytes],
        encoding: str,
        on_output: OutputCallback,
        on_exit: ExitCallback,
        started_at: float,
    ) -> None:
        decoder_factory = codecs.getincrementaldecoder(encoding)
        decoder = decoder_factory(errors="replace")
        stream = process.stdout
        try:
            if stream is not None:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    text = decoder.decode(chunk)
                    if text:
                        accepted, truncated = self._clip_output(process, text)
                        if accepted:
                            self._safe_output_callback(on_output, accepted)
                        if truncated:
                            self._terminate_specific(process)
                            break
                tail = decoder.decode(b"", final=True)
                if tail:
                    accepted, truncated = self._clip_output(process, tail)
                    if accepted:
                        self._safe_output_callback(on_output, accepted)
                    if truncated:
                        self._terminate_specific(process)
        except (OSError, ValueError):
            LOGGER.exception("Terminal output reader failed; terminating child process")
            self._terminate_specific(process)
        finally:
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
            input_stream = process.stdin
            if input_stream is not None and not input_stream.closed:
                try:
                    input_stream.close()
                except OSError:
                    pass
            try:
                exit_code = process.wait()
            except OSError:
                exit_code = int(process.returncode if process.returncode is not None else -1)

        with self._lock:
            is_current = self._process is process
            timed_out = self._timed_out if is_current else False
            cancelled = self._cancelled if is_current else False
            truncated = self._output_truncated if is_current else False
            if is_current:
                self._process = None
                self._finished_event.set()
            else:
                LOGGER.warning("Ignoring stale terminal reader completion for pid=%s", process.pid)
        result = TerminalResult(
            exit_code=int(process.returncode if process.returncode is not None else exit_code),
            duration_seconds=max(0.0, time.monotonic() - started_at),
            timed_out=timed_out,
            cancelled=cancelled,
            output_truncated=truncated,
        )
        try:
            on_exit(result)
        except Exception:                                                                    
            LOGGER.exception("Terminal exit callback failed")

    @staticmethod
    def _safe_output_callback(callback: OutputCallback, text: str) -> None:
        try:
            callback(text)
        except Exception:                                                                 
            LOGGER.exception("Terminal output callback failed")

    def _clip_output(self, process: subprocess.Popen[bytes], text: str) -> tuple[str, bool]:
        with self._lock:
            if self._process is not process:
                return "", False
            remaining = self._max_output_chars - self._output_chars
            if remaining <= 0:
                self._output_truncated = True
                return "", True
            accepted = text[:remaining]
            self._output_chars += len(accepted)
            truncated = len(accepted) < len(text)
            if truncated:
                self._output_truncated = True
            return accepted, truncated

    def _watch_timeout(self, process: subprocess.Popen[bytes], timeout: float) -> None:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            with self._lock:
                if self._process is process and process.poll() is None:
                    self._timed_out = True
            self._terminate_specific(process)

    def send_input(self, text: str, *, append_newline: bool = True) -> bool:
        if "\x00" in text or len(text) > 65_536:
            raise ValueError("terminal input is invalid or too large")
        with self._lock:
            process = self._process
            encoding = self._input_encoding
            stream = None if process is None else process.stdin
        if process is None or process.poll() is not None or stream is None or stream.closed:
            return False
        payload = text + ("\n" if append_newline else "")
        try:
            stream.write(payload.encode(encoding, errors="replace"))
            stream.flush()
        except (BrokenPipeError, OSError, ValueError):
            return False
        return True

    def close_input(self) -> bool:
        with self._lock:
            process = self._process
            stream = None if process is None else process.stdin
        if process is None or process.poll() is not None or stream is None or stream.closed:
            return False
        try:
            stream.close()
        except OSError:
            return False
        return True

    def request_stop(self) -> bool:
        
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                return False
            already_requested = self._cancelled
            self._cancelled = True
        if already_requested:
            return True
        threading.Thread(
            target=self._terminate_specific,
            args=(process,),
            daemon=True,
            name="arenyxa-terminal-stop",
        ).start()
        return True

    def stop(self) -> bool:
        
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                return False
            self._cancelled = True
        self._terminate_specific(process)
        return True

    def _terminate_specific(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                                                                                            
                                                                                        
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)                              
                    process.wait(timeout=0.75)
                    return
                except (AttributeError, OSError, subprocess.TimeoutExpired):
                    pass
                try:
                    subprocess.run(
                        validated_argv(["taskkill", "/PID", str(process.pid), "/T", "/F"]),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2.0,
                        creationflags=int(getattr(subprocess, "CREATE_NO_WINDOW", 0)),
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    process.terminate()
            else:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (OSError, ProcessLookupError):
                    process.terminate()
            process.wait(timeout=1.5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except (OSError, ProcessLookupError):
                pass
                                                                                           
                                                                                           
                                                                                       
                       
            try:
                process.wait(timeout=1.5)
            except (OSError, subprocess.TimeoutExpired):
                LOGGER.warning("Terminal child did not exit after hard termination: pid=%s", process.pid)

    def wait(self, timeout: float | None = None) -> bool:
        return self._finished_event.wait(timeout)

    def close(self) -> None:
        self.stop()
        if not self.wait(2.5):
            LOGGER.warning("Terminal reader did not quiesce within shutdown timeout")
