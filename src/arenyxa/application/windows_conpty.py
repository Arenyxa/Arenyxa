from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import ctypes
import os
import shlex
import shutil
import subprocess
import threading
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable

from arenyxa.application.terminal import TerminalLaunch, TerminalMode, TerminalResult


OutputCallback = Callable[[str], None]
ExitCallback = Callable[[TerminalResult], None]


class ConPtyUnavailable(RuntimeError):
    """Marker type for ConPtyUnavailable."""


class _COORD(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class WindowsConPtySession:
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    WAIT_OBJECT_0 = 0x00000000
    INFINITE = 0xFFFFFFFF

    def __init__(self, root: Path, *, columns: int = 120, rows: int = 36, max_output_chars: int = 2_000_000) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._cwd = self.root
        self._columns = max(40, min(int(columns), 500))
        self._rows = max(10, min(int(rows), 200))
        self._max_output_chars = max(32768, min(int(max_output_chars), 20_000_000))
        self._lock = threading.RLock()
        self._hpc = ctypes.c_void_p()
        self._process_handle = wintypes.HANDLE()
        self._thread_handle = wintypes.HANDLE()
        self._input_write = wintypes.HANDLE()
        self._output_read = wintypes.HANDLE()
        self._reader: threading.Thread | None = None
        self._waiter: threading.Thread | None = None
        self._finished = threading.Event()
        self._finished.set()
        self._running = False
        self._cancelled = False
        self._started_at = 0.0
        self._output_chars = 0
        self._output_truncated = False
        self._mode: TerminalMode | None = None
        self._api = self._load_api()

    @classmethod
    def supported(cls) -> bool:
        if os.name != "nt":
            return False
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            return all(hasattr(kernel32, name) for name in ("CreatePseudoConsole", "ResizePseudoConsole", "ClosePseudoConsole"))
        except (AttributeError, OSError):
            return False

    @property
    def cwd(self) -> Path:
        return self._cwd

    @property
    def is_running(self) -> bool:
        with self._lock:
            return bool(self._running)

    @property
    def active_persistent(self) -> bool:
        return self.is_running

    def build_launch(self, command: str, mode: TerminalMode | str) -> TerminalLaunch:
        selected = TerminalMode(mode)
        if selected not in {TerminalMode.POWERSHELL_SESSION, TerminalMode.CMD_SESSION}:
            raise ValueError("ConPTY supports persistent PowerShell and CMD sessions")
        if selected == TerminalMode.POWERSHELL_SESSION:
            executable = self._find_powershell()
            if not executable:
                raise FileNotFoundError("PowerShell/pwsh was not found in PATH")
            prefix = "$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)"
            args = ("-NoLogo", "-NoProfile", "-NoExit", "-Command", prefix)
            display = "PowerShell ConPTY"
        else:
            executable = os.environ.get("COMSPEC") or shutil.which("cmd.exe") or "cmd.exe"
            args = ("/D", "/Q", "/K", "chcp 65001>nul")
            display = "CMD ConPTY"
        return TerminalLaunch(
            mode=selected,
            executable=str(executable),
            arguments=args,
            cwd=self._cwd,
            display=display,
            encoding="utf-8",
            persistent=True,
        )

    def start(self, launch: TerminalLaunch, on_output: OutputCallback, on_exit: ExitCallback) -> None:
        if os.name != "nt":
            raise ConPtyUnavailable("Windows ConPTY is only available on Windows")
        if not self.supported():
            raise ConPtyUnavailable("This Windows runtime does not expose the ConPTY API")
        with self._lock:
            if self._running:
                raise RuntimeError("ConPTY session is already running")
            self._cancelled = False
            self._output_chars = 0
            self._output_truncated = False
            self._mode = launch.mode
            self._finished.clear()
        input_read = wintypes.HANDLE()
        input_write = wintypes.HANDLE()
        output_read = wintypes.HANDLE()
        output_write = wintypes.HANDLE()
        hpc = ctypes.c_void_p()
        attribute_buffer = None
        process_info = _PROCESS_INFORMATION()
        try:
            self._check(self._api.CreatePipe(ctypes.byref(input_read), ctypes.byref(input_write), None, 0), "CreatePipe(stdin)")
            self._check(self._api.CreatePipe(ctypes.byref(output_read), ctypes.byref(output_write), None, 0), "CreatePipe(stdout)")
            size = _COORD(self._columns, self._rows)
            result = self._api.CreatePseudoConsole(size, input_read, output_write, 0, ctypes.byref(hpc))
            if int(result) != 0:
                raise OSError(int(result), "CreatePseudoConsole failed")
            self._close_handle(input_read)
            input_read = wintypes.HANDLE()
            self._close_handle(output_write)
            output_write = wintypes.HANDLE()

            attribute_size = ctypes.c_size_t(0)
            self._api.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attribute_size))
            if attribute_size.value <= 0:
                self._raise_last_error("InitializeProcThreadAttributeList(size)")
            attribute_buffer = ctypes.create_string_buffer(attribute_size.value)
            attribute_list = ctypes.cast(attribute_buffer, ctypes.c_void_p)
            self._check(
                self._api.InitializeProcThreadAttributeList(attribute_list, 1, 0, ctypes.byref(attribute_size)),
                "InitializeProcThreadAttributeList",
            )
            self._check(
                self._api.UpdateProcThreadAttribute(
                    attribute_list,
                    0,
                    self.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    hpc,
                    ctypes.sizeof(ctypes.c_void_p),
                    None,
                    None,
                ),
                "UpdateProcThreadAttribute(ConPTY)",
            )
            startup = _STARTUPINFOEXW()
            startup.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOEXW)
            startup.lpAttributeList = attribute_list
            command_line = subprocess.list2cmdline([launch.executable, *launch.arguments])
            command_buffer = ctypes.create_unicode_buffer(command_line)
            environment = self._environment_block(dict(os.environ))
            flags = self.EXTENDED_STARTUPINFO_PRESENT | self.CREATE_UNICODE_ENVIRONMENT
            self._check(
                self._api.CreateProcessW(
                    None,
                    command_buffer,
                    None,
                    None,
                    False,
                    flags,
                    ctypes.cast(environment, ctypes.c_void_p),
                    str(launch.cwd),
                    ctypes.byref(startup.StartupInfo),
                    ctypes.byref(process_info),
                ),
                "CreateProcessW(ConPTY)",
            )
            with self._lock:
                self._hpc = hpc
                self._process_handle = process_info.hProcess
                self._thread_handle = process_info.hThread
                self._input_write = input_write
                self._output_read = output_read
                self._running = True
                self._started_at = time.monotonic()
            input_write = wintypes.HANDLE()
            output_read = wintypes.HANDLE()
            process_info.hProcess = wintypes.HANDLE()
            process_info.hThread = wintypes.HANDLE()
            self._reader = threading.Thread(target=self._read_loop, args=(on_output,), name="arenyxa-conpty-read", daemon=True)
            self._waiter = threading.Thread(target=self._wait_loop, args=(on_exit, attribute_buffer), name="arenyxa-conpty-wait", daemon=True)
            self._reader.start()
            self._waiter.start()
            attribute_buffer = None
        except (ConPtyUnavailable, OSError, RuntimeError, ValueError, ctypes.ArgumentError):
            if hpc.value:
                self._api.ClosePseudoConsole(hpc)
            self._close_handle(input_read)
            self._close_handle(input_write)
            self._close_handle(output_read)
            self._close_handle(output_write)
            self._close_handle(process_info.hThread)
            self._close_handle(process_info.hProcess)
            if attribute_buffer is not None:
                try:
                    self._api.DeleteProcThreadAttributeList(ctypes.cast(attribute_buffer, ctypes.c_void_p))
                except (ConPtyUnavailable, OSError, ctypes.ArgumentError):
                    record_current_exception(__name__, 'WindowsConPtySession.start:253')
            self._finished.set()
            raise

    def send_input(self, text: str, *, append_newline: bool = True) -> bool:
        payload = str(text) + ("\r\n" if append_newline else "")
        data = payload.encode("utf-8", errors="replace")
        with self._lock:
            handle = self._input_write
            running = self._running
        if not running or not handle:
            return False
        written = wintypes.DWORD(0)
        buffer = ctypes.create_string_buffer(data)
        self._check(self._api.WriteFile(handle, buffer, len(data), ctypes.byref(written), None), "WriteFile(ConPTY)")
        return int(written.value) == len(data)

    def resize(self, columns: int, rows: int) -> None:
        columns = max(20, min(int(columns), 1000))
        rows = max(5, min(int(rows), 400))
        with self._lock:
            hpc = self._hpc
            if not self._running or not hpc.value:
                self._columns, self._rows = columns, rows
                return
        result = self._api.ResizePseudoConsole(hpc, _COORD(columns, rows))
        if int(result) != 0:
            raise OSError(int(result), "ResizePseudoConsole failed")
        self._columns, self._rows = columns, rows

    def stop(self) -> None:
        with self._lock:
            handle = self._process_handle
            running = self._running
            self._cancelled = True
        if running and handle:
            self._api.TerminateProcess(handle, 130)

    def wait(self, timeout: float | None = None) -> bool:
        return self._finished.wait(timeout)

    def close(self) -> None:
        self.stop()
        self.wait(5.0)
        self._cleanup_handles()

    def _read_loop(self, on_output: OutputCallback) -> None:
        decoder = __import__("codecs").getincrementaldecoder("utf-8")("replace")
        buffer = ctypes.create_string_buffer(8192)
        while True:
            with self._lock:
                handle = self._output_read
                running = self._running
            if not handle or not running:
                break
            read = wintypes.DWORD(0)
            ok = self._api.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None)
            if not ok or read.value == 0:
                break
            text = decoder.decode(buffer.raw[: read.value], final=False)
            if not text:
                continue
            with self._lock:
                remaining = self._max_output_chars - self._output_chars
                if remaining <= 0:
                    self._output_truncated = True
                    continue
                rendered = text[:remaining]
                self._output_chars += len(rendered)
                if len(rendered) < len(text):
                    self._output_truncated = True
            try:
                on_output(rendered)
            except (OSError, RuntimeError, TypeError, ValueError):
                record_current_exception(__name__, 'WindowsConPtySession._read_loop:327')
        tail = decoder.decode(b"", final=True)
        if tail:
            try:
                on_output(tail)
            except (OSError, RuntimeError, TypeError, ValueError):
                record_current_exception(__name__, 'WindowsConPtySession._read_loop:333')

    def _wait_loop(self, on_exit: ExitCallback, attribute_buffer: ctypes.Array[ctypes.c_char]) -> None:
        with self._lock:
            handle = self._process_handle
        if handle:
            self._api.WaitForSingleObject(handle, self.INFINITE)
        exit_code = wintypes.DWORD(0)
        if handle:
            self._api.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        with self._lock:
            duration = max(0.0, time.monotonic() - self._started_at)
            result = TerminalResult(
                exit_code=int(exit_code.value),
                duration_seconds=duration,
                timed_out=False,
                cancelled=bool(self._cancelled),
                output_truncated=bool(self._output_truncated),
            )
            self._running = False
        try:
            on_exit(result)
        finally:
            try:
                self._api.DeleteProcThreadAttributeList(ctypes.cast(attribute_buffer, ctypes.c_void_p))
            except (ConPtyUnavailable, OSError, ctypes.ArgumentError):
                record_current_exception(__name__, 'WindowsConPtySession._wait_loop:359')
            self._cleanup_handles()
            self._finished.set()

    def _cleanup_handles(self) -> None:
        with self._lock:
            hpc = self._hpc
            handles = [self._input_write, self._output_read, self._thread_handle, self._process_handle]
            self._hpc = ctypes.c_void_p()
            self._input_write = wintypes.HANDLE()
            self._output_read = wintypes.HANDLE()
            self._thread_handle = wintypes.HANDLE()
            self._process_handle = wintypes.HANDLE()
        for handle in handles:
            self._close_handle(handle)
        if hpc.value:
            self._api.ClosePseudoConsole(hpc)

    @staticmethod
    def _find_powershell() -> str | None:
        for candidate in ("pwsh.exe", "powershell.exe", "pwsh", "powershell"):
            found = shutil.which(candidate)
            if found:
                return found
        return None

    @staticmethod
    def _environment_block(environment: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
        rows = [f"{key}={value}" for key, value in sorted(environment.items(), key=lambda item: item[0].casefold()) if "\x00" not in key and "\x00" not in value]
        return ctypes.create_unicode_buffer("\x00".join(rows) + "\x00\x00")

    @staticmethod
    def _load_api() -> object:
        if os.name != "nt":
            return _UnavailableWindowsApi()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreatePipe.argtypes = [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD]
        kernel32.CreatePipe.restype = wintypes.BOOL
        kernel32.CreatePseudoConsole.argtypes = [_COORD, wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        kernel32.CreatePseudoConsole.restype = ctypes.c_long
        kernel32.ResizePseudoConsole.argtypes = [ctypes.c_void_p, _COORD]
        kernel32.ResizePseudoConsole.restype = ctypes.c_long
        kernel32.ClosePseudoConsole.argtypes = [ctypes.c_void_p]
        kernel32.ClosePseudoConsole.restype = None
        kernel32.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        kernel32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        kernel32.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
        kernel32.UpdateProcThreadAttribute.restype = wintypes.BOOL
        kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
        kernel32.DeleteProcThreadAttributeList.restype = None
        kernel32.CreateProcessW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.POINTER(_STARTUPINFOW), ctypes.POINTER(_PROCESS_INFORMATION)]
        kernel32.CreateProcessW.restype = wintypes.BOOL
        kernel32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        kernel32.ReadFile.restype = wintypes.BOOL
        kernel32.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        kernel32.WriteFile.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel32.TerminateProcess.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        return kernel32

    def _check(self, value: int, operation: str) -> None:
        if not value:
            self._raise_last_error(operation)

    @staticmethod
    def _raise_last_error(operation: str) -> None:
        code = ctypes.get_last_error()
        raise OSError(code, f"{operation} failed")

    def _close_handle(self, handle: wintypes.HANDLE) -> None:
        if handle:
            self._api.CloseHandle(handle)


class _UnavailableWindowsApi:
    def __getattr__(self, name: str) -> Any:
        raise ConPtyUnavailable(f"Windows API {name} is unavailable on this platform")
