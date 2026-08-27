"""Windows-native service diagnostics: event log, startup reports and minidumps."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import sys
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

from arenyxa.infrastructure.atomic_io import atomic_write_json

LOGGER = logging.getLogger(__name__)
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_CREATE_ALWAYS = 2
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_MINIDUMP_WITH_DATA_SEGS = 0x00000001
_MINIDUMP_WITH_HANDLE_DATA = 0x00000004
_MINIDUMP_WITH_THREAD_INFO = 0x00001000
_EVENTLOG_ERROR_TYPE = 0x0001
_EVENTLOG_WARNING_TYPE = 0x0002
_EVENTLOG_INFORMATION_TYPE = 0x0004


def runtime_context(*, service: bool) -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "executable": str(Path(sys.executable).resolve()),
        "pid": os.getpid(),
        "service": bool(service),
        "runtime_mode": "service" if service else os.getenv("ARENYXA_RUNTIME_MODE", "desktop"),
        "dpapi_scope": os.getenv("ARENYXA_DPAPI_SCOPE", "machine" if service else "user"),
        "session_name": os.getenv("SESSIONNAME", ""),
        "username": os.getenv("USERNAME", ""),
        "computername": os.getenv("COMPUTERNAME", ""),
    }


def write_startup_diagnostic(
    diagnostics_dir: Path,
    *,
    service_name: str,
    data_dir: Path,
    service: bool,
) -> Path:
    diagnostics_dir = Path(diagnostics_dir)
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    path = diagnostics_dir / "windows-runtime-startup.json"
    payload = {
        "schema": "arenyxa.windows-runtime-startup/v1",
        "captured_at_unix_ns": time.time_ns(),
        "service_name": str(service_name),
        "data_dir": str(Path(data_dir).resolve()),
        **runtime_context(service=service),
    }
    atomic_write_json(path, payload)
    return path


def write_windows_event(message: str, *, source: str = "Arenyxa", level: str = "information") -> bool:
    if os.name != "nt":
        return False
    event_type = {
        "error": _EVENTLOG_ERROR_TYPE,
        "warning": _EVENTLOG_WARNING_TYPE,
        "information": _EVENTLOG_INFORMATION_TYPE,
    }.get(str(level).casefold(), _EVENTLOG_INFORMATION_TYPE)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi32.RegisterEventSourceW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    advapi32.RegisterEventSourceW.restype = wintypes.HANDLE
    advapi32.ReportEventW.argtypes = [
        wintypes.HANDLE,
        wintypes.WORD,
        wintypes.WORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.WORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPCWSTR),
        ctypes.c_void_p,
    ]
    advapi32.ReportEventW.restype = wintypes.BOOL
    advapi32.DeregisterEventSource.argtypes = [wintypes.HANDLE]
    advapi32.DeregisterEventSource.restype = wintypes.BOOL
    handle = advapi32.RegisterEventSourceW(None, str(source)[:128])
    if not handle:
        LOGGER.warning("Windows Event Log source registration failed: winerror=%d", ctypes.get_last_error())
        return False
    text = str(message)[:30000]
    strings = (wintypes.LPCWSTR * 1)(text)
    try:
        ok = advapi32.ReportEventW(handle, event_type, 0, 0x1000, None, 1, 0, strings, None)
        if not ok:
            LOGGER.warning("Windows Event Log write failed: winerror=%d", ctypes.get_last_error())
        return bool(ok)
    finally:
        if not advapi32.DeregisterEventSource(handle):
            LOGGER.warning("Windows Event Log source cleanup failed: winerror=%d", ctypes.get_last_error())


def capture_minidump(diagnostics_dir: Path, *, reason: str) -> Path | None:
    if os.name != "nt":
        return None
    diagnostics_dir = Path(diagnostics_dir)
    diagnostics_dir.mkdir(parents=True, exist_ok=True)
    path = diagnostics_dir / f"Arenyxa-{os.getpid()}-{time.time_ns()}.dmp"
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    dbghelp = ctypes.WinDLL("Dbghelp", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    dbghelp.MiniDumpWriteDump.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL
    handle = kernel32.CreateFileW(
        str(path),
        _GENERIC_WRITE,
        _FILE_SHARE_READ,
        None,
        _CREATE_ALWAYS,
        _FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        LOGGER.error("MiniDump file creation failed: winerror=%d", ctypes.get_last_error())
        return None
    try:
        dump_type = _MINIDUMP_WITH_DATA_SEGS | _MINIDUMP_WITH_HANDLE_DATA | _MINIDUMP_WITH_THREAD_INFO
        ok = dbghelp.MiniDumpWriteDump(
            kernel32.GetCurrentProcess(),
            os.getpid(),
            handle,
            dump_type,
            None,
            None,
            None,
        )
        if not ok:
            error = ctypes.get_last_error()
            LOGGER.error("MiniDumpWriteDump failed: winerror=%d reason=%s", error, reason)
            try:
                path.unlink(missing_ok=True)
            except OSError as cleanup_exc:
                LOGGER.warning("Failed to remove incomplete minidump %s: %s", path, cleanup_exc)
            return None
    finally:
        if not kernel32.CloseHandle(handle):
            LOGGER.warning("MiniDump handle close failed: winerror=%d", ctypes.get_last_error())
    metadata = path.with_suffix(".json")
    atomic_write_json(
        metadata,
        {
            "schema": "arenyxa.windows-minidump/v1",
            "dump": str(path),
            "reason": str(reason)[:1024],
            "captured_at_unix_ns": time.time_ns(),
            **runtime_context(service=True),
        },
    )
    return path
