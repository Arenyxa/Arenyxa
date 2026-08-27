from __future__ import annotations

import argparse
import ctypes
import os
import logging
import shutil
import sys
import threading
from ctypes import wintypes
from pathlib import Path
from typing import Any

from arenyxa.application.windows_runtime import _bounded_process
from arenyxa.bootstrap import bootstrap
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.windows_diagnostics import (
    capture_minidump,
    write_startup_diagnostic,
    write_windows_event,
)

LOGGER = logging.getLogger(__name__)

SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004
SERVICE_STOPPED = 0x00000001
SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004
SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_SHUTDOWN = 0x00000005
NO_ERROR = 0


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", ctypes.c_void_p)]


def _require_windows() -> None:
    if os.name != "nt":
        raise ArenyxaError("WINDOWS_SERVICE_UNAVAILABLE", "Windows Service runtime requires Windows", domain="WINDOWS")


def _quote_windows_argument(value: str) -> str:
    # list2cmdline implements CreateProcess-compatible Windows argument quoting.
    import subprocess

    return subprocess.list2cmdline([str(value)])


def service_binary_command(data_dir: Path) -> str:
    executable = Path(sys.executable).resolve()
    frozen = bool(getattr(sys, "frozen", False))
    if frozen:
        service_executable = executable if executable.name.casefold() == "arenyxaservice.exe" else executable.with_name("ArenyxaService.exe")
        return " ".join((
            _quote_windows_argument(str(service_executable)),
            "--service",
            "--data-dir",
            _quote_windows_argument(str(Path(data_dir).resolve())),
        ))
    return " ".join(
        (
            _quote_windows_argument(str(executable)),
            "-m",
            "arenyxa.infrastructure.windows_service",
            "--service",
            "--data-dir",
            _quote_windows_argument(str(Path(data_dir).resolve())),
        )
    )


def install_service(
    data_dir: Path,
    *,
    service_name: str = "Arenyxa",
    display_name: str = "Arenyxa Platform Runtime",
    start: str = "auto",
) -> dict[str, Any]:
    _require_windows()
    sc = shutil.which("sc.exe") or shutil.which("sc")
    if not sc:
        raise ArenyxaError("WINDOWS_SC_UNAVAILABLE", "sc.exe is unavailable", domain="WINDOWS")
    normalized_start = str(start).casefold()
    if normalized_start not in {"auto", "demand"}:
        raise ValueError("service start must be auto or demand")
    name = str(service_name).strip()[:128]
    if not name:
        raise ValueError("service_name is required")
    command = service_binary_command(data_dir)
    created = _bounded_process(
        [
            sc,
            "create",
            name,
            "binPath=",
            command,
            "start=",
            normalized_start,
            "DisplayName=",
            str(display_name)[:256],
        ],
        timeout=15.0,
    )
    if not created.get("ok"):
        raise ArenyxaError(
            "WINDOWS_SERVICE_INSTALL_FAILED",
            "Windows Service registration failed",
            domain="WINDOWS",
            context={"service": name, "returncode": created.get("returncode"), "stderr": str(created.get("stderr", ""))[-512:]},
        )
    description = _bounded_process(
        [sc, "description", name, "Arenyxa Windows-first platform runtime and recovery host"], timeout=10.0
    )
    failure = _bounded_process(
        [sc, "failure", name, "reset=", "86400", "actions=", "restart/5000/restart/15000/none/0"],
        timeout=10.0,
    )
    return {
        "installed": True,
        "service": name,
        "binary": command,
        "create": created,
        "description": description,
        "failure_policy": failure,
    }


def remove_service(*, service_name: str = "Arenyxa") -> dict[str, Any]:
    _require_windows()
    sc = shutil.which("sc.exe") or shutil.which("sc")
    if not sc:
        raise ArenyxaError("WINDOWS_SC_UNAVAILABLE", "sc.exe is unavailable", domain="WINDOWS")
    name = str(service_name).strip()[:128]
    result = _bounded_process([sc, "delete", name], timeout=15.0)
    if not result.get("ok"):
        combined = (str(result.get("stdout", "")) + "\n" + str(result.get("stderr", ""))).casefold()
        if "1060" in combined or "does not exist" in combined:
            return {"removed": False, "already_absent": True, "service": name, "result": result}
        raise ArenyxaError(
            "WINDOWS_SERVICE_REMOVE_FAILED",
            "Windows Service removal failed",
            domain="WINDOWS",
            context={"service": name, "returncode": result.get("returncode"), "stderr": str(result.get("stderr", ""))[-512:]},
        )
    return {"removed": True, "already_absent": False, "service": name, "result": result}


class WindowsServiceHost:
    """Native SCM service host for Arenyxa's shared application runtime.

    The service uses the same bootstrap, Security Kernel, Storage, Job System,
    recovery, audit and control-plane implementations as Desktop/CLI surfaces.
    """

    def __init__(self, data_dir: Path, *, service_name: str = "Arenyxa") -> None:
        self.data_dir = Path(data_dir).resolve()
        self.service_name = str(service_name).strip()[:128] or "Arenyxa"
        self.stop_event = threading.Event()
        self._status_handle: Any = None
        self._status = SERVICE_STATUS()
        self._context: Any = None
        self._callback_refs: list[Any] = []
        self._diagnostics_dir = self.data_dir / "logs" / "windows-service"

    def _set_status(self, state: int, *, wait_hint: int = 0, exit_code: int = 0) -> None:
        if os.name != "nt" or not self._status_handle:
            return
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS)]
        advapi32.SetServiceStatus.restype = wintypes.BOOL
        self._status.dwServiceType = SERVICE_WIN32_OWN_PROCESS
        self._status.dwCurrentState = state
        self._status.dwControlsAccepted = (
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN if state == SERVICE_RUNNING else 0
        )
        self._status.dwWin32ExitCode = int(exit_code)
        self._status.dwServiceSpecificExitCode = 0
        self._status.dwCheckPoint = 0
        self._status.dwWaitHint = max(0, int(wait_hint))
        if not advapi32.SetServiceStatus(self._status_handle, ctypes.byref(self._status)):
            raise ctypes.WinError(ctypes.get_last_error())

    def _prepare_runtime_environment(self, *, service: bool) -> None:
        os.environ["ARENYXA_RUNTIME_MODE"] = "service" if service else "service-console"
        os.environ.setdefault("ARENYXA_DPAPI_SCOPE", "machine" if service else "user")
        diagnostic = write_startup_diagnostic(
            self._diagnostics_dir,
            service_name=self.service_name,
            data_dir=self.data_dir,
            service=service,
        )
        write_windows_event(
            f"Arenyxa runtime starting; service={service}; data_dir={self.data_dir}; diagnostic={diagnostic}",
            source=self.service_name,
            level="information",
        )

    def _run_runtime(self) -> None:
        self._prepare_runtime_environment(service=True)
        self._context = bootstrap(self.data_dir, start_scheduler=True)
        self._set_status(SERVICE_RUNNING)
        write_windows_event(
            f"Arenyxa service entered RUNNING state; pid={os.getpid()}",
            source=self.service_name,
            level="information",
        )
        self.stop_event.wait()

    def run_console(self) -> int:
        try:
            self._prepare_runtime_environment(service=False)
            self._context = bootstrap(self.data_dir, start_scheduler=True)
            self.stop_event.wait()
            return 0
        except KeyboardInterrupt:
            return 0
        finally:
            if self._context is not None:
                self._context.shutdown()
                self._context = None

    def run_service(self) -> int:
        _require_windows()
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        handler_type = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p)
        service_main_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))

        def handler(control: int, event_type: int, event_data: Any, context: Any) -> int:
            del event_type, event_data, context
            if control in {SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN}:
                try:
                    self._set_status(SERVICE_STOP_PENDING, wait_hint=15000)
                finally:
                    self.stop_event.set()
            return NO_ERROR

        handler_callback = handler_type(handler)

        def service_main(argc: int, argv: Any) -> None:
            del argc, argv
            advapi32.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, handler_type, ctypes.c_void_p]
            advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
            self._status_handle = advapi32.RegisterServiceCtrlHandlerExW(self.service_name, handler_callback, None)
            if not self._status_handle:
                return
            exit_code = 0
            try:
                self._set_status(SERVICE_START_PENDING, wait_hint=30000)
                self._run_runtime()
            except Exception as exc:
                exit_code = 1
                LOGGER.exception("Arenyxa Windows Service runtime failed")
                dump_path = capture_minidump(
                    self._diagnostics_dir,
                    reason=f"{type(exc).__name__}: {exc}",
                )
                write_windows_event(
                    f"Arenyxa service runtime failed: {type(exc).__name__}: {exc}; minidump={dump_path}",
                    source=self.service_name,
                    level="error",
                )
            finally:
                if self._context is not None:
                    self._context.shutdown()
                    self._context = None
                try:
                    self._set_status(SERVICE_STOPPED, exit_code=exit_code)
                except OSError as exc:
                    LOGGER.error("Failed to publish final Windows Service status: %s", exc)
                    write_windows_event(
                        f"Failed to publish final service status: {exc}",
                        source=self.service_name,
                        level="warning",
                    )
                write_windows_event(
                    f"Arenyxa service stopped; exit_code={exit_code}",
                    source=self.service_name,
                    level="information" if exit_code == 0 else "error",
                )

        main_callback = service_main_type(service_main)
        self._callback_refs = [handler_callback, main_callback]
        table = (SERVICE_TABLE_ENTRY * 2)()
        table[0].lpServiceName = self.service_name
        table[0].lpServiceProc = ctypes.cast(main_callback, ctypes.c_void_p).value
        table[1].lpServiceName = None
        table[1].lpServiceProc = None
        advapi32.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(SERVICE_TABLE_ENTRY)]
        advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
        if not advapi32.StartServiceCtrlDispatcherW(table):
            raise ctypes.WinError(ctypes.get_last_error())
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Arenyxa Windows Service runtime")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--service-name", default="Arenyxa")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--service", action="store_true")
    mode.add_argument("--console", action="store_true")
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    if args.remove:
        remove_service(service_name=args.service_name)
        return 0
    if args.data_dir is None:
        parser.error("--data-dir is required for service, console, and install modes")
    if args.install:
        install_service(args.data_dir, service_name=args.service_name)
        return 0
    host = WindowsServiceHost(args.data_dir, service_name=args.service_name)
    return host.run_service() if args.service else host.run_console()


if __name__ == "__main__":
    raise SystemExit(main())
