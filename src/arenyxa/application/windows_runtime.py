from __future__ import annotations

import ctypes
import os
import platform
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.security.hardware_identity import WindowsTPMEcdsaP256Provider
from arenyxa.security.key_protection import DPAPIKeyProtectionAdapter

_MAX_COMMAND_OUTPUT = 64 * 1024


def _bounded_process(argv: list[str], *, timeout: float = 5.0) -> dict[str, Any]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            validated_argv(argv),
            capture_output=True,
            text=True,
            timeout=max(0.5, min(30.0, float(timeout))),
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "ok": False,
            "returncode": None,
            "error": f"{type(exc).__name__}: {exc}"[:512],
            "duration_ms": round((time.monotonic() - started) * 1000.0, 3),
        }
    return {
        "ok": completed.returncode == 0,
        "returncode": int(completed.returncode),
        "stdout": completed.stdout[-_MAX_COMMAND_OUTPUT:],
        "stderr": completed.stderr[-_MAX_COMMAND_OUTPUT:],
        "duration_ms": round((time.monotonic() - started) * 1000.0, 3),
    }


class WindowsRuntimeControl:
    """Real Windows platform probes and bounded service/event operations.

    On non-Windows hosts every native probe returns ``not_available`` instead of
    pretending that Windows-native validation succeeded.
    """

    def __init__(self, *, service_name: str = "Arenyxa") -> None:
        self.service_name = str(service_name or "Arenyxa")[:128]

    @property
    def is_windows(self) -> bool:
        return os.name == "nt"

    def status(self, *, deep: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": "arenyxa.windows-runtime/v1",
            "checked_at": utc_now(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "windows": self.is_windows,
            "service": self.service_status(),
            "npcap": self._npcap_status(),
            "etw": self._etw_status(),
            "event_log": self._event_log_status(),
            "named_pipe": self._named_pipe_status(),
            "wfp": self._wfp_status(),
            "elevation": self._elevation_status(),
            "resource_paths": self._resource_path_status(),
            "dpapi": self._dpapi_status(deep=deep),
            "tpm_cng": self._tpm_status(),
        }
        if deep:
            payload["npcap_enumeration"] = self.npcap_devices()
            payload["etw_round_trip"] = self.etw_round_trip()
            payload["wfp_engine_round_trip"] = self.wfp_engine_round_trip()
        native = [
            payload[key]
            for key in (
                "service", "npcap", "etw", "event_log", "named_pipe", "wfp",
                "elevation", "resource_paths", "dpapi", "tpm_cng",
            )
        ]
        available = sum(1 for item in native if item.get("state") == "available")
        payload["summary"] = {
            "native_probes": len(native),
            "available": available,
            "not_available": sum(1 for item in native if item.get("state") == "not_available"),
            "degraded": sum(1 for item in native if item.get("state") == "degraded"),
        }
        return payload

    def service_status(self, *, service_name: str | None = None) -> dict[str, Any]:
        name = str(service_name or self.service_name)[:128]
        if not self.is_windows:
            return {"state": "not_available", "service": name, "reason": "Windows SCM requires Windows"}
        sc = shutil.which("sc.exe") or shutil.which("sc")
        if not sc:
            return {"state": "degraded", "service": name, "reason": "sc.exe not found"}
        result = _bounded_process([sc, "query", name])
        text = (str(result.get("stdout", "")) + "\n" + str(result.get("stderr", ""))).strip()
        if result.get("ok"):
            state = "unknown"
            for candidate in ("RUNNING", "STOPPED", "PAUSED", "START_PENDING", "STOP_PENDING"):
                if candidate in text.upper():
                    state = candidate.casefold()
                    break
            return {"state": "available", "service": name, "service_state": state, "probe": result}
        missing = "1060" in text or "does not exist" in text.casefold()
        return {
            "state": "available" if missing else "degraded",
            "service": name,
            "service_state": "not_installed" if missing else "unknown",
            "probe": result,
        }

    def service_control(self, action: str, *, service_name: str | None = None) -> dict[str, Any]:
        verb = str(action or "").strip().casefold()
        if verb not in {"start", "stop"}:
            raise ValueError("service action must be start or stop")
        if not self.is_windows:
            raise ArenyxaError("WINDOWS_SCM_UNAVAILABLE", "Windows Service Control Manager is unavailable", domain="WINDOWS")
        name = str(service_name or self.service_name)[:128]
        sc = shutil.which("sc.exe") or shutil.which("sc")
        if not sc:
            raise ArenyxaError("WINDOWS_SC_UNAVAILABLE", "sc.exe is unavailable", domain="WINDOWS")
        result = _bounded_process([sc, verb, name], timeout=15.0)
        if not result.get("ok"):
            raise ArenyxaError(
                "WINDOWS_SERVICE_CONTROL_FAILED",
                f"Windows service {verb} failed",
                domain="WINDOWS",
                context={"service": name, "returncode": result.get("returncode"), "stderr": str(result.get("stderr", ""))[-512:]},
            )
        return {"action": verb, "service": name, "result": result, "status": self.service_status(service_name=name)}

    def service_install(
        self, data_dir: Path, *, service_name: str | None = None, start: str = "auto"
    ) -> dict[str, Any]:
        if not self.is_windows:
            raise ArenyxaError("WINDOWS_SCM_UNAVAILABLE", "Windows Service Control Manager is unavailable", domain="WINDOWS")
        from arenyxa.infrastructure.windows_service import install_service

        return install_service(
            Path(data_dir), service_name=str(service_name or self.service_name)[:128], start=start
        )

    def service_remove(self, *, service_name: str | None = None) -> dict[str, Any]:
        if not self.is_windows:
            raise ArenyxaError("WINDOWS_SCM_UNAVAILABLE", "Windows Service Control Manager is unavailable", domain="WINDOWS")
        from arenyxa.infrastructure.windows_service import remove_service

        return remove_service(service_name=str(service_name or self.service_name)[:128])

    def write_event(self, message: str, *, level: str = "INFORMATION") -> dict[str, Any]:
        if not self.is_windows:
            raise ArenyxaError("WINDOWS_EVENT_LOG_UNAVAILABLE", "Windows Event Log is unavailable", domain="WINDOWS")
        eventcreate = shutil.which("eventcreate.exe") or shutil.which("eventcreate")
        if not eventcreate:
            raise ArenyxaError("WINDOWS_EVENTCREATE_UNAVAILABLE", "eventcreate.exe is unavailable", domain="WINDOWS")
        normalized_level = str(level or "INFORMATION").upper()
        type_map = {"INFORMATION": "INFORMATION", "WARNING": "WARNING", "ERROR": "ERROR"}
        event_type = type_map.get(normalized_level, "INFORMATION")
        clean = " ".join(str(message or "").split())[:1024]
        if not clean:
            raise ValueError("event message is required")
        result = _bounded_process([
            eventcreate, "/L", "APPLICATION", "/T", event_type, "/ID", "100", "/SO", "Arenyxa", "/D", clean,
        ], timeout=10.0)
        if not result.get("ok"):
            raise ArenyxaError(
                "WINDOWS_EVENT_LOG_WRITE_FAILED",
                "Windows Event Log write failed",
                domain="WINDOWS",
                context={"returncode": result.get("returncode"), "stderr": str(result.get("stderr", ""))[-512:]},
            )
        return {"written": True, "level": event_type, "event_id": 100}


    def npcap_devices(self) -> dict[str, Any]:
        """Enumerate Npcap/libpcap capture interfaces without starting capture."""
        if not self.is_windows:
            return {"state": "not_available", "reason": "Npcap is Windows-native", "devices": []}
        candidates = [
            Path(os.environ.get("WINDIR", r"C:\\Windows")) / "System32" / "Npcap" / "wpcap.dll",
            Path(os.environ.get("WINDIR", r"C:\\Windows")) / "System32" / "wpcap.dll",
        ]
        library_path = next((path for path in candidates if path.is_file()), None)
        try:
            library = ctypes.WinDLL(str(library_path) if library_path else "wpcap.dll", use_last_error=True)
        except OSError as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512], "devices": []}

        class PcapIf(ctypes.Structure):
            """Marker type for PcapIf."""

        PcapIf._fields_ = [
            ("next", ctypes.POINTER(PcapIf)),
            ("name", ctypes.c_char_p),
            ("description", ctypes.c_char_p),
            ("addresses", ctypes.c_void_p),
            ("flags", ctypes.c_uint),
        ]
        find_all = library.pcap_findalldevs
        find_all.argtypes = [ctypes.POINTER(ctypes.POINTER(PcapIf)), ctypes.c_char_p]
        find_all.restype = ctypes.c_int
        free_all = library.pcap_freealldevs
        free_all.argtypes = [ctypes.POINTER(PcapIf)]
        free_all.restype = None
        head = ctypes.POINTER(PcapIf)()
        error_buffer = ctypes.create_string_buffer(256)
        rc = int(find_all(ctypes.byref(head), error_buffer))
        if rc != 0:
            return {
                "state": "degraded",
                "returncode": rc,
                "reason": error_buffer.value.decode("utf-8", "replace")[:512],
                "devices": [],
            }
        devices: list[dict[str, Any]] = []
        try:
            current = head
            while bool(current) and len(devices) < 512:
                item = current.contents
                devices.append({
                    "name": (item.name or b"").decode("utf-8", "replace")[:1024],
                    "description": (item.description or b"").decode("utf-8", "replace")[:1024],
                    "flags": int(item.flags),
                })
                current = item.next
        finally:
            if bool(head):
                free_all(head)
        return {
            "state": "available",
            "library": str(library_path or "wpcap.dll"),
            "device_count": len(devices),
            "devices": devices,
        }

    def etw_round_trip(self, message: str = "Arenyxa ETW qualification") -> dict[str, Any]:
        """Register a private ETW provider, emit one bounded event, then unregister it."""
        if not self.is_windows:
            return {"state": "not_available", "reason": "ETW requires Windows", "written": False}

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        # Stable private provider GUID: 2fce6ad4-263f-4d23-aee2-16d8e47c4510.
        provider = GUID(0x2FCE6AD4, 0x263F, 0x4D23, (ctypes.c_ubyte * 8)(0xAE, 0xE2, 0x16, 0xD8, 0xE4, 0x7C, 0x45, 0x10))
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            register = advapi32.EventRegister
            register.argtypes = [ctypes.POINTER(GUID), ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong)]
            register.restype = ctypes.c_ulong
            write_string = advapi32.EventWriteString
            write_string.argtypes = [ctypes.c_ulonglong, ctypes.c_ubyte, ctypes.c_ulonglong, ctypes.c_wchar_p]
            write_string.restype = ctypes.c_ulong
            unregister = advapi32.EventUnregister
            unregister.argtypes = [ctypes.c_ulonglong]
            unregister.restype = ctypes.c_ulong
        except (AttributeError, OSError) as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512], "written": False}
        handle = ctypes.c_ulonglong(0)
        rc_register = int(register(ctypes.byref(provider), None, None, ctypes.byref(handle)))
        if rc_register != 0:
            return {"state": "degraded", "register_code": rc_register, "written": False}
        clean = " ".join(str(message or "").split())[:2048] or "Arenyxa ETW qualification"
        try:
            rc_write = int(write_string(handle.value, 4, 0, clean))
        finally:
            rc_unregister = int(unregister(handle.value))
        ok = rc_write == 0 and rc_unregister == 0
        return {
            "state": "available" if ok else "degraded",
            "written": rc_write == 0,
            "register_code": rc_register,
            "write_code": rc_write,
            "unregister_code": rc_unregister,
        }

    def wfp_engine_round_trip(self) -> dict[str, Any]:
        """Open and close the Windows Filtering Platform engine to validate callable ABI."""
        if not self.is_windows:
            return {"state": "not_available", "reason": "WFP requires Windows", "opened": False}
        try:
            library = ctypes.WinDLL("fwpuclnt.dll", use_last_error=True)
            open_engine = library.FwpmEngineOpen0
            open_engine.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
            open_engine.restype = ctypes.c_ulong
            close_engine = library.FwpmEngineClose0
            close_engine.argtypes = [ctypes.c_void_p]
            close_engine.restype = ctypes.c_ulong
        except (AttributeError, OSError) as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512], "opened": False}
        engine = ctypes.c_void_p()
        # RPC_C_AUTHN_WINNT = 10. Opening a read/write engine handle is itself non-destructive.
        rc_open = int(open_engine(None, 10, None, None, ctypes.byref(engine)))
        if rc_open != 0 or not engine.value:
            return {"state": "degraded", "open_code": rc_open, "opened": False}
        rc_close = int(close_engine(engine))
        return {
            "state": "available" if rc_close == 0 else "degraded",
            "opened": True,
            "open_code": rc_open,
            "close_code": rc_close,
        }

    def _npcap_status(self) -> dict[str, Any]:
        if not self.is_windows:
            return {"state": "not_available", "reason": "Npcap is Windows-native"}
        candidates = [
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap" / "wpcap.dll",
            Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "wpcap.dll",
        ]
        present = [str(path) for path in candidates if path.is_file()]
        service = self.service_status(service_name="npcap")
        return {
            "state": "available" if present or service.get("service_state") not in {"not_installed", "unknown"} else "degraded",
            "libraries": present,
            "service": service,
        }

    def _etw_status(self) -> dict[str, Any]:
        if not self.is_windows:
            return {"state": "not_available", "reason": "ETW requires Windows"}
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            available = all(hasattr(advapi32, name) for name in ("EventRegister", "EventWrite", "EventUnregister"))
        except (AttributeError, OSError) as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512]}
        return {"state": "available" if available else "degraded", "provider_api": available}

    def _event_log_status(self) -> dict[str, Any]:
        if not self.is_windows:
            return {"state": "not_available", "reason": "Windows Event Log requires Windows"}
        executable = shutil.which("wevtutil.exe") or shutil.which("wevtutil")
        return {"state": "available" if executable else "degraded", "wevtutil": executable or ""}

    def _named_pipe_status(self) -> dict[str, Any]:
        if not self.is_windows:
            return {"state": "not_available", "reason": "AF_PIPE requires Windows"}
        try:
            from multiprocessing.connection import families

            available = "AF_PIPE" in families
        except (ImportError, AttributeError) as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512]}
        return {"state": "available" if available else "degraded", "family": "AF_PIPE"}

    def _wfp_status(self) -> dict[str, Any]:
        if not self.is_windows:
            return {"state": "not_available", "reason": "Windows Filtering Platform requires Windows"}
        try:
            library = ctypes.WinDLL("fwpuclnt.dll", use_last_error=True)
            required = ("FwpmEngineOpen0", "FwpmEngineClose0", "FwpmFilterAdd0", "FwpmFilterDeleteById0")
            missing = [name for name in required if not hasattr(library, name)]
        except OSError as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512]}
        return {"state": "available" if not missing else "degraded", "api": "WFP", "missing": missing}

    def _elevation_status(self) -> dict[str, Any]:
        if not self.is_windows:
            return {"state": "not_available", "reason": "Windows elevation token requires Windows"}
        try:
            elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError) as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512]}
        return {"state": "available", "elevated": elevated}

    def _resource_path_status(self) -> dict[str, Any]:
        executable = Path(sys.executable).resolve()
        package_root = Path(__file__).resolve().parents[1]
        candidates = {
            "executable": executable,
            "package_root": package_root,
            "resources": package_root / "resources",
        }
        return {
            "state": "available",
            "paths": {name: str(path) for name, path in candidates.items()},
            "exists": {name: path.exists() for name, path in candidates.items()},
        }

    def _dpapi_status(self, *, deep: bool) -> dict[str, Any]:
        if not self.is_windows:
            return {"state": "not_available", "reason": "DPAPI requires Windows"}
        if not deep:
            return {"state": "available", "round_trip": "not_executed"}
        adapter = DPAPIKeyProtectionAdapter()
        probe = secrets.token_bytes(32)
        try:
            protected = adapter.protect(probe)
            restored = adapter.unprotect(protected)
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            return {"state": "degraded", "round_trip": False, "reason": f"{type(exc).__name__}: {exc}"[:512]}
        return {"state": "available" if restored == probe else "degraded", "round_trip": restored == probe}

    @staticmethod
    def _tpm_status() -> dict[str, Any]:
        if os.name != "nt":
            return {"state": "not_available", "reason": "TPM/CNG requires Windows"}
        try:
            status = WindowsTPMEcdsaP256Provider().status()
            payload = status.to_dict()
        except (ArenyxaError, OSError, RuntimeError, ValueError) as exc:
            return {"state": "degraded", "reason": f"{type(exc).__name__}: {exc}"[:512]}
        available = bool(payload.get("available"))
        return {"state": "available" if available else "degraded", **payload}
