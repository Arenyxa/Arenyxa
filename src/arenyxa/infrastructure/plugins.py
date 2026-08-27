from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from arenyxa.infrastructure.process_safety import validated_argv

import json
import os
import re
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import field
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any, Dict, cast

from arenyxa import __compat_version__, __version__
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import read_text_limited
from arenyxa.infrastructure.plugin_trust import verify_plugin_signature

KNOWN_PERMISSIONS = {"network", "storage", "browser", "clipboard", "process", "database"}
SUPPORTED_PLUGIN_API_VERSIONS = frozenset({"1"})
PLUGIN_COMPATIBILITY_ERROR_CODES = frozenset({"PLUGIN_API_UNSUPPORTED", "PLUGIN_APP_VERSION_UNSUPPORTED"})
_VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){0,3}$")


def _version_tuple(value: str) -> tuple[int, int, int, int]:
    text = str(value).strip()
                                                                                 
                                                                              
                                                                                
                                                         
    if len(text) > 31 or not _VERSION_RE.fullmatch(text):
        raise ArenyxaError(
            "PLUGIN_APP_VERSION_INVALID",
            "插件 min_app_version 必须使用数字版本格式，例如 6.0.0。",
            domain="PLUGIN",
        )
    raw_parts = text.split(".")
    if any(len(part) > 7 for part in raw_parts):
        raise ArenyxaError(
            "PLUGIN_APP_VERSION_INVALID",
            "插件版本号分段超出安全范围。",
            domain="PLUGIN",
        )
    try:
        parts = [int(part, 10) for part in raw_parts] + [0, 0, 0, 0]
    except (TypeError, ValueError) as exc:
        raise ArenyxaError(
            "PLUGIN_APP_VERSION_INVALID",
            "插件版本号无法解析。",
            domain="PLUGIN",
        ) from exc
    return (parts[0], parts[1], parts[2], parts[3])


@dataclass(slots=True)
class PluginManifest:
    id: str
    name: str
    version: str
    entry: str
    api_version: str = "1"
    permissions: dict[str, Any] = field(default_factory=dict)
    capabilities: list[str] = field(default_factory=list)
    min_app_version: str = "6.0.0"

    @classmethod
    def load(cls, path: Path) -> PluginManifest:
        try:
            raw_value = json.loads(read_text_limited(path, 1024 * 1024, encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件 manifest 无法解析。", domain="PLUGIN") from exc
        if not isinstance(raw_value, dict):
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件 manifest 根节点必须是 JSON object。", domain="PLUGIN")
        allowed = set(cls.__dataclass_fields__)
        if set(raw_value) - allowed:
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件 manifest 包含未知字段。", domain="PLUGIN")
        try:
            manifest = cls(**raw_value)
        except (TypeError, ValueError) as exc:
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件 manifest 字段类型无效。", domain="PLUGIN") from exc
        required_strings = {
            "id": manifest.id, "name": manifest.name, "version": manifest.version,
            "entry": manifest.entry, "api_version": manifest.api_version,
            "min_app_version": manifest.min_app_version,
        }
        if any(not isinstance(value, str) for value in required_strings.values()):
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件 manifest 字符串字段类型无效。", domain="PLUGIN")
        if not isinstance(manifest.permissions, dict) or not isinstance(manifest.capabilities, list):
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件权限或能力字段类型无效。", domain="PLUGIN")
        if not all(isinstance(name, str) for name in manifest.permissions):
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件权限名称必须是字符串。", domain="PLUGIN")
        if not all(isinstance(item, str) for item in manifest.capabilities):
            raise ArenyxaError("PLUGIN_MANIFEST_INVALID", "插件能力列表格式无效。", domain="PLUGIN")
        unknown = set(manifest.permissions) - KNOWN_PERMISSIONS
        if unknown:
            raise ArenyxaError(
                "PLUGIN_PERMISSION_UNKNOWN", f"未知插件权限：{sorted(unknown)}", domain="PLUGIN"
            )
        if not manifest.id or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for character in manifest.id
        ):
            raise ArenyxaError("PLUGIN_ID_INVALID", "插件 ID 无效。", domain="PLUGIN")
        if not isinstance(manifest.entry, str) or not manifest.entry.strip():
            raise ArenyxaError("PLUGIN_ENTRY_INVALID", "插件入口无效。", domain="PLUGIN")
        entry = (path.parent / manifest.entry).resolve()
        plugin_root = path.parent.resolve()
        if plugin_root not in entry.parents or not entry.is_file():
            raise ArenyxaError("PLUGIN_ENTRY_INVALID", "插件入口不存在或越出插件目录。", domain="PLUGIN")
                                                                                       
                                                                              
        _version_tuple(manifest.min_app_version)
        return manifest

    def validate_compatibility(self, app_version: str = __compat_version__) -> None:
        





        if self.api_version not in SUPPORTED_PLUGIN_API_VERSIONS:
            raise ArenyxaError(
                "PLUGIN_API_UNSUPPORTED",
                f"插件 API {self.api_version} 与当前 Arenyxa 不兼容。",
                domain="PLUGIN",
                context={"supported": sorted(SUPPORTED_PLUGIN_API_VERSIONS)},
            )
        if _version_tuple(app_version) < _version_tuple(self.min_app_version):
            raise ArenyxaError(
                "PLUGIN_APP_VERSION_UNSUPPORTED",
                f"插件要求 Arenyxa >= {self.min_app_version}，当前版本为 {app_version}。",
                domain="PLUGIN",
                context={"required": self.min_app_version, "current": app_version},
            )


@dataclass(slots=True)
class SandboxBudget:
    timeout_seconds: float = 15.0
    max_output_bytes: int = 4 * 1024 * 1024
    max_memory_mb: int = 256
    max_input_bytes: int = 16 * 1024 * 1024
    max_processes: int = 1


@dataclass(frozen=True, slots=True)
class PluginHealth:
    plugin_id: str
    state: str
    success_count: int
    failure_count: int
    consecutive_failures: int
    last_error_code: str | None
    quarantine_remaining_seconds: float


class PluginHealthRegistry:
    

    def __init__(self, failure_threshold: int = 3, window_seconds: float = 60.0, cooldown_seconds: float = 30.0) -> None:
        self.failure_threshold = max(2, min(20, int(failure_threshold)))
        self.window_seconds = max(5.0, min(3600.0, float(window_seconds)))
        self.cooldown_seconds = max(1.0, min(3600.0, float(cooldown_seconds)))
        self._state: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _entry(self, plugin_id: str) -> dict[str, Any]:
        return self._state.setdefault(plugin_id, {
            "success": 0, "failure": 0, "consecutive": 0, "last_error": None,
            "failures": deque(maxlen=64), "quarantine_until": 0.0,
        })

    def allow(self, plugin_id: str) -> None:
        now = time.monotonic()
        with self._lock:
            entry = self._entry(plugin_id)
            until = float(entry["quarantine_until"])
            if until > now:
                raise ArenyxaError(
                    "PLUGIN_HEALTH_QUARANTINED",
                    "插件连续失败后已被临时隔离；冷却期结束前不会再次启动。",
                    domain="PLUGIN",
                    context={"plugin_id": plugin_id, "retry_after_seconds": round(until - now, 3)},
                )
            if until:
                entry["quarantine_until"] = 0.0
                entry["consecutive"] = 0

    def success(self, plugin_id: str) -> None:
        with self._lock:
            entry = self._entry(plugin_id)
            entry["success"] = int(entry["success"]) + 1
            entry["consecutive"] = 0
            entry["last_error"] = None

    def failure(self, plugin_id: str, error_code: str) -> None:
        now = time.monotonic()
        with self._lock:
            entry = self._entry(plugin_id)
            entry["failure"] = int(entry["failure"]) + 1
            entry["consecutive"] = int(entry["consecutive"]) + 1
            entry["last_error"] = str(error_code)
            failures = entry["failures"]
            failures.append(now)
            while failures and now - failures[0] > self.window_seconds:
                failures.popleft()
            if int(entry["consecutive"]) >= self.failure_threshold and len(failures) >= self.failure_threshold:
                entry["quarantine_until"] = now + self.cooldown_seconds

    def snapshot(self) -> list[PluginHealth]:
        now = time.monotonic()
        with self._lock:
            result: list[PluginHealth] = []
            for plugin_id, entry in sorted(self._state.items()):
                remaining = max(0.0, float(entry["quarantine_until"]) - now)
                state = "quarantined" if remaining > 0 else ("degraded" if int(entry["consecutive"]) else "healthy")
                result.append(PluginHealth(
                    plugin_id, state, int(entry["success"]), int(entry["failure"]), int(entry["consecutive"]),
                    None if entry["last_error"] is None else str(entry["last_error"]), round(remaining, 3),
                ))
            return result


def _source_worker_python_executable() -> str:
    










    executable = str(sys.executable)
    if sys.platform != "win32" or sys.prefix == sys.base_prefix:
        return executable
    base_executable = getattr(sys, "_base_executable", None)
    if base_executable:
        candidate = Path(str(base_executable))
        if candidate.is_file():
            return str(candidate)
    return executable


def _plugin_worker_command(worker_script: Path, manifest_path: Path, grant_payload: str) -> list[str]:
    
    if bool(getattr(sys, "frozen", False)):
                                                                                     
                                                                                     
                                                                                       
                                                                              
        return [
            str(sys.executable),
            "--internal-plugin-worker",
            str(manifest_path),
            grant_payload,
        ]
    return [
        _source_worker_python_executable(),
        "-I",
        str(worker_script),
        str(manifest_path),
        grant_payload,
    ]


def _terminate_plugin_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name != "nt":
        try:
            os.killpg(process.pid, 9)
            return
        except (OSError, ProcessLookupError):
            record_current_exception(__name__, '_terminate_plugin_process:280')
    try:
        process.kill()
    except OSError:
        record_current_exception(__name__, '_terminate_plugin_process:284')


class PluginSandbox:
    def __init__(self, worker_script: Path | None = None, health: PluginHealthRegistry | None = None) -> None:
        self.worker_script = worker_script or Path(__file__).with_name("plugin_worker.py")
        self.health = health or PluginHealthRegistry()

    def invoke(
        self,
        plugin_dir: Path,
        request: dict[str, Any],
        granted_permissions: dict[str, Any],
        budget: SandboxBudget | None = None,
    ) -> dict[str, Any]:
        plugin_key = Path(plugin_dir).name or "unknown"
        try:
            manifest = PluginManifest.load(Path(plugin_dir).resolve() / "plugin.json")
            plugin_key = manifest.id
            self.health.allow(plugin_key)
            result = self._invoke_once(plugin_dir, request, granted_permissions, budget)
        except Exception as exc:
            code = str(getattr(exc, "code", type(exc).__name__))
            if code != "PLUGIN_HEALTH_QUARANTINED":
                self.health.failure(plugin_key, code)
            raise
        self.health.success(plugin_key)
        return result

    def health_snapshot(self) -> list[PluginHealth]:
        return self.health.snapshot()

    def _invoke_once(
        self,
        plugin_dir: Path,
        request: dict[str, Any],
        granted_permissions: dict[str, Any],
        budget: SandboxBudget | None = None,
    ) -> dict[str, Any]:
        budget = budget or SandboxBudget()
        if not (0.1 <= float(budget.timeout_seconds) <= 300.0):
            raise ArenyxaError("PLUGIN_BUDGET_INVALID", "插件超时预算超出安全范围。", domain="PLUGIN")
        if not (1024 <= int(budget.max_output_bytes) <= 64 * 1024 * 1024):
            raise ArenyxaError("PLUGIN_BUDGET_INVALID", "插件输出预算超出安全范围。", domain="PLUGIN")
        if not (32 <= int(budget.max_memory_mb) <= 4096):
            raise ArenyxaError("PLUGIN_BUDGET_INVALID", "插件内存预算超出安全范围。", domain="PLUGIN")
        if not (1024 <= int(budget.max_input_bytes) <= 64 * 1024 * 1024):
            raise ArenyxaError("PLUGIN_BUDGET_INVALID", "插件输入预算超出安全范围。", domain="PLUGIN")
        if not (1 <= int(budget.max_processes) <= 8):
            raise ArenyxaError("PLUGIN_BUDGET_INVALID", "插件进程预算超出安全范围。", domain="PLUGIN")
        manifest_path = plugin_dir.resolve() / "plugin.json"
        manifest = PluginManifest.load(manifest_path)
        manifest.validate_compatibility()
        requested_permissions = {
            permission
            for permission, declaration in manifest.permissions.items()
            if declaration is not False and declaration is not None
        }
        for permission in requested_permissions:
            if permission not in granted_permissions or granted_permissions[permission] is False or granted_permissions[permission] is None:
                raise ArenyxaError(
                    "PLUGIN_PERMISSION_DENIED",
                    f"插件请求未授权权限：{permission}",
                    domain="PLUGIN",
                )
                                                                                        
                                                                                      
        effective_grants = {
            permission: granted_permissions[permission]
            for permission in requested_permissions
        }
        grant_payload = json.dumps(effective_grants, ensure_ascii=False)
        if len(grant_payload.encode("utf-8")) > 24 * 1024:
            raise ArenyxaError("PLUGIN_PERMISSION_PAYLOAD_TOO_LARGE", "插件权限配置超过安全上限。", domain="PLUGIN")
        command = _plugin_worker_command(self.worker_script, manifest_path, grant_payload)
        environment = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "TMP": os.environ.get("TMP", ""),
            "PYTHONUTF8": "1",
                                                                                               
                                                                                 
            "ARENYXA_PLUGIN_SANDBOX_BUDGET": json.dumps({
                "timeout_seconds": float(budget.timeout_seconds),
                "max_output_bytes": int(budget.max_output_bytes),
                "max_memory_mb": int(budget.max_memory_mb),
                "max_processes": int(budget.max_processes),
            }, separators=(",", ":")),
        }
        process = subprocess.Popen(
            validated_argv(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            env=environment,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            start_new_session=os.name != "nt",
        )
        try:
            job_handle = _assign_windows_job(process, budget.max_memory_mb, budget.max_processes)
        except (ArenyxaError, OSError, RuntimeError, ValueError):
                                                                                           
                                                                                        
            try:
                _terminate_plugin_process(process)
            except OSError:
                record_current_exception(__name__, 'PluginSandbox._invoke_once:392')
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                record_current_exception(__name__, 'PluginSandbox._invoke_once:396')
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        record_current_exception(__name__, 'PluginSandbox._invoke_once:402')
            raise
                                                                                          
                                                                                         
                                                                                           
                                                                         
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        output_lock = threading.Lock()
        overflow = threading.Event()
        drain_threads: list[threading.Thread] = []

        def drain(stream: Any, target: bytearray) -> None:
            try:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        return
                    with output_lock:
                        used = len(stdout_buffer) + len(stderr_buffer)
                        remaining = max(0, int(budget.max_output_bytes) - used)
                        if remaining:
                            target.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            overflow.set()
                    if overflow.is_set():
                        try:
                            _terminate_plugin_process(process)
                        except OSError:
                            record_current_exception(__name__, 'PluginSandbox._invoke_once.drain:431')
                        return
            finally:
                try:
                    stream.close()
                except OSError:
                    record_current_exception(__name__, 'PluginSandbox._invoke_once.drain:437')

        for stream, target, label in (
            (process.stdout, stdout_buffer, "stdout"),
            (process.stderr, stderr_buffer, "stderr"),
        ):
            if stream is None:
                continue
            thread = threading.Thread(
                target=drain, args=(stream, target), name=f"arenyxa-plugin-{label}", daemon=True
            )
            thread.start()
            drain_threads.append(thread)

        timed_out = False
        try:
            payload = json.dumps(request, ensure_ascii=False).encode("utf-8")
            if len(payload) > int(budget.max_input_bytes):
                raise ArenyxaError(
                    "PLUGIN_INPUT_TOO_LARGE",
                    "插件输入超过本次沙箱预算。",
                    domain="PLUGIN",
                    context={"limit": int(budget.max_input_bytes)},
                )
            if process.stdin is None:
                raise ArenyxaError("PLUGIN_PROTOCOL_INVALID", "插件输入管道不可用。", domain="PLUGIN")
            try:
                process.stdin.write(payload)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                                                                                          
                                                                                
                record_current_exception(__name__, 'PluginSandbox._invoke_once:467')
            try:
                process.wait(timeout=budget.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_plugin_process(process)
                process.wait(timeout=5)
            for thread in drain_threads:
                thread.join(timeout=5)
        finally:
            if process.poll() is None:
                _terminate_plugin_process(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    record_current_exception(__name__, 'PluginSandbox._invoke_once:484')
            if job_handle:
                import ctypes

                ctypes.windll.kernel32.CloseHandle(job_handle)

        if timed_out:
            raise ArenyxaError("PLUGIN_BUDGET_EXCEEDED", "插件执行超时。", domain="PLUGIN")
        if overflow.is_set():
            raise ArenyxaError("PLUGIN_BUDGET_EXCEEDED", "插件输出超过预算。", domain="PLUGIN")
        stdout = bytes(stdout_buffer).decode("utf-8", errors="replace")
        stderr = bytes(stderr_buffer).decode("utf-8", errors="replace")
        if process.returncode != 0:
            raise ArenyxaError(
                "PLUGIN_EXECUTION_FAILED",
                stderr[-2000:] or "插件进程执行失败。",
                domain="PLUGIN",
                context={"plugin_id": manifest.id, "returncode": process.returncode},
            )
        try:
            response = json.loads(stdout)
        except ValueError as exc:
            raise ArenyxaError("PLUGIN_PROTOCOL_INVALID", "插件返回了无效 JSON。", domain="PLUGIN") from exc
        if not isinstance(response, dict):
            raise ArenyxaError("PLUGIN_PROTOCOL_INVALID", "插件响应根节点必须是 JSON object。", domain="PLUGIN")
        return cast(Dict[str, Any], response)


def _assign_windows_job(process: subprocess.Popen[str], max_memory_mb: int, max_processes: int = 1) -> int | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimit),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.windll.kernel32
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ArenyxaError("PLUGIN_SANDBOX_UNAVAILABLE", "无法创建 Windows Job Object。", domain="PLUGIN")
    information = ExtendedLimit()
                                                                                              
                                                                                           
                                                          
    information.BasicLimitInformation.LimitFlags = 0x0100 | 0x2000 | 0x00000008
    information.BasicLimitInformation.ActiveProcessLimit = max(1, min(8, int(max_processes)))
    information.ProcessMemoryLimit = max(32, max_memory_mb) * 1024 * 1024
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(information), ctypes.sizeof(information)):
        kernel32.CloseHandle(job)
        raise ArenyxaError("PLUGIN_SANDBOX_UNAVAILABLE", "无法设置插件内存预算。", domain="PLUGIN")
    process_handle = getattr(process, "_handle", None)
    if process_handle is None or not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(process_handle)):
        kernel32.CloseHandle(job)
        raise ArenyxaError("PLUGIN_SANDBOX_UNAVAILABLE", "无法把插件进程放入沙箱 Job。", domain="PLUGIN")
    return int(job)


class PluginManager:
    def __init__(
        self,
        root: Path,
        *,
        trust_store: Path | None = None,
        require_signatures: bool = False,
    ) -> None:
        self.root = root
        self.trust_store = None if trust_store is None else Path(trust_store)
        self.require_signatures = bool(require_signatures)

    def signature_status(self, plugin_root: Path) -> dict[str, Any]:
        signature_path = Path(plugin_root) / "plugin.sig.json"
        if not signature_path.is_file():
            if self.require_signatures:
                raise ArenyxaError("PLUGIN_SIGNATURE_REQUIRED", "Plugin signature is required", domain="PLUGIN")
            return {"verified": False, "state": "unsigned", "required": False}
        if self.trust_store is None or not self.trust_store.is_file():
            raise ArenyxaError("PLUGIN_TRUST_STORE_UNAVAILABLE", "Plugin trust store is unavailable", domain="PLUGIN")
        return {"state": "verified", "required": self.require_signatures, **verify_plugin_signature(plugin_root, self.trust_store)}

    def discover(self) -> list[tuple[PluginManifest, Path]]:
        found: list[tuple[PluginManifest, Path]] = []
        if not self.root.exists():
            return found
        for manifest_path in self.root.glob("*/plugin.json"):
            try:
                manifest = PluginManifest.load(manifest_path)
                manifest.validate_compatibility()
                self.signature_status(manifest_path.parent)
                found.append((manifest, manifest_path.parent))
            except (OSError, ValueError, ArenyxaError):
                continue
        return found

    def inspect_install(self, source: Path) -> PluginManifest:
        manifest = PluginManifest.load(source / "plugin.json")
        manifest.validate_compatibility()
        self.signature_status(source)
        return manifest
