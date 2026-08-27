from __future__ import annotations
from arenyxa.recoverable import record_current_exception

from arenyxa.infrastructure.process_safety import validated_argv
from arenyxa.compat import path_is_relative_to
import base64
import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import statistics
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from cryptography.fernet import Fernet, InvalidToken
from lxml import etree, html
from arenyxa import __version__
from arenyxa.application.advanced import SmartExecutionPlanner
from arenyxa.application.autopilot import AutopilotEngine, ExperienceStore
from arenyxa.application.reliability import ResourceLeasePool
from arenyxa.application.competitive import (
    CompatibilityLab, ContextBridgeService, ReliabilityAdvisor,
    WebIntelligenceEngine, WorkflowPortabilityService,
)
from arenyxa.application.runtime_ecosystem import BrowserProfileService, RegressionLab, WorkflowMarketplaceService
from arenyxa.application.web_intelligence import WebIntelligenceCenter, WebTimeMachine
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, NetworkEvent, RequestSpec, RetryPolicy, Workflow, WorkflowNode, new_id, utc_now
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_bytes_limited, read_text_limited
from arenyxa.platform_compat import select_runtime

LOGGER = logging.getLogger(__name__)

from arenyxa.application.nextgen_core import ActivityCenter, ActivityEvent
from arenyxa.application.nextgen_browser import BrowserRecorderService, SelectorStudio

_VAULT_KEY_CREATION_LOCK = threading.Lock()

_VAULT_LOCKS_GUARD = threading.Lock()

_VAULT_ROOT_LOCKS: dict[Path, threading.RLock] = {}

def _vault_root_lock(root: Path) -> threading.RLock:
    with _VAULT_LOCKS_GUARD:
        lock = _VAULT_ROOT_LOCKS.get(root)
        if lock is None:
            lock = threading.RLock()
            _VAULT_ROOT_LOCKS[root] = lock
        return lock

class SecretVault:
    






    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.vault_path = self.root / "secrets.vault"
        self.backup_path = self.root / "secrets.vault.bak"
        self.key_path = self.root / "secrets.key"
                                                                                          
                                                                                          
        self._lock = _vault_root_lock(self.root)
        key = self._load_or_create_key()
        try:
            self._fernet = Fernet(key)
        except (TypeError, ValueError) as exc:
            raise ArenyxaError("VAULT_KEY_INVALID", "Secrets Vault 密钥无效或已损坏。", domain="SECURITY") from exc

    def _load_or_create_key(self) -> bytes:
        with _VAULT_KEY_CREATION_LOCK:
            if self.key_path.exists():
                try:
                    raw = read_bytes_limited(self.key_path, 64 * 1024)
                    if raw.startswith(b"DPAPI1:") and os.name == "nt":
                        return self._dpapi_unprotect(base64.b64decode(raw.split(b":", 1)[1], validate=True))
                    return raw.strip()
                except (OSError, ValueError, TypeError) as exc:
                    raise ArenyxaError("VAULT_KEY_INVALID", "Secrets Vault 密钥无法读取或解保护。", domain="SECURITY") from exc
            key = Fernet.generate_key()
            payload = key
            if os.name == "nt":
                payload = b"DPAPI1:" + base64.b64encode(self._dpapi_protect(key))
            atomic_write_bytes(self.key_path, payload, mode=0o600)
            return key

    def _decode_vault(self, payload: bytes) -> dict[str, str]:
        clear = self._fernet.decrypt(payload)
        data = json.loads(clear)
        if not isinstance(data, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in data.items()):
            raise ValueError("vault root or entry type invalid")
        return data

    def _load(self) -> dict[str, str]:
        if not self.vault_path.exists():
            return {}
        try:
            return self._decode_vault(read_bytes_limited(self.vault_path, 8 * 1024 * 1024))
        except (InvalidToken, OSError, UnicodeError, json.JSONDecodeError, ValueError) as primary_exc:
                                                                                             
                                                                                    
            if self.backup_path.exists():
                try:
                    backup_payload = read_bytes_limited(self.backup_path, 8 * 1024 * 1024)
                    recovered = self._decode_vault(backup_payload)
                    atomic_write_bytes(self.vault_path, backup_payload, mode=0o600)
                    return recovered
                except (InvalidToken, OSError, UnicodeError, json.JSONDecodeError, ValueError):
                    record_current_exception(__name__, 'SecretVault._load:125')
            raise ArenyxaError("VAULT_CORRUPT", "Secrets Vault 无法解密或已损坏。", domain="SECURITY") from primary_exc

    def _save(self, data: Mapping[str, str]) -> None:
        clear = json.dumps(dict(data), ensure_ascii=False, sort_keys=True).encode("utf-8")
        if self.vault_path.exists():
                                                                               
            try:
                current = read_bytes_limited(self.vault_path, 8 * 1024 * 1024)
                self._decode_vault(current)
            except (InvalidToken, OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                raise ArenyxaError("VAULT_CORRUPT", "Secrets Vault 已损坏，拒绝覆盖以保留恢复证据。", domain="SECURITY") from exc
            atomic_write_bytes(self.backup_path, current, mode=0o600)
        encrypted = self._fernet.encrypt(clear)
        if len(encrypted) > 8 * 1024 * 1024:
            raise ArenyxaError("VAULT_TOO_LARGE", "Secrets Vault 超过 8 MiB 安全上限。", domain="SECURITY")
        atomic_write_bytes(self.vault_path, encrypted, mode=0o600)

    def set(self, name: str, value: str) -> None:
        name = name.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", name):
            raise ValueError("秘密名称必须由字母开头，只包含字母、数字、点、下划线或连字符。")
        with self._lock:
            data = self._load()
            data[name] = str(value)
            self._save(data)

    def get(self, name: str) -> str | None:
        with self._lock:
            return self._load().get(name)

    def delete(self, name: str) -> bool:
        with self._lock:
            data = self._load()
            existed = name in data
            data.pop(name, None)
            if existed:
                self._save(data)
            return existed

    def names(self) -> list[str]:
        with self._lock:
            return sorted(self._load())

    @staticmethod
    def redact(text: str) -> str:
        text = re.sub(r"(?i)(authorization|api[_-]?key|token|password|cookie)(\s*[:=]\s*)([^\s,;]+)", r"\1\2***", text)
        text = re.sub(r"(https?://[^:/\s]+:)[^@/\s]+(@)", r"\1***\2", text)
        return text

    @staticmethod
    def _dpapi_protect(data: bytes) -> bytes:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
        buffer = ctypes.create_string_buffer(data)
        source = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
        target = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(source), "Arenyxa", None, None, None, 0, ctypes.byref(target)):
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(target.pbData, target.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(target.pbData)

    @staticmethod
    def _dpapi_unprotect(data: bytes) -> bytes:
        import ctypes
        from ctypes import wintypes

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]
        buffer = ctypes.create_string_buffer(data)
        source = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
        target = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(target)):
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(target.pbData, target.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(target.pbData)

class ProjectEnvironmentService:
    def __init__(self, projects_root: Path) -> None:
        self.projects_root = projects_root.resolve()
        self.projects_root.mkdir(parents=True, exist_ok=True)

    def path(self, project_name: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", project_name.strip()).strip(".-")
        if not safe:
            raise ValueError("项目名称无效。")
        target = (self.projects_root / safe).resolve()
        if not path_is_relative_to(target, self.projects_root):
            raise ValueError("项目路径越界。")
        return target

    def ensure(self, project_name: str) -> dict[str, str]:
        root = self.path(project_name)
        directories = {name: root / name for name in ("workflows", "selectors", "schemas", "scripts", "tests", "snapshots", "downloads", "browser-profile")}
        root.mkdir(parents=True, exist_ok=True)
        for path in directories.values(): path.mkdir(parents=True, exist_ok=True)
        return {key: str(value) for key, value in {"root": root, **directories}.items()}

    def save_environment(self, project_name: str, values: Mapping[str, str]) -> Path:
        root = self.path(project_name)
        self.ensure(project_name)
        path = root / ".arenyxa-env.json"
        safe = {str(key): str(value) for key, value in values.items() if not re.search(r"secret|password|token|cookie|authorization|api[_-]?key", str(key), re.I)}
        atomic_write_json(path, safe, ensure_ascii=False, indent=2)
        return path

    def load_environment(self, project_name: str) -> dict[str, str]:
        root = self.path(project_name)
        path = root / ".arenyxa-env.json"
        legacy = root / ".arenyxa-env.json"
        if not path.exists() and legacy.exists():
            path = legacy
        if not path.exists():
            return {}
        try:
            raw = json.loads(read_text_limited(path, 4 * 1024 * 1024, encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise ArenyxaError("PROJECT_ENV_CORRUPT", "项目环境配置已损坏，未加载任何环境变量。", domain="PROJECT") from exc
        if not isinstance(raw, dict):
            raise ArenyxaError("PROJECT_ENV_CORRUPT", "项目环境配置根节点必须是对象。", domain="PROJECT")
        return {str(k): str(v) for k, v in raw.items()}

class ProjectPythonEnvironmentService:
    







    def __init__(self, projects: ProjectEnvironmentService) -> None:
        self.projects = projects

    def venv_path(self, project_name: str) -> Path:
        return self.projects.path(project_name) / ".venv"

    def python_path(self, project_name: str) -> Path:
        root = self.venv_path(project_name)
        return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def status(self, project_name: str) -> dict[str, Any]:
        root = self.venv_path(project_name)
        python = self.python_path(project_name)
        result: dict[str, Any] = {
            "project": project_name,
            "venv": str(root),
            "exists": root.exists(),
            "python": str(python),
            "ready": python.exists(),
        }
        if python.exists():
            try:
                completed = subprocess.run(
                    validated_argv([str(python), "-c", "import platform,sys;print(sys.version.split()[0]);print(platform.architecture()[0])"]),
                    cwd=self.projects.path(project_name),
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=15,
                    check=False,
                )
                lines = completed.stdout.strip().splitlines()
                result.update({"version": lines[0] if lines else "", "architecture": lines[1] if len(lines) > 1 else "", "returncode": completed.returncode})
            except (OSError, subprocess.SubprocessError) as exc:
                result["error"] = str(exc)
        return result

    @staticmethod
    def _discover_python() -> list[str]:
        runtime = select_runtime()
        candidates: list[list[str]] = []
        if not getattr(sys, "frozen", False):
            candidates.append([sys.executable])
        if os.name == "nt":
            if runtime.legacy:
                candidates.extend([["py", "-3.8"], ["python"]])
            else:
                candidates.extend([["py", "-3.13"], ["py", "-3.12"], ["py", "-3.11"], ["python"]])
        else:
            candidates.extend([["python3.13"], ["python3.12"], ["python3.11"], ["python3"], ["python"]])
        seen: set[tuple[str, ...]] = set()
        for command in candidates:
            key = tuple(command)
            if key in seen:
                continue
            seen.add(key)
            try:
                completed = subprocess.run(
                    validated_argv([*command, "-c", "import platform,sys;print(sys.version_info[:2]);print(platform.architecture()[0])"]),
                    capture_output=True,
                    text=True,
                    errors="replace",
                    timeout=10,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            text = completed.stdout
            required_minor = "8" if runtime.legacy else "1[123]"
            match = re.search(rf"\((3),\s*({required_minor})\)", text)
            if completed.returncode == 0 and match and "64bit" in text:
                return command
        requirement = "Python 3.8.x" if runtime.legacy else "Python 3.11–3.13"
        raise RuntimeError(f"未找到受支持的 64-bit {requirement}。请先安装对应 Python，然后重试。")

    def create(self, project_name: str, *, clear: bool = False) -> dict[str, Any]:
        self.projects.ensure(project_name)
        root = self.venv_path(project_name)
        backup: Path | None = None
        if clear and root.exists():
            backup = root.with_name(f".venv.backup-{time.time_ns()}")
            root.replace(backup)
        try:
            command = self._discover_python()
            completed = subprocess.run(
                validated_argv([*command, "-m", "venv", str(root)]),
                cwd=self.projects.path(project_name),
                capture_output=True,
                text=True,
                errors="replace",
                timeout=300,
                check=False,
            )
            if completed.returncode != 0:
                raise RuntimeError((completed.stderr or completed.stdout or "python -m venv failed")[-20_000:])
            status = self.status(project_name)
            if not status.get("ready"):
                raise RuntimeError("新建 Python 环境缺少可执行解释器。")
        except Exception:
                                                                                           
            if backup is not None and backup.exists():
                if root.exists():
                    shutil.rmtree(root, ignore_errors=True)
                backup.replace(root)
            raise
        if backup is not None and backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        return status

    def run(self, project_name: str, arguments: Sequence[str], *, timeout: int = 300) -> dict[str, Any]:
        python = self.python_path(project_name)
        if not python.exists():
            raise RuntimeError("项目 Python 环境尚未创建。")
        args = [str(value) for value in arguments]
        completed = subprocess.run(
            validated_argv([str(python), *args]),
            cwd=self.projects.path(project_name),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(1, min(3600, int(timeout))),
            check=False,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout[-200_000:],
            "stderr": completed.stderr[-200_000:],
        }

    def install(self, project_name: str, packages: Sequence[str], *, timeout: int = 900) -> dict[str, Any]:
        cleaned = [str(value).strip() for value in packages if str(value).strip()]
        if not cleaned:
            raise ValueError("至少提供一个 Python 包。")
        if len(cleaned) > 50 or any(len(value) > 300 or "\x00" in value for value in cleaned):
            raise ValueError("Python 包参数无效或数量过多。")
        return self.run(project_name, ["-m", "pip", "install", *cleaned], timeout=timeout)

    def freeze(self, project_name: str) -> list[str]:
        result = self.run(project_name, ["-m", "pip", "freeze"], timeout=120)
        if result["returncode"] != 0:
            raise RuntimeError(result["stderr"] or "pip freeze failed")
        return [line for line in str(result["stdout"]).splitlines() if line.strip()]

@dataclass(slots=True)
class DistributedWorker:
    id: str
    name: str
    base_url: str
    token_secret: str
    enabled: bool = True
    weight: int = 1

class DistributedWorkerService:
    






    def __init__(self, root: Path, vault: SecretVault) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "workers.json"
        self.vault = vault
        self._lock = threading.RLock()

    @staticmethod
    def _validate(worker: DistributedWorker) -> None:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", worker.id):
            raise ValueError("Worker ID 无效。")
        if not isinstance(worker.name, str) or not worker.name.strip() or len(worker.name.strip()) > 200:
            raise ValueError("Worker 名称无效。")
        worker.name = worker.name.strip()
        if not isinstance(worker.token_secret, str) or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_.-]{0,127}", worker.token_secret.strip()
        ):
            raise ValueError("Worker Secret 引用名称无效。")
        worker.token_secret = worker.token_secret.strip()
        if not isinstance(worker.enabled, bool):
            raise ValueError("Worker enabled 字段必须是布尔值。")
        parsed = urlparse(worker.base_url)
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Worker URL 端口无效。") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
            raise ValueError("Worker URL 必须是有效 http/https 地址。")
        if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
            raise ValueError("Worker URL 不允许内联凭据、query 或 fragment；凭据必须放入 Secrets Vault。")
        if parsed.path not in {"", "/"}:
            raise ValueError("Worker URL 必须指向服务器根路径。")
                                                                                                   
        if parsed.scheme == "http" and (parsed.hostname or "").casefold() not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("非本机 Worker 必须使用 HTTPS。")
        worker.weight = max(1, min(100, int(worker.weight)))

    def _load(self) -> list[DistributedWorker]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(read_text_limited(self.path, 4 * 1024 * 1024, encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError("worker registry root must be an array")
            result: list[DistributedWorker] = []
            seen_ids: set[str] = set()
            allowed = set(DistributedWorker.__dataclass_fields__)
            for item in raw:
                if not isinstance(item, dict) or set(item) - allowed:
                    raise ValueError("worker registry item has invalid fields")
                worker = DistributedWorker(**item)
                self._validate(worker)
                if worker.id in seen_ids:
                    raise ValueError("worker registry contains duplicate IDs")
                seen_ids.add(worker.id)
                result.append(worker)
            return result
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                                                                                        
                                                                                       
                                              
            raise ArenyxaError(
                "WORKER_REGISTRY_CORRUPT",
                "Distributed Worker 配置已损坏，已拒绝覆盖原文件。",
                domain="WORKER",
            ) from exc

    def _save(self, workers: Sequence[DistributedWorker]) -> None:
        atomic_write_json(self.path, [asdict(item) for item in workers], ensure_ascii=False, indent=2)

    def list(self) -> list[DistributedWorker]:
        with self._lock:
            return self._load()

    def upsert(self, worker: DistributedWorker, token: str | None = None) -> DistributedWorker:
        self._validate(worker)
        with self._lock:
                                                                                            
                                                                                             
                                                                  
            workers = [item for item in self._load() if item.id != worker.id]
            old_token = self.vault.get(worker.token_secret) if token is not None else None
            try:
                if token is not None:
                    self.vault.set(worker.token_secret, token)
                workers.append(worker)
                self._save(sorted(workers, key=lambda item: item.id))
            except Exception:
                if token is not None:
                    try:
                        if old_token is None:
                            self.vault.delete(worker.token_secret)
                        else:
                            self.vault.set(worker.token_secret, old_token)
                    except Exception:
                        LOGGER.exception(
                            "Distributed Worker token rollback failed for secret %s",
                            worker.token_secret,
                        )
                raise
        return worker

    def remove(self, worker_id: str) -> bool:
        with self._lock:
            workers = self._load()
            remaining = [item for item in workers if item.id != worker_id]
            if len(remaining) == len(workers):
                return False
            self._save(remaining)
            return True

    def _worker(self, worker_id: str) -> DistributedWorker:
        for worker in self.list():
            if worker.id == worker_id:
                return worker
        raise KeyError(worker_id)

    def _request(self, worker: DistributedWorker, path: str, *, method: str = "GET", payload: Mapping[str, Any] | None = None, timeout: float = 10.0) -> Any:
        token = self.vault.get(worker.token_secret)
        if path != "/health" and not token:
            raise RuntimeError(f"Worker {worker.id} 缺少 SecretVault token：{worker.token_secret}")
        headers = {"Accept": "application/json", "User-Agent": f"Arenyxa/{__version__}"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = None
        if payload is not None:
            data = json.dumps(dict(payload), ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(worker.base_url.rstrip("/") + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=max(1.0, min(60.0, float(timeout)))) as response:
                body = response.read(4 * 1024 * 1024 + 1)
                if len(body) > 4 * 1024 * 1024:
                    raise RuntimeError("Worker 响应超过 4 MiB 上限。")
                return json.loads(body.decode("utf-8")) if body else {}
        except urllib.error.HTTPError as exc:
            body = exc.read(8192).decode("utf-8", errors="replace")
            raise RuntimeError(f"Worker HTTP {exc.code}: {body}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeError) as exc:
            raise RuntimeError(f"Worker 请求失败：{exc}") from exc

    def health(self, worker_id: str) -> dict[str, Any]:
        worker = self._worker(worker_id)
        started = time.perf_counter()
        data = self._request(worker, "/health", timeout=5)
        return {"worker": asdict(worker), "latency_ms": round((time.perf_counter() - started) * 1000, 2), "health": data}

    def health_all(self, *, max_workers: int = 4) -> list[dict[str, Any]]:
        





        workers = self.list()
        if not workers:
            return []
        enabled = [item for item in workers if item.enabled]
        results: dict[str, dict[str, Any]] = {
            item.id: {
                "worker": asdict(item),
                "online": False,
                "latency_ms": None,
                "health": {},
                "error": "disabled" if not item.enabled else None,
            }
            for item in workers
        }
        if enabled:
            with ThreadPoolExecutor(
                max_workers=max(1, min(int(max_workers), 8, len(enabled))),
                thread_name_prefix="arenyxa-worker-health",
            ) as executor:
                future_map = {executor.submit(self.health, item.id): item.id for item in enabled}
                for future in as_completed(future_map):
                    worker_id = future_map[future]
                    try:
                        payload = future.result()
                        results[worker_id] = {
                            **payload,
                            "online": True,
                            "error": None,
                        }
                    except Exception as exc:                                          
                        results[worker_id]["error"] = f"{type(exc).__name__}: {exc}"[:500]
        return [results[item.id] for item in workers]

    def remote_tasks(self, worker_id: str) -> list[dict[str, Any]]:
        result = self._request(self._worker(worker_id), "/api/v1/tasks", timeout=15)
        return result if isinstance(result, list) else []

    def remote_runs(self, worker_id: str) -> list[dict[str, Any]]:
        result = self._request(self._worker(worker_id), "/api/v1/runs", timeout=15)
        return result if isinstance(result, list) else []

    def run_task(self, worker_id: str, task_id: str) -> dict[str, Any]:
        result = self._request(self._worker(worker_id), f"/api/v1/tasks/{quote(str(task_id), safe='')}/runs", method="POST", payload={}, timeout=15)
        if not isinstance(result, dict):
            raise RuntimeError("Worker 返回无效运行结果。")
        return result

    def partition(self, values: Sequence[Any], worker_ids: Sequence[str] | None = None) -> dict[str, list[Any]]:
        allowed_ids = None if not worker_ids else {str(item) for item in worker_ids}
        selected = [
            item for item in self.list()
            if item.enabled and (allowed_ids is None or item.id in allowed_ids)
        ]
        if not selected:
            return {"local": list(values)}
        wheel: list[str] = ["local"]
        for worker in selected:
            wheel.extend([worker.id] * worker.weight)
        result: dict[str, list[Any]] = {name: [] for name in dict.fromkeys(wheel)}
        for index, value in enumerate(values):
            result[wheel[index % len(wheel)]].append(value)
        return result

