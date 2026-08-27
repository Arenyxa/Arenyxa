from __future__ import annotations

from arenyxa.console_io import console_write
from arenyxa.infrastructure.process_safety import validated_argv
import hashlib
import importlib.util
import json
import logging
import math
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict, field
from arenyxa.compat import dataclass
from datetime import datetime, timezone
from arenyxa.compat import StrEnum
from pathlib import Path
from typing import Any, Iterable, Optional
from arenyxa.branding import (
    APP_NAME,
    DATA_DIR_ENV,
    LEGACY_DATA_DIR_ENV,
    SOURCE_INTEGRITY_ENV,
    LEGACY_SOURCE_INTEGRITY_ENV,
    EXECUTABLE_NAME,
)
from arenyxa.config import AppPaths, AppSettings
from arenyxa.provenance import ProvenanceState, verify_release_attestation
from arenyxa.platform_compat import select_runtime, validate_python_for_runtime
from arenyxa.qt_compat import available_binding_name
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.atomic_io import atomic_write_bytes, atomic_write_json, read_text_limited
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.plugins import PLUGIN_COMPATIBILITY_ERROR_CODES, PluginManifest
from arenyxa.application.runtime_recovery import RuntimeRecoveryService

REPAIR_LEASE_WAIT_SECONDS = 8.0

REPAIR_MARKER_NAME = "repair_in_progress.json"

REPAIR_HANDOFF_GRACE_SECONDS = 30.0

REPAIR_PIP_TIMEOUT_SECONDS = 900.0

REPAIR_OPTIONAL_PIP_TIMEOUT_SECONDS = 300.0

LOGGER = logging.getLogger(__name__)

def _repair_marker_path(data_root: Path) -> Path:
    return Path(data_root).resolve() / "repair" / REPAIR_MARKER_NAME

def _windows_process_running(pid: int, wait_milliseconds: int = 0) -> bool | None:
    










    try:
        import ctypes
        from ctypes import wintypes

        synchronize = 0x00100000
        wait_object_0 = 0x00000000
        wait_timeout = 0x00000102
        error_access_denied = 5
        error_invalid_parameter = 87

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL

        ctypes.set_last_error(0)
        handle = kernel32.OpenProcess(synchronize, False, int(pid))
        if not handle:
            error = ctypes.get_last_error()
            if error == error_invalid_parameter:
                return False
            if error == error_access_denied:
                                                                                     
                return True
            return None
        try:
            result = int(
                kernel32.WaitForSingleObject(handle, max(0, int(wait_milliseconds)))
            )
        finally:
            kernel32.CloseHandle(handle)
        if result == wait_object_0:
            return False
        if result == wait_timeout:
            return True
        return None
    except (AttributeError, OSError, TypeError, ValueError):
        return None

def _process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        state = _windows_process_running(pid)
                                                                                            
                                                                                             
        return True if state is None else state
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
                                                               
        return True
    except OSError:
        return False
    return True

def _load_repair_marker(data_root: Path) -> Optional[dict[str, Any]]:
    path = _repair_marker_path(data_root)
    try:
        payload = json.loads(read_text_limited(path, 64 * 1024, encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload

def repair_worker_active(data_root: Path) -> bool:
    





    path = _repair_marker_path(data_root)
    marker = _load_repair_marker(data_root)
    if marker is None:
        return False
    try:
        owner_pid = int(marker.get("owner_pid", 0))
    except (TypeError, ValueError):
        owner_pid = 0
    state = str(marker.get("state", "active"))
    if _process_is_running(owner_pid):
        return True

                                                                                             
                                                                                            
                                                                           
    if state == "handoff":
        try:
            age = max(0.0, time.time() - float(marker.get("created_epoch", 0.0)))
        except (TypeError, ValueError):
            age = REPAIR_HANDOFF_GRACE_SECONDS + 1.0
        if age <= REPAIR_HANDOFF_GRACE_SECONDS:
            return True

                                                                                          
                                                                                         
    latest = _load_repair_marker(data_root)
    if latest == marker:
        try:
            path.unlink(missing_ok=True)
        except OSError:
                                                                                               
                                                                                              
            return True
    else:
        return repair_worker_active(data_root)
    return False

def _write_repair_marker(data_root: Path, owner_pid: int, token: str, state: str) -> Path:
    path = _repair_marker_path(data_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        path,
        {
            "owner_pid": int(owner_pid),
            "token": str(token),
            "state": str(state),
            "created_epoch": time.time(),
        },
        mode=stat.S_IRUSR | stat.S_IWUSR,
    )
    return path

def clear_repair_marker(data_root: Path, token: Optional[str] = None) -> None:
    path = _repair_marker_path(data_root)
    if token is not None:
        marker = _load_repair_marker(data_root)
        if marker is None or str(marker.get("token", "")) != str(token):
            return
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        LOGGER.warning("Failed to clear Repair Center marker %s: %s", path, exc)

from arenyxa.repair_models import (
    RepairCategory, CATEGORY_LABELS, fault_fingerprint, RepairFinding, HealthReport,
    RepairPlan, RepairActionResult, RepairResult, _utc_now,
)
from arenyxa.repair_diagnostics import append_feature_integration_findings

def installation_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[2]

def source_mode() -> bool:
    return not bool(getattr(sys, "frozen", False))

def repair_resource(name: str) -> Path:
    
    candidates = [Path(__file__).resolve().parent / "resources" / name]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "arenyxa" / "resources" / name)
        candidates.append(Path(meipass) / "arenyxa" / "resources" / name)
    if getattr(sys, "frozen", False):
        candidates.append(Path(sys.executable).resolve().parent / "_internal" / "arenyxa" / "resources" / name)
        candidates.append(Path(sys.executable).resolve().parent / "_internal" / "arenyxa" / "resources" / name)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]

def _packaged_repair_artifacts(install_root: Path, data_root: Path | None = None) -> tuple[Path, Path]:
    installed_manifest = install_root / "repair" / "install_manifest.json"
    installed_payload = install_root / "repair" / "recovery_payload.zip"
    if installed_manifest.is_file() and installed_payload.is_file():
        return installed_manifest, installed_payload
    if data_root is not None:
        known_good = data_root / "repair" / "known_good"
        return known_good / "install_manifest.json", known_good / "recovery_payload.zip"
    return installed_manifest, installed_payload

def _validate_packaged_recovery(manifest_path: Path, payload_path: Path, *, deep: bool = True) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise FileNotFoundError(f"install_manifest.json 缺失: {manifest_path}")
    if not payload_path.is_file():
        raise FileNotFoundError(f"recovery_payload.zip 缺失: {payload_path}")
    manifest = json.loads(read_text_limited(manifest_path, 32 * 1024 * 1024, encoding="utf-8"))
    recovery = dict(manifest.get("recovery_payload", {}))
    expected = str(recovery.get("sha256", ""))
    expected_size = int(recovery.get("size", -1))
    if not expected:
        raise ValueError("recovery payload SHA-256 is missing from manifest")
    if expected_size >= 0 and payload_path.stat().st_size != expected_size:
        raise ValueError("recovery_payload.zip size mismatch")
    if deep:
        if _sha256(payload_path) != expected:
            raise ValueError("recovery_payload.zip SHA-256 不匹配")
        with zipfile.ZipFile(payload_path, "r") as archive:
            bad = archive.testzip()
            if bad is not None:
                raise zipfile.BadZipFile(f"recovery payload CRC failed: {bad}")
    return manifest

def ensure_known_good_seed(paths: AppPaths) -> None:
    
    known_good = paths.root / "repair" / "known_good"
    try:
        known_good.mkdir(parents=True, exist_ok=True)
        if getattr(sys, "frozen", False):
            install_root = installation_root()
            attestation_path = install_root / "repair" / "release_attestation.json"
            if attestation_path.is_file():
                provenance = verify_release_attestation(install_root, deep_files=False)
                if provenance.state not in {ProvenanceState.VERIFIED_OFFICIAL, ProvenanceState.VERIFIED_COMMUNITY}:
                                                                                                    
                    return
            manifest_path, payload_path = _packaged_repair_artifacts(install_root)
            manifest = _validate_packaged_recovery(manifest_path, payload_path, deep=False)
            recovery = dict(manifest.get("recovery_payload", {}))
            expected = str(recovery.get("sha256", ""))
            expected_size = int(recovery.get("size", -1))
            target = known_good / "recovery_payload.zip"
            cached_manifest = known_good / "install_manifest.json"
            cache_current = False
            if target.is_file() and cached_manifest.is_file():
                try:
                    cached = json.loads(read_text_limited(cached_manifest, 32 * 1024 * 1024, encoding="utf-8"))
                    cached_hash = str(dict(cached.get("recovery_payload", {})).get("sha256", ""))
                    cache_current = cached_hash == expected and (expected_size < 0 or target.stat().st_size == expected_size)
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    cache_current = False
            if not cache_current:
                                                                                            
                _validate_packaged_recovery(manifest_path, payload_path, deep=True)
                temporary = target.with_suffix(".tmp")
                shutil.copy2(payload_path, temporary)
                temporary.replace(target)
                shutil.copy2(manifest_path, cached_manifest)
            attestation_path = install_root / "repair" / "release_attestation.json"
            if attestation_path.is_file():
                                                                                                
                shutil.copy2(attestation_path, known_good / "release_attestation.json")
            return

        seed = repair_resource("repair_seed.zip")
        manifest_path = repair_resource("repair_manifest.json")
        if not seed.is_file() or not manifest_path.is_file():
            return
        manifest = json.loads(read_text_limited(manifest_path, 32 * 1024 * 1024, encoding="utf-8"))
        expected = str(manifest.get("seed_sha256", ""))
        if not expected or _sha256(seed) != expected:
            return
        with zipfile.ZipFile(seed, "r") as archive:
            if archive.testzip() is not None:
                return
        target = known_good / "repair_seed.zip"
        if not target.is_file() or _sha256(target) != expected:
            temporary = target.with_suffix(".tmp")
            shutil.copy2(seed, temporary)
            temporary.replace(target)
        shutil.copy2(manifest_path, known_good / "repair_manifest.json")
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError):
        return

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def _safe_relative(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    base = root.resolve()
    try:
        return resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError(f"Path escapes repair root: {resolved}") from exc

def _directory_size(root: Path, limit: int = 3 * 1024 * 1024 * 1024) -> int:
    total = 0
    if not root.exists():
        return 0
    try:
        for path in root.rglob("*"):
            try:
                if path.is_file() and not path.is_symlink():
                    total += path.stat().st_size
                    if total >= limit:
                        return total
            except OSError:
                continue
    except OSError:
        return total
    return total

def _wait_for_parent(pid: int, timeout_seconds: float) -> None:
    if pid <= 0 or pid == os.getpid():
        return
    deadline = time.monotonic() + timeout_seconds
    if os.name == "nt":
        remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
        state = _windows_process_running(pid, remaining_ms)
        if state is False:
            return
                                                                                                
                                                                                                 
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
        return
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except (OSError, ProcessLookupError):
            return
        time.sleep(0.15)

