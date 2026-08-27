from __future__ import annotations

import ctypes
import os
import platform
from arenyxa.compat import dataclass


@dataclass(frozen=True, slots=True)
class DeviceCapability:
    logical_cpus: int
    memory_gb: float | None
    recommended_mode: str


@dataclass(frozen=True, slots=True)
class PerformancePolicy:
    






    requested_mode: str
    mode: str
    device: DeviceCapability
    runner_workers: int
    request_workers: int
    per_host_workers: int
    runner_progress_interval_ms: int
    result_write_batch_size: int
    background_workers: int
    capture_queue_capacity: int
    capture_flush_size: int
    result_page_size: int
    network_event_limit: int
    network_history_limit: int
    network_ui_refresh_ms: int
    status_refresh_ms: int
    animation_hz_cap: int
    glass_specular: bool

    @classmethod
    def resolve(
        cls,
        requested_mode: str,
        configured_workers: int = 4,
        configured_request_workers: int = 8,
        configured_per_host_workers: int = 4,
    ) -> "PerformancePolicy":
        device = detect_device_capability()
        requested = requested_mode if requested_mode in {"auto", "quality", "balanced", "efficiency"} else "auto"
        if requested == "auto":
            mode = device.recommended_mode
        elif requested == "quality":
            mode = "high"
        elif requested == "balanced" and device.recommended_mode == "efficiency":
                                                                                      
                                                                                     
                                                                                   
            mode = "efficiency"
        else:
            mode = requested
        workers = max(1, int(configured_workers))
        request_workers = max(1, int(configured_request_workers))
        per_host_workers = max(1, min(int(configured_per_host_workers), request_workers))
        if mode == "efficiency":
            return cls(
                requested, mode, device,
                runner_workers=min(workers, 2),
                request_workers=min(request_workers, 4),
                per_host_workers=min(per_host_workers, 2),
                runner_progress_interval_ms=350,
                result_write_batch_size=32,
                background_workers=2,
                capture_queue_capacity=8_000,
                capture_flush_size=900,
                result_page_size=120,
                network_event_limit=5_000,
                network_history_limit=5_000,
                network_ui_refresh_ms=500,
                status_refresh_ms=1_500,
                animation_hz_cap=30,
                glass_specular=False,
            )
        if mode == "balanced":
            return cls(
                requested, mode, device,
                runner_workers=min(workers, 4),
                request_workers=min(request_workers, 8),
                per_host_workers=min(per_host_workers, 4),
                runner_progress_interval_ms=220,
                result_write_batch_size=48,
                background_workers=4,
                capture_queue_capacity=24_000,
                capture_flush_size=700,
                result_page_size=220,
                network_event_limit=10_000,
                network_history_limit=10_000,
                network_ui_refresh_ms=300,
                status_refresh_ms=900,
                animation_hz_cap=60,
                glass_specular=True,
            )
        return cls(
            requested, "high", device,
            runner_workers=workers,
            request_workers=request_workers,
            per_host_workers=per_host_workers,
                                                                                             
                                                                                                
                                                                                            
                                                                                              
            runner_progress_interval_ms=160,
            result_write_batch_size=min(192, max(96, request_workers * 12)),
            background_workers=min(8, max(4, device.logical_cpus)),
            capture_queue_capacity=50_000,
            capture_flush_size=500,
            result_page_size=300,
            network_event_limit=20_000,
            network_history_limit=20_000,
            network_ui_refresh_ms=160,
            status_refresh_ms=500,
            animation_hz_cap=240,
            glass_specular=True,
        )


def detect_device_capability() -> DeviceCapability:
    cpus = max(1, int(os.cpu_count() or 1))
    memory_gb = _total_memory_gb()

                                                                                             
                                                                                            
    if cpus <= 4 or (memory_gb is not None and memory_gb <= 8.5):
        recommended = "efficiency"
    elif cpus <= 8 or (memory_gb is not None and memory_gb <= 16.5):
        recommended = "balanced"
    else:
        recommended = "high"
    return DeviceCapability(cpus, memory_gb, recommended)


def _total_memory_gb() -> float | None:
    try:
        if platform.system() == "Windows":
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            status = MEMORYSTATUSEX()
            status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return float(status.ullTotalPhys) / (1024.0 ** 3)
        if hasattr(os, "sysconf"):
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            if isinstance(pages, int) and isinstance(page_size, int) and pages > 0 and page_size > 0:
                return float(pages * page_size) / (1024.0 ** 3)
    except (AttributeError, OSError, ValueError):
        return None
    return None
