from __future__ import annotations

"""Phase 3 reliability and resource-governance primitives.

The module intentionally stays independent from presentation and persistence.  Runtime services
can consume these policies, tests can inject deterministic snapshots, and later Enterprise/
Server phases can reuse the same semantics instead of inventing a second resource model.
"""

import errno
import math
import os
import shutil
import statistics
import threading
import time
from collections import Counter, deque
from dataclasses import asdict, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from arenyxa.compat import dataclass
from arenyxa.domain.errors import ArenyxaError


class FailureCategory(str, Enum):
    TRANSIENT = "transient"
    RECOVERABLE = "recoverable"
    CONFIGURATION = "configuration"
    PERMISSION = "permission"
    CORRUPTION = "corruption"
    FATAL = "fatal"


@dataclass(frozen=True, slots=True)
class FailureDiagnosis:
    category: FailureCategory
    code: str
    retryable: bool
    safe_to_resume: bool
    terminal: bool
    reason: str
    suggested_actions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["category"] = self.category.value
        return payload


class RecoveryTaxonomy:
    






    _TRANSIENT_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
    _PERMISSION_STATUS = frozenset({401, 403})
    _TRANSIENT_ERRNO = frozenset(
        value
        for value in (
            getattr(errno, "EAGAIN", None),
            getattr(errno, "EWOULDBLOCK", None),
            getattr(errno, "EINTR", None),
            getattr(errno, "ETIMEDOUT", None),
            getattr(errno, "ECONNRESET", None),
            getattr(errno, "ECONNABORTED", None),
            getattr(errno, "ENETRESET", None),
            getattr(errno, "ENETDOWN", None),
            getattr(errno, "ENETUNREACH", None),
            getattr(errno, "EHOSTUNREACH", None),
        )
        if isinstance(value, int)
    )
    _RECOVERABLE_ERRNO = frozenset(
        value
        for value in (
            getattr(errno, "ENOSPC", None),
            getattr(errno, "EDQUOT", None),
            getattr(errno, "EMFILE", None),
            getattr(errno, "ENFILE", None),
        )
        if isinstance(value, int)
    )
    _CORRUPTION_MARKERS = (
        "database disk image is malformed",
        "file is not a database",
        "database corruption",
        "checksum mismatch",
        "hash mismatch",
        "integrity check failed",
        "malformed database schema",
    )

    @staticmethod
    def _normalise_code(value: str | None) -> str:
        return str(value or "UNCLASSIFIED").strip().upper().replace("-", "_") or "UNCLASSIFIED"

    @classmethod
    def classify(
        cls,
        error: BaseException | None = None,
        *,
        error_code: str | None = None,
        status: int | None = None,
        persisted_data: bool = False,
    ) -> FailureDiagnosis:
        code = cls._normalise_code(error_code or getattr(error, "code", None))
        context = getattr(error, "context", None)
        if status is None and isinstance(context, Mapping):
            raw_status = context.get("status")
            if isinstance(raw_status, int):
                status = raw_status
        message = str(error or "").casefold()

        if status in cls._PERMISSION_STATUS or isinstance(error, PermissionError) or any(
            marker in code for marker in ("PERMISSION", "FORBIDDEN", "UNAUTHORIZED", "AUTH_DENIED", "ACCESS_DENIED")
        ):
            return FailureDiagnosis(
                FailureCategory.PERMISSION,
                code,
                False,
                False,
                True,
                "The operation was denied by an authorization or operating-system boundary.",
                ("verify credentials/capability", "do not retry without a changed authorization context"),
            )

        if any(marker in message for marker in cls._CORRUPTION_MARKERS) or any(
            marker in code for marker in ("CORRUPT", "INTEGRITY", "CHECKSUM", "MALFORMED_DB")
        ):
            return FailureDiagnosis(
                FailureCategory.CORRUPTION,
                code,
                False,
                False,
                True,
                "Durable state failed an integrity/corruption check.",
                ("stop mutation", "preserve evidence", "use verified repair/restore path"),
            )

        if isinstance(error, OSError):
            err_no = getattr(error, "errno", None)
            if err_no in cls._RECOVERABLE_ERRNO:
                return FailureDiagnosis(
                    FailureCategory.RECOVERABLE,
                    code,
                    False,
                    True,
                    True,
                    "A local resource limit interrupted progress; the last durable checkpoint can remain valid.",
                    ("restore local capacity", "resume from the last durable checkpoint when supported"),
                )
            if err_no in cls._TRANSIENT_ERRNO:
                return FailureDiagnosis(
                    FailureCategory.TRANSIENT,
                    code,
                    True,
                    True,
                    False,
                    "The operating system reported a transient I/O or network condition.",
                    ("bounded retry with backoff",),
                )

        if status in cls._TRANSIENT_STATUS or isinstance(error, (TimeoutError, ConnectionError)) or any(
            marker in code for marker in ("TIMEOUT", "RATE_LIMIT", "TEMPORARY", "TRANSIENT", "CONNECTION_RESET")
        ):
            return FailureDiagnosis(
                FailureCategory.TRANSIENT,
                code,
                True,
                True,
                False,
                "The failure is likely temporary and may be retried only within the operation's retry budget.",
                ("bounded retry", "honor Retry-After/backoff", "preserve cancellation"),
            )

        if any(
            marker in code
            for marker in (
                "CONFIG",
                "SETTING",
                "INVALID",
                "UNSUPPORTED",
                "SCHEMA",
                "MISSING_REQUIRED",
                "MANIFEST",
            )
        ) or (isinstance(error, ValueError) and not persisted_data):
            return FailureDiagnosis(
                FailureCategory.CONFIGURATION,
                code,
                False,
                False,
                True,
                "Input or configuration is invalid and must be corrected before execution.",
                ("reject before side effects", "surface the invalid field/contract"),
            )

        if any(marker in code for marker in ("INTERRUPTED", "CHECKPOINT", "DISK_FULL", "RESOURCE_PRESSURE")):
            return FailureDiagnosis(
                FailureCategory.RECOVERABLE,
                code,
                False,
                True,
                True,
                "Execution stopped at a defined recovery boundary and may be resumed after the cause is removed.",
                ("restore the required resource", "validate checkpoint", "resume explicitly"),
            )

        if isinstance(error, ArenyxaError) and error.code == "RUN_CANCELLED":
            return FailureDiagnosis(
                FailureCategory.RECOVERABLE,
                code,
                False,
                True,
                True,
                "Execution was cooperatively cancelled at a checkpoint.",
                ("resume only through an explicit supported recovery flow",),
            )

        return FailureDiagnosis(
            FailureCategory.FATAL,
            code,
            False,
            False,
            True,
            "The failure is not known to be safe for automatic retry or recovery.",
            ("finalize owned resources", "preserve diagnostics", "require explicit investigation"),
        )

    @classmethod
    def may_retry(
        cls,
        diagnosis: FailureDiagnosis,
        *,
        attempt: int,
        max_attempts: int,
        idempotent: bool,
    ) -> bool:
        return bool(
            diagnosis.category is FailureCategory.TRANSIENT
            and diagnosis.retryable
            and idempotent
            and max_attempts > 0
            and 0 <= attempt < max_attempts
        )


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    

    max_request_concurrency: int = 8
    max_worker_count: int = 4
    max_browser_instances: int = 4
    cpu_soft_percent: float = 88.0
    cpu_critical_percent: float = 97.0
    memory_soft_percent: float = 82.0
    memory_critical_percent: float = 92.0
    min_free_disk_bytes: int = 512 * 1024 * 1024
    critical_free_disk_bytes: int = 128 * 1024 * 1024

    def normalized(self) -> "ResourceLimits":
        requests = max(1, min(256, int(self.max_request_concurrency)))
        workers = max(1, min(128, int(self.max_worker_count)))
        browsers = max(0, min(64, int(self.max_browser_instances)))
        cpu_soft = max(10.0, min(99.0, float(self.cpu_soft_percent)))
        cpu_critical = max(cpu_soft, min(100.0, float(self.cpu_critical_percent)))
        memory_soft = max(10.0, min(99.0, float(self.memory_soft_percent)))
        memory_critical = max(memory_soft, min(100.0, float(self.memory_critical_percent)))
        critical_disk = max(0, int(self.critical_free_disk_bytes))
        soft_disk = max(critical_disk, int(self.min_free_disk_bytes))
        return ResourceLimits(
            requests,
            workers,
            browsers,
            cpu_soft,
            cpu_critical,
            memory_soft,
            memory_critical,
            soft_disk,
            critical_disk,
        )


@dataclass(frozen=True, slots=True)
class ResourceSnapshot:
    sampled_at: float
    cpu_percent: float | None
    memory_percent: float | None
    process_rss_bytes: int | None
    available_memory_bytes: int | None
    disk_free_bytes: int | None
    active_browser_instances: int = 0
    active_workers: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class SystemResourceProbe:
    

    def __init__(self, data_root: Path) -> None:
        self.data_root = Path(data_root)
        self._process: Any = None
        self._psutil: Any = None
        self._lock = threading.Lock()
        try:
            import psutil                

            self._psutil = psutil
            self._process = psutil.Process(os.getpid())
                                                                                            
                                                                                   
            psutil.cpu_percent(None)
        except Exception:
            self._psutil = None
            self._process = None

    def sample(self, *, active_browser_instances: int = 0, active_workers: int = 0) -> ResourceSnapshot:
        cpu: float | None = None
        memory: float | None = None
        rss: int | None = None
        available: int | None = None
        with self._lock:
            if self._psutil is not None and self._process is not None:
                try:
                    cpu = float(self._psutil.cpu_percent(None))
                    rss = int(self._process.memory_info().rss)
                    vm = self._psutil.virtual_memory()
                    memory = float(vm.percent)
                    available = int(vm.available)
                except Exception:
                                                                             
                    cpu = memory = None
                    rss = available = None
        try:
            disk_free = int(shutil.disk_usage(self.data_root).free)
        except (OSError, ValueError):
            disk_free = None
        return ResourceSnapshot(
            sampled_at=time.monotonic(),
            cpu_percent=cpu,
            memory_percent=memory,
            process_rss_bytes=rss,
            available_memory_bytes=available,
            disk_free_bytes=disk_free,
            active_browser_instances=max(0, int(active_browser_instances)),
            active_workers=max(0, int(active_workers)),
        )


@dataclass(frozen=True, slots=True)
class ResourceDecision:
    pressure: str
    request_ceiling: int
    worker_ceiling: int
    browser_ceiling: int
    admit_new_runs: bool
    admit_new_browser: bool
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResourceGovernor:
    






    def __init__(self, limits: ResourceLimits) -> None:
        self.limits = limits.normalized()
        self._lock = threading.RLock()
        self._request_ceiling = self.limits.max_request_concurrency
        self._worker_ceiling = self.limits.max_worker_count
        self._healthy_streak = 0
        self._last = ResourceDecision(
            "normal",
            self._request_ceiling,
            self._worker_ceiling,
            self.limits.max_browser_instances,
            True,
            True,
            (),
        )

    @staticmethod
    def _at_least(value: float | None, threshold: float) -> bool:
        return value is not None and math.isfinite(value) and value >= threshold

    def evaluate(self, snapshot: ResourceSnapshot) -> ResourceDecision:
        with self._lock:
            limits = self.limits
            critical: list[str] = []
            soft: list[str] = []
            if self._at_least(snapshot.cpu_percent, limits.cpu_critical_percent):
                critical.append("cpu-critical")
            elif self._at_least(snapshot.cpu_percent, limits.cpu_soft_percent):
                soft.append("cpu-high")
            if self._at_least(snapshot.memory_percent, limits.memory_critical_percent):
                critical.append("memory-critical")
            elif self._at_least(snapshot.memory_percent, limits.memory_soft_percent):
                soft.append("memory-high")
            if snapshot.disk_free_bytes is not None:
                if snapshot.disk_free_bytes <= limits.critical_free_disk_bytes:
                    critical.append("disk-critical")
                elif snapshot.disk_free_bytes <= limits.min_free_disk_bytes:
                    soft.append("disk-low")
            if limits.max_browser_instances >= 0 and snapshot.active_browser_instances >= limits.max_browser_instances > 0:
                soft.append("browser-saturated")

            if critical:
                self._healthy_streak = 0
                self._request_ceiling = max(1, min(self._request_ceiling, max(1, limits.max_request_concurrency // 4)))
                self._worker_ceiling = max(1, min(self._worker_ceiling, max(1, limits.max_worker_count // 2)))
                disk_critical = "disk-critical" in critical
                decision = ResourceDecision(
                    "critical",
                    self._request_ceiling,
                    self._worker_ceiling,
                    0 if disk_critical else max(0, min(limits.max_browser_instances, 1)),
                    not disk_critical,
                    False,
                    tuple(critical),
                )
            elif soft:
                self._healthy_streak = 0
                self._request_ceiling = max(1, min(self._request_ceiling, max(1, (limits.max_request_concurrency + 1) // 2)))
                self._worker_ceiling = max(1, min(self._worker_ceiling, max(1, (limits.max_worker_count + 1) // 2)))
                decision = ResourceDecision(
                    "warning",
                    self._request_ceiling,
                    self._worker_ceiling,
                    max(0, min(limits.max_browser_instances, max(1, limits.max_browser_instances // 2))) if limits.max_browser_instances else 0,
                    True,
                    "browser-saturated" not in soft,
                    tuple(soft),
                )
            else:
                self._healthy_streak += 1
                                                                                            
                                                                                             
                if self._healthy_streak >= 3:
                    self._request_ceiling = min(limits.max_request_concurrency, self._request_ceiling + 1)
                    self._worker_ceiling = min(limits.max_worker_count, self._worker_ceiling + 1)
                    self._healthy_streak = 0
                decision = ResourceDecision(
                    "normal",
                    self._request_ceiling,
                    self._worker_ceiling,
                    limits.max_browser_instances,
                    True,
                    True,
                    (),
                )
            self._last = decision
            return decision

    def snapshot(self) -> ResourceDecision:
        with self._lock:
            return self._last


@dataclass(slots=True)
class ResourceLease:
    pool: "ResourceLeasePool"
    _released: bool = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self.pool._release()

    def __enter__(self) -> "ResourceLease":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.release()


class ResourceLeasePool:
    

    def __init__(self, maximum: int) -> None:
        self.maximum = max(0, int(maximum))
        self._limit = self.maximum
        self._active = 0
        self._lock = threading.Lock()

    def try_acquire(self) -> ResourceLease | None:
        with self._lock:
            if self._active >= self._limit:
                return None
            self._active += 1
        return ResourceLease(self)

    def acquire(self, *, code: str = "RESOURCE_LIMIT", message: str = "资源预算已达到上限。") -> ResourceLease:
        lease = self.try_acquire()
        if lease is None:
            raise ArenyxaError(code, message, domain="RESOURCE", context={"limit": self.limit(), "active": self.active_count()})
        return lease

    def _release(self) -> None:
        with self._lock:
            self._active = max(0, self._active - 1)

    def set_limit(self, limit: int) -> int:
        with self._lock:
            self._limit = max(0, min(self.maximum, int(limit)))
            return self._limit

    def limit(self) -> int:
        with self._lock:
            return self._limit

    def active_count(self) -> int:
        with self._lock:
            return self._active


@dataclass(frozen=True, slots=True)
class PreflightRequest:
    target_count: int
    average_response_bytes: int = 512 * 1024
    browser_ratio: float = 0.0
    request_concurrency: int = 8
    expected_latency_ms: float = 800.0
    records_per_target: float = 1.0


@dataclass(frozen=True, slots=True)
class PreflightEstimate:
    target_count: int
    estimated_download_bytes: int
    estimated_disk_bytes_low: int
    estimated_disk_bytes_high: int
    estimated_peak_ram_bytes: int
    estimated_seconds_low: float
    estimated_seconds_high: float
    browser_target_count: int
    risk_level: str
    risks: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PreflightEstimator:
    






    def __init__(self, limits: ResourceLimits | None = None) -> None:
        self.limits = (limits or ResourceLimits()).normalized()

    def estimate(
        self,
        request: PreflightRequest,
        *,
        resource_snapshot: ResourceSnapshot | None = None,
    ) -> PreflightEstimate:
        count = max(0, int(request.target_count))
        avg = max(1, min(1024 * 1024 * 1024, int(request.average_response_bytes)))
        browser_ratio = max(0.0, min(1.0, float(request.browser_ratio)))
        concurrency = max(1, min(256, int(request.request_concurrency)))
        latency_ms = max(1.0, min(600_000.0, float(request.expected_latency_ms)))
        records_per_target = max(0.0, min(100_000.0, float(request.records_per_target)))
        download = count * avg
        browser_count = int(math.ceil(count * browser_ratio))

                                                                                              
                                                                               
        extracted_low = int(download * 0.08 * max(0.5, min(4.0, records_per_target)))
        extracted_high = int(download * 0.70 * max(1.0, min(8.0, records_per_target)))
        disk_low = int(download * 0.10) + extracted_low + count * 256
        disk_high = int(download * 1.15) + extracted_high + count * 2048 + 64 * 1024 * 1024

        concurrent_payload = avg * concurrency
        browser_ram = min(browser_count, max(1, concurrency)) * 220 * 1024 * 1024
        peak_ram = int(192 * 1024 * 1024 + concurrent_payload * 2.2 + browser_ram)

        network_seconds = (count * latency_ms / 1000.0) / concurrency
        browser_multiplier = 1.0 + browser_ratio * 4.0
        seconds_low = max(0.0, network_seconds * 0.70 * browser_multiplier)
        seconds_high = max(seconds_low, network_seconds * 2.4 * browser_multiplier + count * 0.004)

        risks: list[str] = []
        if count > 500:
            risks.append("large-target-set")
        if browser_ratio >= 0.35 and browser_count >= 20:
            risks.append("browser-heavy")
        if peak_ram >= 4 * 1024 * 1024 * 1024:
            risks.append("high-peak-memory")
        if resource_snapshot is not None:
            if resource_snapshot.disk_free_bytes is not None and disk_high >= int(resource_snapshot.disk_free_bytes * 0.80):
                risks.append("disk-capacity")
            if resource_snapshot.available_memory_bytes is not None and peak_ram >= int(resource_snapshot.available_memory_bytes * 0.80):
                risks.append("memory-capacity")
        severity = "low"
        if risks:
            severity = "medium"
        if "disk-capacity" in risks or "memory-capacity" in risks or len(risks) >= 3:
            severity = "high"
        return PreflightEstimate(
            count,
            download,
            max(0, disk_low),
            max(disk_low, disk_high),
            max(0, peak_ram),
            round(seconds_low, 3),
            round(seconds_high, 3),
            browser_count,
            severity,
            tuple(risks),
        )


@dataclass(frozen=True, slots=True)
class PerformanceSample:
    timestamp: float
    completed: int = 0
    failed: int = 0
    retries: int = 0
    http_429: int = 0
    latency_ms: float | None = None
    local_processing_ms: float | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    disk_free_bytes: int | None = None
    request_limit: int = 1
    request_active: int = 0
    request_waiting: int = 0
    browser_active: int = 0
    browser_limit: int = 0


@dataclass(frozen=True, slots=True)
class PerformanceExplanation:
    primary: str
    confidence: float
    throughput_per_second: float
    evidence: tuple[str, ...]
    contributors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PerformanceIntelligence:
    

    @staticmethod
    def _p95(values: Sequence[float]) -> float:
        clean = sorted(value for value in values if math.isfinite(value) and value >= 0.0)
        if not clean:
            return 0.0
        index = min(len(clean) - 1, int(math.ceil(len(clean) * 0.95)) - 1)
        return float(clean[index])

    def explain(self, samples: Iterable[PerformanceSample]) -> PerformanceExplanation:
        items = list(samples)[-256:]
        if not items:
            return PerformanceExplanation("insufficient-data", 0.0, 0.0, ("no telemetry samples",), ())
        duration = max(0.001, max(item.timestamp for item in items) - min(item.timestamp for item in items))
        completed = sum(max(0, item.completed) for item in items)
        failed = sum(max(0, item.failed) for item in items)
        retries = sum(max(0, item.retries) for item in items)
        throttled = sum(max(0, item.http_429) for item in items)
        throughput = completed / duration if len(items) > 1 else float(completed)
        latency = self._p95([float(item.latency_ms) for item in items if item.latency_ms is not None])
        local = self._p95([float(item.local_processing_ms) for item in items if item.local_processing_ms is not None])
        max_cpu = max((float(item.cpu_percent) for item in items if item.cpu_percent is not None), default=0.0)
        max_memory = max((float(item.memory_percent) for item in items if item.memory_percent is not None), default=0.0)
        min_disk = min((int(item.disk_free_bytes) for item in items if item.disk_free_bytes is not None), default=None)
        saturated = sum(1 for item in items if item.request_limit > 0 and item.request_active >= item.request_limit)
        browser_saturated = sum(
            1 for item in items if item.browser_limit > 0 and item.browser_active >= item.browser_limit
        )

        scores: Counter[str] = Counter()
        evidence: dict[str, list[str]] = {}

        def add(kind: str, score: float, detail: str) -> None:
            scores[kind] += max(0.0, score)
            evidence.setdefault(kind, []).append(detail)

        if throttled:
            add("rate-limit", min(10.0, 4.0 + throttled), f"HTTP 429 observed {throttled} time(s)")
        if latency >= 1500:
            add("origin-latency", min(8.0, latency / 750.0), f"network latency p95 {latency:.0f} ms")
        if max_cpu >= 88:
            add("cpu-pressure", min(8.0, max_cpu / 15.0), f"CPU reached {max_cpu:.1f}%")
        if max_memory >= 82:
            add("memory-pressure", min(8.0, max_memory / 15.0), f"memory reached {max_memory:.1f}%")
        if min_disk is not None and min_disk <= 512 * 1024 * 1024:
            add("disk-pressure", 7.0, f"free disk fell to {min_disk / (1024 * 1024):.0f} MiB")
        if retries >= max(3, completed // 5):
            add("retry-amplification", min(8.0, retries / max(1.0, completed / 5.0)), f"{retries} retries for {completed} completions")
        if local >= 25:
            add("local-processing", min(7.0, local / 20.0), f"parse/extract p95 {local:.1f} ms")
        if saturated >= max(2, len(items) // 3):
            add("worker-saturation", 5.0, f"request budget saturated in {saturated}/{len(items)} samples")
        if browser_saturated >= max(2, len(items) // 3):
            add("browser-saturation", 5.0, f"browser budget saturated in {browser_saturated}/{len(items)} samples")
        if failed > completed and failed >= 3:
            add("failure-pressure", 4.0, f"{failed} failed versus {completed} completed")

        if not scores:
            return PerformanceExplanation(
                "healthy-or-unexplained",
                0.35,
                round(throughput, 3),
                (f"latency p95 {latency:.0f} ms", f"local processing p95 {local:.1f} ms"),
                (),
            )
        ranked = scores.most_common()
        primary, top_score = ranked[0]
        total_score = sum(value for _, value in ranked) or 1.0
        confidence = max(0.35, min(0.99, top_score / total_score + 0.25))
        contributors = tuple(name for name, _ in ranked[1:4])
        return PerformanceExplanation(
            primary,
            round(confidence, 3),
            round(throughput, 3),
            tuple(evidence.get(primary, ())),
            contributors,
        )


class BoundedPerformanceHistory:
    

    def __init__(self, capacity: int = 256) -> None:
        self._items: deque[PerformanceSample] = deque(maxlen=max(16, min(4096, int(capacity))))
        self._lock = threading.Lock()

    def append(self, sample: PerformanceSample) -> None:
        with self._lock:
            self._items.append(sample)

    def snapshot(self) -> tuple[PerformanceSample, ...]:
        with self._lock:
            return tuple(self._items)
