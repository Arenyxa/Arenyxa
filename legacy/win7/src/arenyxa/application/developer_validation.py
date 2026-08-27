from __future__ import annotations

import gc
import json
import math
import tempfile
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from arenyxa.application.export import ExportService
from arenyxa.application.feature_audit import audit_advanced_features
from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.scheduler import ScheduleRule
from arenyxa.application.terminal import TerminalSession
from arenyxa.application.workflows import WorkflowEngine
from arenyxa.compat import UTC, dataclass
from arenyxa.domain.enums import CaptureSource, RunStatus, TaskStatus
from arenyxa.domain.models import (
    CaptureSession,
    FetchResponse,
    FieldSpec,
    NetworkEvent,
    RequestSpec,
    ResultRecord,
    Run,
    Task,
    Workflow,
    WorkflowNode,
)
from arenyxa.infrastructure.atomic_io import atomic_write_text
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.parsers import FieldExtractor, ParserRegistry

ProgressCallback = Callable[[str], None]


@dataclass(slots=True)
class ValidationItem:
    name: str
    status: str
    duration_ms: float
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "duration_ms": round(self.duration_ms, 2),
            "detail": self.detail,
        }


@dataclass(slots=True)
class ValidationReport:
    started_at: str
    duration_seconds: float
    items: list[ValidationItem]

    @property
    def passed(self) -> int:
        return sum(1 for item in self.items if item.status == "passed")

    @property
    def failed(self) -> int:
        return sum(1 for item in self.items if item.status == "failed")

    @property
    def skipped(self) -> int:
        return sum(1 for item in self.items if item.status == "skipped")

    @property
    def healthy(self) -> bool:
        return self.failed == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "healthy": self.healthy,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "passed": self.passed,
            "failed": self.failed,
            "skipped": self.skipped,
            "items": [item.to_dict() for item in self.items],
        }


@dataclass(frozen=True, slots=True)
class StressProfile:
    name: str
    worker_levels: tuple[int, ...]
    operations_per_level: int
    max_duration_seconds: float


STRESS_PROFILES: dict[str, StressProfile] = {
    "quick": StressProfile("quick", (1, 2, 4), 80, 20.0),
    "standard": StressProfile("standard", (1, 2, 4, 8, 12), 240, 90.0),
    "extreme": StressProfile("extreme", (1, 2, 4, 8, 12, 16, 24, 32, 48, 64), 600, 300.0),
}


@dataclass(slots=True)
class StressLevelResult:
    workers: int
    operations: int
    errors: int
    duration_seconds: float
    throughput_ops_per_second: float
    p95_ms: float
    peak_python_memory_mib: float
    first_error: str = ""

    @property
    def stable(self) -> bool:
        return self.errors == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "workers": self.workers,
            "operations": self.operations,
            "errors": self.errors,
            "duration_seconds": round(self.duration_seconds, 3),
            "throughput_ops_per_second": round(self.throughput_ops_per_second, 2),
            "p95_ms": round(self.p95_ms, 2),
                                                                                         
                                                                                           
                                                   
            "peak_python_memory_mib": round(self.peak_python_memory_mib, 2),
            "memory_probe_peak_mib": round(self.peak_python_memory_mib, 2),
            "stable": self.stable,
            "first_error": self.first_error,
        }


@dataclass(slots=True)
class StressReport:
    profile: str
    started_at: str
    duration_seconds: float
    levels: list[StressLevelResult]
    stopped_reason: str

    @property
    def observed_stable_workers(self) -> int:
        stable = [level.workers for level in self.levels if level.stable]
        return max(stable) if stable else 0

    @property
    def first_unstable_workers(self) -> int | None:
        for level in self.levels:
            if not level.stable:
                return level.workers
        return None

    @property
    def peak_throughput_workers(self) -> int:
        stable = [level for level in self.levels if level.stable]
        if not stable:
            return 0
        return max(stable, key=lambda level: level.throughput_ops_per_second).workers

    @property
    def peak_throughput_ops_per_second(self) -> float:
        stable = [level.throughput_ops_per_second for level in self.levels if level.stable]
        return max(stable) if stable else 0.0

    @property
    def recommended_local_workers(self) -> int:
        
        stable = [level for level in self.levels if level.stable]
        if not stable:
            return 0
        peak = max(stable, key=lambda level: level.throughput_ops_per_second)
                                                                                            
                                                                                         
                                                                       
        candidates = [
            level for level in stable
            if level.throughput_ops_per_second >= peak.throughput_ops_per_second * 0.97
            and level.p95_ms <= max(peak.p95_ms * 1.5, peak.p95_ms + 5.0)
        ]
        return min(candidates, key=lambda level: level.workers).workers if candidates else peak.workers

    @property
    def max_p95_ms(self) -> float:
        stable = [level.p95_ms for level in self.levels if level.stable]
        return max(stable) if stable else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
                                                                                                 
                                                                                   
            "workload": "local-persistence-mixed-v2",
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "observed_stable_workers": self.observed_stable_workers,
            "first_unstable_workers": self.first_unstable_workers,
            "peak_throughput_workers": self.peak_throughput_workers,
            "peak_throughput_ops_per_second": round(self.peak_throughput_ops_per_second, 2),
            "recommended_local_workers": self.recommended_local_workers,
            "max_p95_ms": round(self.max_p95_ms, 2),
            "stopped_reason": self.stopped_reason,
            "levels": [level.to_dict() for level in self.levels],
        }


class _LoopbackHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        payload = b'{"value":7,"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _LoopbackServer:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackHandler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, name="arenyxa-validation-http", daemon=True)

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/probe"

    def __enter__(self) -> _LoopbackServer:
        self.thread.start()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


class DeveloperValidationSuite:
    

    def __init__(self, context: object) -> None:
        self.context = context

    def run_all(self, progress: ProgressCallback | None = None) -> ValidationReport:
        started_clock = time.monotonic()
        started_at = datetime.now(UTC).isoformat()
        items: list[ValidationItem] = []
        cases: tuple[tuple[str, Callable[[], str]], ...] = (
            ("runtime-feature-wiring", self._feature_wiring),
            ("current-database-health", self._current_database_health),
            ("atomic-file-write", self._atomic_file_write),
            ("html-json-xml-parsers", self._parsers),
            ("selector-analysis-and-recovery", self._selector),
            ("workflow-engine", self._workflow),
            ("scheduler-rule", self._scheduler),
            ("isolated-database-roundtrip", self._database_roundtrip),
            ("capture-event-persistence", self._capture_roundtrip),
            ("export-csv-json-xlsx", self._export_roundtrip),
            ("loopback-http-client", self._http_loopback),
            ("loopback-run-orchestrator", self._runner_loopback),
            ("terminal-sandbox-boundary", self._terminal_boundary),
            ("data-quality-and-variables", self._nextgen_local),
        )
        for index, (name, case) in enumerate(cases, start=1):
            if progress:
                progress(f"[{index}/{len(cases)}] {name}")
            began = time.perf_counter()
            try:
                detail = case()
            except Exception as exc:                                                                 
                items.append(ValidationItem(name, "failed", (time.perf_counter() - began) * 1000.0, f"{type(exc).__name__}: {exc}"))
            else:
                items.append(ValidationItem(name, "passed", (time.perf_counter() - began) * 1000.0, detail))
        return ValidationReport(started_at, time.monotonic() - started_clock, items)

    def _feature_wiring(self) -> str:
        report = audit_advanced_features(self.context)
        if not report.healthy:
            raise RuntimeError(json.dumps(report.to_dict(), ensure_ascii=False, default=str))
        return f"{report.implemented}/{report.checked} advanced contracts wired"

    def _current_database_health(self) -> str:
        store = self.context.store
        if not store.ping():
            raise RuntimeError("database ping failed")
        result = str(store.quick_check())
        if result.casefold() != "ok":
            raise RuntimeError(f"database quick_check={result}")
        return "ping=ok, quick_check=ok"

    @staticmethod
    def _atomic_file_write() -> str:
        with tempfile.TemporaryDirectory(prefix="arenyxa-validate-atomic-") as raw:
            path = Path(raw) / "state.txt"
            atomic_write_text(path, "stable")
            if path.read_text(encoding="utf-8") != "stable":
                raise RuntimeError("atomic writer content mismatch")
        return "atomic replace roundtrip passed"

    @staticmethod
    def _parsers() -> str:
        samples = (
            FetchResponse("http://127.0.0.1/", "http://127.0.0.1/", 200, {}, b"<html><body><b id='x'>ok</b></body></html>", 1.0, "utf-8", "text/html"),
            FetchResponse("http://127.0.0.1/", "http://127.0.0.1/", 200, {}, b'{"value":7}', 1.0, "utf-8", "application/json"),
            FetchResponse("http://127.0.0.1/", "http://127.0.0.1/", 200, {}, b"<root><value>7</value></root>", 1.0, "utf-8", "application/xml"),
        )
        kinds = [ParserRegistry.parse(sample).kind for sample in samples]
        if kinds != ["html", "json", "xml"]:
            raise RuntimeError(f"unexpected parser kinds: {kinds}")
        document = ParserRegistry.parse(samples[1])
        record, quality = FieldExtractor().extract(document, [FieldSpec("value", "value", data_type="integer")])
        if record.get("value") != 7 or quality:
            raise RuntimeError(f"field extraction mismatch: {record}, {quality}")
        return "html/json/xml + field extraction passed"

    def _selector(self) -> str:
        markup = "<html><body><button id='save' data-testid='save-button'>Save</button></body></html>"
        result = self.context.nextgen.selector.analyze(markup, "#save")
        if int(result.get("matches", 0)) != 1 or not result.get("fingerprint"):
            raise RuntimeError(f"selector result invalid: {result}")
        healed = self.context.nextgen.selector.heal(markup, result["fingerprint"])
        if not healed:
            raise RuntimeError("selector recovery returned no candidates")
        return f"matches=1, recovery_candidates={len(healed)}"

    @staticmethod
    def _workflow() -> str:
        source = WorkflowNode("source", {}, id="source", next_ids=["map"])
        mapper = WorkflowNode("map", {"constants": {"validated": True}}, id="map", next_ids=["sink"])
        sink = WorkflowNode("sink", {}, id="sink")
        result = WorkflowEngine().execute(Workflow("validation", [source, mapper, sink]), [{"value": 7}])
        if result.outputs != [{"value": 7, "validated": True}] or result.errors:
            raise RuntimeError(f"workflow mismatch: {result.outputs}, {result.errors}")
        return "source -> map -> sink passed"

    @staticmethod
    def _scheduler() -> str:
        rule = ScheduleRule(kind="interval", interval_minutes=5, timezone="UTC")
        now = datetime.now(UTC)
        next_run = rule.next_after(now)
        delta = (next_run - now).total_seconds()
        if not 299.0 <= delta <= 301.0:
            raise RuntimeError(f"interval mismatch: {delta}")
        return "UTC interval calculation passed"

    @staticmethod
    def _isolated_store(root: Path) -> SQLiteStore:
        store = SQLiteStore(root / "validation.db")
        store.initialize()
        return store

    def _database_roundtrip(self) -> str:
        with tempfile.TemporaryDirectory(prefix="arenyxa-validate-db-") as raw:
            store = self._isolated_store(Path(raw))
            task = Task("validation-task", [RequestSpec("http://127.0.0.1/")], status=TaskStatus.READY)
            store.save_task(task)
            loaded = store.get_task(task.id)
            if loaded is None or loaded.name != task.name:
                raise RuntimeError("task roundtrip failed")
            if store.quick_check() != "ok":
                raise RuntimeError("isolated database quick_check failed")
        return "task persistence + integrity passed"

    def _capture_roundtrip(self) -> str:
        with tempfile.TemporaryDirectory(prefix="arenyxa-validate-capture-") as raw:
            store = self._isolated_store(Path(raw))
            session = CaptureSession("validation", CaptureSource.HTTP_RUNNER)
            store.save_capture(session)
            event = NetworkEvent(session.id, CaptureSource.HTTP_RUNNER, "http", "response", 64, method="GET", url="http://127.0.0.1/", status=200, host="127.0.0.1")
            written = store.append_network_events([event])
            rows = list(store.iter_network_events(session.id, 10))
            if written != 1 or len(rows) != 1:
                raise RuntimeError(f"capture roundtrip mismatch: written={written}, rows={len(rows)}")
        return "synthetic capture event persisted"

    def _export_roundtrip(self) -> str:
        with tempfile.TemporaryDirectory(prefix="arenyxa-validate-export-") as raw:
            root = Path(raw)
            store = self._isolated_store(root)
            task = Task("export-task", [RequestSpec("http://127.0.0.1/")], status=TaskStatus.READY)
            store.save_task(task)
            run = Run(task.id, task.to_dict(), status=RunStatus.COMPLETED)
            store.save_run(run)
            store.append_results([ResultRecord(task.id, run.id, "http://127.0.0.1/", {"value": 7})])
            service = ExportService(store)
            for extension in ("csv", "json", "xlsx"):
                destination = root / f"result.{extension}"
                count = service.export_run(run.id, destination, extension)
                if count != 1 or not destination.is_file() or destination.stat().st_size <= 0:
                    raise RuntimeError(f"{extension} export failed")
        return "csv/json/xlsx exports passed"

    @staticmethod
    def _http_loopback() -> str:
        with _LoopbackServer() as server:
            response = HttpFetcher(max_response_bytes=1024 * 1024).fetch(RequestSpec(server.url, connect_timeout=2.0, read_timeout=2.0))
            if response.status != 200:
                raise RuntimeError(f"loopback status={response.status}")
            payload = json.loads(response.body.decode("utf-8"))
            if payload.get("value") != 7:
                raise RuntimeError(f"loopback payload mismatch: {payload}")
        return "127.0.0.1 HTTP fetch passed"

    @staticmethod
    def _runner_loopback() -> str:
        with tempfile.TemporaryDirectory(prefix="arenyxa-validate-runner-") as raw, _LoopbackServer() as server:
            store = DeveloperValidationSuite._isolated_store(Path(raw))
            runner = RunOrchestrator(store, max_workers=2, max_response_bytes=1024 * 1024, request_workers=2, per_host_workers=2)
            try:
                task = Task("runner-task", [RequestSpec(server.url)], [FieldSpec("value", "value")], status=TaskStatus.READY, parser_hint="json")
                store.save_task(task)
                run = runner.submit(task).future.result(timeout=10.0)
                if run.status != RunStatus.COMPLETED or run.result_count != 1:
                    raise RuntimeError(f"runner status={run.status}, result_count={run.result_count}")
            finally:
                runner.shutdown(wait=True)
        return "loopback collection pipeline passed"

    @staticmethod
    def _terminal_boundary() -> str:
        with tempfile.TemporaryDirectory(prefix="arenyxa-validate-terminal-") as raw:
            root = Path(raw) / "projects"
            nested = root / "inside"
            nested.mkdir(parents=True)
            session = TerminalSession(root)
            session.set_cwd("inside")
            try:
                session.set_cwd("../../outside")
            except PermissionError:
                pass
            else:
                raise RuntimeError("terminal path confinement did not reject escape")
        return "project-root confinement passed"

    def _nextgen_local(self) -> str:
        cleaned = self.context.nextgen.quality.clean([{"name": "  Example  ", "count": "7"}])
        if not cleaned:
            raise RuntimeError("quality clean returned no data")
        resolved = self.context.nextgen.variables.resolve("${project.name}", {"project": {"name": "demo"}})
        if resolved != "demo":
            raise RuntimeError(f"variable resolution mismatch: {resolved}")
        templates = self.context.nextgen.templates.templates()
        if not isinstance(templates, dict) or not templates:
            raise RuntimeError("template library is empty")
        return f"quality/variables/templates passed ({len(templates)} templates)"



@dataclass(frozen=True, slots=True)
class FaultInjectionResult:
    scenario: str
    classification: str
    retry_allowed: bool
    rollback_required: bool
    terminal: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "classification": self.classification,
            "retry_allowed": self.retry_allowed,
            "rollback_required": self.rollback_required,
            "terminal": self.terminal,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class FaultInjectionReport:
    started_at: str
    scenarios: tuple[FaultInjectionResult, ...]

    @property
    def healthy(self) -> bool:
        expected = {name: name for name in ("transient", "recoverable", "configuration", "permission", "corruption", "fatal")}
        return all(expected.get(item.scenario) == item.classification for item in self.scenarios)

    def to_dict(self) -> dict[str, Any]:
        return {"healthy": self.healthy, "started_at": self.started_at, "scenarios": [item.to_dict() for item in self.scenarios]}


class _SyntheticFault(RuntimeError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class DeveloperFaultInjectionSuite:
    

    SCENARIOS: dict[str, tuple[str, BaseException]] = {
        "transient": ("FETCH_TIMEOUT", TimeoutError("synthetic timeout")),
        "recoverable": ("RESOURCE_EXHAUSTED", OSError(28, "synthetic no space left")),
        "configuration": ("TASK_INVALID", _SyntheticFault("synthetic invalid task", "TASK_INVALID")),
        "permission": ("AUTHORIZATION_DENIED", PermissionError("synthetic authorization denial")),
        "corruption": ("DATASET_CORRUPTION", _SyntheticFault("synthetic checksum mismatch", "DATASET_CORRUPTION")),
        "fatal": ("UNKNOWN_SYNTHETIC_FATAL", RuntimeError("synthetic unknown fatal failure")),
    }

    def __init__(self, context: object) -> None:
        self.context = context

    def run(self, scenario: str = "all") -> FaultInjectionReport:
        from arenyxa.application.reliability import FailureCategory, RecoveryTaxonomy
        selected = str(scenario).casefold()
        if selected == "all":
            names = tuple(self.SCENARIOS)
        elif selected in self.SCENARIOS:
            names = (selected,)
        else:
            allowed = ", ".join((*self.SCENARIOS.keys(), "all"))
            raise ValueError(f"unknown fault injection scenario: {scenario}; choose {allowed}")
        taxonomy = RecoveryTaxonomy()
        values: list[FaultInjectionResult] = []
        for name in names:
            code, error = self.SCENARIOS[name]
            diagnosis = taxonomy.classify(error, error_code=code, persisted_data=name in {"recoverable", "corruption"})
            values.append(FaultInjectionResult(
                scenario=name,
                classification=diagnosis.category.value,
                retry_allowed=diagnosis.retryable,
                rollback_required=diagnosis.category in {FailureCategory.RECOVERABLE, FailureCategory.CORRUPTION},
                terminal=diagnosis.terminal,
                reason=diagnosis.reason,
            ))
        report = FaultInjectionReport(datetime.now(UTC).isoformat(), tuple(values))
        if not report.healthy:
            raise RuntimeError("synthetic fault injection produced an unexpected recovery classification")
        return report

class DeveloperStressSuite:
    

    def __init__(self, context: object) -> None:
        self.context = context

    def run(self, profile_name: str = "standard", progress: ProgressCallback | None = None) -> StressReport:
        profile = STRESS_PROFILES.get(profile_name.casefold())
        if profile is None:
            raise ValueError(f"unknown stress profile: {profile_name}; choose quick, standard, or extreme")
        started_at = datetime.now(UTC).isoformat()
        overall_start = time.monotonic()
        levels: list[StressLevelResult] = []
        stopped_reason = "configured safety ceiling reached without an observed instability"
        with tempfile.TemporaryDirectory(prefix="arenyxa-stress-") as raw:
            root = Path(raw)
            store = SQLiteStore(root / "stress.db")
            store.initialize()
            for workers in profile.worker_levels:
                if time.monotonic() - overall_start >= profile.max_duration_seconds:
                    stopped_reason = "profile time budget reached"
                    break
                if progress:
                    progress(f"stress level: {workers} workers")
                result = self._run_level(store, root, workers, profile.operations_per_level)
                levels.append(result)
                if not result.stable:
                    stopped_reason = f"first observable instability at {workers} workers"
                    break
                if store.quick_check() != "ok":
                    levels[-1].errors += 1
                    levels[-1].first_error = "SQLite quick_check failed after level"
                    stopped_reason = f"database integrity failure after {workers} workers"
                    break
        return StressReport(profile.name, started_at, time.monotonic() - overall_start, levels, stopped_reason)

    def _run_level(self, store: SQLiteStore, root: Path, workers: int, operations: int) -> StressLevelResult:
        if tracemalloc.is_tracing():
                                                                                              
                                                                                                 
                                                                                                
                                                                   
            raise RuntimeError(
                "stress timing requires tracemalloc to be disabled before the level starts"
            )
        (root / "atomic").mkdir(parents=True, exist_ok=True)
        latencies: list[float] = []
        errors: list[str] = []
        lock = threading.Lock()

        def execute_unit(index: int) -> None:
            task = Task(
                f"stress-{workers}-{index}",
                [RequestSpec(f"http://127.0.0.1/{workers}/{index}")],
                status=TaskStatus.READY,
            )
            store.save_task(task)
            payload = FetchResponse(
                task.requests[0].url,
                task.requests[0].url,
                200,
                {},
                json.dumps({"value": index}).encode("utf-8"),
                0.1,
                "utf-8",
                "application/json",
            )
            parsed = ParserRegistry.parse(payload)
            if parsed.value.get("value") != index:
                raise RuntimeError("parser invariant mismatch")
            if index % 4 == 0:
                atomic_write_text(root / "atomic" / f"slot-{index % max(1, workers)}.txt", str(index))
            if index % 8 == 0:
                selector = self.context.nextgen.selector.analyze("<html><body><i id='x'>x</i></body></html>", "#x")
                if selector.get("matches") != 1:
                    raise RuntimeError("selector invariant mismatch")

        def unit(index: int, *, record_latency: bool) -> None:
            began = time.perf_counter() if record_latency else 0.0
            try:
                execute_unit(index)
            except Exception as exc:                                                          
                with lock:
                    errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                if record_latency:
                    elapsed = (time.perf_counter() - began) * 1000.0
                    with lock:
                        latencies.append(elapsed)

                                                                                             
                                                                                             
                                                                                                
                                                                                                
                                                                                                 
        owns_trace = not tracemalloc.is_tracing()
        if owns_trace:
            tracemalloc.start(1)
        probe_operations = max(1, min(workers, 8))
        try:
            with ThreadPoolExecutor(
                max_workers=min(workers, probe_operations),
                thread_name_prefix="arenyxa-stress-probe",
            ) as executor:
                probe_futures = [
                    executor.submit(unit, -(index + 1), record_latency=False)
                    for index in range(probe_operations)
                ]
                for future in as_completed(probe_futures):
                    future.result()
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            if owns_trace:
                tracemalloc.stop()

                                                                                               
                                                                                                
                                       
        gc.collect()
        started = time.monotonic()

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="arenyxa-stress") as executor:
            futures = [executor.submit(unit, index, record_latency=True) for index in range(operations)]
            for future in as_completed(futures):
                future.result()

        duration = max(0.000001, time.monotonic() - started)
        sorted_latency = sorted(latencies)
        if sorted_latency:
            position = min(len(sorted_latency) - 1, max(0, math.ceil(len(sorted_latency) * 0.95) - 1))
            p95 = sorted_latency[position]
        else:
            p95 = 0.0
        return StressLevelResult(
            workers=workers,
            operations=operations,
            errors=len(errors),
            duration_seconds=duration,
            throughput_ops_per_second=operations / duration,
            p95_ms=p95,
            peak_python_memory_mib=peak / (1024.0 * 1024.0),
            first_error=errors[0] if errors else "",
        )
