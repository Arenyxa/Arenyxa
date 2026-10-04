from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPLEMENTATION = ROOT / "src" / "arenyxa"
REMOVED_NAMESPACE = "n" + "exora"
# Modularization baseline; this ratchet may only decrease in later releases.
MAX_BROAD_EXCEPTION_CATCHES = 284
MAX_ENTERPRISE_BROAD_EXCEPTION_CATCHES = 50
MAX_PROXY_BROAD_EXCEPTION_CATCHES = 1
MAX_PYTHON_MODULE_LINES = 1000
MAX_PUBLIC_RUNNER_LINES = 500
# Explicit ownership boundaries are reviewed separately from ordinary catches.
# Each entry is (maximum handlers in this function, existing unclassified debt,
# rationale). The ordinary 284/50/1 ratchets remain unchanged. Exact scopes stop
# this registry from allowing unrelated catches elsewhere in the same module.
OWNERSHIP_EXCEPTION_BOUNDARIES = {
    ("bootstrap.py", "ApplicationContext.prepare_for_repair_shutdown"): (1, 0, "Stop intake failure preserves the irreversible repair state and refuses handoff."),
    ("bootstrap.py", "ApplicationContext.shutdown"): (1, 0, "Component failure retains context ownership and permits cleanup retry."),
    ("bootstrap.py", "_rollback_bootstrap"): (2, 0, "Partial construction owns execution and service resources that need independent rollback."),
    ("bootstrap.py", "bootstrap"): (1, 0, "Construction failure rolls back created owners and re-raises the original error."),
    ("application/job_system.py", "JobSystem._persist_rejected_submission"): (1, 0, "Rejected-job persistence failure must not replace admission failure or leak capacity."),
    ("application/job_system.py", "JobSystem._run"): (1, 0, "An arbitrary submitted operation is isolated and persisted as a failed job."),
    ("application/job_system.py", "JobSystem.begin_shutdown.cancel_owned"): (1, 0, "Future cancellation invokes user work; failed cleanup must retain retry state."),
    ("application/resilience_scheduler.py", "ResilienceDrillScheduler._loop"): (1, 0, "Automatic drill failure is observed without silently killing its supervising thread."),
    ("application/runner.py", "RunOrchestrator.begin_shutdown.cancel_owned"): (1, 0, "Future cancellation performs persistence and must retain retry ownership on failure."),
    ("application/runner.py", "RunOrchestrator.shutdown"): (1, 0, "Injected transport cleanup failure must preserve the transport for retry."),
    ("infrastructure/capture/proxy_resilience.py", "ProxyResilienceMixin.stop.stop_owned"): (1, 0, "Background listener shutdown reports failure while retaining the runtime owner."),
    ("infrastructure/capture/proxy_resilience.py", "ProxyResilienceMixin._stop_runtime"): (1, 0, "Listener close failure restores detached server, thread, and session references."),
    ("presentation/main_window_lifecycle.py", "MainWindowLifecycleMixin.closeEvent"): (1, 0, "A failing component prevents accepting close and preserves the recovery marker."),
    ("presentation/main_window_operations.py", "MainWindowOperationsMixin.prepare_for_repair_shutdown"): (1, 0, "Repair refusal preserves the stopped-intake state and prevents worker launch."),
    ("presentation/main_window_operations.py", "MainWindowOperationsMixin.handoff_repair"): (1, 0, "Worker launch failure marks repair failure and re-raises rather than committing handoff."),
    ("repair_executor.py", "run_repair_worker"): (2, 1, "Worker errors become failure records while finally cleanup still owns its runtime."),
    ("infrastructure/capture/controller.py", "CaptureController._notify_finalized"): (1, 0, "One finalization listener cannot prevent the remaining owners from retiring."),
    ("infrastructure/capture/mitm_bridge.py", "_spawn_background.completed"): (1, 0, "Task.result exceptions must be observed before strong task ownership retires."),
}
CRITICAL_BROAD_EXCEPTION_FILES = (
    "application/async_runner.py",
    "application/run_execution.py",
    "infrastructure/capture/adapters.py",
)
BROAD_BOUNDARY_MARKER = "broad-exception-boundary:"
HEAVY_BASE_DEPENDENCIES = (
    "PySide6", "playwright", "SQLAlchemy", "psycopg", "pymysql", "psutil",
    "opentelemetry", "lxml", "cssselect", "dnspython", "openpyxl",
)


def broad_catches(path: Path) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == "Exception"
    )


def ownership_boundary_catches(relative: str, source: str) -> int:
    """Count only registered function boundaries and reject growth within them."""
    counts: dict[str, int] = {}

    def visit(node: ast.AST, scope: tuple[str, ...] = ()) -> None:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = (*scope, node.name)
        if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == "Exception":
            qualified = ".".join(scope)
            counts[qualified] = counts.get(qualified, 0) + 1
        for child in ast.iter_child_nodes(node):
            visit(child, scope)

    visit(ast.parse(source))
    classified = 0
    for (path, function), (maximum, legacy, reason) in OWNERSHIP_EXCEPTION_BOUNDARIES.items():
        if path != relative:
            continue
        observed = counts.get(function, 0)
        if observed > maximum:
            raise SystemExit(f"ownership exception boundary grew: {path}:{function} {observed}>{maximum}")
        if not reason or legacy > maximum:
            raise SystemExit(f"invalid ownership exception boundary: {path}:{function}")
        classified += max(0, observed - legacy)
    return classified



def unclassified_critical_broad_catches(path: Path) -> list[int]:
    text = path.read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    tree = ast.parse(text, filename=str(path))
    failures: list[int] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == "Exception"):
            continue
        window = " ".join(lines[max(0, node.lineno - 3):node.lineno]).casefold()
        if BROAD_BOUNDARY_MARKER not in window:
            failures.append(node.lineno)
    return failures


def main() -> int:
    python_files = sorted(IMPLEMENTATION.rglob("*.py"))
    counts = {path: broad_catches(path) for path in python_files}
    classified = {
        path: ownership_boundary_catches(path.relative_to(IMPLEMENTATION).as_posix(), path.read_text(encoding="utf-8-sig"))
        for path in python_files
    }
    raw_total = sum(counts.values())
    counts = {path: count - classified[path] for path, count in counts.items()}
    total = sum(counts.values())
    enterprise = sum(value for path, value in counts.items() if "enterprise" in path.relative_to(IMPLEMENTATION).parts)
    proxy = counts.get(IMPLEMENTATION / "infrastructure" / "capture" / "proxy.py", 0)
    if total > MAX_BROAD_EXCEPTION_CATCHES:
        raise SystemExit(f"broad Exception catch ratchet regressed: {total}>{MAX_BROAD_EXCEPTION_CATCHES}")
    if enterprise > MAX_ENTERPRISE_BROAD_EXCEPTION_CATCHES:
        raise SystemExit(f"enterprise broad Exception catch ratchet regressed: {enterprise}>{MAX_ENTERPRISE_BROAD_EXCEPTION_CATCHES}")
    if proxy > MAX_PROXY_BROAD_EXCEPTION_CATCHES:
        raise SystemExit(f"proxy broad Exception catch ratchet regressed: {proxy}>{MAX_PROXY_BROAD_EXCEPTION_CATCHES}")
    unclassified: list[str] = []
    for relative in CRITICAL_BROAD_EXCEPTION_FILES:
        target = IMPLEMENTATION / relative
        for line in unclassified_critical_broad_catches(target):
            unclassified.append(f"{relative}:{line}")
    if unclassified:
        raise SystemExit(
            "critical broad Exception catches require an explicit boundary classification: "
            + ", ".join(unclassified)
        )
    residue = []
    for path in python_files:
        text = path.read_text(encoding="utf-8-sig")
        if REMOVED_NAMESPACE in text.casefold() or REMOVED_NAMESPACE in path.as_posix().casefold():
            residue.append(path.relative_to(ROOT).as_posix())
    if residue:
        raise SystemExit("removed namespace residue: " + ", ".join(residue))

    oversized = []
    for path in python_files:
        line_count = len(path.read_text(encoding="utf-8-sig").splitlines())
        if line_count > MAX_PYTHON_MODULE_LINES:
            oversized.append(f"{path.relative_to(ROOT).as_posix()}={line_count}")
    if oversized:
        raise SystemExit("python module size ratchet regressed: " + ", ".join(oversized))
    runner_lines = len((IMPLEMENTATION / "application" / "runner.py").read_text(encoding="utf-8").splitlines())
    if runner_lines > MAX_PUBLIC_RUNNER_LINES:
        raise SystemExit(f"public run orchestrator grew back into a monolith: {runner_lines}>{MAX_PUBLIC_RUNNER_LINES}")

    for relative in (
        "application/async_runner.py",
        "infrastructure/async_http_client.py",
    ):
        source = (IMPLEMENTATION / relative).read_text(encoding="utf-8")
        if "ThreadPoolExecutor" in source:
            raise SystemExit(f"async I/O boundary must not allocate request thread pools: {relative}")

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_section = pyproject.split("[project.optional-dependencies]", 1)[0]
    forbidden = [name for name in HEAVY_BASE_DEPENDENCIES if name.casefold() in project_section.casefold()]
    if forbidden:
        raise SystemExit("heavy capability leaked into base dependencies: " + ", ".join(forbidden))
    for group in ("desktop", "analysis", "browser", "server", "database", "capture", "telemetry", "full"):
        if f"{group} = [" not in pyproject:
            raise SystemExit(f"missing optional capability dependency group: {group}")

    architecture_docs = (
        ROOT / "docs" / "architecture" / "V7_8_ARCHITECTURE_CONSOLIDATION.md",
        ROOT / "docs" / "architecture" / "V8_PLATFORM_CONTROL_PLANE.md",
    )
    missing_docs = [str(path.relative_to(ROOT)) for path in architecture_docs if not path.is_file()]
    if missing_docs:
        raise SystemExit("architecture/data-flow documents are missing: " + ", ".join(missing_docs))

    print(
        f"architecture debt gate: PASS · unclassified_broad_exception={total} · classified_ownership={sum(classified.values())} · total_broad_exception={raw_total} · enterprise={enterprise} "
        f"· proxy={proxy} · runner_lines={runner_lines} · module_ceiling={MAX_PYTHON_MODULE_LINES}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
