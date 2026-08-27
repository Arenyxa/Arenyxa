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
        f"architecture debt gate: PASS · broad_exception={total} · enterprise={enterprise} "
        f"· proxy={proxy} · runner_lines={runner_lines} · module_ceiling={MAX_PYTHON_MODULE_LINES}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
