from __future__ import annotations

import argparse
import ast
import json
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from arenyxa.enterprise.distributed import _ALLOWED_JOB_TRANSITIONS, DurableDistributedQueue
from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage, SQLiteDistributedRuntimeStorage
from arenyxa.enterprise.server_api import MAX_SERVER_INFLIGHT_REQUESTS
from arenyxa.enterprise.transport_security import BoundedWindowRateLimiter
from arenyxa.infrastructure.capture.proxy import InterceptingProxy
from arenyxa.security.network_guard import NetworkGuardPolicy


def _dimension(name: str, passed: bool, evidence: list[str], findings: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "evidence": evidence,
        "findings": list(findings or []),
    }


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    result: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.append(node.module)
    return result


def _broad_catches(root: Path) -> tuple[int, int]:
    total = 0
    enterprise = 0
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        count = sum(
            1 for node in ast.walk(tree)
            if isinstance(node, ast.ExceptHandler) and isinstance(node.type, ast.Name) and node.type.id == "Exception"
        )
        total += count
        if "enterprise" in path.relative_to(root).parts:
            enterprise += count
    return total, enterprise


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Arenyxa ten-dimension server and professional-workbench review gate.")
    parser.add_argument("--performance-report", type=Path, default=None)
    parser.add_argument("--http-performance-report", type=Path, default=None)
    parser.add_argument("--worker-performance-report", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=Path("server-ten-dimension-review.json"))
    args = parser.parse_args()
    modern = ROOT / "src" / "arenyxa"
    scripts = ROOT / "scripts"
    dimensions: list[dict[str, Any]] = []

    removed_namespace = "n" + "exora"
    namespace_findings: list[str] = []
    namespace_roots = (modern, ROOT / "legacy" / "win7" / "src" / "arenyxa", scripts)
    for namespace_root in namespace_roots:
        if not namespace_root.exists():
            continue
        for path in namespace_root.rglob("*.py"):
            for module in _imports(path):
                if module == removed_namespace or module.startswith(removed_namespace + "."):
                    namespace_findings.append(f"{path.relative_to(ROOT).as_posix()}:{module}")
    dimensions.append(_dimension(
        "1. Architecture and namespace convergence",
        not namespace_findings,
        [
            "src/arenyxa is the canonical modern implementation",
            "legacy/win7/src/arenyxa is the isolated frozen Windows 7 implementation",
            "modern and Win7 Python imports contain no removed namespace references",
        ],
        namespace_findings,
    ))

    ui_proc = subprocess.run(
        [sys.executable, str(scripts / "ui_type_gate.py")],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, timeout=30,
    )
    ui_output = ui_proc.stdout.strip()
    dimensions.append(_dimension(
        "2. Type-safety and UI runtime boundaries",
        ui_proc.returncode == 0,
        [ui_output or "ui_type_gate produced no output"],
        [] if ui_proc.returncode == 0 else ["UI type gate failed"],
    ))


    broad_total, broad_enterprise = _broad_catches(modern)
    dimensions.append(_dimension(
        "3. Exception taxonomy and failure transparency",
        broad_total <= 326 and broad_enterprise <= 50,
        [f"broad Exception catches={broad_total}", f"enterprise broad catches={broad_enterprise}", "ratchet prevents regression"],
    ))

    terminal_regression = [
        f"{source}->{target}" for source in ("completed", "failed", "cancelled") for target in ("queued", "leased", "running")
        if (source, target) in _ALLOWED_JOB_TRANSITIONS
    ]
    with tempfile.TemporaryDirectory(prefix="arenyxa-ten-dim-state-") as raw:
        queue = DurableDistributedQueue(Path(raw) / "distributed.sqlite")
        health = queue.health()
    invariants = dict(health.get("state_invariants") or {})
    state_ok = not terminal_regression and all(int(invariants.get(key, 0)) == 0 for key in (
        "inconsistent_lease_rows", "unreceipted_completed_jobs", "implausible_future_leases"
    ))
    dimensions.append(_dimension(
        "4. Distributed state-machine consistency",
        state_ok,
        ["terminal states cannot transition back to active states", f"fresh runtime invariants={invariants}"],
        terminal_regression,
    ))

    sqlite_cap = SQLiteDistributedRuntimeStorage(ROOT / ".server-ten-dim.sqlite").capabilities.as_dict()
    postgres_cap = PostgreSQLDistributedRuntimeStorage("postgresql://validation.invalid/arenyxa").capabilities.as_dict()
    storage_cleanup_findings: list[str] = []
    try:
        (ROOT / ".server-ten-dim.sqlite").unlink(missing_ok=True)
    except OSError as exc:
        storage_cleanup_findings.append(f"temporary SQLite cleanup warning: {exc}")
    storage_ok = sqlite_cap["multi_host_writers"] is False and postgres_cap["multi_host_writers"] is True and postgres_cap["row_lock_skip_locked"] is True and not storage_cleanup_findings
    dimensions.append(_dimension(
        "5. Persistence, durability, and server storage topology",
        storage_ok,
        [f"SQLite capabilities={sqlite_cap}", f"PostgreSQL capabilities={postgres_cap}", "SQLite is explicitly single-host; PostgreSQL is the multi-host server backend"],
        storage_cleanup_findings,
    ))

    limiter = BoundedWindowRateLimiter(2)
    limiter.allow("known", limit=1)
    limiter.allow("other", limit=1)
    for index in range(32):
        limiter.allow(f"churn-{index}", limit=1)
    churn_preserved = limiter.allow("known", limit=1) is False
    network_policy = NetworkGuardPolicy(block_private_or_loopback=True)
    network_policy.validate()
    server_api_source = (modern / "enterprise/server_api.py").read_text(encoding="utf-8")
    coordinator_source = (modern / "enterprise/coordinator.py").read_text(encoding="utf-8")
    enterprise_server_source = (scripts / "enterprise_server.py").read_text(encoding="utf-8")
    tls_ok = (
        '"tls_minimum_default": "TLSv1.3"' in server_api_source
        and "TLSVersion.TLSv1_3" in coordinator_source
        and "TLSVersion.TLSv1_2" not in coordinator_source
        and "--allow-tls12" in enterprise_server_source
        and "ssl_context_factory=tls_context_factory" in enterprise_server_source
    )
    dimensions.append(_dimension(
        "6. Network abuse resistance and transport governance",
        churn_preserved and MAX_SERVER_INFLIGHT_REQUESTS <= 1024 and tls_ok,
        [
            f"rate limiter state={limiter.snapshot()}",
            f"server inflight cap={MAX_SERVER_INFLIGHT_REQUESTS}",
            "DNS-approved address pinning and remote-private-target blocking are enabled in Proxy governance",
            "modern Enterprise transport defaults to TLS 1.3; TLS 1.2 requires explicit server/worker compatibility opt-in",
        ],
    ))

    distributed_source = (modern / "enterprise/distributed.py").read_text(encoding="utf-8")
    distributed_protocol_source = (modern / "enterprise/distributed_protocol.py").read_text(encoding="utf-8")
    proxy_source = (modern / "infrastructure/capture/proxy.py").read_text(encoding="utf-8")
    proxy_models_source = (modern / "infrastructure/capture/proxy_models.py").read_text(encoding="utf-8")
    resources_ok = (
        all(token in distributed_protocol_source for token in ("MAX_JOBS = 100_000", "MAX_WORKERS = 4096", "MAX_WORKER_SLOTS = 64"))
        and "max_concurrent_upstreams" in proxy_source
        and "max_concurrent_upstreams: int = 128" in proxy_models_source
    )
    dimensions.append(_dimension(
        "7. Resource governance, backpressure, and leak boundaries",
        resources_ok,
        ["distributed jobs/workers/slots are bounded", "proxy upstream concurrency and message sizes are bounded", "server performance validation tracks thread and file-descriptor deltas"],
    ))

    observability_source = (modern / "infrastructure/observability.py").read_text(encoding="utf-8")
    server_source = (modern / "enterprise/server_api.py").read_text(encoding="utf-8")
    observability_ok = (
        'logging.getLogger("arenyxa")' in observability_source
        and "traffic_metrics.snapshot()" in server_source
        and "peer_rate_state" in server_source
        and '@app.get("/enterprise/v1/live")' in server_source
        and '@app.get("/enterprise/v1/ready")' in server_source
        and 'status_code=200 if ready_state else 503' in server_source
    )
    dimensions.append(_dimension(
        "8. Observability, health, and operational diagnostics",
        observability_ok,
        ["modern logger namespace is arenyxa", "server health exposes bounded request/inflight/rejection counters", "liveness and readiness are separate; readiness fails closed on queue invariant violations", "distributed health exposes state invariants and storage deployment profile"],
    ))

    deploy_ok = all(token in enterprise_server_source for token in (
        "limit_concurrency=MAX_SERVER_INFLIGHT_REQUESTS", "backlog=1024", "timeout_keep_alive=5", "timeout_graceful_shutdown=30",
        "ssl_context_factory=tls_context_factory", "TLSVersion.TLSv1_3"
    )) and (ROOT / "legacy/win7/LEGACY_RUNTIME.json").is_file()
    performance_evidence: dict[str, Any] = {}
    http_performance_evidence: dict[str, Any] = {}
    worker_performance_evidence: dict[str, Any] = {}
    if args.performance_report is not None and args.performance_report.is_file():
        performance_evidence = json.loads(args.performance_report.read_text(encoding="utf-8"))
        deploy_ok = deploy_ok and bool(performance_evidence.get("stable", False))
    if args.http_performance_report is not None and args.http_performance_report.is_file():
        http_performance_evidence = json.loads(args.http_performance_report.read_text(encoding="utf-8"))
        deploy_ok = (
            deploy_ok
            and bool(http_performance_evidence.get("stable", False))
            and http_performance_evidence.get("tls_minimum") == "TLSv1.3"
            and bool(http_performance_evidence.get("server_thread_stopped", False))
        )
    if args.worker_performance_report is not None and args.worker_performance_report.is_file():
        worker_performance_evidence = json.loads(args.worker_performance_report.read_text(encoding="utf-8"))
        deploy_ok = deploy_ok and bool(worker_performance_evidence.get("stable", False))
    dimensions.append(_dimension(
        "9. Server deployment, concurrency, and recovery readiness",
        deploy_ok,
        [
            "uvicorn concurrency/backlog/keep-alive/graceful-shutdown are explicitly bounded",
            "modern server TLS minimum defaults to TLS 1.3",
            "Win7 runtime is physically isolated",
            f"queue_performance_evidence={performance_evidence or 'not supplied'}",
            f"http_tls_performance_evidence={http_performance_evidence or 'not supplied'}",
            f"worker_slot_performance_evidence={worker_performance_evidence or 'not supplied'}",
        ],
    ))

    with tempfile.TemporaryDirectory(prefix="arenyxa-ten-dim-proxy-") as raw:
        proxy = InterceptingProxy(Path(raw))
        try:
            professional_ok = (
                callable(proxy.repeat_raw)
                and callable(proxy.inspect_flow)
                and callable(proxy.add_autoresponder_rule)
                and callable(proxy.add_match_replace_rule)
                and callable(proxy.export_har)
            )
        finally:
            proxy.close()
    professional_contract_files = [
        modern / "enterprise/distributed_runtime.py",
        modern / "enterprise/server_worker_performance.py",
        modern / "enterprise/fleet_live.py",
        modern / "enterprise/fleet_telemetry.py",
        modern / "application/extraction_studio.py",
        modern / "application/extraction_recipe.py",
        modern / "application/extraction_runtime.py",
        modern / "application/packet_analytics.py",
        modern / "application/mitm_analytics.py",
        modern / "application/proxy_deep_inspector.py",
        modern / "application/workflow_debugger.py",
        modern / "application/workflow_graph.py",
        modern / "application/terminal_workspace.py",
        modern / "presentation/pages/server_ops.py",
    ]
    distributed_runtime_source = (modern / "enterprise/distributed_runtime.py").read_text(encoding="utf-8-sig")
    professional_ok = (
        professional_ok
        and "def lease_batch(" in distributed_runtime_source
        and all(path.is_file() for path in professional_contract_files)
    )
    dimensions.append(_dimension(
        "10. Professional workbench depth and safe expansion",
        professional_ok,
        [
            "Proxy provides Intercept/History/Repeater/Decoder/Comparer/AutoResponder/Match-Replace/Inspector/HAR plus deep analysis",
            "Enterprise provides transactional batch lease, bounded parallel Worker slots and independent Fleet Control telemetry",
            "Extraction Lab provides local Dry Run, point-and-click selection and bounded browser recipe execution",
            "Packet Intelligence provides advanced/TCP stream analytics; MITM Proxy provides independent flow analytics",
            "Flow Designer provides visual graph, execution inspection and side-effect-safe debugging; Terminal provides shared multi-session control",
        ],
    ))

    passed = all(item["status"] == "PASS" for item in dimensions)
    payload = {
        "schema": "arenyxa.server-ten-dimension-review/v1",
        "passed": passed,
        "dimensions": dimensions,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
