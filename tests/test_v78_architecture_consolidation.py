from __future__ import annotations

import asyncio
import tomllib
from pathlib import Path

from arenyxa import __package_version__, __version__
from arenyxa.application.async_runner import AsyncRunOrchestrator
from arenyxa.application.traffic_automation import (
    TrafficAction,
    TrafficAutomationEngine,
    TrafficEvent,
)
from arenyxa.infrastructure.async_http_client import AsyncHttpFetcher
from arenyxa.infrastructure.http_client import HttpFetcher

ROOT = Path(__file__).resolve().parents[1]


def test_v78_release_identity_and_architecture_documents() -> None:
    assert __version__ == "8.1"
    assert __package_version__ == "8.1.0"
    assert (ROOT / "docs/architecture/V7_8_ARCHITECTURE_CONSOLIDATION.md").is_file()
    assert (ROOT / "docs/adr/ADR_V78_ASYNC_IO_AND_CAPABILITY_LAYERS.md").is_file()


def test_heavy_integrations_are_optional_capabilities() -> None:
    value = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    base = "\n".join(value["project"]["dependencies"]).casefold()
    for dependency in ("pyside6", "playwright", "sqlalchemy", "psycopg", "tshark", "lxml", "openpyxl"):
        assert dependency not in base
    optional = value["project"]["optional-dependencies"]
    for group in ("desktop", "analysis", "browser", "server", "database", "capture", "telemetry", "full"):
        assert group in optional


def test_public_runner_is_split_from_execution_engine() -> None:
    runner = ROOT / "src/arenyxa/application/runner.py"
    execution = ROOT / "src/arenyxa/application/run_execution.py"
    assert len(runner.read_text(encoding="utf-8").splitlines()) <= 500
    assert execution.is_file()
    assert "class RunExecutionMixin" in execution.read_text(encoding="utf-8")


def test_modern_async_request_plane_has_no_per_request_thread_pool() -> None:
    async_fetcher = (ROOT / "src/arenyxa/infrastructure/async_http_client.py").read_text(encoding="utf-8")
    async_runner = (ROOT / "src/arenyxa/application/async_runner.py").read_text(encoding="utf-8")
    assert "ThreadPoolExecutor" not in async_fetcher
    assert "ThreadPoolExecutor" not in async_runner
    assert AsyncRunOrchestrator.request_backend == "asyncio-httpx"


def test_sync_httpx_transport_reuses_connection_pool() -> None:
    fetcher = HttpFetcher(transport="httpx")
    try:
        first = fetcher._httpx_client(True, None)
        second = fetcher._httpx_client(True, None)
        assert first is second
    finally:
        fetcher.close()


def test_async_httpx_transport_reuses_connection_pool() -> None:
    async def verify() -> None:
        fetcher = AsyncHttpFetcher()
        try:
            first = await fetcher._async_client(True, None)
            second = await fetcher._async_client(True, None)
            assert first is second
        finally:
            await fetcher.aclose()

    asyncio.run(verify())


def test_traffic_automation_priority_preview_stop_and_throttle(tmp_path: Path) -> None:
    engine = TrafficAutomationEngine(tmp_path / "rules.json")
    calls: list[str] = []
    engine.register(TrafficAction.RECORD, lambda _payload, params: calls.append(str(params["name"])))
    later = engine.add(
        "later",
        "HTTP_REQUEST",
        ["RECORD"],
        priority=200,
        parameters={"name": "later"},
    )
    first = engine.add(
        "first",
        "HTTP_REQUEST",
        ["RECORD"],
        priority=10,
        stop_processing=True,
        cooldown_seconds=60,
        parameters={"name": "first"},
        field_patterns={"protocol": "http*"},
    )
    payload = {"host": "example.test", "url": "https://example.test/", "method": "GET", "protocol": "https"}
    preview = engine.preview(TrafficEvent.HTTP_REQUEST, payload)
    assert [row["rule_id"] for row in preview] == [first["id"]]
    result = engine.process(TrafficEvent.HTTP_REQUEST, payload)
    assert result[0]["ok"] is True
    assert calls == ["first"]
    throttled = engine.process(TrafficEvent.HTTP_REQUEST, payload)
    assert throttled[0]["error_code"] == "TRAFFIC_AUTOMATION_THROTTLED"
    updated = engine.update(first["id"], stop_processing=False, priority=300, cooldown_seconds=0)
    assert updated is not None and updated["priority"] == 300
    assert later["id"] in [row["rule_id"] for row in engine.preview(TrafficEvent.HTTP_REQUEST, payload)]


def test_modern_ci_is_lightweight_and_heavy_integration_is_isolated() -> None:
    quality = (ROOT / ".github/workflows/quality.yml").read_text(encoding="utf-8").casefold()
    integration = (ROOT / ".github/workflows/capability-integration.yml").read_text(encoding="utf-8").casefold()
    assert "postgres:" not in quality
    assert "tshark" not in quality
    assert "playwright install" not in quality
    assert "postgres:" in integration
    assert "tshark" in integration
    assert "playwright install" in integration
    assert "win7_legacy_quality_gate.py" in integration


def test_async_orchestrator_executes_real_loopback_io_without_request_worker_threads(store) -> None:
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from arenyxa.domain.enums import RunStatus, TaskStatus
    from arenyxa.domain.models import FieldSpec, RequestSpec, Task

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            body = json.dumps({"value": self.path}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *args: object) -> None:
            del args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    runner = AsyncRunOrchestrator(store, max_workers=1, request_workers=4, per_host_workers=4)
    try:
        task = Task(
            "Async v7.8",
            [RequestSpec(f"http://127.0.0.1:{server.server_port}/{index}") for index in range(4)],
            fields=[FieldSpec("value", "value")],
            parser_hint="json",
            status=TaskStatus.READY,
        )
        store.save_task(task)
        run = runner.submit(task).future.result(timeout=10)
        assert run.status == RunStatus.COMPLETED
        assert run.success_count == 4
        assert run.failure_count == 0
        assert store.count_results(run.id) == 4
        assert runner.concurrency_snapshot()["request_worker_model"] == "event-loop"
    finally:
        runner.shutdown(wait=True)
        server.shutdown()
        server.server_close()
