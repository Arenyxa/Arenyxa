from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from arenyxa.application.runner import RunOrchestrator
from arenyxa.application.scheduler import ScheduleRule, SchedulerService
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.models import FetchResponse, FieldSpec, RequestSpec, Task
from arenyxa.infrastructure.atomic_io import atomic_write_text
from arenyxa.infrastructure.data_root_lock import DataRootLease
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import HttpFetcher


class _FastFetcher:
    def fetch(self, spec, token, on_attempt=None):
        token.checkpoint()
        if on_attempt:
            on_attempt(0)
        return FetchResponse(
            url=spec.url,
            final_url=spec.url,
            status=200,
            headers={"Content-Type": "application/json"},
            body=b'{"value":1}',
            elapsed_ms=1.0,
            encoding="utf-8",
            content_type="application/json",
        )


def test_atomic_write_retries_transient_replace_sharing_violation(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "settings.json"
    real_replace = os.replace
    calls = 0

    def flaky_replace(source, destination):
        nonlocal calls
        calls += 1
        if calls <= 2:
            raise PermissionError("simulated antivirus sharing violation")
        return real_replace(source, destination)

    monkeypatch.setattr(os, "replace", flaky_replace)
    atomic_write_text(target, "stable")
    assert target.read_text(encoding="utf-8") == "stable"
    assert calls == 3
    assert list(tmp_path.glob("*.tmp")) == []


def test_http_connect_wait_has_runtime_safety_cap(monkeypatch) -> None:
    observed: list[float] = []

    class _Headers(dict):
        def items(self):
            return super().items()

    class _Response:
        status = 200
        headers = _Headers({"Content-Type": "application/json"})
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, _size=-1): return b""
        def geturl(self): return "https://example.test/"

    class _Opener:
        def open(self, _request, timeout):
            observed.append(float(timeout))
            return _Response()

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_handlers: _Opener())
    monkeypatch.setattr(
        socket, "getaddrinfo",
        lambda *_args, **_kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))],
    )
    spec = RequestSpec("https://example.test/", connect_timeout=600.0, read_timeout=1.0)
    response = HttpFetcher(transport="urllib").fetch(spec)
    assert response.status == 200
    assert observed and observed[0] <= HttpFetcher.MAX_EFFECTIVE_CONNECT_TIMEOUT
    assert HttpFetcher.MAX_EFFECTIVE_CONNECT_TIMEOUT <= 60.0


def test_repeated_runner_shutdown_leaves_no_arenyxa_run_or_fetch_threads(store) -> None:
    for index in range(12):
        runner = RunOrchestrator(store, max_workers=2, request_workers=2, per_host_workers=1)
        runner.fetcher = _FastFetcher()
        task = Task(
            f"runner-cycle-{index}",
            [RequestSpec(f"https://example.test/{index}")],
            fields=[FieldSpec("value", "value")],
            parser_hint="json",
            status=TaskStatus.READY,
        )
        store.save_task(task)
        assert runner.submit(task).future.result(timeout=2).status == RunStatus.COMPLETED
        runner.shutdown(wait=True)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        names = [t.name for t in threading.enumerate() if t.name.startswith(("arenyxa-run", "arenyxa-fetch"))]
        if not names:
            break
        time.sleep(0.02)
    assert [t.name for t in threading.enumerate() if t.name.startswith(("arenyxa-run", "arenyxa-fetch"))] == []


def test_repeated_scheduler_start_stop_leaves_no_scheduler_threads() -> None:
    for index in range(20):
        scheduler = SchedulerService(max_callback_workers=2)
        scheduler.add(
            f"job-{index}",
            ScheduleRule(kind="interval", interval_minutes=60, timezone="UTC"),
            lambda: None,
        )
        scheduler.start()
        scheduler.stop()
    assert [t.name for t in threading.enumerate() if t.name.startswith("arenyxa-scheduler")] == []
    assert [t.name for t in threading.enumerate() if t.name.startswith("arenyxa-schedule")] == []


def test_data_root_lease_repeated_reacquire_and_competitor_exclusion(tmp_path: Path) -> None:
    root = tmp_path / "data"
    for _ in range(40):
        first = DataRootLease(root)
        second = DataRootLease(root)
        assert first.acquire() is True
        assert second.acquire() is False
        first.release()
        assert second.acquire() is True
        second.release()


def test_sqlite_concurrent_writers_are_serialized_without_corruption(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "stress.db")
    store.initialize()

    def write(index: int) -> None:
        task = Task(
            f"concurrent-{index}",
            [RequestSpec(f"https://example.test/{index}")],
            status=TaskStatus.READY,
        )
        store.save_task(task)

    with ThreadPoolExecutor(max_workers=12) as executor:
        list(executor.map(write, range(120)))
    assert len(store.list_tasks(include_archived=True)) == 120
    assert store.quick_check() == "ok"


def test_v660_release_surfaces_are_consistent() -> None:
    import arenyxa
    root = Path(__file__).resolve().parents[1]
    assert arenyxa.__version__ == "8.1"
    assert 'version = "8.1.1"' in (root / "pyproject.toml").read_text(encoding="utf-8")
    version_info = (root / "packaging/version_info.txt").read_text(encoding="utf-8")
    assert "filevers=(8,1,1,0)" in version_info
    assert "ProductVersion', '8.1.1'" in version_info
    assert '#define MyAppVersion "8.1.1"' in (root / "packaging/installer.iss").read_text(encoding="utf-8")


def test_repeated_bootstrap_shutdown_quiesces_owned_threads(tmp_path: Path) -> None:
    from arenyxa.bootstrap import bootstrap

    root = tmp_path / "bootstrap"
    for _ in range(6):
        context = bootstrap(root, safe_mode=True)
        context.shutdown()
    deadline = time.monotonic() + 2.0
    prefixes = ("arenyxa-run", "arenyxa-fetch", "arenyxa-scheduler", "arenyxa-schedule")
    while time.monotonic() < deadline:
        alive = [t.name for t in threading.enumerate() if t.name.startswith(prefixes)]
        if not alive:
            break
        time.sleep(0.02)
    assert [t.name for t in threading.enumerate() if t.name.startswith(prefixes)] == []


def test_repeated_headless_lifespan_does_not_leave_runner_threads(tmp_path: Path) -> None:
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from arenyxa.infrastructure.server import create_app

    for index in range(6):
        app = create_app(tmp_path / f"server-{index}", {})
        with TestClient(app) as client:
            assert client.get("/health").status_code == 200
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        alive = [t.name for t in threading.enumerate() if t.name.startswith(("arenyxa-run", "arenyxa-fetch"))]
        if not alive:
            break
        time.sleep(0.02)
    assert [t.name for t in threading.enumerate() if t.name.startswith(("arenyxa-run", "arenyxa-fetch"))] == []


@pytest.mark.skipif(not Path("/proc/self/fd").exists(), reason="POSIX /proc fd accounting unavailable")
def test_repeated_sqlite_and_data_lease_cycles_do_not_leak_file_descriptors(tmp_path: Path) -> None:
    fd_root = Path("/proc/self/fd")
    before = len(list(fd_root.iterdir()))
    store = SQLiteStore(tmp_path / "fd.db")
    store.initialize()
    for _ in range(100):
        assert store.ping()
        lease = DataRootLease(tmp_path / "lease")
        assert lease.acquire()
        lease.release()
                                                                                           
                                                                       
    after = len(list(fd_root.iterdir()))
    assert after <= before + 4


def test_atomic_write_permanent_replace_failure_preserves_existing_target(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    target.write_text("old", encoding="utf-8")

    def denied(_source, _destination):
        raise PermissionError("permanent denial")

    monkeypatch.setattr(os, "replace", denied)
    with pytest.raises(PermissionError):
        atomic_write_text(target, "new")
    assert target.read_text(encoding="utf-8") == "old"
    assert list(tmp_path.glob("*.tmp")) == []


def test_sqlite_runtime_capability_probe_is_stable() -> None:
    SQLiteStore.validate_runtime()


def test_bootstrap_failure_report_preserves_runtime_compatibility_error(tmp_path: Path) -> None:
    from arenyxa.app import _bootstrap_failure_report
    from arenyxa.config import AppPaths
    from arenyxa.domain.errors import ArenyxaError
    from arenyxa.repair import RepairCategory

    paths = AppPaths.discover(tmp_path / "compat")
    error = ArenyxaError(
        "SQLITE_FTS5_UNAVAILABLE",
        "FTS5 missing",
        domain="DATABASE",
    )
    report = _bootstrap_failure_report(paths, error)
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.code == "SQLITE_FTS5_UNAVAILABLE"
    assert finding.category == RepairCategory.DATABASE_INDEX
    assert finding.detail == "FTS5 missing"
    assert "SQLITE_FTS5_UNAVAILABLE" in finding.evidence


def test_python_runtime_contract_accepts_current_supported_interpreter() -> None:
    from arenyxa.bootstrap import _validate_python_runtime
    _validate_python_runtime()
