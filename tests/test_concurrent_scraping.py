from __future__ import annotations

import json
import threading
import time

from arenyxa.application.runner import RunOrchestrator
from arenyxa.domain.enums import RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import FetchResponse, FieldSpec, RequestSpec, Task


class ControlledFetcher:
    def __init__(self, delay: float = 0.06, fail_suffix: str | None = None) -> None:
        self.delay = delay
        self.fail_suffix = fail_suffix
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0

    def fetch(self, spec, token, on_attempt=None):
        if on_attempt:
            on_attempt(0)
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            stop = time.monotonic() + self.delay
            while time.monotonic() < stop:
                token.checkpoint()
                time.sleep(0.005)
            if self.fail_suffix and spec.url.endswith(self.fail_suffix):
                raise ArenyxaError("FETCH_TEST_FAILURE", "synthetic failure", domain="FETCH")
            body = json.dumps({"value": spec.url}).encode("utf-8")
            return FetchResponse(
                url=spec.url,
                final_url=spec.url,
                status=200,
                headers={"Content-Type": "application/json; charset=utf-8"},
                body=body,
                elapsed_ms=self.delay * 1000,
                encoding="utf-8",
                content_type="application/json",
                redirect_chain=[],
            )
        finally:
            with self._lock:
                self.active -= 1


def _task(urls: list[str]) -> Task:
    return Task(
        "Concurrent",
        [RequestSpec(url) for url in urls],
        fields=[FieldSpec("value", "value")],
        parser_hint="json",
        status=TaskStatus.READY,
    )


def test_requests_within_one_run_execute_concurrently_and_respect_host_limit(store) -> None:
    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=4,
        per_host_workers=2,
        progress_interval_ms=50,
        result_write_batch_size=2,
    )
    fake = ControlledFetcher(delay=0.07)
    runner.fetcher = fake
    task = _task([f"https://example.com/page/{index}" for index in range(6)])
    store.save_task(task)
    try:
        run = runner.submit(task).future.result(timeout=5)
    finally:
        runner.shutdown(wait=True)

    assert run.status == RunStatus.COMPLETED
    assert run.success_count == 6
    assert run.failure_count == 0
    assert run.completed_units == 6
    assert store.count_results(run.id) == 6
                                                                                          
                                                                                            
                                                                                           
                                                                            
    assert fake.max_active == 2


def test_different_hosts_can_use_global_request_pool(store) -> None:
    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=4,
        per_host_workers=2,
        progress_interval_ms=50,
    )
    fake = ControlledFetcher(delay=0.06)
    runner.fetcher = fake
    task = _task(
        [
            "https://a.example/1",
            "https://a.example/2",
            "https://b.example/1",
            "https://b.example/2",
            "https://c.example/1",
            "https://c.example/2",
        ]
    )
    store.save_task(task)
    try:
        run = runner.submit(task).future.result(timeout=5)
    finally:
        runner.shutdown(wait=True)

    assert run.status == RunStatus.COMPLETED
    assert fake.max_active == 4
    assert runner.concurrency_snapshot()["request_workers"] == 4


def test_one_failed_request_does_not_abort_other_concurrent_urls(store) -> None:
    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=3,
        per_host_workers=3,
        progress_interval_ms=50,
    )
    runner.fetcher = ControlledFetcher(delay=0.02, fail_suffix="/bad")
    task = _task(
        [
            "https://example.com/one",
            "https://example.com/bad",
            "https://example.com/two",
        ]
    )
    store.save_task(task)
    try:
        run = runner.submit(task).future.result(timeout=5)
    finally:
        runner.shutdown(wait=True)

    assert run.status == RunStatus.PARTIAL
    assert run.error_code == "RUN_PARTIAL_FAILURE"
    assert run.success_count == 2
    assert run.failure_count == 1
    assert run.completed_units == 3
    assert store.count_results(run.id) == 2


def test_cancelling_concurrent_run_stops_workers_cooperatively(store) -> None:
    runner = RunOrchestrator(
        store,
        max_workers=1,
        request_workers=4,
        per_host_workers=4,
        progress_interval_ms=50,
    )
    fake = ControlledFetcher(delay=0.30)
    runner.fetcher = fake
    task = _task([f"https://example.com/{index}" for index in range(12)])
    store.save_task(task)
    handle = runner.submit(task)
    deadline = time.monotonic() + 1.0
    while fake.max_active < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    handle.cancel()
    run = handle.future.result(timeout=3)
    runner.shutdown(wait=True)

    assert run.status == RunStatus.CANCELLED
    assert run.completed_units < run.total_units
    assert fake.active == 0


def test_real_http_requests_are_parallelized(store) -> None:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    lock = threading.Lock()
    state = {"active": 0, "max_active": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                state["active"] += 1
                state["max_active"] = max(state["max_active"], state["active"])
            try:
                time.sleep(0.06)
                payload = json.dumps({"value": self.path}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                with lock:
                    state["active"] -= 1

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    runner = RunOrchestrator(
        store, max_workers=1, request_workers=4, per_host_workers=2, progress_interval_ms=50
    )
    task = _task(
        [f"http://127.0.0.1:{server.server_port}/{index}" for index in range(6)]
    )
    store.save_task(task)
    try:
        run = runner.submit(task).future.result(timeout=5)
    finally:
        runner.shutdown(wait=True)
        server.shutdown()
        server.server_close()

    assert run.status == RunStatus.COMPLETED
    assert state["max_active"] == 2
    assert store.count_results(run.id) == 6


def test_per_host_limit_is_shared_across_multiple_runs(store) -> None:
    runner = RunOrchestrator(
        store, max_workers=2, request_workers=4, per_host_workers=2, progress_interval_ms=50
    )
    fake = ControlledFetcher(delay=0.05)
    runner.fetcher = fake
    first = _task([f"https://shared.example/a/{index}" for index in range(4)])
    second = _task([f"https://shared.example/b/{index}" for index in range(4)])
    store.save_task(first)
    store.save_task(second)
    try:
        h1 = runner.submit(first)
        h2 = runner.submit(second)
        r1 = h1.future.result(timeout=5)
        r2 = h2.future.result(timeout=5)
    finally:
        runner.shutdown(wait=True)

    assert r1.status == RunStatus.COMPLETED
    assert r2.status == RunStatus.COMPLETED
    assert fake.max_active == 2


def test_pause_and_resume_are_persisted_immediately(store) -> None:
    runner = RunOrchestrator(
        store, max_workers=1, request_workers=1, per_host_workers=1, progress_interval_ms=500
    )
    runner.fetcher = ControlledFetcher(delay=0.20)
    task = _task(["https://example.com/one", "https://example.com/two", "https://example.com/three"])
    store.save_task(task)
    try:
        handle = runner.submit(task)
        deadline = time.monotonic() + 2.0
        while handle.run.status != RunStatus.RUNNING and time.monotonic() < deadline:
            time.sleep(0.01)
        assert handle.run.status == RunStatus.RUNNING

        handle.pause()
        assert handle.run.status == RunStatus.PAUSED
        persisted = next(row for row in store.list_runs(task.id) if row["id"] == handle.run.id)
        assert persisted["status"] == RunStatus.PAUSED.value

        handle.resume()
        assert handle.run.status == RunStatus.RUNNING
        persisted = next(row for row in store.list_runs(task.id) if row["id"] == handle.run.id)
        assert persisted["status"] == RunStatus.RUNNING.value
        assert handle.future.result(timeout=5).status == RunStatus.COMPLETED
    finally:
        runner.shutdown(wait=True)


def test_pause_resume_after_terminal_run_do_not_corrupt_final_state(store) -> None:
    runner = RunOrchestrator(
        store, max_workers=1, request_workers=2, per_host_workers=2, progress_interval_ms=50
    )
    runner.fetcher = ControlledFetcher(delay=0.01)
    task = _task(["https://example.com/one", "https://example.com/two"])
    store.save_task(task)
    try:
        handle = runner.submit(task)
        run = handle.future.result(timeout=5)
        assert run.status == RunStatus.COMPLETED
        handle.pause()
        assert run.status == RunStatus.COMPLETED
        handle.resume()
        assert run.status == RunStatus.COMPLETED
        handle.cancel()
        assert run.status == RunStatus.COMPLETED
    finally:
        runner.shutdown(wait=True)


def test_same_hostname_on_different_ports_shares_domain_budget(store) -> None:
    runner = RunOrchestrator(
        store, max_workers=1, request_workers=4, per_host_workers=1, progress_interval_ms=50
    )
    fake = ControlledFetcher(delay=0.025)
    runner.fetcher = fake
    task = _task(
        [
            "http://same.example:8001/a",
            "http://same.example:8002/b",
            "http://same.example:8003/c",
        ]
    )
    store.save_task(task)
    try:
        run = runner.submit(task).future.result(timeout=5)
    finally:
        runner.shutdown(wait=True)

    assert run.status == RunStatus.COMPLETED
    assert fake.max_active == 1


def test_idn_and_punycode_spellings_share_the_same_host_budget(store) -> None:
    runner = RunOrchestrator(
        store, max_workers=1, request_workers=2, per_host_workers=1, progress_interval_ms=50
    )
    fake = ControlledFetcher(delay=0.02)
    runner.fetcher = fake
    task = _task(["https://bücher.de/a", "https://xn--bcher-kva.de/b"])
    store.save_task(task)
    try:
        run = runner.submit(task).future.result(timeout=5)
    finally:
        runner.shutdown(wait=True)
    assert run.status == RunStatus.COMPLETED
    assert fake.max_active == 1


def test_pause_persistence_failure_rolls_back_volatile_pause(store) -> None:
    runner = RunOrchestrator(
        store, max_workers=1, request_workers=1, per_host_workers=1, progress_interval_ms=500
    )
    runner.fetcher = ControlledFetcher(delay=0.20)
    task = _task(["https://example.com/one", "https://example.com/two"])
    store.save_task(task)
    try:
        handle = runner.submit(task)
        deadline = time.monotonic() + 2.0
        while handle.run.status != RunStatus.RUNNING and time.monotonic() < deadline:
            time.sleep(0.01)
        assert handle.run.status == RunStatus.RUNNING

        handle.persist_status = lambda _run_id, _status: False
        handle.pause()
        assert handle.run.status == RunStatus.RUNNING
        assert handle.token.paused is False
        assert handle.future.result(timeout=5).status == RunStatus.COMPLETED
    finally:
        runner.shutdown(wait=True)


def test_resume_persistence_failure_restores_pause(store) -> None:
    runner = RunOrchestrator(
        store, max_workers=1, request_workers=1, per_host_workers=1, progress_interval_ms=500
    )
    runner.fetcher = ControlledFetcher(delay=0.20)
    task = _task(["https://example.com/one", "https://example.com/two"])
    store.save_task(task)
    try:
        handle = runner.submit(task)
        deadline = time.monotonic() + 2.0
        while handle.run.status != RunStatus.RUNNING and time.monotonic() < deadline:
            time.sleep(0.01)
        handle.pause()
        assert handle.run.status == RunStatus.PAUSED

        handle.persist_status = lambda _run_id, _status: False
        handle.resume()
        assert handle.run.status == RunStatus.PAUSED
        assert handle.token.paused is True

                                                                       
        handle.persist_status = store.update_run_control_status
        handle.resume()
        assert handle.future.result(timeout=5).status == RunStatus.COMPLETED
    finally:
        runner.shutdown(wait=True)
