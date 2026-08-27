from __future__ import annotations

import base64
import json
import ssl
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise.server_performance import ServerConcurrencyValidator
from arenyxa.enterprise.server_http_performance import ServerHTTPConcurrencyValidator
from arenyxa.enterprise.transport_security import BoundedWindowRateLimiter
from arenyxa.infrastructure.capture.proxy import ProxyFlow, inspect_proxy_flow
from arenyxa.infrastructure.observability import configure_logging
from arenyxa.security.network_guard import NetworkGuardPolicy, NetworkUseGuard


def _public_key() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_rate_limiter_high_cardinality_churn_does_not_reset_tracked_peer() -> None:
    limiter = BoundedWindowRateLimiter(2)
    assert limiter.allow("known-peer", limit=1)
    assert limiter.allow("other-peer", limit=1)
    for index in range(50):
        limiter.allow(f"churn-{index}", limit=1)
    assert limiter.allow("known-peer", limit=1) is False
    state = limiter.snapshot()
    assert state["tracked_buckets"] <= 2
    assert state["overflow_window_count"] > 0


def test_network_guard_pins_checked_dns_address(monkeypatch) -> None:
    import arenyxa.security.network_guard as guard_module

    def resolved(*_args, **_kwargs):
        return [(2, 1, 6, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(guard_module.socket, "getaddrinfo", resolved)
    guard = NetworkUseGuard(NetworkGuardPolicy())
    with guard.connection("example.test") as connect_host:
        assert connect_host == "8.8.8.8"


def test_remote_exposure_policy_blocks_private_loopback_targets() -> None:
    guard = NetworkUseGuard(NetworkGuardPolicy(block_private_or_loopback=True))
    with pytest.raises(Exception) as captured:
        with guard.connection("127.0.0.1"):
            pass
    assert getattr(captured.value, "code", "") == "NETWORK_PRIVATE_TARGET_BLOCKED"


def test_proxy_inspector_reports_headers_cookies_cors_and_timing() -> None:
    flow = ProxyFlow(
        id="flow-inspector",
        sequence=1,
        started_at="2026-08-18T00:00:00+00:00",
        client="127.0.0.1",
        scheme="https",
        method="GET",
        host="example.com",
        port=443,
        target="/api",
        request_raw=(
            b"GET /api HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer redacted\r\n\r\n"
        ),
        response_raw=(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Set-Cookie: sid=abc; Secure; HttpOnly; SameSite=Lax\r\n"
            b"Content-Security-Policy: default-src 'self'\r\n"
            b"Access-Control-Allow-Origin: https://app.example.com\r\n"
            b"Content-Length: 2\r\n\r\n{}"
        ),
        status=200,
        duration_ms=125.0,
        request_bytes=80,
        response_bytes=220,
    )
    report = inspect_proxy_flow(flow).snapshot()
    assert report["request"]["authorization_present"] is True
    assert report["response"]["content_type"] == "application/json"
    assert report["cookies"][0]["secure"] is True
    assert report["cookies"][0]["http_only"] is True
    assert report["security_headers"]["content_security_policy"] is True
    assert report["timing"]["class"] == "fast"



def test_proxy_har_export_redacts_sensitive_headers(tmp_path: Path) -> None:
    from arenyxa.infrastructure.capture.proxy import InterceptingProxy

    proxy = InterceptingProxy(tmp_path / "proxy")
    flow = ProxyFlow(
        id="har-flow", sequence=1, started_at="2026-08-18T00:00:00+00:00", client="127.0.0.1",
        scheme="https", method="POST", host="example.com", port=443, target="/api?q=1", status=200,
        request_raw=(b"POST /api?q=1 HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer secret\r\nCookie: sid=secret\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"),
        response_raw=(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=next; Secure\r\nContent-Length: 2\r\n\r\n{}"),
        duration_ms=10.0, request_bytes=160, response_bytes=100,
    )
    with proxy._lock:
        proxy._history.append(flow)
    destination = proxy.export_har(tmp_path / "history.har")
    payload = json.loads(destination.read_text(encoding="utf-8"))
    entry = payload["log"]["entries"][0]
    request_headers = {item["name"].casefold(): item["value"] for item in entry["request"]["headers"]}
    response_headers = {item["name"].casefold(): item["value"] for item in entry["response"]["headers"]}
    assert request_headers["authorization"] == "[REDACTED]"
    assert request_headers["cookie"] == "[REDACTED]"
    assert response_headers["set-cookie"] == "[REDACTED]"
    assert entry["request"]["queryString"] == [{"name": "q", "value": "1"}]

def test_distributed_batch_lease_respects_worker_slots(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite")
    queue.register_worker("batch-worker", _public_key(), {"slots": 4}, max_slots=4)
    for index in range(6):
        queue.enqueue(
            "task.run",
            {"index": index},
            resource_id="batch-test",
            permission="workflow.execute",
            idempotency_key=f"batch-{index}",
        )
    leases = queue.lease_many("batch-worker", max_items=16, lease_seconds=60)
    assert len(leases) == 4
    assert len({item.job_id for item in leases}) == 4
    assert queue.worker("batch-worker")["active_leases"] == 4


def test_server_concurrency_validator_is_stable_on_bounded_matrix() -> None:
    report = ServerConcurrencyValidator(jobs_per_level=64, worker_levels=(1, 2)).run()
    payload = report.to_dict()
    assert payload["stable"] is True
    assert len(payload["levels"]) == 2
    assert all(item["errors"] == 0 for item in payload["levels"])
    assert all(item["fd_delta"] in (None, 0, 1, 2, 3, 4) for item in payload["levels"])



def test_server_http_tls13_concurrency_validator_is_stable() -> None:
    report = ServerHTTPConcurrencyValidator(requests_per_level=16, client_levels=(1, 4)).run().to_dict()
    assert report["stable"] is True
    assert report["server_thread_stopped"] is True
    assert all(level["errors"] == 0 for level in report["levels"])
    assert all(level["status_counts"] == {"200": 16} for level in report["levels"])
    assert all(level["tls_versions"] == {"TLSv1.3": 16} for level in report["levels"])

def test_observability_uses_arenyxa_logger_namespace(tmp_path: Path) -> None:
    logger = configure_logging(tmp_path / "logs")
    assert logger.name == "arenyxa"


def test_server_operational_scripts_use_modern_namespace_and_bounded_uvicorn() -> None:
    root = Path(__file__).resolve().parents[1]
    scripts = root / "scripts"
    for path in scripts.glob("*.py"):
        if "win7" in path.name.casefold() or path.name in {"architecture_debt_gate.py", "arenyxa_namespace_gate.py"}:
            continue
        text = path.read_text(encoding="utf-8-sig")
        removed_namespace = "n" + "exora"
        assert removed_namespace not in text.casefold()
    server_source = (scripts / "enterprise_server.py").read_text(encoding="utf-8")
    assert "limit_concurrency=MAX_SERVER_INFLIGHT_REQUESTS" in server_source
    assert "timeout_graceful_shutdown=30" in server_source



def test_modern_enterprise_tls_defaults_to_tls13_with_explicit_tls12_compatibility() -> None:
    from arenyxa.enterprise.server_api import EnterpriseWorkerHTTPClient

    fingerprint = "0" * 64
    modern = EnterpriseWorkerHTTPClient("https://example.com", fingerprint)
    compatibility = EnterpriseWorkerHTTPClient("https://example.com", fingerprint, allow_tls12=True)
    assert modern.context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert compatibility.context.minimum_version == ssl.TLSVersion.TLSv1_2

    root = Path(__file__).resolve().parents[1]
    server_source = (root / "scripts" / "enterprise_server.py").read_text(encoding="utf-8")
    coordinator_source = (root / "src" / "arenyxa" / "enterprise" / "coordinator.py").read_text(encoding="utf-8")
    assert "ssl_context_factory=tls_context_factory" in server_source
    assert "--allow-tls12" in server_source
    assert "TLSVersion.TLSv1_3" in coordinator_source
    assert "TLSVersion.TLSv1_2" not in coordinator_source


def test_server_liveness_and_readiness_separate_process_health_from_queue_invariants() -> None:
    from fastapi.testclient import TestClient
    from arenyxa.enterprise.server_api import create_enterprise_server_app

    class Queue:
        @staticmethod
        def health():
            return {
                "healthy": True,
                "state_invariants": {"inconsistent_lease_rows": 1},
                "deployment_profile": {"mode": "embedded-single-host"},
            }

    class Runtime:
        queue = Queue()

    app = create_enterprise_server_app(Runtime(), {"schema": "test-identity"})
    with TestClient(app) as client:
        live = client.get("/enterprise/v1/live")
        ready = client.get("/enterprise/v1/ready")
        assert live.status_code == 200
        assert live.json()["live"] is True
        assert ready.status_code == 503
        assert ready.json()["ready"] is False
        assert ready.json()["invariant_failures"] == {"inconsistent_lease_rows": 1}

def test_server_health_exposes_bounded_transport_metrics() -> None:
    from fastapi.testclient import TestClient
    from arenyxa.enterprise.server_api import create_enterprise_server_app

    class Queue:
        @staticmethod
        def health():
            return {"healthy": True}

    class Runtime:
        queue = Queue()

    app = create_enterprise_server_app(Runtime(), {"schema": "test-identity"})
    with TestClient(app) as client:
        response = client.get("/enterprise/v1/health")
        assert response.status_code == 200
        transport = response.json()["transport_security"]
        assert "traffic_metrics" in transport
        assert "peer_rate_state" in transport
        assert transport["traffic_metrics"]["inflight_peak"] >= 1


def test_enterprise_worker_loop_uses_bounded_parallel_slots(monkeypatch) -> None:
    import argparse
    import importlib.util
    import threading
    import time
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("arenyxa_enterprise_worker_script", root / "scripts" / "enterprise_worker.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class AuthState:
        @staticmethod
        def snapshot():
            return ({"schema": "cached"}, "shared-session", 1)

    leases = [
        {
            "job_id": f"job-{index}", "worker_id": "worker-1", "lease_token": f"token-{index}",
            "lease_expires_at": time.time() + 60.0, "kind": "task.run", "payload": {},
            "resource_id": "server-test", "permission": "workflow.execute", "attempt": 1,
            "max_attempts": 3, "side_effect_mode": "idempotent", "checkpoint": {},
            "checkpoint_seq": 0, "protocol_version": 2,
        }
        for index in range(4)
    ]

    class FakeClient:
        def __init__(self):
            self._auth_state = AuthState()
            self._lock = threading.Lock()
            self._leased = False

        def fork(self):
            return self

        def request(self, path, body, *, authenticated=True, correlation_id=None):
            if path.endswith("/heartbeat"):
                return {"status": "ok"}
            if path.endswith("/lease/batch"):
                with self._lock:
                    if self._leased:
                        return {"leases": []}
                    self._leased = True
                    return {"leases": list(leases)}
            raise AssertionError(path)

    client = FakeClient()
    monkeypatch.setattr(module, "_new_authenticated_client", lambda _args, _private: client)

    class FakeWorker:
        def __init__(self):
            self.lock = threading.Lock()
            self.active = 0
            self.max_active = 0
            self.completed = 0

        def execute_lease(self, _queue, _lease):
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            time.sleep(0.05)
            with self.lock:
                self.active -= 1
                self.completed += 1
            return {"ok": True}

    worker = FakeWorker()
    args = argparse.Namespace(
        concurrency=4, heartbeat_seconds=10.0, worker_id="worker-1", once=True, poll_seconds=0.01,
    )
    module._run_worker_loop(args, None, worker)
    assert worker.completed == 4
    assert worker.max_active >= 2


def test_worker_http_client_reuses_cached_signed_identity_without_extra_identity_roundtrip(monkeypatch) -> None:
    import json
    import arenyxa.enterprise.server_api as server_api

    calls: list[tuple[str, str]] = []

    class Sock:
        @staticmethod
        def getpeercert(binary_form=False):
            return b"peer-cert" if binary_form else {}

    class Response:
        def __init__(self, payload):
            self.status = 200
            self._payload = json.dumps(payload).encode("utf-8")

        def read(self, _limit=-1):
            return self._payload

    class Connection:
        def __init__(self):
            self.sock = Sock()
            self._last = None

        def connect(self):
            return None

        def request(self, method, path, body=None, headers=None):
            calls.append((method, path))
            self._last = path

        def getresponse(self):
            if self._last.endswith("/identity"):
                return Response({"schema": "cached-identity"})
            return Response({"status": "ok"})

        def close(self):
            return None

    client = server_api.EnterpriseWorkerHTTPClient("https://example.com", "0" * 64)
    monkeypatch.setattr(client, "_connection", lambda: Connection())
    monkeypatch.setattr(server_api, "verify_enterprise_server_identity", lambda artifact, _fp, _der: dict(artifact))

    assert client.request("/one", {}, authenticated=False) == {"status": "ok"}
    assert client.request("/two", {}, authenticated=False) == {"status": "ok"}
    assert calls == [
        ("GET", "/enterprise/v1/identity"),
        ("POST", "/one"),
        ("POST", "/two"),
    ]


def test_worker_slot_concurrency_validator_is_stable() -> None:
    from arenyxa.enterprise.server_worker_performance import WorkerSlotConcurrencyValidator

    payload = WorkerSlotConcurrencyValidator(jobs_per_level=64, slot_levels=(1, 4)).run().to_dict()
    assert payload["stable"] is True
    assert payload["storage_backend"] == "sqlite-single-host"
    assert all(level["errors"] == 0 for level in payload["levels"])
    assert all(level["invariants"]["active_jobs_remaining"] == 0 for level in payload["levels"])


def test_worker_slot_recommendation_penalizes_sqlite_tail_latency(monkeypatch) -> None:
    from arenyxa.enterprise.server_worker_performance import WorkerSlotConcurrencyValidator, WorkerSlotLevel

    samples = {
        1: (128.0, 7.0),
        2: (134.0, 12.0),
        4: (152.0, 22.0),
        8: (174.0, 42.0),
        16: (197.0, 75.0),
        32: (204.0, 145.0),
    }

    def fake_level(self, slots: int) -> WorkerSlotLevel:
        throughput, p95 = samples[slots]
        return WorkerSlotLevel(
            slots=slots, jobs=192, throughput_jobs_per_second=throughput,
            p95_ms=p95, p99_ms=p95 * 1.05, max_ms=p95 * 1.1,
            errors=0, completed=192, thread_delta=0, fd_delta=0,
            invariants={"inconsistent_lease_rows": 0, "unreceipted_completed_jobs": 0,
                        "implausible_future_leases": 0, "active_jobs_remaining": 0},
            stable=True,
        )

    monkeypatch.setattr(WorkerSlotConcurrencyValidator, "_run_level", fake_level)
    report = WorkerSlotConcurrencyValidator(slot_levels=(1, 2, 4, 8, 16, 32)).run()
    assert report.recommended_slots == 4
    assert report.peak_throughput_jobs_per_second == 204.0
