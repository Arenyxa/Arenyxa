from __future__ import annotations

import socket
import ssl
import sys
import types
from pathlib import Path

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec
from arenyxa.enterprise.distributed_queue import DurableDistributedQueue
from arenyxa.infrastructure.capture.inspectors import DnsAnalyzer, TlsInspector
from arenyxa.infrastructure.database import SQLiteStore
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.shutdown import DependencyShutdownCoordinator
from arenyxa.security.dlp import DlpMode, DlpPolicy, GLOBAL_DLP_ENGINE
from arenyxa.security.zero_trust import ZeroTrustEvaluator, ZeroTrustPolicy


def test_tls_inspector_explicitly_requires_chain_and_hostname_verification(monkeypatch) -> None:
    captured = {}

    class Secure:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def getpeercert(self):
            return {
                "subject": ((('commonName', 'example.test'),),),
                "issuer": ((('commonName', 'Test CA'),),),
                "subjectAltName": (("DNS", "example.test"),),
            }

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self):
            return "TLSv1.3"

    class Context:
        verify_mode = ssl.CERT_NONE
        check_hostname = False

        def wrap_socket(self, raw, server_hostname):
            captured["verify_mode"] = self.verify_mode
            captured["check_hostname"] = self.check_hostname
            captured["server_hostname"] = server_hostname
            return Secure()

    class Raw:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(ssl, "create_default_context", lambda: Context())
    monkeypatch.setattr(socket, "create_connection", lambda *args, **kwargs: Raw())
    report = TlsInspector.inspect("example.test")
    assert report.host == "example.test"
    assert captured == {
        "verify_mode": ssl.CERT_REQUIRED,
        "check_hostname": True,
        "server_hostname": "example.test",
    }


def test_dns_analyzer_bounds_addresses_and_extended_record_text(monkeypatch) -> None:
    rows = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"10.0.0.{(index % 250) + 1}", 443))
        for index in range(100)
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: rows)

    payloads = []

    class Item:
        def to_text(self):
            return "x" * 4096

    class Resolver:
        timeout = 0.0
        lifetime = 0.0

        def use_edns(self, *, edns, payload):
            payloads.append((edns, payload))

        def resolve(self, host, record_type, raise_on_no_answer=False):
            return [Item() for _ in range(100)]

    dns_pkg = types.ModuleType("dns")
    resolver_mod = types.ModuleType("dns.resolver")
    resolver_mod.Resolver = Resolver
    dns_pkg.resolver = resolver_mod
    monkeypatch.setitem(sys.modules, "dns", dns_pkg)
    monkeypatch.setitem(sys.modules, "dns.resolver", resolver_mod)

    report = DnsAnalyzer.resolve("example.test")
    assert len(report.addresses) <= DnsAnalyzer.MAX_ADDRESSES
    assert payloads == [(0, DnsAnalyzer.EDNS_UDP_PAYLOAD)]
    assert all(len(values) <= DnsAnalyzer.MAX_RECORDS_PER_TYPE for values in report.records.values())
    assert sum(len(value) for values in report.records.values() for value in values) <= DnsAnalyzer.MAX_TOTAL_RECORD_TEXT_CHARS
    assert report.errors["bounds"] == "response_truncated"


def test_zero_trust_dynamic_context_is_fail_closed_when_enabled() -> None:
    policy = ZeroTrustPolicy(
        enabled=True,
        require_managed_device=True,
        require_compliant_device=True,
        require_mfa=True,
        allowed_network_trust=("trusted",),
        max_risk_score=25,
        max_auth_age_seconds=300,
    )
    denied = ZeroTrustEvaluator.evaluate(policy, {"managed_device": True, "risk_score": 80})
    assert not denied.allowed
    assert {"device_compliant", "mfa_verified", "network_trust", "risk_score", "auth_age"}.issubset(set(denied.reasons))

    allowed = ZeroTrustEvaluator.evaluate(
        policy,
        {
            "managed_device": True,
            "device_compliant": True,
            "mfa_verified": True,
            "network_trust": "trusted",
            "risk_score": 10,
            "auth_age_seconds": 30,
        },
    )
    assert allowed.allowed
    assert allowed.code == "ZERO_TRUST_ALLOW"


def test_http_fetcher_dlp_enforcement_blocks_plaintext_secret_before_transport(monkeypatch) -> None:
    original = GLOBAL_DLP_ENGINE.policy()
    called = []
    try:
        GLOBAL_DLP_ENGINE.configure(DlpPolicy(mode=DlpMode.ENFORCE))
        fetcher = HttpFetcher(transport="urllib")
        monkeypatch.setattr(fetcher, "_fetch_once_urllib", lambda spec, token: called.append(True))
        with pytest.raises(ArenyxaError) as exc:
            fetcher.fetch(RequestSpec("http://example.test/upload", headers={"Authorization": "Bearer not-recorded"}))
        assert exc.value.code == "DLP_EGRESS_BLOCKED"
        assert called == []
        decision = GLOBAL_DLP_ENGINE.last_decision()
        assert decision.destination_host == "example.test"
        assert decision.findings
        assert all("not-recorded" not in repr(item) for item in decision.findings)
    finally:
        GLOBAL_DLP_ENGINE.configure(original)


def test_dependency_shutdown_coordinator_uses_graph_order_and_continues_after_failure() -> None:
    import logging

    order = []
    coordinator = DependencyShutdownCoordinator(logging.getLogger("test.shutdown"))
    coordinator.add("intake", lambda: order.append("intake"))
    coordinator.add("producer", lambda: order.append("producer"), after=("intake",))

    def fail_consumer():
        order.append("consumer")
        raise RuntimeError("synthetic")

    coordinator.add("consumer", fail_consumer, after=("producer",))
    coordinator.add("storage", lambda: order.append("storage"), after=("consumer",))
    failures = coordinator.run()
    assert order == ["intake", "producer", "consumer", "storage"]
    assert failures == ("consumer",)


def test_sqlite_transaction_commit_failure_rolls_back_closes_and_preserves_original(tmp_path: Path, monkeypatch) -> None:
    store = SQLiteStore(tmp_path / "unused.sqlite")

    class Connection:
        in_transaction = False
        rolled_back = False
        closed = False

        def execute(self, statement):
            if statement == "BEGIN IMMEDIATE":
                self.in_transaction = True
            return self

        def commit(self):
            raise sqlite_error

        def rollback(self):
            self.rolled_back = True
            self.in_transaction = False

        def close(self):
            self.closed = True

    sqlite_error = __import__("sqlite3").OperationalError("synthetic commit failure")
    connection = Connection()
    monkeypatch.setattr(store, "connect", lambda: connection)
    with pytest.raises(type(sqlite_error), match="synthetic commit failure"):
        with store.transaction():
            pass
    assert connection.rolled_back
    assert connection.closed


def test_sqlite_distributed_backend_surfaces_serialized_writer_guidance(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite")
    health = queue.health()
    caps = health["storage"]
    assert caps["backend"] == "sqlite"
    assert caps["write_model"] == "serialized-wal"
    assert caps["recommended_parallel_writers"] == 1
    assert caps["recommended_worker_slots"] == 4


def test_enterprise_authorization_executes_zero_trust_gate_before_operation_mutation() -> None:
    from arenyxa.enterprise.governance import EnterpriseGovernanceService

    service = object.__new__(EnterpriseGovernanceService)
    policy = ZeroTrustPolicy(
        enabled=True,
        require_mfa=True,
        allowed_network_trust=("trusted",),
        max_risk_score=20,
        max_auth_age_seconds=120,
    )
    service.require_resource = lambda permission, resource_id: {"zero_trust_policy": policy.as_dict()}
    with pytest.raises(ArenyxaError) as exc:
        service.authorize_operation(
            "dataset.read",
            "dataset:example",
            access_context={
                "mfa_verified": False,
                "network_trust": "untrusted",
                "risk_score": 80,
                "auth_age_seconds": 999,
            },
        )
    assert exc.value.code == "ZERO_TRUST_CONTEXT_DENIED"
    assert "risk_score" in exc.value.context["reasons"]


def test_professional_suite_exposes_independent_zero_trust_and_dlp_tabs() -> None:
    root = Path(__file__).resolve().parents[1]
    suite = (root / "src/arenyxa/presentation/pages/professional_suite.py").read_text(encoding="utf-8")
    assert 'self.tabs.addTab(self.zero_trust_page, "Zero Trust")' in suite
    assert 'self.tabs.addTab(self.dlp_page, "DLP")' in suite
    assert (root / "src/arenyxa/presentation/pages/zero_trust.py").is_file()
    assert (root / "src/arenyxa/presentation/pages/dlp.py").is_file()


def test_source_has_no_bare_except_and_baseexception_handlers_are_explicit_boundaries() -> None:
    import ast

    root = Path(__file__).resolve().parents[1] / "src" / "arenyxa"
    bare = []
    base_handlers = []
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                if node.type is None:
                    bare.append((str(path), node.lineno))
                if isinstance(node.type, ast.Name) and node.type.id == "BaseException":
                    base_handlers.append((path.relative_to(root).as_posix(), node.lineno))
    assert bare == []
    allowed_modules = {
        "enterprise/production_validation.py",
        "infrastructure/database.py",
        "infrastructure/safe_regex.py",
    }
    assert {item[0] for item in base_handlers}.issubset(allowed_modules)


def test_zero_trust_policy_upgrade_path_accepts_legacy_resource_without_policy() -> None:
    policy = ZeroTrustPolicy.from_mapping(None)
    assert not policy.enabled
    assert set(policy.allowed_network_trust) == {"trusted", "private", "unknown"}


def test_zero_trust_guard_uses_provider_and_caller_cannot_elevate_context() -> None:
    from arenyxa.enterprise.operations import EnterpriseOperationGuard

    guard = object.__new__(EnterpriseOperationGuard)
    guard._access_context_provider = lambda: {
        "managed_device": False, "device_compliant": False, "mfa_verified": False,
        "network_trust": "unknown", "risk_score": 70, "auth_age_seconds": 300,
    }
    guard.identity = None
    resolved = guard._resolved_access_context({
        "managed_device": True, "device_compliant": True, "mfa_verified": True,
        "network_trust": "trusted", "risk_score": 1, "auth_age_seconds": 1,
    })
    assert resolved["managed_device"] is False
    assert resolved["device_compliant"] is False
    assert resolved["mfa_verified"] is False
    assert resolved["network_trust"] == "unknown"
    assert resolved["risk_score"] == 70
    assert resolved["auth_age_seconds"] == 300


def test_dynamic_access_context_defaults_missing_telemetry_fail_closed() -> None:
    from arenyxa.enterprise.identity_auth import IdentityAuthMixin
    from arenyxa.security.models import Session, TrustDomain
    from datetime import datetime, timedelta
    from arenyxa.compat import UTC

    class Identity(IdentityAuthMixin):
        pass
    identity = Identity()
    identity._lock = __import__("threading").Lock()
    now = datetime.now(UTC)
    identity._session = Session(
        id="session", principal_id="principal", identity_id="identity",
        trust_domain=TrustDomain.ENTERPRISE, issued_at=(now - timedelta(seconds=30)).isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(), identity_generation=1,
        metadata={},
    )
    identity.status = lambda: type("Status", (), {"authenticated": True})()
    context = identity.dynamic_access_context()
    assert context["risk_score"] == 100
    assert context["network_trust"] == "unknown"
    assert context["mfa_verified"] is False
    assert 0 <= context["auth_age_seconds"] <= 120


def test_proxy_dlp_gate_blocks_visible_plaintext_credentials_without_secret_echo(tmp_path: Path) -> None:
    from arenyxa.infrastructure.capture.proxy import InterceptingProxy
    from arenyxa.security.dlp import DlpMode, DlpPolicy, GLOBAL_DLP_ENGINE

    previous = GLOBAL_DLP_ENGINE.policy()
    try:
        GLOBAL_DLP_ENGINE.configure(DlpPolicy(mode=DlpMode.ENFORCE))
        decision = InterceptingProxy._dlp_decision(
            "http", "example.com", 80, "/submit",
            [("Authorization", "Bearer do-not-record-this")], b"",
        )
        assert decision.allowed is False
        assert decision.code == "DLP_EGRESS_BLOCKED"
        assert "do-not-record-this" not in repr(decision)
    finally:
        GLOBAL_DLP_ENGINE.configure(previous)


def test_proxy_source_runs_dlp_before_upstream_send() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/infrastructure/capture/proxy.py").read_text(encoding="utf-8")
    handle = source.index("def _handle_http")
    segment = source[handle:handle + 9000]
    assert segment.index("self._dlp_decision") < segment.index("self._forward_upstream")
    forward = source[source.index("def _forward_upstream"):handle]
    assert "upstream.sendall(request)" in forward
