from __future__ import annotations

import time
from pathlib import Path

import pytest

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import RequestSpec
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage
from arenyxa.infrastructure.http_client import HttpFetcher
from arenyxa.infrastructure.safe_regex import safe_search, safe_sub
from arenyxa.platform_compat import LEGACY_RUNTIME, MODERN_RUNTIME


def test_sqlite_runtime_storage_is_backend_neutral(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite")
    capabilities = queue.storage_capabilities
    assert {
        "backend": capabilities["backend"],
        "multi_host_writers": capabilities["multi_host_writers"],
        "row_lock_skip_locked": capabilities["row_lock_skip_locked"],
        "external_server": capabilities["external_server"],
    } == {
        "backend": "sqlite",
        "multi_host_writers": False,
        "row_lock_skip_locked": False,
        "external_server": False,
    }
    assert capabilities["write_model"] == "serialized-wal"
    assert capabilities["recommended_parallel_writers"] == 1


def test_postgresql_backend_declares_multi_host_queue_semantics() -> None:
    backend = PostgreSQLDistributedRuntimeStorage("postgresql://user:secret@example/db")
    assert backend.capabilities.multi_host_writers is True
    assert backend.capabilities.row_lock_skip_locked is True
    sql = backend.lease_candidate_sql().upper()
    assert "LIMIT 1 FOR UPDATE SKIP LOCKED" in sql
    assert "ACTIVE_LEASES<MAX_SLOTS" in backend.claim_worker_slot_sql().upper()
    assert "STATE='ACTIVE'" in backend.claim_worker_slot_sql().upper()
    assert "FOR UPDATE SKIP LOCKED" in backend.expired_lease_candidates_sql().upper()
    assert "FOR UPDATE OF J SKIP LOCKED" in backend.invalid_lease_candidates_sql().upper()
    assert "SECRET" not in repr(backend.capabilities)


def test_http_transport_has_modern_and_explicit_legacy_paths() -> None:
    legacy = HttpFetcher(transport="urllib")
    assert legacy.transport == "urllib"
    modern = HttpFetcher(transport="auto")
    assert modern.transport in {"urllib", "httpx"}
    assert RequestSpec("https://example.com").validate() == []


def test_safe_regex_preserves_search_and_sub_semantics() -> None:
    match = safe_search(r"(ab+)", "xxabbbzz")
    assert match is not None
    assert match.group(0) == "abbb"
    assert match.group(1) == "abbb"
    assert safe_sub(r"b+", "B", "abbbc") == "aBc"


def test_catastrophic_regex_is_hard_timed_out() -> None:
    started = time.monotonic()
    with pytest.raises(ArenyxaError) as raised:
        safe_search(r"(a+)+$", "a" * 100_000 + "!", timeout_seconds=0.10)
    assert raised.value.code == "REGEX_TIMEOUT"
    assert time.monotonic() - started < 2.0


def test_legacy_lane_is_feature_frozen_not_parity_blocking() -> None:
    assert MODERN_RUNTIME.feature_policy == "active-development"
    assert MODERN_RUNTIME.feature_parity_required is True
    assert LEGACY_RUNTIME.feature_policy == "security-maintenance"
    assert LEGACY_RUNTIME.feature_parity_required is False
