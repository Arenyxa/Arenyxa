from __future__ import annotations

from pathlib import Path

from arenyxa.enterprise.runtime_storage import (
    PostgreSQLDistributedRuntimeStorage,
    SQLiteDistributedRuntimeStorage,
)
from arenyxa.enterprise.storage_capacity import assess_storage_capacity

ROOT = Path(__file__).resolve().parents[1]


def test_sqlite_capacity_marks_high_worker_fanout_for_postgresql(tmp_path: Path) -> None:
    capabilities = SQLiteDistributedRuntimeStorage(tmp_path / "distributed.sqlite").capabilities
    result = assess_storage_capacity(
        capabilities,
        worker_count=32,
        total_worker_slots=32,
        active_leases=16,
    )
    assert result.severity == "critical"
    assert result.postgresql_recommended is True
    assert result.code == "SQLITE_HIGH_CONCURRENCY_CUTOVER"
    assert "PostgreSQL" in result.guidance


def test_sqlite_capacity_preserves_small_single_host_profile(tmp_path: Path) -> None:
    capabilities = SQLiteDistributedRuntimeStorage(tmp_path / "distributed.sqlite").capabilities
    result = assess_storage_capacity(
        capabilities,
        worker_count=2,
        total_worker_slots=4,
        active_leases=2,
    )
    assert result.severity == "healthy"
    assert result.postgresql_recommended is False


def test_postgresql_capacity_does_not_request_backend_migration() -> None:
    capabilities = PostgreSQLDistributedRuntimeStorage("postgresql://user:secret@example.invalid/db").capabilities
    result = assess_storage_capacity(
        capabilities,
        worker_count=32,
        total_worker_slots=128,
        active_leases=64,
    )
    assert result.severity == "healthy"
    assert result.postgresql_recommended is False


def test_quality_workflows_separate_lightweight_core_from_heavy_capabilities() -> None:
    workflow = (ROOT / ".github" / "workflows" / "quality.yml").read_text(encoding="utf-8")
    integration = (ROOT / ".github" / "workflows" / "capability-integration.yml").read_text(encoding="utf-8")
    assert "scripts/static_quality_gate.py" in workflow
    assert "scripts/architecture_debt_gate.py" in workflow
    assert "tests/test_v68_stability_hardening.py" in workflow
    assert "tests/test_v71_page_runtime_contract.py" in workflow
    assert "QT_QPA_PLATFORM: offscreen" in workflow
    assert 'python-version: "3.11"' in workflow
    assert 'ARENYXA_CI_FORBID_ENVIRONMENT_SKIPS: "1"' in workflow
    assert '.[dev,analysis]' in workflow
    assert "tshark" not in workflow.lower()
    assert "postgres:" not in workflow
    assert "playwright install" not in workflow
    assert "tshark" in integration.lower()
    assert "postgres:" in integration
    assert "test_v71_protocol_differential_tshark.py" in integration
    assert "--require-tshark" in integration
    assert "final_quality_gate.py --full" in integration
    assert "win7_legacy_quality_gate.py" in integration


def test_runtime_storage_capabilities_publish_capacity_envelope(tmp_path: Path) -> None:
    sqlite_caps = SQLiteDistributedRuntimeStorage(tmp_path / "distributed.sqlite").capabilities.as_dict()
    postgres_caps = PostgreSQLDistributedRuntimeStorage("postgresql://user:secret@example.invalid/db").capabilities.as_dict()
    assert sqlite_caps["recommended_total_worker_slots"] == 8
    assert sqlite_caps["high_concurrency_cutover_slots"] == 16
    assert postgres_caps["recommended_total_worker_slots"] >= sqlite_caps["recommended_total_worker_slots"]


def test_sqlite_enterprise_registration_fails_closed_at_cutover(tmp_path: Path) -> None:
    import base64

    import pytest
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from arenyxa.enterprise.distributed import DurableDistributedQueue

    raw = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite")
    queue.register_worker("worker-a", public, {"slots": 15}, max_slots=15, enforce_capacity=True)
    with pytest.raises(Exception) as exc_info:
        queue.register_worker("worker-b", public, {"slots": 1}, max_slots=1, enforce_capacity=True)
    assert "SQLITE_DISTRIBUTED_CAPACITY_EXCEEDED" in str(exc_info.value)
    # Direct diagnostic/benchmark users can still characterize the backend without
    # accidentally changing the production Enterprise admission policy.
    queue.register_worker("benchmark-only", public, {"slots": 1}, max_slots=1)
