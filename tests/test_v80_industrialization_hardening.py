from __future__ import annotations

import base64
import gc
import io
import logging
import os
import random
import time
import weakref
from concurrent.futures import Future
from pathlib import Path

import pytest

from arenyxa.application.future_callbacks import WeakMethodFutureCallback
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.infrastructure.external_supervisor import ExternalSupervisorClient
from arenyxa.infrastructure.observability import ResilientSinkHandler
from arenyxa.infrastructure.timebase import StableEpochClock
from arenyxa.security.audit import AuditFailurePolicy, AuditLog
from arenyxa.security.key_protection import DPAPIKeyProtectionAdapter, DPAPIScope, detect_dpapi_scope
from arenyxa.security.models import TrustDomain
from arenyxa.security.sql_safety import sql_identifier


def _worker_public_key() -> str:
    return base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")


def _queue(tmp_path: Path, *, clock: StableEpochClock | None = None, grace: float = 5.0) -> DurableDistributedQueue:
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite", clock=clock, lease_grace_seconds=grace)
    queue.register_worker("worker-a", _worker_public_key(), {"slots": 1}, max_slots=1)
    return queue


def _enqueue(queue: DurableDistributedQueue, key: str, *, mode: str = "idempotent") -> str:
    return queue.enqueue(
        "task.run",
        {"task": key},
        resource_id="resource-a",
        permission="workflow.execute",
        idempotency_key=key,
        side_effect_mode=mode,
        max_attempts=3,
    )


def test_stable_epoch_clock_ignores_wall_rollback_and_fast_forward() -> None:
    wall = [1_000.0]
    mono = [10.0]
    clock = StableEpochClock(wall=lambda: wall[0], monotonic=lambda: mono[0])
    assert clock.stable_epoch() == pytest.approx(1_000.0)

    mono[0] += 5.0
    wall[0] -= 900.0
    assert clock.stable_epoch() == pytest.approx(1_005.0)
    assert clock.snapshot().wall_drift_seconds < -800.0

    mono[0] += 7.0
    wall[0] += 10_000.0
    assert clock.stable_epoch() == pytest.approx(1_012.0)
    assert clock.snapshot().wall_drift_seconds > 9_000.0

    # Suspend/resume is represented by monotonic elapsed time.  The projected epoch advances
    # once, without consulting a potentially NTP-adjusted wall clock.
    mono[0] += 3_600.0
    assert clock.stable_epoch() == pytest.approx(4_612.0)


def test_distributed_lease_is_not_expired_by_wall_clock_jump(tmp_path: Path) -> None:
    wall = [2_000.0]
    mono = [100.0]
    clock = StableEpochClock(wall=lambda: wall[0], monotonic=lambda: mono[0])
    queue = _queue(tmp_path, clock=clock, grace=5.0)
    job_id = _enqueue(queue, "clock-safe-job")
    lease = queue.lease_next("worker-a", lease_seconds=15)
    assert lease is not None
    queue.start_job(job_id, "worker-a", lease.lease_token)

    wall[0] += 100_000.0
    mono[0] += 2.0
    assert queue.recover_expired_leases() == 0
    assert queue.job(job_id)["state"] == "running"

    wall[0] -= 200_000.0
    mono[0] += 20.0
    assert queue.recover_expired_leases() == 1
    assert queue.job(job_id)["state"] == "queued"

    # The old fencing token cannot commit after recovery/handover.
    with pytest.raises(Exception) as stale:
        queue.complete(job_id, "worker-a", lease.lease_token, {"unsafe": True})
    assert getattr(stale.value, "code", "") == "DISTRIBUTED_LEASE_STALE"


def test_network_partition_handover_preserves_non_idempotent_fence(tmp_path: Path) -> None:
    idem_queue = _queue(tmp_path / "idem", grace=5.0)

    idem_job = _enqueue(idem_queue, "partition-idempotent")
    idem_lease = idem_queue.lease_next("worker-a")
    assert idem_lease is not None and idem_lease.job_id == idem_job
    idem_queue.start_job(idem_job, "worker-a", idem_lease.lease_token)
    assert idem_queue.handover_lease(idem_job, "worker-a", idem_lease.lease_token, reason="NETWORK_PARTITION") == "queued"

    queue = _queue(tmp_path / "non-idem", grace=5.0)
    non_idem_job = _enqueue(queue, "partition-non-idempotent", mode="non_idempotent")
    non_idem_lease = queue.lease_next("worker-a")
    assert non_idem_lease is not None and non_idem_lease.job_id == non_idem_job
    queue.start_job(non_idem_job, "worker-a", non_idem_lease.lease_token)
    queue.mark_side_effect_started(non_idem_job, "worker-a", non_idem_lease.lease_token)
    assert (
        queue.handover_lease(
            non_idem_job,
            "worker-a",
            non_idem_lease.lease_token,
            reason="NETWORK_PARTITION",
        )
        == "review_required"
    )
    assert queue.job(non_idem_job)["state"] == "review_required"


def _audit_emit(audit: AuditLog, action: str) -> None:
    audit.emit(
        actor="industrial-test",
        action=action,
        resource="test-resource",
        decision="allow",
        trust_domain=TrustDomain.ENTERPRISE,
    )


def test_audit_fail_closed_refuses_to_extend_tampered_primary_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    first = AuditLog(path)
    _audit_emit(first, "before-tamper")
    original = path.read_bytes()
    path.write_bytes(original + b"not-json\n")

    audit = AuditLog(path, failure_policy=AuditFailurePolicy.FAIL_CLOSED)
    valid, _reason = audit.verify()
    assert valid is False
    with pytest.raises(Exception) as blocked:
        _audit_emit(audit, "after-tamper")
    assert getattr(blocked.value, "code", "") == "AUDIT_INTEGRITY_BROKEN"
    assert path.read_bytes() == original + b"not-json\n"


def test_audit_fail_operational_keeps_primary_evidence_and_uses_recovery_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    seed = AuditLog(path)
    _audit_emit(seed, "before-tamper")
    tampered = path.read_bytes() + b"corrupted-evidence\n"
    path.write_bytes(tampered)

    recovery = tmp_path / "audit.recovery.jsonl"
    audit = AuditLog(
        path,
        failure_policy=AuditFailurePolicy.FAIL_OPERATIONAL,
        recovery_path=recovery,
    )
    _audit_emit(audit, "business-continues")

    assert path.read_bytes() == tampered
    assert recovery.is_file()
    valid, reason = audit.recovery_verify()
    assert (valid, reason) == (True, "ok")
    status = audit.status()
    assert status["mode"] == "recovery"
    assert status["failure_policy"] == "fail_operational"
    assert status["primary_integrity_error"]
    assert status["emergency_memory_events"] == 0


class _ExplodingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        raise OSError("simulated disk full/permission/handler failure")


class _CapturingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def test_business_logging_sink_failure_isolated_from_caller() -> None:
    fallback = _CapturingHandler()
    sink = ResilientSinkHandler(_ExplodingHandler(), fallback)
    record = logging.LogRecord("arenyxa.test", logging.ERROR, __file__, 1, "survives", (), None)

    sink.handle(record)

    assert fallback.messages == ["survives"]
    assert sink.status()["primary_failures"] == 1
    assert "OSError" in sink.status()["last_error"]


def test_external_supervisor_detects_event_loop_stall_out_of_process(tmp_path: Path) -> None:
    client = ExternalSupervisorClient(tmp_path / "diagnostics", stale_seconds=1.0)
    client.start()
    try:
        client.heartbeat("ui_thread", {"sequence": 1})
        deadline = time.monotonic() + 4.0
        incidents: list[Path] = []
        while time.monotonic() < deadline:
            incidents = list((tmp_path / "diagnostics").glob("external-stall-ui_thread-*.json"))
            if incidents:
                break
            time.sleep(0.1)
        assert incidents, client.snapshot()
        assert client.snapshot()["running"] is True
    finally:
        client.stop()


def test_dpapi_scope_auto_separates_desktop_and_service(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARENYXA_DPAPI_SCOPE", raising=False)
    monkeypatch.setenv("ARENYXA_RUNTIME_MODE", "desktop")
    assert detect_dpapi_scope() is DPAPIScope.USER
    monkeypatch.setenv("ARENYXA_RUNTIME_MODE", "service")
    assert detect_dpapi_scope() is DPAPIScope.MACHINE
    monkeypatch.setenv("ARENYXA_DPAPI_SCOPE", "user")
    assert detect_dpapi_scope() is DPAPIScope.USER


def test_dpapi_envelope_records_scope_and_accepts_legacy_ciphertext() -> None:
    ciphertext = b"opaque-dpapi-bytes"
    encoded = DPAPIKeyProtectionAdapter._encode_envelope(DPAPIScope.MACHINE, ciphertext)
    assert DPAPIKeyProtectionAdapter._decode_envelope(encoded) == (DPAPIScope.MACHINE, ciphertext)
    assert DPAPIKeyProtectionAdapter._decode_envelope(ciphertext) == (None, ciphertext)


def test_future_callback_does_not_keep_owner_alive() -> None:
    calls: list[str] = []

    class Owner:
        def done(self, future: Future[object]) -> None:
            calls.append(str(future.result()))

    owner = Owner()
    ref = weakref.ref(owner)
    future: Future[object] = Future()
    future.add_done_callback(WeakMethodFutureCallback(owner, "done"))
    del owner
    gc.collect()
    assert ref() is None
    future.set_result("finished")
    assert calls == []


def test_sql_identifier_fuzz_rejects_injection_unicode_and_overlength() -> None:
    valid = ["x", "_private", "table_123", "ArenyxaNode"]
    for value in valid:
        assert sql_identifier(value) == f'"{value}"'

    invalid = [
        "", "1name", "name-with-dash", "name;drop table x", 'name"quoted', "schema.table",
        "naïve", "表", "x\x00y", "x y", "x" * 64,
    ]
    rng = random.Random(80)
    alphabet = "';- /\\\t\n()[]{}😀"
    invalid.extend("safe" + "".join(rng.choice(alphabet) for _ in range(5)) for _ in range(100))
    for value in invalid:
        with pytest.raises(ValueError):
            sql_identifier(value)

    long_sqlite = "x" * 200
    assert sql_identifier(long_sqlite, dialect="sqlite") == f'"{long_sqlite}"'
    with pytest.raises(ValueError):
        sql_identifier(long_sqlite, dialect="postgresql")
