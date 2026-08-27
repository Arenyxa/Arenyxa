from __future__ import annotations

import asyncio
import base64
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.application.async_runner import AsyncRunOrchestrator
from arenyxa.application.headless_developer_access import HeadlessDeveloperCredential
from arenyxa.cli import build_parser
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.infrastructure.capture.tcp_reassembly import TcpReassemblyManager
from arenyxa.infrastructure.external_tools import ExternalToolProbe


def _public_key() -> str:
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _queue(tmp_path: Path) -> DurableDistributedQueue:
    queue = DurableDistributedQueue(tmp_path / "p0-p1.sqlite")
    queue.register_worker("worker-a", _public_key(), {"slots": 2}, max_slots=2)
    queue.register_worker("worker-b", _public_key(), {"slots": 2}, max_slots=2)
    return queue


def _job(queue: DurableDistributedQueue, key: str = "job") -> str:
    return queue.enqueue(
        "task.run",
        {"task": {"name": key}},
        resource_id="p0-p1",
        permission="workflow.execute",
        idempotency_key=key,
        max_attempts=3,
    )


def test_external_tool_probe_rejects_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: None)
    cap = ExternalToolProbe.tshark()
    assert not cap.usable
    assert cap.detail == "executable not found"


def test_external_tool_probe_enforces_minimum(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _name: "/bin/tool")
    monkeypatch.setattr(
        ExternalToolProbe,
        "_run_probe",
        staticmethod(lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "TShark 2.6.0")),
    )
    cap = ExternalToolProbe.tshark()
    assert cap.available and not cap.compatible
    assert "requires" in cap.detail


def test_tshark_contract_rejects_missing_required_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(_executable: str, args: tuple[str, ...], _timeout: float):
        if tuple(args) == ("-v",):
            return subprocess.CompletedProcess([], 0, "TShark 4.4.0")
        return subprocess.CompletedProcess([], 0, "F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0")

    monkeypatch.setattr(ExternalToolProbe, "_run_probe", staticmethod(fake_run))
    cap = ExternalToolProbe.tshark(
        executable="/opt/tshark",
        required_fields=("frame.number", "frame.time_epoch"),
    )
    assert cap.available and cap.compatible and not cap.usable
    assert cap.missing_capabilities == ("frame.time_epoch",)


def test_headless_credentials_require_callback_and_cli_avoids_env_secret(tmp_path: Path) -> None:
    cred = HeadlessDeveloperCredential(
        tmp_path / "x.aryxdev", tmp_path / "vault.json", lambda: "secret"
    )
    assert callable(cred.passphrase_provider)
    assert not hasattr(cred, "passphrase")
    args = build_parser().parse_args(
        [
            "--developer-bundle", str(cred.bundle_path),
            "--developer-vault", str(cred.vault_path),
            "--developer-passphrase-stdin",
            "version",
        ]
    )
    assert args.developer_passphrase_stdin is True
    cli_source = Path("src/arenyxa/cli.py").read_text(encoding="utf-8")
    assert "ARENYXA_ROOT_PASSPHRASE" not in cli_source
    assert "passphrase-stdin" in cli_source


def test_distributed_queue_invariants_hold_across_expiry_and_reassignment(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    job = _job(queue, "reassign")
    first = queue.lease_next("worker-a", lease_seconds=15)
    assert first is not None
    queue.start_job(job, "worker-a", first.lease_token)
    assert queue.invariant_violations() == []
    assert queue.recover_expired_leases(now=first.lease_expires_at + 1) == 1
    assert queue.invariant_violations() == []
    second = queue.lease_next("worker-b", lease_seconds=15)
    assert second is not None
    with pytest.raises(Exception) as stale:
        queue.complete(job, "worker-a", first.lease_token, {"winner": "stale"})
    assert getattr(stale.value, "code", "") == "DISTRIBUTED_LEASE_STALE"
    queue.start_job(job, "worker-b", second.lease_token)
    queue.complete(job, "worker-b", second.lease_token, {"winner": "fresh"})
    assert queue.invariant_violations() == []


def test_distributed_queue_invariant_audit_detects_counter_corruption(tmp_path: Path) -> None:
    queue = _queue(tmp_path)
    _job(queue, "counter")
    lease = queue.lease_next("worker-a")
    assert lease is not None
    with queue._connection() as connection:  # explicit corruption for invariant test only
        connection.execute("UPDATE distributed_workers SET active_leases=2 WHERE worker_id=?", ("worker-a",))
        connection.commit()
    violations = queue.invariant_violations()
    assert any("worker:worker-a:active-leases" in item for item in violations)
    queue.reconcile_durable_state()
    assert queue.invariant_violations() == []


def test_tcp_reassembly_handles_sequence_wrap_overlap_duplicate_and_close() -> None:
    manager = TcpReassemblyManager()
    key = ("192.0.2.1", 51000, "198.51.100.2", 443)
    first = manager.feed(key, sequence=0xFFFFFFFC, payload=b"ABCD", flags={"ack"})
    assert first.contiguous_bytes == 4
    wrapped = manager.feed(key, sequence=0, payload=b"EFGH", flags={"ack"})
    assert wrapped.stream_bytes == b"ABCDEFGH"
    overlap = manager.feed(key, sequence=2, payload=b"GHijkl", flags={"ack"})
    assert overlap.retransmission is True
    assert overlap.stream_bytes.endswith(b"ijkl")
    duplicate = manager.feed(key, sequence=2, payload=b"GH", flags={"ack"})
    assert duplicate.retransmission is True
    closed = manager.feed(key, sequence=12, payload=b"", flags={"fin"})
    assert closed.closed is True
    assert manager.diagnostics["active_directions"] == 0


def test_tcp_reassembly_pending_budget_is_bounded() -> None:
    manager = TcpReassemblyManager()
    key = ("10.0.0.1", 1, "10.0.0.2", 2)
    manager.feed(key, sequence=100, payload=b"a")
    for index in range(manager.MAX_PENDING_SEGMENTS + 20):
        manager.feed(key, sequence=1000 + index * 32, payload=b"x" * 32)
    diagnostics = manager.diagnostics
    assert diagnostics["retained_bytes"] <= manager.MAX_GLOBAL_BYTES


@pytest.mark.asyncio
async def test_async_storage_boundary_does_not_block_event_loop(store) -> None:
    runner = AsyncRunOrchestrator(store, max_workers=1, request_workers=2)
    ticks = 0
    def slow_persist(run, callback):
        del run, callback
        time.sleep(0.08)

    runner._persist_progress = slow_persist  # type: ignore[method-assign]
    from arenyxa.domain.models import Run

    run = Run(task_id="boundary", task_snapshot={}, total_units=0)

    async def ticker() -> None:
        nonlocal ticks
        stop = asyncio.get_running_loop().time() + 0.06
        while asyncio.get_running_loop().time() < stop:
            ticks += 1
            await asyncio.sleep(0.005)

    try:
        await asyncio.gather(runner._persist_progress_async(run, None), ticker())
        assert ticks >= 5
    finally:
        runner.shutdown(wait=True)


def test_quality_ratchets_are_hardened() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    gate = Path("scripts/architecture_debt_gate.py").read_text(encoding="utf-8")
    assert "fail_under = 40.0" in pyproject
    assert "MAX_BROAD_EXCEPTION_CATCHES = 284" in gate
    assert "CRITICAL_BROAD_EXCEPTION_FILES" in gate
