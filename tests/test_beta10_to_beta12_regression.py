from pathlib import Path

from arenyxa import __release_channel__
from arenyxa.infrastructure.timebase import StableEpochClock

ROOT = Path(__file__).resolve().parents[1]


def test_beta12_preserves_beta11_runtime_hardening():
    assert __release_channel__ == "stable"


def test_stable_epoch_ignores_wall_clock_rollback():
    wall = [1000.0]
    mono = [50.0]
    clock = StableEpochClock(wall=lambda: wall[0], monotonic=lambda: mono[0])
    first = clock.stable_epoch()
    wall[0] = 900.0
    mono[0] = 51.0
    assert clock.stable_epoch() >= first + 1.0


def test_request_admission_checks_host_before_global_gate():
    for rel in ("src/arenyxa/application/run_execution.py", "src/arenyxa/application/async_runner.py"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        host = text.index("self._host_limiter.try_acquire")
        gate = text.index("self._request_gate.try_acquire", host)
        assert host < gate


def test_non_idempotent_fence_and_terminal_update_are_conditional():
    text = (ROOT / "src/arenyxa/enterprise/distributed_queue.py").read_text(encoding="utf-8")
    assert "DISTRIBUTED_SIDE_EFFECT_ALREADY_STARTED" in text
    assert "DISTRIBUTED_SIDE_EFFECT_FENCE_CONFLICT" in text
    assert "state IN ('leased','running') AND lease_worker_id=? AND lease_token_sha256=?" in text


def test_key_protection_downgrade_is_explicit_and_can_fail_closed():
    text = (ROOT / "src/arenyxa/enterprise/enrollment.py").read_text(encoding="utf-8")
    assert "ARENYXA_REQUIRE_TPM" in text
    assert "TPM_KEY_PROTECTION_REQUIRED" in text
    assert "Hardware key protection downgrade" in text


def test_coordinator_certificate_lifetime_and_expiry_header():
    text = (ROOT / "src/arenyxa/enterprise/coordinator.py").read_text(encoding="utf-8")
    assert "COORDINATOR_CERT_VALID_DAYS = 7" in text
    assert '"X-Arenyxa-Cert-Expiry"' in text
