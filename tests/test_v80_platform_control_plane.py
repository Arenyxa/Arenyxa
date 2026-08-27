from __future__ import annotations

import hashlib
import json
import threading
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from arenyxa.application.developer_safety import DEVELOPER_TERMS_VERSION
from arenyxa.application.job_system import JobSystem
from arenyxa.bootstrap import bootstrap
from arenyxa.domain.enums import WorkspaceRole
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import new_id, utc_now
from arenyxa.infrastructure.server import create_app


@pytest.fixture()
def context(tmp_path: Path):
    value = bootstrap(tmp_path / "runtime", start_scheduler=False)
    value.settings.developer_mode = True
    value.settings.developer_terms_version = DEVELOPER_TERMS_VERSION
    value.settings.developer_terms_accepted_at = "2026-08-22T12:00:00+00:00"
    value.settings.save(value.paths.root / "settings.json")
    try:
        yield value
    finally:
        value.shutdown()


def test_deep_health_is_connected_to_cli_core_storage_security_and_jobs(context) -> None:
    result = context.command_runtime.execute("health-check --deep")
    health = result["data"]
    assert health["schema"] == "arenyxa.platform-health/v1"
    assert health["status"] == "healthy"
    assert health["components"]["storage"]["details"]["integrity"] == "ok"
    assert health["components"]["storage"]["details"]["platform_jobs_schema"] is True
    assert health["components"]["audit"]["details"]["integrity"] == "valid"
    assert health["components"]["jobs"]["details"]["accepting"] is True
    assert context.control_plane is not None
    assert context.job_system is not None
    assert context.local_control_session is not None
    assert {"health-check", "diagnostics", "job"}.issubset(context.command_runtime.COMMAND_TREE)


def test_diagnostics_export_runs_as_persistent_audited_job_and_redacts_secrets(context) -> None:
    log_path = context.paths.logs / "v8-control-plane.log"
    log_path.write_text(
        "Authorization: Bearer should-not-escape\npassword=also-secret\nnormal=visible\n",
        encoding="utf-8",
    )
    result = context.command_runtime.execute(
        "diagnostics export --output v8-control-plane-diagnostics.zip --timeout 30"
    )["data"]
    assert result["state"] == "succeeded"
    bundle = Path(result["result"]["path"])
    assert bundle.is_file()
    assert bundle.is_relative_to(context.paths.exports)
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == result["result"]["sha256"]
    with zipfile.ZipFile(bundle, "r") as archive:
        assert archive.testzip() is None
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["version"] == "8.1"
        combined_logs = "\n".join(
            archive.read(name).decode("utf-8")
            for name in archive.namelist()
            if name.startswith("logs/")
        )
    assert "should-not-escape" not in combined_logs
    assert "also-secret" not in combined_logs
    assert "[REDACTED]" in combined_logs
    stored = context.store.get_platform_job(result["id"])
    assert stored is not None and stored["state"] == "succeeded"
    valid, reason = context.security.audit.verify()
    assert valid is True, reason


def test_job_system_enforces_cancellation_timeout_and_backpressure(context) -> None:
    assert context.control_plane is not None
    session = context.local_control_session
    assert session is not None
    blocker = threading.Event()

    def blocking(execution):
        while not blocker.wait(0.01):
            execution.report_progress(0.2, "waiting")
        execution.check_cancelled()
        return {"released": True}

    isolated = JobSystem(context.store, context.security, max_workers=1, queue_capacity=1)
    try:
        first = isolated.submit(
            "bounded-one",
            blocking,
            session=session,
            capability="logs.read",
            resource="job:bounded-one",
            surface="test",
            timeout_seconds=5,
        )
        second = isolated.submit(
            "bounded-two",
            blocking,
            session=session,
            capability="logs.read",
            resource="job:bounded-two",
            surface="test",
            timeout_seconds=5,
        )
        with pytest.raises(ArenyxaError) as captured:
            isolated.submit(
                "bounded-three",
                blocking,
                session=session,
                capability="logs.read",
                resource="job:bounded-three",
                surface="test",
                timeout_seconds=5,
            )
        assert captured.value.code == "JOB_BACKPRESSURE"
        cancelled = isolated.cancel(first["id"], session=session, surface="test")
        assert cancelled["message"] == "Cancellation requested"
        blocker.set()
        first_done = isolated.wait(first["id"], 5)
        second_done = isolated.wait(second["id"], 5)
        assert first_done["state"] == "cancelled"
        assert second_done["state"] == "succeeded"
    finally:
        blocker.set()
        isolated.shutdown(wait=True)

    def timeout_operation(execution):
        while True:
            time.sleep(0.01)
            execution.check_cancelled()

    timeout_job = context.job_system.submit(
        "timeout-proof",
        timeout_operation,
        session=session,
        capability="logs.read",
        resource="job:timeout-proof",
        surface="test",
        timeout_seconds=0.05,
    )
    timed_out = context.job_system.wait(timeout_job["id"], 5)
    assert timed_out["state"] == "timed_out"
    assert timed_out["error_code"] == "JOB_TIMEOUT"


def test_platform_job_recovery_marks_orphaned_work_as_interrupted(context) -> None:
    job_id = new_id("job")
    context.store.create_platform_job(
        {
            "id": job_id,
            "kind": "recovery-proof",
            "surface": "test",
            "state": "running",
            "progress": 0.4,
            "message": "orphaned",
            "actor": "test",
            "correlation_id": new_id("corr"),
            "timeout_seconds": 30,
            "created_at": utc_now(),
            "started_at": utc_now(),
        }
    )
    recovered = JobSystem(context.store, context.security, max_workers=1, queue_capacity=1)
    try:
        assert recovered.recovered_jobs >= 1
        row = context.store.get_platform_job(job_id)
        assert row is not None
        assert row["state"] == "interrupted"
        assert row["error_code"] == "JOB_PROCESS_INTERRUPTED"
    finally:
        recovered.shutdown(wait=True)


def test_server_surface_uses_the_same_control_plane_and_security_boundary(tmp_path: Path) -> None:
    token = "v8-admin-token"
    digest = hashlib.sha256(token.encode()).hexdigest()
    app = create_app(tmp_path / "server", {digest: ("v8-admin", WorkspaceRole.ADMIN)})
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app) as client:
        response = client.get("/api/v1/platform/health", headers=headers)
        assert response.status_code == 200
        assert response.json()["components"]["jobs"]["details"]["accepting"] is True
        denied = client.get("/api/v1/platform/jobs")
        assert denied.status_code == 401
        submitted = client.post("/api/v1/platform/diagnostics", headers=headers)
        assert submitted.status_code == 202
        job_id = submitted.json()["id"]
        deadline = time.monotonic() + 10
        payload = {}
        while time.monotonic() < deadline:
            current = client.get(f"/api/v1/platform/jobs/{job_id}", headers=headers)
            assert current.status_code == 200
            payload = current.json()
            if payload["state"] in {"succeeded", "failed", "cancelled", "timed_out"}:
                break
            time.sleep(0.02)
        assert payload["state"] == "succeeded"
        assert Path(payload["result"]["path"]).is_file()
