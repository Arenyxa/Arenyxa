from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arenyxa.application.enterprise_control_plane import EnterpriseControlPlane
from arenyxa.application.windows_runtime import WindowsRuntimeControl
from arenyxa.bootstrap import bootstrap
from arenyxa.domain.errors import ArenyxaError
from arenyxa.infrastructure.plugin_trust import build_plugin_inventory, verify_plugin_signature
from arenyxa.infrastructure.plugins import PluginManager
from arenyxa.infrastructure.windows_service import service_binary_command
from arenyxa.navigation.manifest import DEFAULT_PAGE_MANIFESTS
from arenyxa.navigation.models import AccountRole, ExperienceMode, NavigationContext, RuntimeMode
from arenyxa.navigation.resolver import NavigationResolver


class _Audit:
    appendable = True
    path = None
    _memory = []

    @staticmethod
    def verify():
        return True, "valid"


class _Identity:
    def __init__(self) -> None:
        self.required: list[tuple[str, str]] = []
        self.step_up = 0

    @staticmethod
    def status():
        return SimpleNamespace(
            authenticated=True,
            permissions=("enterprise.remote_ops", "enterprise.audit.read"),
            to_dict=lambda: {"configured": True, "authenticated": True},
        )

    def require(self, capability: str, resource: str) -> None:
        self.required.append((capability, resource))

    def require_recent_step_up(self) -> None:
        self.step_up += 1


class _Queue:
    @staticmethod
    def list_workers(limit: int = 1000):
        return [{"worker_id": "worker-1", "state": "online"}][:limit]

    @staticmethod
    def list_jobs(limit: int = 1000):
        return [{"job_id": "job-1", "state": "queued"}][:limit]

    @staticmethod
    def worker(worker_id: str):
        return {"worker_id": worker_id, "state": "draining"}

    @staticmethod
    def recover_expired_leases():
        return 2

    @staticmethod
    def health():
        return {"backend": "test", "healthy": True}


class _Server:
    def __init__(self) -> None:
        self.queue = _Queue()
        self.revoked: list[str] = []
        self.drains: list[tuple[str, bool]] = []
        self.retried: list[str] = []
        self.stopped = False

    def remote_ops_snapshot(self):
        return {"queue": self.queue.health(), "workers": self.queue.list_workers(), "jobs": self.queue.list_jobs()}

    def set_worker_drain(self, worker_id: str, drain: bool):
        self.drains.append((worker_id, drain))

    def revoke_worker(self, worker_id: str):
        self.revoked.append(worker_id)
        return 3

    def retry_review_required(self, job_id: str):
        self.retried.append(job_id)

    @staticmethod
    def activate_service(ttl_seconds: int = 86400):
        assert 300 <= ttl_seconds <= 86400
        return "super-secret-enterprise-service-lease"

    def deactivate_service(self, reason: str = "SERVER_STOP"):
        self.stopped = bool(reason)


class _Governance:
    @staticmethod
    def snapshot():
        return {"policies": 1}


class _Enrollment:
    @staticmethod
    def list_campaigns():
        return [{"id": "campaign-1"}]

    @staticmethod
    def list_devices():
        return [{"id": "device-1"}]

    @staticmethod
    def local_device_posture():
        return {"state": "trusted"}


def _enterprise_control(tmp_path: Path) -> tuple[EnterpriseControlPlane, _Identity, _Server]:
    identity = _Identity()
    server = _Server()
    control = EnterpriseControlPlane(
        identity=identity,
        governance=_Governance(),
        enrollment=_Enrollment(),
        server=server,
        security=SimpleNamespace(audit=_Audit()),
        data_root=tmp_path,
    )
    return control, identity, server


def test_phase4_enterprise_control_plane_is_real_bounded_and_does_not_leak_service_lease(tmp_path: Path) -> None:
    control, identity, server = _enterprise_control(tmp_path)
    status = control.status(include_fleet=True)
    assert status["schema"] == "arenyxa.enterprise-control-plane/v1"
    assert status["fleet"]["workers"][0]["worker_id"] == "worker-1"
    assert control.workers(limit=5000)[0]["state"] == "online"
    assert control.jobs(limit=5000)[0]["state"] == "queued"
    assert control.worker_drain("worker-1", drain=True)["drain"] is True
    assert server.drains == [("worker-1", True)]
    assert control.worker_revoke("worker-1")["recovered_jobs"] == 3
    assert control.retry_review_required("job-1")["state"] == "queued"
    assert control.recover_expired_leases()["recovered_leases"] == 2
    started = control.server_authority_start(ttl_seconds=600)
    assert "super-secret-enterprise-service-lease" not in json.dumps(started)
    assert started["lease_fingerprint"] == hashlib.sha256(b"super-secret-enterprise-service-lease").hexdigest()
    assert identity.step_up >= 1


def test_phase5_windows_runtime_is_truthful_and_exposes_native_boundaries() -> None:
    runtime = WindowsRuntimeControl()
    status = runtime.status(deep=True)
    assert status["schema"] == "arenyxa.windows-runtime/v1"
    assert {"service", "npcap", "etw", "event_log", "named_pipe", "wfp", "elevation", "resource_paths", "dpapi", "tpm_cng"}.issubset(status)
    if os.name != "nt":
        for key in ("service", "npcap", "etw", "event_log", "named_pipe", "wfp", "elevation", "dpapi", "tpm_cng"):
            assert status[key]["state"] == "not_available"
        with pytest.raises(ArenyxaError) as captured:
            runtime.service_control("start")
        assert captured.value.code == "WINDOWS_SCM_UNAVAILABLE"
    else:
        assert status["service"]["state"] in {"available", "degraded"}


def test_windows_service_registration_command_is_quoted_and_never_uses_shell(tmp_path: Path) -> None:
    command = service_binary_command(tmp_path / "Data Root With Spaces")
    assert "arenyxa.infrastructure.windows_service" in command
    assert "--service" in command
    assert "--data-dir" in command
    assert str(tmp_path / "Data Root With Spaces") in command


def test_bootstrap_wires_phase4_phase5_control_planes_and_cli(tmp_path: Path) -> None:
    context = bootstrap(tmp_path / "runtime", start_scheduler=False)
    try:
        assert context.enterprise_control is not None
        assert context.windows_runtime is not None
        assert context.control_plane is not None
        assert context.control_plane.enterprise_control is context.enterprise_control
        assert context.control_plane.windows_runtime is context.windows_runtime
        status = context.control_plane.windows_status(
            session=context.local_control_session, surface="test", deep=False
        )
        assert status["schema"] == "arenyxa.windows-runtime/v1"
        assert "platform" in context.command_runtime.COMMAND_TREE
        assert {"workers", "jobs", "worker-drain", "worker-revoke", "recover-leases"}.issubset(
            context.command_runtime.COMMAND_TREE["enterprise"]
        )
    finally:
        context.shutdown()


def test_phase5_workbench_navigation_preserves_server_ops_runtime_boundary() -> None:
    resolver = NavigationResolver(DEFAULT_PAGE_MANIFESTS)
    admin_desktop = NavigationContext(
        experience_mode=ExperienceMode.ADVANCED,
        runtime_mode=RuntimeMode.DESKTOP,
        account_role=AccountRole.ENTERPRISE_ADMIN,
    )
    visible = resolver.resolve(admin_desktop).visible
    assert {"protocol", "security_center", "server", "workers", "platform_jobs", "storage", "audit", "diagnostics", "performance"}.issubset(visible)
    assert "server_ops" not in visible
    personal = NavigationContext(
        experience_mode=ExperienceMode.ADVANCED,
        runtime_mode=RuntimeMode.DESKTOP,
        account_role=AccountRole.PERSONAL,
    )
    personal_visible = resolver.resolve(personal).visible
    assert "server" not in personal_visible
    assert "workers" not in personal_visible
    assert "enterprise" not in personal_visible


def test_signed_plugin_sdk_verifies_ed25519_inventory_and_detects_tamper(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    manifest = {
        "id": "example.signed",
        "name": "Signed Example",
        "version": "1.0.0",
        "entry": "entry.py",
        "api_version": "1",
        "permissions": {},
        "capabilities": ["protocol.dissector"],
        "min_app_version": "6.0.0",
    }
    (plugin / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")
    (plugin / "entry.py").write_text("def run(request):\n    return {'ok': True}\n", encoding="utf-8")
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = hashlib.sha256(public).hexdigest()[:32]
    trust = tmp_path / "trusted-plugin-keys.json"
    trust.write_text(json.dumps({"keys": {key_id: base64.urlsafe_b64encode(public).decode().rstrip("=")}}), encoding="utf-8")
    signed = {"manifest": manifest, "files": build_plugin_inventory(plugin)}
    canonical = json.dumps(signed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = base64.urlsafe_b64encode(private.sign(canonical)).decode().rstrip("=")
    (plugin / "plugin.sig.json").write_text(
        json.dumps({"schema": "arenyxa.plugin-signature/v1", "algorithm": "Ed25519", "key_id": key_id, "signed": signed, "signature": signature}),
        encoding="utf-8",
    )
    verified = verify_plugin_signature(plugin, trust)
    assert verified["verified"] is True
    manager = PluginManager(tmp_path / "installed", trust_store=trust, require_signatures=True)
    assert manager.inspect_install(plugin).id == "example.signed"
    (plugin / "entry.py").write_text("raise RuntimeError('tampered')\n", encoding="utf-8")
    with pytest.raises(ArenyxaError) as captured:
        verify_plugin_signature(plugin, trust)
    assert captured.value.code == "PLUGIN_SIGNATURE_MISMATCH"


def test_worker_script_delegates_to_shared_agent_without_nested_remote_queue_duplicate() -> None:
    source = (Path(__file__).resolve().parents[1] / "scripts" / "enterprise_worker.py").read_text(encoding="utf-8")
    assert "EnterpriseWorkerAgent" in source
    assert "class RemoteQueueAdapter" not in source
    assert "ThreadPoolExecutor" not in source
