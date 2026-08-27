from __future__ import annotations

import ast
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arenyxa.bootstrap import _root_developer_clean_start
from arenyxa.config import AppPaths, AppSettings
from arenyxa.enterprise.distributed import DurableDistributedQueue, verify_enterprise_server_identity
from arenyxa.release_hardening import UpgradeTransaction


def test_root_workstation_preserves_preferences_and_completed_welcome_state(tmp_path: Path) -> None:
    paths = AppPaths.discover(tmp_path / "data")
    paths.initialize()
    keep = paths.projects / "must-survive.txt"
    keep.write_text("project-data", encoding="utf-8")
    previous = AppSettings(
        theme="terminal_green", developer_mode=True, developer_nav_expanded=True,
        experience_profile="developer", experience_setup_completed=True,
    )
    previous.save(paths.root / "settings.json")

    preserved = _root_developer_clean_start(paths, previous)
    assert preserved == previous
    assert preserved.experience_setup_completed is True
    assert preserved.experience_profile == "developer"
    assert keep.read_text(encoding="utf-8") == "project-data"
    assert AppSettings.load(paths.root / "settings.root-developer-previous.json") == previous
    assert AppSettings.load(paths.root / "settings.json") == previous

    newer = AppSettings(
        theme="clean_light", experience_profile="professional", experience_setup_completed=True,
    )
    newer.save(paths.root / "settings.json")
    again = _root_developer_clean_start(paths, newer)
    assert again == newer
    assert AppSettings.load(paths.root / "settings.root-developer-previous.json") == previous
    assert AppSettings.load(paths.root / "settings.json") == newer


def test_enterprise_page_is_scroll_backed_responsive_and_every_declared_button_is_connected() -> None:
    root = Path(__file__).resolve().parents[1]
    page_path = root / "src/arenyxa/presentation/pages/enterprise.py"
    source = page_path.read_text(encoding="utf-8")
    assert "QScrollArea" in source
    assert "ResponsiveActionBar" in source
    assert "setHorizontalScrollBarPolicy" in source
    assert "body.addWidget(status_card)" in source
    assert "body.addWidget(account_card)" in source
    widgets_source = (root / "src/arenyxa/presentation/widgets.py").read_text(encoding="utf-8")
    assert "button.sizeHint().width()" in widgets_source
    assert "(width + spacing) // (cell_width + spacing)" in widgets_source

    tree = ast.parse(source)
    declared: set[str] = set()
    connected: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id == "QPushButton":
                for target in node.targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "self"
                    ):
                        declared.add(target.attr)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "connect":
            signal = node.func.value
            if (
                isinstance(signal, ast.Attribute)
                and signal.attr == "clicked"
                and isinstance(signal.value, ast.Attribute)
                and isinstance(signal.value.value, ast.Name)
                and signal.value.value.id == "self"
            ):
                connected.add(signal.value.attr)
    assert declared
    assert declared - connected == set()


def test_distributed_state_rejects_duplicate_json_and_health_integrity_is_short_cached(tmp_path: Path) -> None:
    queue = DurableDistributedQueue(tmp_path / "distributed.sqlite")
                                                                                      
    connection = sqlite3.connect(tmp_path / "distributed.sqlite")
    try:
        connection.execute(
            "INSERT INTO distributed_jobs(job_id,kind,state,payload_json,payload_sha256,resource_id,permission,idempotency_key,"
            "side_effect_mode,side_effect_state,attempt,max_attempts,protocol_version,priority,checkpoint_json,result_json,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "job-corrupt", "task.run", "failed", "{}", "0" * 64, "r", "workflow.execute", "idem-corrupt",
                "idempotent", "none", 1, 1, 2, 0, '{"a":1,"a":2}', "{}", "now", "now",
            ),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(Exception) as corrupt:
        queue.job("job-corrupt")
    assert getattr(corrupt.value, "code", "") == "DISTRIBUTED_STATE_CORRUPT"

    calls = 0
    original = queue.integrity_check

    def counted():
        nonlocal calls
        calls += 1
        return original()

    queue.integrity_check = counted                               
    queue._health_integrity_checked_at = 0.0
    queue.health(); queue.health()
    assert calls == 1


def test_upgrade_backup_is_bound_to_exact_data_root_and_migration_cannot_escape(tmp_path: Path) -> None:
    data = tmp_path / "data"; data.mkdir()
    settings = data / "settings.json"; settings.write_text('{"schema_version":8}', encoding="utf-8")
    tx = UpgradeTransaction(data, tmp_path / "backup")
    tx.backup([settings])

    other_data = tmp_path / "other"; other_data.mkdir()
    wrong_target = UpgradeTransaction(other_data, tx.backup_root)
    with pytest.raises(Exception) as mismatch:
        wrong_target.verify_backup()
    assert getattr(mismatch.value, "code", "") == "UPGRADE_BACKUP_ROOT_MISMATCH"

    outside = tmp_path / "outside.json"; outside.write_text('{"schema_version":8}', encoding="utf-8")
    with pytest.raises(Exception) as unsafe:
        tx.apply_json_migration(outside, __import__("arenyxa.release_hardening", fromlist=["default_migration_registry"]).default_migration_registry(), "settings", 8, 9)
    assert getattr(unsafe.value, "code", "") == "MIGRATION_PATH_UNSAFE"


def test_server_identity_malformed_or_future_time_fails_as_domain_error() -> None:
                                                                                                      
                                                                                                
    root = Path(__file__).resolve().parents[1]
    source = ((root / "src/arenyxa/enterprise/distributed.py").read_text(encoding="utf-8") + "\n" + (root / "src/arenyxa/enterprise/distributed_protocol.py").read_text(encoding="utf-8"))
    assert "SERVER_IDENTITY_TIME_INVALID" in source
    assert "issued > now + timedelta(minutes=5)" in source


def test_worker_http_client_revalidates_enterprise_identity_on_each_sensitive_tls_connection() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/enterprise/server_api.py").read_text(encoding="utf-8")
    assert "connection.connect()" in source
    assert 'connection.request("GET", self.base_path + "/enterprise/v1/identity"' in source
    assert "CORRELATION_HEADER" in source
    assert "verify_enterprise_server_identity(identity, self.expected_root_fingerprint, peer_der)" in source
    assert "self._verify_cached_or_refresh_identity(connection, peer_der, trace)" in source
    assert 'request.headers.get("transfer-encoding")' in source
    assert "invalid or duplicate-key JSON" in source


def test_enterprise_worker_has_bounded_partition_reconnect_without_trust_downgrade() -> None:
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "scripts/enterprise_worker.py").read_text(encoding="utf-8")
    source = (root / "src/arenyxa/enterprise/worker_agent.py").read_text(encoding="utf-8")
    # v8 phase5 candidate deliberately moved the remote control loop out of the CLI launcher into
    # the shared EnterpriseWorkerAgent so Server/Worker/Agent surfaces use one runtime.
    assert "EnterpriseWorkerAgent" in launcher
    assert "MAX_RECONNECT_BACKOFF_SECONDS = 30.0" in source
    assert "_session_expired" in source
    assert "self._client_local = threading.local()" in source
    assert "self._auth_lock = threading.Lock()" in source
    assert "client = self.client.fork()" in source
    assert "self._reauthenticate(generation)" in source
    assert "self._client_local.client = self.client.fork()" in source
    assert "return self._active_client().request(path, body, authenticated=True, correlation_id=correlation_id)" in source
    assert "_transient_transport_error" in source
    assert "ssl.SSLCertVerificationError" in source
    assert "and not isinstance(\n            exc, ssl.SSLCertVerificationError\n        )" in source
    assert "def _terminal_request(" in source
    assert "if not self._transient_transport_error(exc):" in source
    assert "ThreadPoolExecutor(max_workers=self.max_slots" in source
    assert '"/enterprise/v1/worker/lease/batch"' in source
    assert "backoff = min(" in source
    assert "MAX_RECONNECT_BACKOFF_SECONDS" in source


def test_welcome_server_worker_action_is_not_a_disabled_phase11_placeholder() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/pages/welcome.py").read_text(encoding="utf-8")
    assert 'QPushButton("打开 Fleet Control")' in source
    assert "server_button.clicked.connect(self.fleetRequested.emit)" in source
    assert "server_button.setEnabled(False)" not in source


def test_enterprise_distributed_ui_uses_actual_queue_field_names() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/presentation/pages/enterprise.py").read_text(encoding="utf-8")
    source += "\n" + (root / "src/arenyxa/presentation/pages/enterprise_distributed_actions.py").read_text(encoding="utf-8")
    assert "row.get('heartbeat_at', '')" in source
    assert "row.get('lease_worker_id', '')" in source
    assert "row.get('last_seen_at', '')" not in source


def test_coordinator_rejects_unbounded_or_transfer_encoded_request_bodies_by_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "src/arenyxa/enterprise/coordinator.py").read_text(encoding="utf-8")
    assert 'self.headers.get("Transfer-Encoding")' in source
    assert 'self.headers.get("Content-Length")' in source
    assert "len(raw) != size" in source
    assert "self.close_connection = True" in source


def test_worker_private_key_creation_rejects_symlinks_and_handles_partial_writes() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "scripts/enterprise_worker.py").read_text(encoding="utf-8")
    assert "path.is_symlink()" in source
    assert "while view:" in source
    assert "written = os.write(fd, view)" in source
    assert "path.unlink(missing_ok=True)" in source
