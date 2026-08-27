from __future__ import annotations

from arenyxa.security.sql_safety import sql_placeholders, sqlite_wal_checkpoint
import hashlib
import json
import logging
import os
import sqlite3
import tempfile
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from arenyxa.domain.enums import CaptureSource, RunStatus, TaskStatus
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import (
    CaptureSession,
    DatasetRevision,
    FieldSpec,
    NetworkEvent,
    Project,
    ProjectSource,
    RequestSpec,
    ResultRecord,
    RetryPolicy,
    Run,
    Task,
    utc_now,
)
from arenyxa.domain.network import NetworkNormalizer
from arenyxa.infrastructure.atomic_io import fsync_existing_file

LOGGER = logging.getLogger(__name__)


class _ClosingConnection(sqlite3.Connection):
    

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        try:
            return bool(super().__exit__(exc_type, exc, tb))
        finally:
            self.close()


MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        status TEXT NOT NULL,
        tags_json TEXT NOT NULL,
        parser_hint TEXT NOT NULL,
        definition_json TEXT NOT NULL,
        snapshot_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        deleted_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_tasks_status_updated ON tasks(status, updated_at DESC);
    CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id),
        status TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        stage TEXT NOT NULL,
        completed_units INTEGER NOT NULL DEFAULT 0,
        total_units INTEGER,
        request_count INTEGER NOT NULL DEFAULT 0,
        success_count INTEGER NOT NULL DEFAULT 0,
        failure_count INTEGER NOT NULL DEFAULT 0,
        result_count INTEGER NOT NULL DEFAULT 0,
        retry_count INTEGER NOT NULL DEFAULT 0,
        error_code TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        schema_version INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_runs_task_created ON runs(task_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_runs_status_created ON runs(status, created_at DESC);
    CREATE TABLE IF NOT EXISTS result_records (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id),
        run_id TEXT NOT NULL REFERENCES runs(id),
        source_url TEXT NOT NULL,
        fetched_at TEXT NOT NULL,
        data_json TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        quality_flags_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_results_run_id ON result_records(run_id, id);
    CREATE INDEX IF NOT EXISTS idx_results_task_time ON result_records(task_id, fetched_at DESC);
    CREATE INDEX IF NOT EXISTS idx_results_hash ON result_records(task_id, content_hash);
    CREATE TABLE IF NOT EXISTS schedules (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES tasks(id),
        rule_json TEXT NOT NULL,
        timezone TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        next_run_at TEXT,
        last_run_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS export_jobs (
        id TEXT PRIMARY KEY,
        run_id TEXT,
        format TEXT NOT NULL,
        destination TEXT NOT NULL,
        status TEXT NOT NULL,
        row_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        finished_at TEXT,
        error_code TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS capture_sessions (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        state TEXT NOT NULL,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        event_count INTEGER NOT NULL DEFAULT 0,
        bytes_captured INTEGER NOT NULL DEFAULT 0,
        dropped_events INTEGER NOT NULL DEFAULT 0,
        filter_expression TEXT NOT NULL DEFAULT '',
        permission_state TEXT NOT NULL,
        schema_version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS network_events (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id),
        source_type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        process_ref TEXT,
        flow_ref TEXT,
        request_ref TEXT,
        protocol TEXT NOT NULL,
        direction TEXT NOT NULL,
        size INTEGER NOT NULL,
        method TEXT,
        url TEXT,
        status INTEGER,
        host TEXT,
        timing_json TEXT NOT NULL,
        request_headers_json TEXT NOT NULL,
        response_headers_json TEXT NOT NULL,
        request_body_ref TEXT,
        response_body_ref TEXT,
        sensitivity_json TEXT NOT NULL,
        initiator TEXT,
        metadata_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_network_session_time ON network_events(session_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_network_host_status ON network_events(host, status);
    CREATE TABLE IF NOT EXISTS capture_chunks (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id),
        sequence INTEGER NOT NULL,
        path TEXT NOT NULL,
        byte_size INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        committed_at TEXT NOT NULL,
        UNIQUE(session_id, sequence)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS dataset_revisions (
        id TEXT PRIMARY KEY,
        dataset_id TEXT NOT NULL,
        parent_revision TEXT,
        label TEXT,
        source_run_ids_json TEXT NOT NULL,
        schema_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_revisions_dataset_time ON dataset_revisions(dataset_id, created_at DESC);
    CREATE TABLE IF NOT EXISTS revision_records (
        revision_id TEXT NOT NULL REFERENCES dataset_revisions(id),
        record_identity TEXT NOT NULL,
        data_json TEXT NOT NULL,
        data_hash TEXT NOT NULL,
        PRIMARY KEY(revision_id, record_identity)
    );
    CREATE TABLE IF NOT EXISTS workflows (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        definition_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS visualizations (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        dataset_ref TEXT NOT NULL,
        chart_type TEXT NOT NULL,
        config_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS browser_profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        config_json TEXT NOT NULL,
        secret_refs_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS plugins (
        id TEXT PRIMARY KEY,
        version TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        permissions_json TEXT NOT NULL,
        installed_at TEXT NOT NULL,
        last_error TEXT
    );
    CREATE TABLE IF NOT EXISTS workspaces (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS workspace_members (
        workspace_id TEXT NOT NULL REFERENCES workspaces(id),
        actor_id TEXT NOT NULL,
        role TEXT NOT NULL,
        PRIMARY KEY(workspace_id, actor_id)
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        workspace_id TEXT,
        action TEXT NOT NULL,
        object_type TEXT NOT NULL,
        object_id TEXT,
        outcome TEXT NOT NULL,
        details_json TEXT NOT NULL
    );
    """,
    """
    CREATE VIRTUAL TABLE IF NOT EXISTS local_search USING fts5(
        object_type UNINDEXED,
        object_id UNINDEXED,
        title,
        url,
        content,
        tokenize='unicode61'
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS run_result_hashes (
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        content_hash TEXT NOT NULL,
        PRIMARY KEY(run_id, content_hash)
    ) WITHOUT ROWID;
    INSERT OR IGNORE INTO run_result_hashes(run_id, content_hash)
        SELECT run_id, content_hash FROM result_records;
    """,
    """
    CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        workspace_id TEXT REFERENCES workspaces(id) ON DELETE SET NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        tags_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_projects_workspace_updated ON projects(workspace_id, updated_at DESC);
    CREATE TABLE IF NOT EXISTS project_sources (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        config_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_project_sources_project_kind ON project_sources(project_id, kind);
    CREATE TABLE IF NOT EXISTS capture_bindings (
        session_id TEXT PRIMARY KEY REFERENCES capture_sessions(id) ON DELETE CASCADE,
        project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
        source_id TEXT REFERENCES project_sources(id) ON DELETE SET NULL
    );
    CREATE INDEX IF NOT EXISTS idx_capture_bindings_project ON capture_bindings(project_id, session_id);
    CREATE TABLE IF NOT EXISTS network_flows (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        source_type TEXT NOT NULL,
        protocol TEXT NOT NULL,
        transport TEXT NOT NULL,
        local_address TEXT,
        remote_address TEXT,
        process_ref TEXT,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        event_count INTEGER NOT NULL DEFAULT 0,
        bytes_seen INTEGER NOT NULL DEFAULT 0,
        metadata_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_network_flows_session_time ON network_flows(session_id, first_seen, id);
    CREATE TABLE IF NOT EXISTS network_projection_events (
        event_id TEXT PRIMARY KEY REFERENCES network_events(id) ON DELETE CASCADE,
        projected_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS http_requests (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE REFERENCES network_events(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        flow_id TEXT REFERENCES network_flows(id) ON DELETE SET NULL,
        timestamp TEXT NOT NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        host TEXT NOT NULL,
        query_json TEXT NOT NULL DEFAULT '{}',
        headers_json TEXT NOT NULL DEFAULT '{}',
        body_ref TEXT,
        initiator TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_http_requests_session_time ON http_requests(session_id, timestamp, id);
    CREATE INDEX IF NOT EXISTS idx_http_requests_host_method ON http_requests(host, method);
    CREATE TABLE IF NOT EXISTS http_responses (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE REFERENCES http_requests(id) ON DELETE CASCADE,
        event_id TEXT NOT NULL REFERENCES network_events(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        timestamp TEXT NOT NULL,
        status INTEGER,
        headers_json TEXT NOT NULL DEFAULT '{}',
        body_ref TEXT,
        content_type TEXT NOT NULL DEFAULT '',
        size INTEGER NOT NULL DEFAULT 0,
        timing_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_http_responses_session_status ON http_responses(session_id, status);
    CREATE TABLE IF NOT EXISTS dns_transactions (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE REFERENCES network_events(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        timestamp TEXT NOT NULL,
        query_name TEXT NOT NULL,
        query_type TEXT NOT NULL,
        answers_json TEXT NOT NULL DEFAULT '[]',
        elapsed_ms REAL,
        error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_dns_session_query ON dns_transactions(session_id, query_name);
    CREATE TABLE IF NOT EXISTS tls_handshakes (
        id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL UNIQUE REFERENCES network_events(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        flow_id TEXT REFERENCES network_flows(id) ON DELETE SET NULL,
        timestamp TEXT NOT NULL,
        host TEXT NOT NULL,
        version TEXT NOT NULL DEFAULT '',
        cipher TEXT NOT NULL DEFAULT '',
        alpn TEXT NOT NULL DEFAULT '',
        certificate_ref TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_tls_session_host ON tls_handshakes(session_id, host);
    CREATE TABLE IF NOT EXISTS websocket_channels (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        flow_id TEXT REFERENCES network_flows(id) ON DELETE SET NULL,
        url TEXT NOT NULL DEFAULT '',
        host TEXT NOT NULL DEFAULT '',
        opened_at TEXT NOT NULL,
        closed_at TEXT,
        message_count INTEGER NOT NULL DEFAULT 0,
        bytes_seen INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_ws_channels_session ON websocket_channels(session_id, opened_at);
    CREATE TABLE IF NOT EXISTS websocket_messages (
        id TEXT PRIMARY KEY,
        channel_id TEXT NOT NULL REFERENCES websocket_channels(id) ON DELETE CASCADE,
        event_id TEXT NOT NULL UNIQUE REFERENCES network_events(id) ON DELETE CASCADE,
        timestamp TEXT NOT NULL,
        direction TEXT NOT NULL,
        opcode TEXT NOT NULL,
        size INTEGER NOT NULL DEFAULT 0,
        payload_ref TEXT,
        metadata_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX IF NOT EXISTS idx_ws_messages_channel_time ON websocket_messages(channel_id, timestamp, id);
    """,
    """
    CREATE TABLE IF NOT EXISTS network_bodies (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        sha256 TEXT NOT NULL,
        stored_sha256 TEXT NOT NULL,
        byte_size INTEGER NOT NULL DEFAULT 0,
        stored_size INTEGER NOT NULL DEFAULT 0,
        content_type TEXT NOT NULL DEFAULT '',
        encoding TEXT NOT NULL DEFAULT '',
        storage_kind TEXT NOT NULL DEFAULT 'file',
        storage_ref TEXT NOT NULL DEFAULT '',
        truncated INTEGER NOT NULL DEFAULT 0,
        sensitive INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_network_bodies_session_sha ON network_bodies(session_id, sha256);
    CREATE INDEX IF NOT EXISTS idx_network_bodies_session_created ON network_bodies(session_id, created_at, id);
    """,
    """
    CREATE TABLE IF NOT EXISTS api_map_snapshots (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        endpoint_count INTEGER NOT NULL DEFAULT 0,
        source_event_count INTEGER NOT NULL DEFAULT 0,
        host_count INTEGER NOT NULL DEFAULT 0,
        graphql_endpoint_count INTEGER NOT NULL DEFAULT 0,
        pagination_endpoint_count INTEGER NOT NULL DEFAULT 0,
        definition_json TEXT NOT NULL,
        schema_version INTEGER NOT NULL DEFAULT 6
    );
    CREATE INDEX IF NOT EXISTS idx_api_map_snapshots_session_created
        ON api_map_snapshots(session_id, created_at DESC, id);
    CREATE TABLE IF NOT EXISTS api_endpoints (
        id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL REFERENCES api_map_snapshots(id) ON DELETE CASCADE,
        session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
        method TEXT NOT NULL,
        host TEXT NOT NULL,
        path_template TEXT NOT NULL,
        sample_count INTEGER NOT NULL DEFAULT 0,
        confidence REAL NOT NULL DEFAULT 0,
        risk_level TEXT NOT NULL DEFAULT 'read',
        definition_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(snapshot_id, id)
    );
    CREATE INDEX IF NOT EXISTS idx_api_endpoints_session_route
        ON api_endpoints(session_id, host, path_template, method);
    CREATE TABLE IF NOT EXISTS replay_runs (
        id TEXT PRIMARY KEY,
        session_id TEXT REFERENCES capture_sessions(id) ON DELETE SET NULL,
        source_request_id TEXT REFERENCES http_requests(id) ON DELETE SET NULL,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        state TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT NOT NULL,
        status INTEGER,
        elapsed_ms REAL,
        request_fingerprint TEXT NOT NULL DEFAULT '',
        request_json TEXT NOT NULL DEFAULT '{}',
        response_json TEXT NOT NULL DEFAULT '{}',
        diff_json TEXT NOT NULL DEFAULT '{}',
        error_code TEXT,
        error_message TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_replay_runs_session_started
        ON replay_runs(session_id, started_at DESC, id);
    CREATE INDEX IF NOT EXISTS idx_replay_runs_request_started
        ON replay_runs(source_request_id, started_at DESC, id);
    """,
    """
    ALTER TABLE dataset_revisions ADD COLUMN build_state TEXT NOT NULL DEFAULT 'ready';
    CREATE INDEX IF NOT EXISTS idx_revisions_dataset_state_time
        ON dataset_revisions(dataset_id, build_state, created_at DESC);

    CREATE TABLE IF NOT EXISTS datasets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
        current_revision_id TEXT REFERENCES dataset_revisions(id) ON DELETE SET NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL DEFAULT 6
    );
    CREATE INDEX IF NOT EXISTS idx_datasets_project_updated
        ON datasets(project_id, updated_at DESC, id);

    CREATE TABLE IF NOT EXISTS lineage_nodes (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        object_id TEXT NOT NULL,
        label TEXT NOT NULL DEFAULT '',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        UNIQUE(kind, object_id)
    );
    CREATE INDEX IF NOT EXISTS idx_lineage_nodes_kind_object
        ON lineage_nodes(kind, object_id);

    CREATE TABLE IF NOT EXISTS lineage_edges (
        id TEXT PRIMARY KEY,
        from_node_id TEXT NOT NULL REFERENCES lineage_nodes(id) ON DELETE CASCADE,
        to_node_id TEXT NOT NULL REFERENCES lineage_nodes(id) ON DELETE CASCADE,
        relation TEXT NOT NULL,
        evidence_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        UNIQUE(from_node_id, to_node_id, relation)
    );
    CREATE INDEX IF NOT EXISTS idx_lineage_edges_from ON lineage_edges(from_node_id, id);
    CREATE INDEX IF NOT EXISTS idx_lineage_edges_to ON lineage_edges(to_node_id, id);
    """,
    """
    CREATE TABLE IF NOT EXISTS workflow_executions (
        id TEXT PRIMARY KEY,
        workflow_id TEXT NOT NULL,
        source_revision_id TEXT NOT NULL REFERENCES dataset_revisions(id) ON DELETE RESTRICT,
        output_dataset_id TEXT NOT NULL,
        output_revision_id TEXT NOT NULL REFERENCES dataset_revisions(id) ON DELETE RESTRICT,
        state TEXT NOT NULL,
        definition_hash TEXT NOT NULL,
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        finished_at TEXT,
        last_input_identity TEXT,
        processed_inputs INTEGER NOT NULL DEFAULT 0,
        staged_outputs INTEGER NOT NULL DEFAULT 0,
        error_count INTEGER NOT NULL DEFAULT 0,
        checkpoint_json TEXT NOT NULL DEFAULT '{}',
        error_code TEXT,
        error_message TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow_started
        ON workflow_executions(workflow_id, started_at DESC, id);
    CREATE INDEX IF NOT EXISTS idx_workflow_executions_source_started
        ON workflow_executions(source_revision_id, started_at DESC, id);
    CREATE INDEX IF NOT EXISTS idx_workflow_executions_state_updated
        ON workflow_executions(state, updated_at DESC, id);

    CREATE TABLE IF NOT EXISTS workflow_node_executions (
        execution_id TEXT NOT NULL REFERENCES workflow_executions(id) ON DELETE CASCADE,
        node_id TEXT NOT NULL,
        input_count INTEGER NOT NULL DEFAULT 0,
        output_count INTEGER NOT NULL DEFAULT 0,
        error_count INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT 'pending',
        PRIMARY KEY(execution_id, node_id)
    ) WITHOUT ROWID;
    """,
    """
    ALTER TABLE workflow_executions ADD COLUMN definition_json TEXT NOT NULL DEFAULT '{}';
    UPDATE workflow_executions
    SET definition_json=COALESCE(
        (SELECT definition_json FROM workflows WHERE workflows.id=workflow_executions.workflow_id),
        '{}'
    )
    WHERE definition_json='{}';
    """,
    """
    CREATE TABLE IF NOT EXISTS enterprise_resource_bindings (
        kind TEXT NOT NULL,
        external_id TEXT NOT NULL,
        resource_id TEXT NOT NULL UNIQUE,
        enterprise_id TEXT NOT NULL,
        bound_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(kind, external_id)
    ) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS idx_enterprise_bindings_enterprise
        ON enterprise_resource_bindings(enterprise_id, kind, external_id);
    """

)


class SQLiteStore:
    

    def __init__(self, path: Path) -> None:
        self.path = path
        self._migration_lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=_ClosingConnection)
        try:
            connection.row_factory = sqlite3.Row
                                                                                           
                                                                                             
                                                                                             
                                                                                           
                                                                                            
                                                                                             
            connection.executescript(
                """
                PRAGMA foreign_keys=ON;
                PRAGMA synchronous=NORMAL;
                PRAGMA wal_autocheckpoint=4096;
                PRAGMA cache_size=-8192;
                PRAGMA temp_store=MEMORY;
                """
            )
            return connection
        except Exception:
                                                                                           
                                                                                            
                                                                                            
                                                                                             
                                                                    
            connection.close()
            raise

    @staticmethod
    def validate_runtime() -> None:
        






        if tuple(sqlite3.sqlite_version_info) < (3, 24, 0):
            raise ArenyxaError(
                "SQLITE_RUNTIME_UNSUPPORTED",
                f"SQLite {sqlite3.sqlite_version} 过旧；Arenyxa 需要 SQLite >= 3.24。",
                domain="DATABASE",
                context={"sqlite_version": sqlite3.sqlite_version},
            )
        try:
            probe = sqlite3.connect(":memory:")
            try:
                probe.execute("CREATE VIRTUAL TABLE __arenyxa_fts_probe USING fts5(value)")
            finally:
                probe.close()
        except sqlite3.DatabaseError as exc:
            raise ArenyxaError(
                "SQLITE_FTS5_UNAVAILABLE",
                "当前 SQLite 运行时未启用 FTS5；本地搜索索引无法安全初始化。",
                domain="DATABASE",
                context={"sqlite_version": sqlite3.sqlite_version},
            ) from exc

    def initialize(self) -> None:
        self.validate_runtime()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._migration_lock:
            existed_before = self.path.exists() and self.path.stat().st_size > 0
            applied: set[int] = set()
            if existed_before:
                                                                                            
                                                                                           
                                                                                       
                                          
                probe = sqlite3.connect(self.path, timeout=30.0)
                try:
                    has_table = probe.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
                    ).fetchone()
                    if has_table is not None:
                        applied = {
                            int(row[0])
                            for row in probe.execute("SELECT version FROM schema_migrations")
                        }
                finally:
                    probe.close()
                pending = [
                    version for version in range(1, len(MIGRATIONS) + 1) if version not in applied
                ]
                if pending:
                    self.backup_to(self.path.with_name(f"{self.path.stem}.pre-migration.bak"))

            with self.connect() as connection:
                                                                                           
                                                                                           
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations "
                    "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
                )
                connection.commit()
                if not existed_before:
                    applied = {
                        int(row[0])
                        for row in connection.execute("SELECT version FROM schema_migrations")
                    }
                for version, script in enumerate(MIGRATIONS, start=1):
                    if version in applied:
                        continue
                    applied_at = utc_now()
                    try:
                        connection.executescript("BEGIN IMMEDIATE;\n" + script)
                        connection.execute(
                            "INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                            (int(version), applied_at),
                        )
                        connection.commit()
                    except sqlite3.DatabaseError:
                        if connection.in_transaction:
                            connection.rollback()
                        raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def integrity_check(self) -> str:
        with self.connect() as connection:
            return str(connection.execute("PRAGMA integrity_check").fetchone()[0])

    def quick_check(self) -> str:
        
        with self.connect() as connection:
            return str(connection.execute("PRAGMA quick_check(1)").fetchone()[0])

    def ping(self) -> bool:
        
        try:
            with self.connect() as connection:
                row = connection.execute("SELECT 1").fetchone()
            return bool(row and int(row[0]) == 1)
        except (sqlite3.DatabaseError, OSError, ValueError):
            return False


    def checkpoint(self, mode: str = "PASSIVE") -> tuple[int, int, int]:
        
        statement = sqlite_wal_checkpoint(mode)
        with self.connect() as connection:
            row = connection.execute(statement).fetchone()
        return (int(row[0]), int(row[1]), int(row[2]))

    def optimize(self) -> None:
        
        with self.connect() as connection:
            connection.execute("PRAGMA optimize")

    def backup_to(self, destination: Path) -> Path:
        





        target = Path(destination).expanduser().resolve()
        source_path = self.path.expanduser().resolve()
        if target == source_path:
            raise ValueError("备份目标不能覆盖正在使用的 Arenyxa 数据库。")
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            with self.connect() as source:
                backup = sqlite3.connect(temporary)
                try:
                    source.backup(backup, pages=256, sleep=0.01)
                    backup.commit()
                    row = backup.execute("PRAGMA quick_check(1)").fetchone()
                    if row is None or str(row[0]).casefold() != "ok":
                        raise ArenyxaError(
                            "DATABASE_BACKUP_VERIFY_FAILED",
                            "SQLite 备份完整性检查失败，未替换现有备份。",
                            domain="DATABASE",
                        )
                finally:
                    backup.close()
            fsync_existing_file(temporary)
            os.replace(temporary, target)
            return target
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def recover_interrupted_state(self) -> dict[str, int]:
        







        finished_at = utc_now()
        with self.transaction() as connection:
            run_cursor = connection.execute(
                "UPDATE runs SET status='failed',stage='failed',"
                "error_code=COALESCE(error_code,'RUN_INTERRUPTED'),"
                "finished_at=COALESCE(finished_at,?) "
                "WHERE status IN ('queued','running','paused')",
                (finished_at,),
            )
            capture_cursor = connection.execute(
                "UPDATE capture_sessions SET state='failed',finished_at=COALESCE(finished_at,?),"
                "event_count=(SELECT count(*) FROM network_events e WHERE e.session_id=capture_sessions.id),"
                "bytes_captured=COALESCE((SELECT sum(e.size) FROM network_events e "
                "WHERE e.session_id=capture_sessions.id),0) "
                "WHERE state IN ('preparing','capturing','paused','finalizing')",
                (finished_at,),
            )
        return {
            "runs": max(0, int(run_cursor.rowcount)),
            "captures": max(0, int(capture_cursor.rowcount)),
        }

    def recover_interrupted_pipeline_state(self) -> dict[str, int]:
        







        recovered_at = utc_now()
        with self.transaction() as connection:
            completed_cursor = connection.execute(
                """
                UPDATE workflow_executions
                SET state=CASE WHEN error_count>0 THEN 'completed_with_errors' ELSE 'completed' END,
                    updated_at=?,finished_at=COALESCE(finished_at,?),error_code=NULL,error_message=NULL
                WHERE state IN ('queued','running','interrupted')
                  AND EXISTS (
                      SELECT 1 FROM dataset_revisions r
                      WHERE r.id=workflow_executions.output_revision_id AND r.build_state='ready'
                  )
                """,
                (recovered_at, recovered_at),
            )
            workflow_cursor = connection.execute(
                "UPDATE workflow_executions SET state='interrupted',updated_at=?,"
                "error_code=COALESCE(error_code,'WORKFLOW_INTERRUPTED') "
                "WHERE state IN ('queued','running')",
                (recovered_at,),
            )
            revision_cursor = connection.execute(
                "UPDATE dataset_revisions SET build_state='interrupted' "
                "WHERE build_state='building'"
            )
        return {
            "completed_workflows": max(0, int(completed_cursor.rowcount)),
            "workflows": max(0, int(workflow_cursor.rowcount)),
            "revisions": max(0, int(revision_cursor.rowcount)),
        }

    def set_setting(self, key: str, value: Any) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,updated_at=excluded.updated_at",
                (key, json.dumps(value, ensure_ascii=False), utc_now()),
            )

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self.connect() as connection:
            row = connection.execute("SELECT value_json FROM settings WHERE key=?", (key,)).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except (json.JSONDecodeError, TypeError, UnicodeError) as exc:
                                                                                           
                                                                                      
            LOGGER.error("Ignoring corrupt setting %s: %s", key, exc)
            return default

    def bind_enterprise_resource(
        self, kind: str, external_id: str, resource_id: str, enterprise_id: str
    ) -> None:
        
        values = tuple(str(value).strip() for value in (kind, external_id, resource_id, enterprise_id))
        if any(not value or len(value) > 160 for value in values):
            raise ValueError("enterprise resource binding fields must contain 1-160 characters")
        resource_kind, local_id, governed_id, domain_id = values
        now = utc_now()
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT enterprise_id,resource_id FROM enterprise_resource_bindings WHERE kind=? AND external_id=?",
                (resource_kind, local_id),
            ).fetchone()
            if existing is not None and (
                str(existing["enterprise_id"]) != domain_id or str(existing["resource_id"]) != governed_id
            ):
                raise ArenyxaError(
                    "ENTERPRISE_BINDING_CONFLICT",
                    "Local resource is already bound to a different Enterprise resource.",
                    domain="ENTERPRISE",
                    context={"kind": resource_kind, "external_id": local_id},
                )
            connection.execute(
                """
                INSERT INTO enterprise_resource_bindings(kind,external_id,resource_id,enterprise_id,bound_at,updated_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(kind,external_id) DO UPDATE SET
                    resource_id=excluded.resource_id, enterprise_id=excluded.enterprise_id, updated_at=excluded.updated_at
                """,
                (resource_kind, local_id, governed_id, domain_id, now, now),
            )

    def enterprise_resource_binding(self, kind: str, external_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM enterprise_resource_bindings WHERE kind=? AND external_id=?",
                (str(kind).strip(), str(external_id).strip()),
            ).fetchone()
        return None if row is None else dict(row)

    def unbind_enterprise_resource(
        self, kind: str, external_id: str, *, enterprise_id: str | None = None
    ) -> bool:
        with self.transaction() as connection:
            if enterprise_id is None:
                cursor = connection.execute(
                    "DELETE FROM enterprise_resource_bindings WHERE kind=? AND external_id=?",
                    (str(kind).strip(), str(external_id).strip()),
                )
            else:
                cursor = connection.execute(
                    "DELETE FROM enterprise_resource_bindings WHERE kind=? AND external_id=? AND enterprise_id=?",
                    (str(kind).strip(), str(external_id).strip(), str(enterprise_id).strip()),
                )
            return int(cursor.rowcount) > 0

    def list_enterprise_resource_bindings(self, *, enterprise_id: str = "", limit: int = 1000) -> list[dict[str, Any]]:
        cap = max(1, min(20_000, int(limit)))
        sql = "SELECT * FROM enterprise_resource_bindings"
        values: list[Any] = []
        if enterprise_id:
            sql += " WHERE enterprise_id=?"
            values.append(str(enterprise_id))
        sql += " ORDER BY kind,external_id LIMIT ?"
        values.append(cap)
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]

    def save_task(self, task: Task) -> None:
        task.updated_at = utc_now()
                                                                                               
                                                                                                 
                                                                                            
        payload = task.to_dict()
        definition = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        snapshot_hash = hashlib.sha256(definition.encode("utf-8")).hexdigest()
                                                                                       
                                                                                    
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO tasks(id,name,status,tags_json,parser_hint,definition_json,snapshot_hash,
                                  created_at,updated_at,schema_version,deleted_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,NULL)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,status=excluded.status,tags_json=excluded.tags_json,
                    parser_hint=excluded.parser_hint,definition_json=excluded.definition_json,
                    snapshot_hash=excluded.snapshot_hash,updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version,
                    deleted_at=CASE WHEN excluded.status='deleted' THEN excluded.updated_at ELSE NULL END
                """,
                (
                    task.id, task.name, task.status.value, json.dumps(task.tags, ensure_ascii=False),
                    task.parser_hint, definition, snapshot_hash, task.created_at,
                    task.updated_at, task.schema_version,
                ),
            )
            connection.execute(
                "DELETE FROM local_search WHERE object_type=? AND object_id=?", ("task", task.id)
            )
            if task.status != TaskStatus.DELETED:
                connection.execute(
                    "INSERT INTO local_search(object_type,object_id,title,url,content) VALUES(?,?,?,?,?)",
                    (
                        "task", task.id, task.name,
                        task.requests[0].url if task.requests else "",
                        " ".join(task.tags),
                    ),
                )

    def get_task(self, task_id: str) -> Task | None:
        with self.connect() as connection:
            row = connection.execute("SELECT definition_json FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            return None
        try:
            raw = json.loads(row[0])
            return self._task_from_dict(raw)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ArenyxaError(
                "TASK_DEFINITION_CORRUPT",
                "任务定义已损坏，无法安全加载。请在日志与诊断中查看详情。",
                domain="TASK",
                context={"task_id": task_id},
            ) from exc

    def list_tasks(self, include_archived: bool = False, query: str = "", limit: int = 500) -> list[Task]:
        values: list[Any] = []
        has_query = bool(query)
        if has_query:
            wildcard = "%" + str(query) + "%"
            values.extend([wildcard, wildcard, wildcard])
        values.append(max(1, min(5_000, int(limit))))

        # Four fixed statements avoid constructing a WHERE clause from runtime strings.
        if include_archived and has_query:
            sql = (
                "SELECT id,definition_json FROM tasks "
                "WHERE status <> 'deleted' AND (name LIKE ? OR tags_json LIKE ? OR definition_json LIKE ?) "
                "ORDER BY updated_at DESC LIMIT ?"
            )
        elif include_archived:
            sql = "SELECT id,definition_json FROM tasks WHERE status <> 'deleted' ORDER BY updated_at DESC LIMIT ?"
        elif has_query:
            sql = (
                "SELECT id,definition_json FROM tasks "
                "WHERE status <> 'deleted' AND status <> 'archived' "
                "AND (name LIKE ? OR tags_json LIKE ? OR definition_json LIKE ?) "
                "ORDER BY updated_at DESC LIMIT ?"
            )
        else:
            sql = (
                "SELECT id,definition_json FROM tasks "
                "WHERE status <> 'deleted' AND status <> 'archived' ORDER BY updated_at DESC LIMIT ?"
            )
        with self.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        tasks: list[Task] = []
        for row in rows:
            try:
                tasks.append(self._task_from_dict(json.loads(row["definition_json"])))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                LOGGER.error("Skipping corrupt task definition %s: %s", row["id"], exc)
        return tasks

    def save_run(self, run: Run) -> None:
        with self.connect() as connection:
                                                                                            
                                                                                             
                                                                                              
                                                                                               
            status = run.status.value
            updated = connection.execute(
                """
                UPDATE runs SET
                    status=CASE
                        -- Pause/resume is written through update_run_control_status(). A stale
                        -- progress snapshot must never reverse the latest control transition.
                        WHEN status IN ('running','paused') AND ? IN ('running','paused')
                        THEN status
                        -- Once a Run is terminal, delayed active/queued snapshots must not
                        -- resurrect it. Terminal-to-terminal writes remain allowed for explicit
                        -- recovery/reconciliation code paths.
                        WHEN status IN ('completed','partial','failed','cancelled')
                         AND ? IN ('queued','running','paused')
                        THEN status
                        ELSE ?
                    END,
                    stage=?,completed_units=?,total_units=?,request_count=?,success_count=?,
                    failure_count=?,result_count=?,retry_count=?,error_code=?,started_at=?,finished_at=?
                WHERE id=?
                """,
                (
                    status,
                    status,
                    status,
                    run.stage,
                    run.completed_units,
                    run.total_units,
                    run.request_count,
                    run.success_count,
                    run.failure_count,
                    run.result_count,
                    run.retry_count,
                    run.error_code,
                    run.started_at,
                    run.finished_at,
                    run.id,
                ),
            )
            if updated.rowcount:
                return
            connection.execute(
                """
                INSERT INTO runs(id,task_id,status,snapshot_json,stage,completed_units,total_units,
                    request_count,success_count,failure_count,result_count,retry_count,error_code,
                    created_at,started_at,finished_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    run.id,
                    run.task_id,
                    status,
                    json.dumps(run.task_snapshot, ensure_ascii=False, default=str),
                    run.stage,
                    run.completed_units,
                    run.total_units,
                    run.request_count,
                    run.success_count,
                    run.failure_count,
                    run.result_count,
                    run.retry_count,
                    run.error_code,
                    run.created_at,
                    run.started_at,
                    run.finished_at,
                    run.schema_version,
                ),
            )

    def update_run_control_status(self, run_id: str, status: RunStatus) -> bool:
        





        if status == RunStatus.PAUSED:
            allowed = (RunStatus.QUEUED.value, RunStatus.RUNNING.value, RunStatus.PAUSED.value)
        elif status == RunStatus.RUNNING:
            allowed = (RunStatus.PAUSED.value, RunStatus.RUNNING.value)
        else:
            raise ValueError("control status must be paused or running")
        placeholders = sql_placeholders(len(allowed))
        with self.connect() as connection:
            cursor = connection.execute(
                "UPDATE runs SET status=? WHERE id=? AND status IN (" + placeholders + ")",
                (status.value, run_id, *allowed),
            )
            return cursor.rowcount == 1

    def list_runs(self, task_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM runs"
        values: list[Any] = []
        if task_id:
            sql += " WHERE task_id=?"
            values.append(task_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        values.append(max(1, min(5_000, int(limit))))
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]

    def append_results(self, records: Iterable[ResultRecord], batch_size: int = 500) -> int:
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
                                                                                                 
                                                                                
        target_batch_size = min(5_000, batch_size)
        batch: list[tuple[Any, ...]] = []
        total = 0
        with self.transaction() as connection:
            for record in records:
                                                                                               
                                                                                               
                                                                                               
                                                                                             
                marker = connection.execute(
                    "INSERT OR IGNORE INTO run_result_hashes(run_id,content_hash) VALUES(?,?)",
                    (record.run_id, record.content_hash),
                )
                if marker.rowcount != 1:
                    continue
                batch.append(
                    (
                        record.id,
                        record.task_id,
                        record.run_id,
                        record.source_url,
                        record.fetched_at,
                        json.dumps(record.data, ensure_ascii=False, default=str),
                        record.content_hash,
                        json.dumps(record.quality_flags, ensure_ascii=False),
                    )
                )
                if len(batch) >= target_batch_size:
                    connection.executemany(
                        "INSERT INTO result_records VALUES(?,?,?,?,?,?,?,?)",
                        batch,
                    )
                    total += len(batch)
                    batch.clear()
            if batch:
                connection.executemany("INSERT INTO result_records VALUES(?,?,?,?,?,?,?,?)", batch)
                total += len(batch)
        return total

    def iter_results(self, run_id: str, page_size: int = 1000) -> Iterator[dict[str, Any]]:
        last_id = ""
        while True:
            with self.connect() as connection:
                rows = connection.execute(
                    "SELECT id,source_url,fetched_at,data_json,quality_flags_json FROM result_records "
                    "WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
                    (run_id, last_id, page_size),
                ).fetchall()
            if not rows:
                break
            for row in rows:
                last_id = str(row["id"])
                yield {
                    "id": last_id,
                    "source_url": row["source_url"],
                    "fetched_at": row["fetched_at"],
                    **json.loads(row["data_json"]),
                    "_quality_flags": json.loads(row["quality_flags_json"]),
                }

    def count_results(self, run_id: str | None = None) -> int:
        with self.connect() as connection:
            if run_id:
                row = connection.execute(
                    "SELECT count(*) FROM result_records WHERE run_id=?", (run_id,)
                ).fetchone()
            else:
                row = connection.execute("SELECT count(*) FROM result_records").fetchone()
        return int(row[0])

    def result_page(self, run_id: str, offset: int, limit: int) -> list[dict[str, Any]]:
        safe_offset = max(0, int(offset))
        safe_limit = max(1, min(5_000, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id,source_url,fetched_at,data_json,quality_flags_json FROM result_records "
                "WHERE run_id=? ORDER BY id LIMIT ? OFFSET ?",
                (run_id, safe_limit, safe_offset),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "source_url": row["source_url"],
                "fetched_at": row["fetched_at"],
                **json.loads(row["data_json"]),
                "_quality_flags": json.loads(row["quality_flags_json"]),
            }
            for row in rows
        ]


    def save_project(self, project: Project) -> None:
        errors = project.validate()
        if errors:
            raise ArenyxaError("PROJECT_INVALID", "; ".join(errors), domain="PROJECT")
        project.updated_at = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO projects(id,workspace_id,name,description,tags_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET workspace_id=excluded.workspace_id,name=excluded.name,
                    description=excluded.description,tags_json=excluded.tags_json,
                    updated_at=excluded.updated_at,schema_version=excluded.schema_version
                """,
                (
                    project.id, project.workspace_id, project.name, project.description,
                    json.dumps(project.tags, ensure_ascii=False), project.created_at,
                    project.updated_at, project.schema_version,
                ),
            )

    def get_project(self, project_id: str) -> Project | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
        if row is None:
            return None
        return self._project_from_row(row)

    @staticmethod
    def _project_from_row(row: sqlite3.Row) -> Project:
        return Project(
            id=str(row["id"]), workspace_id=row["workspace_id"], name=str(row["name"]),
            description=str(row["description"]), tags=json.loads(row["tags_json"]),
            created_at=str(row["created_at"]), updated_at=str(row["updated_at"]),
            schema_version=int(row["schema_version"]),
        )

    def list_projects(self, workspace_id: str | None = None, limit: int = 200) -> list[Project]:
                                                                                                 
                                                                                             
                                                                                             
        sql = "SELECT * FROM projects"
        values: list[Any] = []
        if workspace_id is not None:
            sql += " WHERE workspace_id=?"
            values.append(workspace_id)
        sql += " ORDER BY updated_at DESC LIMIT ?"
        values.append(max(1, min(int(limit), 5000)))
        with self.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        return [self._project_from_row(row) for row in rows]

    def save_project_source(self, source: ProjectSource) -> None:
        errors = source.validate()
        if errors:
            raise ArenyxaError("PROJECT_SOURCE_INVALID", "; ".join(errors), domain="PROJECT")
        source.updated_at = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO project_sources(id,project_id,name,kind,config_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET project_id=excluded.project_id,name=excluded.name,
                    kind=excluded.kind,config_json=excluded.config_json,
                    updated_at=excluded.updated_at,schema_version=excluded.schema_version
                """,
                (
                    source.id, source.project_id, source.name, source.kind.value,
                    json.dumps(source.config, ensure_ascii=False, default=str), source.created_at,
                    source.updated_at, source.schema_version,
                ),
            )

    def list_project_sources(self, project_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM project_sources WHERE project_id=? ORDER BY created_at,id", (project_id,)
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["config"] = json.loads(item.pop("config_json"))
            result.append(item)
        return result

    @staticmethod
    def _bind_capture_connection(
        connection: sqlite3.Connection, session_id: str, project_id: str | None, source_id: str | None
    ) -> None:
        session_exists = connection.execute(
            "SELECT 1 FROM capture_sessions WHERE id=?", (session_id,)
        ).fetchone()
        if session_exists is None:
            raise ArenyxaError("CAPTURE_NOT_FOUND", "无法绑定不存在的捕获会话。", domain="PROJECT")
        resolved_project = project_id
        if source_id is not None:
            row = connection.execute("SELECT project_id FROM project_sources WHERE id=?", (source_id,)).fetchone()
            if row is None:
                raise ArenyxaError("PROJECT_SOURCE_NOT_FOUND", "捕获绑定的数据源不存在。", domain="PROJECT")
            source_project = str(row[0])
            if resolved_project is None:
                resolved_project = source_project
            elif resolved_project != source_project:
                raise ArenyxaError(
                    "PROJECT_SOURCE_MISMATCH", "捕获数据源不属于指定项目。", domain="PROJECT",
                    context={"project_id": resolved_project, "source_id": source_id},
                )
        if resolved_project is not None:
            exists = connection.execute("SELECT 1 FROM projects WHERE id=?", (resolved_project,)).fetchone()
            if exists is None:
                raise ArenyxaError("PROJECT_NOT_FOUND", "捕获绑定的项目不存在。", domain="PROJECT")
        if resolved_project is None and source_id is None:
            return
        connection.execute(
            """
            INSERT INTO capture_bindings(session_id,project_id,source_id) VALUES(?,?,?)
            ON CONFLICT(session_id) DO UPDATE SET project_id=excluded.project_id,source_id=excluded.source_id
            """,
            (session_id, resolved_project, source_id),
        )

    def bind_capture(self, session_id: str, project_id: str | None, source_id: str | None) -> None:
        with self.transaction() as connection:
            self._bind_capture_connection(connection, session_id, project_id, source_id)

    def network_core_metrics(self, session_id: str) -> dict[str, int]:
        queries = {
            "flows": "SELECT count(*) FROM network_flows WHERE session_id=?",
            "http_requests": "SELECT count(*) FROM http_requests WHERE session_id=?",
            "http_responses": "SELECT count(*) FROM http_responses WHERE session_id=?",
            "dns": "SELECT count(*) FROM dns_transactions WHERE session_id=?",
            "tls": "SELECT count(*) FROM tls_handshakes WHERE session_id=?",
            "websockets": "SELECT count(*) FROM websocket_channels WHERE session_id=?",
            "websocket_messages": (
                "SELECT count(*) FROM websocket_messages m "
                "JOIN websocket_channels c ON c.id=m.channel_id WHERE c.session_id=?"
            ),
        }
        with self.connect() as connection:
            return {
                label: int(connection.execute(statement, (session_id,)).fetchone()[0])
                for label, statement in queries.items()
            }

    @staticmethod
    def _decode_network_json(raw: Any, *, request_id: str, field: str) -> dict[str, Any]:
        if raw in (None, ""):
            return {}
        try:
            value = json.loads(str(raw))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ArenyxaError(
                "NETWORK_CORE_CORRUPT",
                "规范化 Network Core 包含损坏的 JSON 字段。",
                domain="NETWORK",
                context={"request_id": request_id, "field": field},
            ) from exc
        if not isinstance(value, dict):
            raise ArenyxaError(
                "NETWORK_CORE_CORRUPT",
                "规范化 Network Core JSON 字段类型不正确。",
                domain="NETWORK",
                context={"request_id": request_id, "field": field},
            )
        return value

    @classmethod
    def _materialize_http_exchange_row(cls, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        item = dict(row)
        request_id = str(item.get("request_id") or "")
        item["query"] = cls._decode_network_json(
            item.pop("query_json", "{}"), request_id=request_id, field="query_json"
        )
        item["request_headers"] = cls._decode_network_json(
            item.pop("request_headers_json", "{}"), request_id=request_id, field="request_headers_json"
        )
        item["response_headers"] = cls._decode_network_json(
            item.pop("response_headers_json", "{}"), request_id=request_id, field="response_headers_json"
        )
        item["timing"] = cls._decode_network_json(
            item.pop("timing_json", "{}"), request_id=request_id, field="timing_json"
        )
        return item

    def iter_http_exchanges(self, session_id: str, limit: int = 10000) -> Iterator[dict[str, Any]]:
        bounded = max(0, min(int(limit), 100_000))
        if bounded == 0:
            return
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT q.id AS request_id,q.event_id,q.session_id,q.flow_id,q.timestamp,q.method,q.url,q.host,q.query_json,
                       q.headers_json AS request_headers_json,q.body_ref AS request_body_ref,q.initiator,
                       r.id AS response_id,r.status,r.headers_json AS response_headers_json,
                       r.body_ref AS response_body_ref,r.content_type,r.size,r.timing_json
                FROM http_requests q LEFT JOIN http_responses r ON r.request_id=q.id
                WHERE q.session_id=? ORDER BY q.timestamp,q.id LIMIT ?
                """,
                (session_id, bounded),
            ).fetchall()
        for row in rows:
            yield self._materialize_http_exchange_row(row)

    def get_http_exchange(self, request_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT q.id AS request_id,q.event_id,q.session_id,q.flow_id,q.timestamp,q.method,q.url,q.host,q.query_json,
                       q.headers_json AS request_headers_json,q.body_ref AS request_body_ref,q.initiator,
                       r.id AS response_id,r.status,r.headers_json AS response_headers_json,
                       r.body_ref AS response_body_ref,r.content_type,r.size,r.timing_json
                FROM http_requests q LEFT JOIN http_responses r ON r.request_id=q.id
                WHERE q.id=?
                """,
                (str(request_id),),
            ).fetchone()
        return None if row is None else self._materialize_http_exchange_row(row)

    def get_http_exchange_by_event(self, event_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT q.id AS request_id,q.event_id,q.session_id,q.flow_id,q.timestamp,q.method,q.url,q.host,q.query_json,
                       q.headers_json AS request_headers_json,q.body_ref AS request_body_ref,q.initiator,
                       r.id AS response_id,r.status,r.headers_json AS response_headers_json,
                       r.body_ref AS response_body_ref,r.content_type,r.size,r.timing_json
                FROM http_requests q LEFT JOIN http_responses r ON r.request_id=q.id
                WHERE q.event_id=?
                """,
                (str(event_id),),
            ).fetchone()
        return None if row is None else self._materialize_http_exchange_row(row)

    def get_network_body(self, body_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM network_bodies WHERE id=?", (body_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["truncated"] = bool(item["truncated"])
        item["sensitive"] = bool(item["sensitive"])
        return item

    def list_network_bodies(self, session_id: str, limit: int = 10000) -> list[dict[str, Any]]:
        bounded = max(0, min(int(limit), 100_000))
        if bounded == 0:
            return []
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM network_bodies WHERE session_id=? ORDER BY created_at,id LIMIT ?",
                (session_id, bounded),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["truncated"] = bool(item["truncated"])
            item["sensitive"] = bool(item["sensitive"])
            result.append(item)
        return result

    def save_api_map_snapshot(self, snapshot: dict[str, Any]) -> None:
        session_id = str(snapshot.get("session_id") or "")
        snapshot_id = str(snapshot.get("id") or "")
        endpoints = snapshot.get("endpoints")
        if not snapshot_id or not session_id or not isinstance(endpoints, list):
            raise ValueError("invalid API Map snapshot")
        definition = json.dumps(snapshot, ensure_ascii=False, default=str)
        created_at = str(snapshot.get("created_at") or utc_now())
        with self.transaction() as connection:
            if connection.execute("SELECT 1 FROM capture_sessions WHERE id=?", (session_id,)).fetchone() is None:
                raise ArenyxaError("CAPTURE_NOT_FOUND", "API Map 对应的捕获会话不存在。", domain="NETWORK")
            connection.execute(
                """
                INSERT INTO api_map_snapshots(
                    id,session_id,created_at,endpoint_count,source_event_count,host_count,
                    graphql_endpoint_count,pagination_endpoint_count,definition_json,schema_version
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    session_id=excluded.session_id,created_at=excluded.created_at,endpoint_count=excluded.endpoint_count,
                    source_event_count=excluded.source_event_count,host_count=excluded.host_count,
                    graphql_endpoint_count=excluded.graphql_endpoint_count,
                    pagination_endpoint_count=excluded.pagination_endpoint_count,definition_json=excluded.definition_json,
                    schema_version=excluded.schema_version
                """,
                (
                    snapshot_id, session_id, created_at, int(snapshot.get("endpoint_count") or len(endpoints)),
                    int(snapshot.get("source_event_count") or 0), int(snapshot.get("host_count") or 0),
                    int(snapshot.get("graphql_endpoint_count") or 0),
                    int(snapshot.get("pagination_endpoint_count") or 0), definition, 6,
                ),
            )
            connection.execute("DELETE FROM api_endpoints WHERE snapshot_id=?", (snapshot_id,))
            rows: list[tuple[Any, ...]] = []
            for endpoint in endpoints:
                if not isinstance(endpoint, dict):
                    continue
                endpoint_id = str(endpoint.get("id") or "")
                if not endpoint_id:
                    continue
                rows.append((
                    endpoint_id, snapshot_id, session_id, str(endpoint.get("method") or "GET"),
                    str(endpoint.get("host") or ""), str(endpoint.get("path") or "/"),
                    int(endpoint.get("samples") or 0), float(endpoint.get("confidence") or 0.0),
                    str(endpoint.get("risk_level") or "read"),
                    json.dumps(endpoint, ensure_ascii=False, default=str), created_at,
                ))
            if rows:
                connection.executemany(
                    "INSERT INTO api_endpoints(id,snapshot_id,session_id,method,host,path_template,sample_count,confidence,risk_level,definition_json,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    rows,
                )

    def list_api_map_snapshots(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        bounded = max(0, min(int(limit), 500))
        if bounded == 0:
            return []
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM api_map_snapshots WHERE session_id=? ORDER BY created_at DESC,id DESC LIMIT ?",
                (session_id, bounded),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["definition"] = json.loads(item.pop("definition_json"))
            except json.JSONDecodeError as exc:
                raise ArenyxaError("API_MAP_CORRUPT", "API Map Snapshot 已损坏。", domain="NETWORK") from exc
            result.append(item)
        return result

    def list_api_endpoints(self, snapshot_id: str, limit: int = 10_000) -> list[dict[str, Any]]:
        bounded = max(0, min(int(limit), 100_000))
        if bounded == 0:
            return []
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM api_endpoints WHERE snapshot_id=? ORDER BY sample_count DESC,host,path_template,method LIMIT ?",
                (snapshot_id, bounded),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["definition"] = json.loads(item.pop("definition_json"))
            except json.JSONDecodeError as exc:
                raise ArenyxaError("API_MAP_CORRUPT", "API Endpoint 定义已损坏。", domain="NETWORK") from exc
            result.append(item)
        return result

    def save_replay_run(self, record: dict[str, Any]) -> None:
        replay_id = str(record.get("id") or "")
        if not replay_id:
            raise ValueError("replay run requires id")
        state = str(record.get("state") or "failed")
        if state not in {"completed", "failed", "cancelled"}:
            raise ValueError("invalid replay state")
        with self.transaction() as connection:
            session_id = record.get("session_id")
            if session_id is not None and connection.execute(
                "SELECT 1 FROM capture_sessions WHERE id=?", (str(session_id),)
            ).fetchone() is None:
                session_id = None
            source_request_id = record.get("source_request_id")
            if source_request_id is not None and connection.execute(
                "SELECT 1 FROM http_requests WHERE id=?", (str(source_request_id),)
            ).fetchone() is None:
                source_request_id = None
            connection.execute(
                """
                INSERT INTO replay_runs(
                    id,session_id,source_request_id,method,url,state,started_at,finished_at,status,elapsed_ms,
                    request_fingerprint,request_json,response_json,diff_json,error_code,error_message
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    state=excluded.state,finished_at=excluded.finished_at,status=excluded.status,elapsed_ms=excluded.elapsed_ms,
                    request_fingerprint=excluded.request_fingerprint,request_json=excluded.request_json,
                    response_json=excluded.response_json,diff_json=excluded.diff_json,error_code=excluded.error_code,
                    error_message=excluded.error_message
                """,
                (
                    replay_id, session_id, source_request_id,
                    str(record.get("method") or "GET"), str(record.get("url") or ""), state,
                    str(record.get("started_at") or utc_now()), str(record.get("finished_at") or utc_now()),
                    record.get("status"), record.get("elapsed_ms"), str(record.get("request_fingerprint") or ""),
                    json.dumps(record.get("request") or {}, ensure_ascii=False, default=str),
                    json.dumps(record.get("response") or {}, ensure_ascii=False, default=str),
                    json.dumps(record.get("comparison") or {}, ensure_ascii=False, default=str),
                    record.get("error_code"), record.get("error_message"),
                ),
            )

    def list_replay_runs(self, session_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        bounded = max(0, min(int(limit), 5000))
        if bounded == 0:
            return []
        sql = "SELECT * FROM replay_runs"
        values: tuple[Any, ...]
        if session_id is None:
            sql += " ORDER BY started_at DESC,id DESC LIMIT ?"
            values = (bounded,)
        else:
            sql += " WHERE session_id=? ORDER BY started_at DESC,id DESC LIMIT ?"
            values = (session_id, bounded)
        with self.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            for key in ("request_json", "response_json", "diff_json"):
                try:
                    item[key[:-5] if key.endswith("_json") else key] = json.loads(item.pop(key))
                except json.JSONDecodeError as exc:
                    raise ArenyxaError("REPLAY_HISTORY_CORRUPT", "Replay 历史记录已损坏。", domain="REPLAY") from exc
            result.append(item)
        return result

    def network_capture_quality_metrics(self, session_id: str) -> dict[str, int]:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT count(*) AS bodies,
                       COALESCE(sum(byte_size),0) AS body_bytes,
                       COALESCE(sum(stored_size),0) AS stored_body_bytes,
                       COALESCE(sum(truncated),0) AS truncated_bodies,
                       COALESCE(sum(sensitive),0) AS sensitive_bodies
                FROM network_bodies WHERE session_id=?
                """,
                (session_id,),
            ).fetchone()
            endpoint_flows = int(connection.execute(
                "SELECT count(*) FROM network_flows WHERE session_id=? AND (local_address IS NOT NULL OR remote_address IS NOT NULL)",
                (session_id,),
            ).fetchone()[0])
        return {
            "bodies": int(row["bodies"]),
            "body_bytes": int(row["body_bytes"]),
            "stored_body_bytes": int(row["stored_body_bytes"]),
            "truncated_bodies": int(row["truncated_bodies"]),
            "sensitive_bodies": int(row["sensitive_bodies"]),
            "flows_with_endpoints": endpoint_flows,
        }

    def network_core_backlog(self, session_id: str | None = None) -> int:
        sql = (
            "SELECT count(*) FROM network_events e LEFT JOIN network_projection_events p ON p.event_id=e.id "
            "WHERE p.event_id IS NULL"
        )
        values: tuple[Any, ...] = ()
        if session_id is not None:
            sql += " AND e.session_id=?"
            values = (session_id,)
        with self.connect() as connection:
            return int(connection.execute(sql, values).fetchone()[0])

    def backfill_network_core(self, session_id: str | None = None, batch_size: int = 1000) -> int:
        bounded_batch = max(1, min(int(batch_size), 5000))
        projected = 0
        while True:
            sql = (
                "SELECT e.* FROM network_events e LEFT JOIN network_projection_events p ON p.event_id=e.id "
                "WHERE p.event_id IS NULL"
            )
            values: list[Any] = []
            if session_id is not None:
                sql += " AND e.session_id=?"
                values.append(session_id)
            sql += " ORDER BY e.timestamp,e.id LIMIT ?"
            values.append(bounded_batch)
            with self.connect() as connection:
                rows = connection.execute(sql, values).fetchall()
            if not rows:
                return projected
            events: list[NetworkEvent] = []
            for row in rows:
                item = dict(row)
                try:
                    events.append(
                        NetworkEvent(
                            session_id=str(item["session_id"]),
                            source_type=CaptureSource(str(item["source_type"])),
                            protocol=str(item["protocol"]),
                            direction=str(item["direction"]),
                            size=int(item["size"]),
                            id=str(item["id"]),
                            timestamp=str(item["timestamp"]),
                            process_ref=item["process_ref"], flow_ref=item["flow_ref"], request_ref=item["request_ref"],
                            method=item["method"], url=item["url"], status=item["status"], host=item["host"],
                            timing=json.loads(item["timing_json"]),
                            request_headers=json.loads(item["request_headers_json"]),
                            response_headers=json.loads(item["response_headers_json"]),
                            request_body_ref=item["request_body_ref"], response_body_ref=item["response_body_ref"],
                            sensitivity_flags=json.loads(item["sensitivity_json"]), initiator=item["initiator"],
                            metadata=json.loads(item["metadata_json"]),
                        )
                    )
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ArenyxaError(
                        "NETWORK_CORE_BACKFILL_CORRUPT",
                        "历史网络事件已损坏，无法安全投影到 Network Core。",
                        domain="NETWORK",
                        context={"event_id": str(item.get("id", ""))},
                    ) from exc
            with self.transaction() as connection:
                projected += self._append_network_core(connection, events)

    @staticmethod
    def _append_network_core(connection: sqlite3.Connection, events: list[NetworkEvent]) -> int:
        projected = 0
        for event in events:
            claimed = connection.execute(
                "INSERT OR IGNORE INTO network_projection_events(event_id,projected_at) VALUES(?,?)",
                (event.id, utc_now()),
            )
            if int(claimed.rowcount) == 0:
                continue
            projected += 1
            bundle = NetworkNormalizer.normalize(event)
            for body in bundle.body_artifacts:
                connection.execute(
                    """
                    INSERT INTO network_bodies(id,session_id,sha256,stored_sha256,byte_size,stored_size,content_type,encoding,
                        storage_kind,storage_ref,truncated,sensitive,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET sha256=excluded.sha256,stored_sha256=excluded.stored_sha256,byte_size=excluded.byte_size,
                        stored_size=excluded.stored_size,content_type=excluded.content_type,encoding=excluded.encoding,
                        storage_kind=excluded.storage_kind,storage_ref=excluded.storage_ref,truncated=excluded.truncated,
                        sensitive=MAX(network_bodies.sensitive,excluded.sensitive)
                    """,
                    (
                        body.id, body.session_id, body.sha256, body.stored_sha256, body.byte_size, body.stored_size, body.content_type,
                        body.encoding, body.storage_kind, body.storage_ref, int(body.truncated), int(body.sensitive),
                        body.created_at or event.timestamp,
                    ),
                )
            flow = bundle.flow
            connection.execute(
                """
                INSERT INTO network_flows(id,session_id,source_type,protocol,transport,local_address,
                    remote_address,process_ref,first_seen,last_seen,event_count,bytes_seen,metadata_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    first_seen=MIN(network_flows.first_seen,excluded.first_seen),
                    last_seen=MAX(network_flows.last_seen,excluded.last_seen),
                    event_count=network_flows.event_count+excluded.event_count,
                    bytes_seen=network_flows.bytes_seen+excluded.bytes_seen,
                    process_ref=COALESCE(excluded.process_ref,network_flows.process_ref),
                    local_address=COALESCE(excluded.local_address,network_flows.local_address),
                    remote_address=COALESCE(excluded.remote_address,network_flows.remote_address),
                    metadata_json=CASE WHEN excluded.metadata_json<>'{}' THEN excluded.metadata_json ELSE network_flows.metadata_json END
                """,
                (
                    flow.id, flow.session_id, flow.source_type, flow.protocol, flow.transport,
                    flow.local_address, flow.remote_address, flow.process_ref, flow.first_seen,
                    flow.last_seen, flow.event_count, flow.bytes_seen,
                    json.dumps(flow.metadata, ensure_ascii=False, default=str),
                ),
            )
            request = bundle.request
            if request is not None:
                connection.execute(
                    """
                    INSERT INTO http_requests(id,event_id,session_id,flow_id,timestamp,method,url,host,
                        query_json,headers_json,body_ref,initiator) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET flow_id=excluded.flow_id,timestamp=excluded.timestamp,
                        method=excluded.method,url=excluded.url,host=excluded.host,query_json=excluded.query_json,
                        headers_json=excluded.headers_json,body_ref=excluded.body_ref,initiator=excluded.initiator
                    """,
                    (
                        request.id, request.event_id, request.session_id, request.flow_id, request.timestamp,
                        request.method, request.url, request.host, json.dumps(request.query, ensure_ascii=False),
                        json.dumps(request.headers, ensure_ascii=False), request.body_ref, request.initiator,
                    ),
                )
            response = bundle.response
            if response is not None:
                connection.execute(
                    """
                    INSERT INTO http_responses(id,request_id,event_id,session_id,timestamp,status,headers_json,
                        body_ref,content_type,size,timing_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(request_id) DO UPDATE SET event_id=excluded.event_id,timestamp=excluded.timestamp,
                        status=excluded.status,headers_json=excluded.headers_json,body_ref=excluded.body_ref,
                        content_type=excluded.content_type,size=excluded.size,timing_json=excluded.timing_json
                    """,
                    (
                        response.id, response.request_id, response.event_id, response.session_id,
                        response.timestamp, response.status, json.dumps(response.headers, ensure_ascii=False),
                        response.body_ref, response.content_type, response.size,
                        json.dumps(response.timing, ensure_ascii=False),
                    ),
                )
            dns = bundle.dns
            if dns is not None:
                connection.execute(
                    """
                    INSERT INTO dns_transactions(id,event_id,session_id,timestamp,query_name,query_type,
                        answers_json,elapsed_ms,error) VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(event_id) DO UPDATE SET timestamp=excluded.timestamp,query_name=excluded.query_name,
                        query_type=excluded.query_type,answers_json=excluded.answers_json,
                        elapsed_ms=excluded.elapsed_ms,error=excluded.error
                    """,
                    (
                        dns.id, dns.event_id, dns.session_id, dns.timestamp, dns.query_name, dns.query_type,
                        json.dumps(dns.answers, ensure_ascii=False), dns.elapsed_ms, dns.error,
                    ),
                )
            tls = bundle.tls
            if tls is not None:
                connection.execute(
                    """
                    INSERT INTO tls_handshakes(id,event_id,session_id,flow_id,timestamp,host,version,cipher,
                        alpn,certificate_ref,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(event_id) DO UPDATE SET flow_id=excluded.flow_id,timestamp=excluded.timestamp,
                        host=excluded.host,version=excluded.version,cipher=excluded.cipher,alpn=excluded.alpn,
                        certificate_ref=excluded.certificate_ref,metadata_json=excluded.metadata_json
                    """,
                    (
                        tls.id, tls.event_id, tls.session_id, tls.flow_id, tls.timestamp, tls.host,
                        tls.version, tls.cipher, tls.alpn, tls.certificate_ref,
                        json.dumps(tls.metadata, ensure_ascii=False, default=str),
                    ),
                )
            channel = bundle.websocket_channel
            if channel is not None:
                connection.execute(
                    """
                    INSERT INTO websocket_channels(id,session_id,flow_id,url,host,opened_at,closed_at,
                        message_count,bytes_seen) VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET closed_at=COALESCE(excluded.closed_at,websocket_channels.closed_at),
                        message_count=websocket_channels.message_count+excluded.message_count,
                        bytes_seen=websocket_channels.bytes_seen+excluded.bytes_seen
                    """,
                    (
                        channel.id, channel.session_id, channel.flow_id, channel.url, channel.host,
                        channel.opened_at, channel.closed_at, channel.message_count, channel.bytes_seen,
                    ),
                )
            message = bundle.websocket_message
            if message is not None:
                connection.execute(
                    """
                    INSERT INTO websocket_messages(id,channel_id,event_id,timestamp,direction,opcode,size,
                        payload_ref,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(event_id) DO UPDATE SET timestamp=excluded.timestamp,direction=excluded.direction,
                        opcode=excluded.opcode,size=excluded.size,payload_ref=excluded.payload_ref,
                        metadata_json=excluded.metadata_json
                    """,
                    (
                        message.id, message.channel_id, message.event_id, message.timestamp, message.direction,
                        message.opcode, message.size, message.payload_ref,
                        json.dumps(message.metadata, ensure_ascii=False, default=str),
                    ),
                )
        return projected


    @staticmethod
    def _upsert_capture_connection(connection: sqlite3.Connection, session: CaptureSession) -> None:
        connection.execute(
            """
            INSERT INTO capture_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET state=excluded.state,started_at=excluded.started_at,
                finished_at=excluded.finished_at,event_count=excluded.event_count,
                bytes_captured=excluded.bytes_captured,dropped_events=excluded.dropped_events,
                filter_expression=excluded.filter_expression,permission_state=excluded.permission_state
            """,
            (
                session.id,
                session.name,
                session.source_type.value,
                session.state.value,
                session.created_at,
                session.started_at,
                session.finished_at,
                session.event_count,
                session.bytes_captured,
                session.dropped_events,
                session.filter_expression,
                session.permission_state,
                session.schema_version,
            ),
        )

    def save_capture(self, session: CaptureSession) -> None:
        with self.transaction() as connection:
            self._upsert_capture_connection(connection, session)
            if session.project_id is not None or session.source_id is not None:
                self._bind_capture_connection(connection, session.id, session.project_id, session.source_id)

    def append_network_events(self, events: Iterable[NetworkEvent]) -> int:
        event_list = list(events)
        rows = []
        for event in event_list:
            rows.append(
                (
                    event.id, event.session_id, event.source_type.value, event.timestamp,
                    event.process_ref, event.flow_ref, event.request_ref, event.protocol, event.direction,
                    event.size, event.method, event.url, event.status, event.host, json.dumps(event.timing),
                    json.dumps(event.request_headers, ensure_ascii=False),
                    json.dumps(event.response_headers, ensure_ascii=False), event.request_body_ref,
                    event.response_body_ref, json.dumps(event.sensitivity_flags), event.initiator,
                    json.dumps(event.metadata, ensure_ascii=False, default=str),
                )
            )
        if not rows:
            return 0
        with self.transaction() as connection:
            connection.executemany(
                "INSERT INTO network_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
            )
            self._append_network_core(connection, event_list)
        return len(rows)

    def append_capture_events(self, session: CaptureSession, events: Iterable[NetworkEvent]) -> int:
        





        event_list = list(events)
        rows = [
            (
                event.id, event.session_id, event.source_type.value, event.timestamp,
                event.process_ref, event.flow_ref, event.request_ref, event.protocol,
                event.direction, event.size, event.method, event.url, event.status, event.host,
                json.dumps(event.timing),
                json.dumps(event.request_headers, ensure_ascii=False),
                json.dumps(event.response_headers, ensure_ascii=False),
                event.request_body_ref, event.response_body_ref,
                json.dumps(event.sensitivity_flags), event.initiator,
                json.dumps(event.metadata, ensure_ascii=False, default=str),
            )
            for event in event_list
        ]
        with self.transaction() as connection:
            self._upsert_capture_connection(connection, session)
            if session.project_id is not None or session.source_id is not None:
                self._bind_capture_connection(connection, session.id, session.project_id, session.source_id)
            if rows:
                connection.executemany(
                    "INSERT INTO network_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    rows,
                )
                self._append_network_core(connection, event_list)
        return len(rows)

    def save_capture_chunks(self, session_id: str, chunks: list[dict[str, Any]]) -> None:
        if not chunks:
            return
        with self.connect() as connection:
            connection.executemany(
                "INSERT OR REPLACE INTO capture_chunks(id,session_id,sequence,path,byte_size,sha256,committed_at) "
                "VALUES(?,?,?,?,?,?,?)",
                [
                    (
                        chunk["id"],
                        session_id,
                        chunk["sequence"],
                        chunk["path"],
                        chunk["byte_size"],
                        chunk["sha256"],
                        chunk.get("committed_at", utc_now()),
                    )
                    for chunk in chunks
                ],
            )

    def list_captures(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM capture_sessions ORDER BY created_at DESC LIMIT ?",
                    (max(1, min(5_000, int(limit))),),
                )
            ]

    def iter_network_events(self, session_id: str, limit: int = 10000) -> Iterator[dict[str, Any]]:
                                                                                           
                                                                                          
                                            
        remaining = max(0, int(limit))
        last_timestamp = ""
        last_id = ""
        while remaining > 0:
            page_size = min(1000, remaining)
            with self.connect() as connection:
                rows = connection.execute(
                    "SELECT * FROM network_events WHERE session_id=? "
                    "AND (timestamp>? OR (timestamp=? AND id>?)) "
                    "ORDER BY timestamp,id LIMIT ?",
                    (session_id, last_timestamp, last_timestamp, last_id, page_size),
                ).fetchall()
            if not rows:
                return
            for row in rows:
                last_timestamp = str(row["timestamp"])
                last_id = str(row["id"])
                remaining -= 1
                item = dict(row)
                for name in (
                    "timing_json", "request_headers_json", "response_headers_json",
                    "sensitivity_json", "metadata_json",
                ):
                    item[name[:-5] if name.endswith("_json") else name] = json.loads(item.pop(name))
                yield item
                if remaining <= 0:
                    return

    def save_revision(self, revision: DatasetRevision) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO dataset_revisions
                (id,dataset_id,parent_revision,label,source_run_ids_json,schema_json,created_at,schema_version,build_state)
                VALUES(?,?,?,?,?,?,?,?, 'ready')
                """,
                (
                    revision.id,
                    revision.dataset_id,
                    revision.parent_revision,
                    revision.label,
                    json.dumps(revision.source_run_ids),
                    json.dumps(revision.schema, ensure_ascii=False),
                    revision.created_at,
                    revision.schema_version,
                ),
            )

            batch: list[tuple[str, str, str, str]] = []
            for identity, data in revision.records.items():
                raw = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
                batch.append((revision.id, identity, raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()))
                if len(batch) >= 500:
                    connection.executemany("INSERT INTO revision_records VALUES(?,?,?,?)", batch)
                    batch.clear()
            if batch:
                connection.executemany("INSERT INTO revision_records VALUES(?,?,?,?)", batch)

    def count_revision_records(self, revision_id: str) -> int:
        with self.connect() as connection:
            return int(connection.execute(
                "SELECT count(*) FROM revision_records WHERE revision_id=?", (revision_id,)
            ).fetchone()[0])

    def load_revision_records(self, revision_id: str) -> dict[str, dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT record_identity,data_json FROM revision_records WHERE revision_id=?", (revision_id,)
            ).fetchall()
        return {str(row[0]): json.loads(row[1]) for row in rows}

    def list_revisions(
        self, dataset_id: str | None = None, *, include_incomplete: bool = False
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if dataset_id:
            clauses.append("dataset_id=?")
            values.append(dataset_id)
        if not include_incomplete:
            clauses.append("build_state='ready'")
        sql = "SELECT * FROM dataset_revisions"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC"
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return None if row is None else dict(row)

    def iter_result_records_raw(
        self, run_id: str, *, after_id: str = "", page_size: int = 1000
    ) -> Iterator[dict[str, Any]]:
        
        if not isinstance(page_size, int) or isinstance(page_size, bool) or page_size <= 0:
            raise ValueError("page_size must be a positive integer")
        page_size = min(page_size, 10_000)
        last_id = str(after_id or "")
        while True:
            with self.connect() as connection:
                rows = connection.execute(
                    "SELECT id,task_id,run_id,source_url,fetched_at,data_json,content_hash,quality_flags_json "
                    "FROM result_records WHERE run_id=? AND id>? ORDER BY id LIMIT ?",
                    (run_id, last_id, page_size),
                ).fetchall()
            if not rows:
                return
            for row in rows:
                last_id = str(row["id"])
                try:
                    data = json.loads(str(row["data_json"]))
                    flags = json.loads(str(row["quality_flags_json"]))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise ArenyxaError(
                        "DATASET_SOURCE_CORRUPT",
                        "结果记录包含损坏的 JSON，无法安全构建数据集修订。",
                        domain="DATASET",
                        context={"run_id": run_id, "record_id": last_id},
                    ) from exc
                if not isinstance(data, dict) or not isinstance(flags, list):
                    raise ArenyxaError(
                        "DATASET_SOURCE_CORRUPT",
                        "结果记录结构无效，无法安全构建数据集修订。",
                        domain="DATASET",
                        context={"run_id": run_id, "record_id": last_id},
                    )
                yield {
                    "id": last_id,
                    "task_id": str(row["task_id"]),
                    "run_id": str(row["run_id"]),
                    "source_url": str(row["source_url"]),
                    "fetched_at": str(row["fetched_at"]),
                    "data": data,
                    "content_hash": str(row["content_hash"]),
                    "quality_flags": [str(item) for item in flags],
                }

    def upsert_dataset(
        self,
        dataset_id: str,
        name: str,
        *,
        project_id: str | None = None,
        current_revision_id: str | None = None,
        schema_version: int = 6,
    ) -> None:
        dataset_id = str(dataset_id).strip()
        name = str(name).strip()
        if not dataset_id or not name:
            raise ValueError("dataset_id and name must be non-empty")
        now = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO datasets(id,name,project_id,current_revision_id,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    project_id=COALESCE(excluded.project_id,datasets.project_id),
                    current_revision_id=COALESCE(excluded.current_revision_id,datasets.current_revision_id),
                    updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version
                """,
                (dataset_id, name, project_id, current_revision_id, now, now, int(schema_version)),
            )

    def get_dataset(self, dataset_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM datasets WHERE id=?", (dataset_id,)).fetchone()
        return None if row is None else dict(row)

    def list_datasets(self, project_id: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        cap = max(1, min(10_000, int(limit)))
        sql = "SELECT * FROM datasets"
        values: list[Any] = []
        if project_id is not None:
            sql += " WHERE project_id=?"
            values.append(project_id)
        sql += " ORDER BY updated_at DESC,id LIMIT ?"
        values.append(cap)
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(sql, values)]

    def get_revision_metadata(
        self, revision_id: str, *, include_incomplete: bool = False
    ) -> dict[str, Any] | None:
        sql = "SELECT * FROM dataset_revisions WHERE id=?"
        values: list[Any] = [revision_id]
        if not include_incomplete:
            sql += " AND build_state='ready'"
        with self.connect() as connection:
            row = connection.execute(sql, values).fetchone()
        if row is None:
            return None
        item = dict(row)
        for raw_name, out_name, default in (
            ("source_run_ids_json", "source_run_ids", []),
            ("schema_json", "schema", {}),
        ):
            raw = item.pop(raw_name, None)
            try:
                parsed = json.loads(str(raw)) if raw is not None else default
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ArenyxaError(
                    "DATASET_REVISION_CORRUPT",
                    "数据集修订元数据损坏。",
                    domain="DATASET",
                    context={"revision_id": revision_id, "field": raw_name},
                ) from exc
            item[out_name] = parsed
        return item

    def iter_revision_records(
        self,
        revision_id: str,
        *,
        after_identity: str = "",
        page_size: int = 1000,
        include_incomplete: bool = False,
    ) -> Iterator[tuple[str, dict[str, Any]]]:
        if not isinstance(page_size, int) or isinstance(page_size, bool) or page_size <= 0:
            raise ValueError("page_size must be a positive integer")
        page_size = min(page_size, 10_000)
        metadata = self.get_revision_metadata(revision_id, include_incomplete=include_incomplete)
        if metadata is None:
            raise ArenyxaError(
                "DATASET_REVISION_NOT_FOUND",
                "找不到可读取的数据集修订。",
                domain="DATASET",
                context={"revision_id": revision_id},
            )
        last_identity = str(after_identity or "")
        while True:
            with self.connect() as connection:
                rows = connection.execute(
                    "SELECT record_identity,data_json FROM revision_records "
                    "WHERE revision_id=? AND record_identity>? ORDER BY record_identity LIMIT ?",
                    (revision_id, last_identity, page_size),
                ).fetchall()
            if not rows:
                return
            for row in rows:
                last_identity = str(row["record_identity"])
                try:
                    data = json.loads(str(row["data_json"]))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise ArenyxaError(
                        "DATASET_REVISION_CORRUPT",
                        "数据集修订记录损坏。",
                        domain="DATASET",
                        context={"revision_id": revision_id, "record_identity": last_identity},
                    ) from exc
                if not isinstance(data, dict):
                    raise ArenyxaError(
                        "DATASET_REVISION_CORRUPT",
                        "数据集修订记录必须是对象。",
                        domain="DATASET",
                        context={"revision_id": revision_id, "record_identity": last_identity},
                    )
                yield last_identity, data

    def begin_revision_build(self, revision: DatasetRevision) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO dataset_revisions
                (id,dataset_id,parent_revision,label,source_run_ids_json,schema_json,created_at,schema_version,build_state)
                VALUES(?,?,?,?,?,?,?,?, 'building')
                """,
                (
                    revision.id,
                    revision.dataset_id,
                    revision.parent_revision,
                    revision.label,
                    json.dumps(revision.source_run_ids, ensure_ascii=False),
                    json.dumps(revision.schema, ensure_ascii=False),
                    revision.created_at,
                    revision.schema_version,
                ),
            )

    def append_revision_records(
        self,
        revision_id: str,
        records: Iterable[tuple[str, dict[str, Any]]],
        *,
        replace: bool = True,
        batch_size: int = 500,
    ) -> int:
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise ValueError("batch_size must be a positive integer")
        batch_size = min(batch_size, 5000)
        sql = (
            "INSERT INTO revision_records(revision_id,record_identity,data_json,data_hash) VALUES(?,?,?,?) "
            "ON CONFLICT(revision_id,record_identity) DO UPDATE SET "
            "data_json=excluded.data_json,data_hash=excluded.data_hash"
            if replace
            else "INSERT INTO revision_records(revision_id,record_identity,data_json,data_hash) VALUES(?,?,?,?)"
        )
        total = 0
        batch: list[tuple[str, str, str, str]] = []
        with self.transaction() as connection:
            state_row = connection.execute(
                "SELECT build_state FROM dataset_revisions WHERE id=?", (revision_id,)
            ).fetchone()
            if state_row is None:
                raise ArenyxaError(
                    "DATASET_REVISION_NOT_FOUND", "找不到数据集修订。", domain="DATASET",
                    context={"revision_id": revision_id},
                )
            if str(state_row[0]) not in {"building", "interrupted"}:
                raise ArenyxaError(
                    "DATASET_REVISION_IMMUTABLE",
                    "已完成的数据集修订不可原地修改。",
                    domain="DATASET",
                    context={"revision_id": revision_id, "state": str(state_row[0])},
                )
            for identity, data in records:
                identity = str(identity)
                if not identity or len(identity) > 256 or not isinstance(data, dict):
                    raise ArenyxaError(
                        "DATASET_RECORD_INVALID",
                        "数据集记录标识或内容无效。",
                        domain="DATASET",
                        context={"revision_id": revision_id},
                    )
                raw = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
                batch.append((revision_id, identity, raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()))
                if len(batch) >= batch_size:
                    connection.executemany(sql, batch)
                    total += len(batch)
                    batch.clear()
            if batch:
                connection.executemany(sql, batch)
                total += len(batch)
        return total

    def set_revision_build_state(self, revision_id: str, state: str) -> None:
        if state not in {"building", "interrupted", "failed", "cancelled"}:
            raise ValueError("unsupported revision build state")
        with self.transaction() as connection:
            cursor = connection.execute(
                "UPDATE dataset_revisions SET build_state=? WHERE id=? AND build_state<>'ready'",
                (state, revision_id),
            )
            if cursor.rowcount != 1:
                raise ArenyxaError(
                    "DATASET_REVISION_STATE_CONFLICT",
                    "数据集修订状态已发生变化。",
                    domain="DATASET",
                    context={"revision_id": revision_id},
                )

    def finalize_revision_build(
        self,
        revision_id: str,
        *,
        schema: dict[str, str],
        dataset_name: str,
        project_id: str | None = None,
    ) -> int:
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT dataset_id,build_state FROM dataset_revisions WHERE id=?", (revision_id,)
            ).fetchone()
            if row is None:
                raise ArenyxaError(
                    "DATASET_REVISION_NOT_FOUND", "找不到数据集修订。", domain="DATASET",
                    context={"revision_id": revision_id},
                )
            state = str(row["build_state"])
            if state not in {"building", "interrupted"}:
                raise ArenyxaError(
                    "DATASET_REVISION_STATE_CONFLICT",
                    "当前修订不能完成构建。",
                    domain="DATASET",
                    context={"revision_id": revision_id, "state": state},
                )
            dataset_id = str(row["dataset_id"])
            count = int(connection.execute(
                "SELECT count(*) FROM revision_records WHERE revision_id=?", (revision_id,)
            ).fetchone()[0])
            connection.execute(
                "UPDATE dataset_revisions SET schema_json=?,build_state='ready' WHERE id=?",
                (json.dumps(schema, ensure_ascii=False, sort_keys=True), revision_id),
            )
            connection.execute(
                """
                INSERT INTO datasets(id,name,project_id,current_revision_id,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,6)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    project_id=COALESCE(excluded.project_id,datasets.project_id),
                    current_revision_id=excluded.current_revision_id,
                    updated_at=excluded.updated_at
                """,
                (dataset_id, dataset_name, project_id, revision_id, now, now),
            )
        return count

    @staticmethod
    def _lineage_node_id(kind: str, object_id: str) -> str:
        digest = hashlib.sha256(f"{kind}\0{object_id}".encode("utf-8")).hexdigest()[:32]
        return f"lineage_{digest}"

    @staticmethod
    def _lineage_edge_id(from_node_id: str, to_node_id: str, relation: str) -> str:
        digest = hashlib.sha256(
            f"{from_node_id}\0{to_node_id}\0{relation}".encode("utf-8")
        ).hexdigest()[:32]
        return f"edge_{digest}"

    def ensure_lineage_node(
        self,
        kind: str,
        object_id: str,
        *,
        label: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        kind = str(kind).strip().casefold()
        object_id = str(object_id).strip()
        if not kind or not object_id or len(kind) > 64 or len(object_id) > 256:
            raise ValueError("invalid lineage node identity")
        safe_metadata = metadata if isinstance(metadata, dict) else {}
        raw_metadata = json.dumps(safe_metadata, ensure_ascii=False, sort_keys=True, default=str)
        node_id = self._lineage_node_id(kind, object_id)
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO lineage_nodes(id,kind,object_id,label,metadata_json,created_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(kind,object_id) DO UPDATE SET
                    label=CASE WHEN excluded.label<>'' THEN excluded.label ELSE lineage_nodes.label END,
                    metadata_json=CASE WHEN excluded.metadata_json<>'{}' THEN excluded.metadata_json ELSE lineage_nodes.metadata_json END
                """,
                (node_id, kind, object_id, str(label)[:240], raw_metadata, utc_now()),
            )
        return node_id

    def add_lineage_edge(
        self,
        from_node_id: str,
        to_node_id: str,
        relation: str,
        *,
        evidence: dict[str, Any] | None = None,
    ) -> str:
        relation = str(relation).strip().casefold()
        if not relation or len(relation) > 80:
            raise ValueError("invalid lineage relation")
        edge_id = self._lineage_edge_id(from_node_id, to_node_id, relation)
        raw_evidence = json.dumps(
            evidence if isinstance(evidence, dict) else {},
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO lineage_edges(id,from_node_id,to_node_id,relation,evidence_json,created_at)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(from_node_id,to_node_id,relation) DO UPDATE SET
                    evidence_json=CASE WHEN excluded.evidence_json<>'{}' THEN excluded.evidence_json ELSE lineage_edges.evidence_json END
                """,
                (edge_id, from_node_id, to_node_id, relation, raw_evidence, utc_now()),
            )
        return edge_id

    def get_lineage_node(self, kind: str, object_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM lineage_nodes WHERE kind=? AND object_id=?",
                (str(kind).casefold(), str(object_id)),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["metadata"] = json.loads(str(item.pop("metadata_json")))
        except (json.JSONDecodeError, TypeError, ValueError):
            item["metadata"] = {}
        return item

    def lineage_neighbors(
        self, node_id: str, *, direction: str = "both", limit: int = 500
    ) -> list[dict[str, Any]]:
        if direction not in {"upstream", "downstream", "both"}:
            raise ValueError("direction must be upstream/downstream/both")
        cap = max(1, min(5000, int(limit)))
        queries: list[tuple[str, str]] = []
        if direction in {"downstream", "both"}:
            queries.append((
                "downstream",
                "SELECT e.*,n.kind,n.object_id,n.label,n.metadata_json "
                "FROM lineage_edges e JOIN lineage_nodes n ON n.id=e.to_node_id "
                "WHERE e.from_node_id=? ORDER BY e.id LIMIT ?",
            ))
        if direction in {"upstream", "both"}:
            queries.append((
                "upstream",
                "SELECT e.*,n.kind,n.object_id,n.label,n.metadata_json "
                "FROM lineage_edges e JOIN lineage_nodes n ON n.id=e.from_node_id "
                "WHERE e.to_node_id=? ORDER BY e.id LIMIT ?",
            ))
        output: list[dict[str, Any]] = []
        with self.connect() as connection:
            for edge_direction, sql in queries:
                for row in connection.execute(sql, (node_id, cap)).fetchall():
                    item = dict(row)
                    item["direction"] = edge_direction
                    try:
                        item["evidence"] = json.loads(str(item.pop("evidence_json")))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        item["evidence"] = {}
                    try:
                        item["metadata"] = json.loads(str(item.pop("metadata_json")))
                    except (json.JSONDecodeError, TypeError, ValueError):
                        item["metadata"] = {}
                    output.append(item)
                    if len(output) >= cap:
                        return output
        return output

    def save_schedule(self, schedule: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO schedules(id,task_id,rule_json,timezone,enabled,next_run_at,last_run_at,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET rule_json=excluded.rule_json,timezone=excluded.timezone,
                    enabled=excluded.enabled,next_run_at=excluded.next_run_at,last_run_at=excluded.last_run_at,
                    updated_at=excluded.updated_at
                """,
                (
                    schedule["id"],
                    schedule["task_id"],
                    json.dumps(schedule["rule"], ensure_ascii=False),
                    schedule["timezone"],
                    int(schedule.get("enabled", True)),
                    schedule.get("next_run_at"),
                    schedule.get("last_run_at"),
                    schedule.get("created_at", utc_now()),
                    utc_now(),
                ),
            )

    def list_schedules(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT s.*,t.name AS task_name FROM schedules s JOIN tasks t ON t.id=s.task_id ORDER BY s.updated_at DESC"
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            raw_rule = item.pop("rule_json", "{}")
            try:
                parsed_rule = json.loads(raw_rule)
                if not isinstance(parsed_rule, dict):
                    raise ValueError("rule_json root is not an object")
                item["rule"] = parsed_rule
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                                                                                            
                                                                                          
                item["rule"] = {}
                item["rule_error"] = f"Invalid persisted schedule rule: {exc}"
                LOGGER.error("Invalid schedule rule for %s: %s", item.get("id"), exc)
            item["enabled"] = bool(item.get("enabled"))
            result.append(item)
        return result

    def update_schedule_next_run(self, schedule_id: str, next_run_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE schedules SET next_run_at=?,updated_at=? WHERE id=?",
                (next_run_at, utc_now(), schedule_id),
            )

    def mark_schedule_executed(self, schedule_id: str, last_run_at: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE schedules SET last_run_at=?,updated_at=? WHERE id=?",
                (last_run_at, utc_now(), schedule_id),
            )

    def mark_schedule_fired(self, schedule_id: str, next_run_at: str, last_run_at: str) -> None:
        
        with self.connect() as connection:
            connection.execute(
                "UPDATE schedules SET next_run_at=?,last_run_at=?,updated_at=? WHERE id=?",
                (next_run_at, last_run_at, utc_now(), schedule_id),
            )

    def save_workflow(self, workflow: dict[str, Any]) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO workflows(id,name,version,definition_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version,
                    definition_json=excluded.definition_json,updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version
                """,
                (
                    workflow["id"],
                    workflow["name"],
                    workflow.get("version", "1.0.0"),
                    json.dumps(workflow, ensure_ascii=False, default=str),
                    workflow.get("created_at", now),
                    now,
                    workflow.get("schema_version", 6),
                ),
            )

    def list_workflows(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [
                json.loads(row[0])
                for row in connection.execute(
                    "SELECT definition_json FROM workflows ORDER BY updated_at DESC"
                )
            ]

    def get_workflow(self, workflow_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT definition_json FROM workflows WHERE id=?", (workflow_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row[0]))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ArenyxaError(
                "WORKFLOW_DEFINITION_CORRUPT",
                "持久化的工作流定义损坏。",
                domain="WORKFLOW",
                context={"workflow_id": workflow_id},
            ) from exc
        if not isinstance(payload, dict):
            raise ArenyxaError(
                "WORKFLOW_DEFINITION_CORRUPT",
                "持久化的工作流定义根节点必须是对象。",
                domain="WORKFLOW",
                context={"workflow_id": workflow_id},
            )
        return payload

    def begin_workflow_execution(
        self,
        execution: dict[str, Any],
        node_ids: Iterable[str],
    ) -> None:
        required = {
            "id", "workflow_id", "source_revision_id", "output_dataset_id",
            "output_revision_id", "definition_hash", "started_at",
        }
        missing = sorted(required - set(execution))
        if missing:
            raise ValueError(f"missing workflow execution fields: {', '.join(missing)}")
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO workflow_executions(
                    id,workflow_id,source_revision_id,output_dataset_id,output_revision_id,
                    state,definition_hash,started_at,updated_at,finished_at,last_input_identity,
                    processed_inputs,staged_outputs,error_count,checkpoint_json,error_code,error_message,
                    definition_json
                ) VALUES(?,?,?,?,?,'running',?,?,?,NULL,NULL,0,0,0,'{}',NULL,NULL,?)
                """,
                (
                    execution["id"], execution["workflow_id"], execution["source_revision_id"],
                    execution["output_dataset_id"], execution["output_revision_id"],
                    execution["definition_hash"], execution["started_at"], execution["started_at"],
                    str(execution.get("definition_json") or "{}"),
                ),
            )
            rows = [(execution["id"], str(node_id)) for node_id in node_ids]
            if rows:
                connection.executemany(
                    "INSERT INTO workflow_node_executions(execution_id,node_id) VALUES(?,?)",
                    rows,
                )

    def get_workflow_execution(self, execution_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM workflow_executions WHERE id=?", (execution_id,)
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        try:
            item["checkpoint"] = json.loads(str(item.pop("checkpoint_json")))
        except (json.JSONDecodeError, TypeError, ValueError):
            item["checkpoint"] = {}
        return item

    def claim_workflow_execution_for_resume(self, execution_id: str) -> bool:
        






        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT state,output_revision_id FROM workflow_executions WHERE id=?",
                (execution_id,),
            ).fetchone()
            if row is None:
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW",
                    context={"execution_id": execution_id},
                )
            state = str(row[0])
            output_revision_id = str(row[1] or "")
            if state not in {"interrupted", "cancelled"}:
                return False
            revision = connection.execute(
                "SELECT build_state FROM dataset_revisions WHERE id=?",
                (output_revision_id,),
            ).fetchone()
            if revision is None or str(revision[0]) == "ready":
                raise ArenyxaError(
                    "WORKFLOW_RESUME_OUTPUT_INVALID",
                    "工作流输出 Revision 不存在或已经完成，无法恢复。",
                    domain="WORKFLOW",
                    context={"execution_id": execution_id, "revision_id": output_revision_id},
                )
            cursor = connection.execute(
                "UPDATE workflow_executions SET state='running',updated_at=?,finished_at=NULL,"
                "error_code=NULL,error_message=NULL WHERE id=? AND state=?",
                (now, execution_id, state),
            )
            if cursor.rowcount != 1:
                return False
            revision_cursor = connection.execute(
                "UPDATE dataset_revisions SET build_state='building' WHERE id=? AND build_state<>'ready'",
                (output_revision_id,),
            )
            if revision_cursor.rowcount != 1:
                raise ArenyxaError(
                    "WORKFLOW_RESUME_OUTPUT_CONFLICT",
                    "工作流输出 Revision 状态发生并发变化，已取消恢复。",
                    domain="WORKFLOW",
                    context={"execution_id": execution_id, "revision_id": output_revision_id},
                )
        return True

    def list_workflow_executions(
        self, workflow_id: str | None = None, *, limit: int = 200
    ) -> list[dict[str, Any]]:
        cap = max(1, min(5000, int(limit)))
        sql = "SELECT * FROM workflow_executions"
        values: list[Any] = []
        if workflow_id is not None:
            sql += " WHERE workflow_id=?"
            values.append(workflow_id)
        sql += " ORDER BY started_at DESC,id LIMIT ?"
        values.append(cap)
        with self.connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["checkpoint"] = json.loads(str(item.pop("checkpoint_json")))
            except (json.JSONDecodeError, TypeError, ValueError):
                item["checkpoint"] = {}
            output.append(item)
        return output

    def list_completed_workflow_executions_missing_lineage(
        self, *, limit: int = 5000
    ) -> list[dict[str, Any]]:
        





        cap = max(1, min(20_000, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT e.*
                FROM workflow_executions e
                JOIN dataset_revisions r ON r.id=e.output_revision_id AND r.build_state='ready'
                LEFT JOIN lineage_nodes source_node
                  ON source_node.kind='workflow_execution' AND source_node.object_id=e.id
                LEFT JOIN lineage_nodes target_node
                  ON target_node.kind='revision' AND target_node.object_id=e.output_revision_id
                LEFT JOIN lineage_edges edge
                  ON edge.from_node_id=source_node.id
                 AND edge.to_node_id=target_node.id
                 AND edge.relation='produced'
                WHERE e.state IN ('completed','completed_with_errors')
                  AND edge.id IS NULL
                ORDER BY e.started_at DESC,e.id
                LIMIT ?
                """,
                (cap,),
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["checkpoint"] = json.loads(str(item.pop("checkpoint_json")))
            except (json.JSONDecodeError, TypeError, ValueError):
                item["checkpoint"] = {}
            output.append(item)
        return output

    def list_ready_dataset_revisions_missing_lineage(
        self, *, limit: int = 5000
    ) -> list[dict[str, Any]]:
        
        cap = max(1, min(20_000, int(limit)))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT r.*
                FROM dataset_revisions r
                LEFT JOIN lineage_nodes revision_node
                  ON revision_node.kind='revision' AND revision_node.object_id=r.id
                LEFT JOIN lineage_nodes dataset_node
                  ON dataset_node.kind='dataset' AND dataset_node.object_id=r.dataset_id
                LEFT JOIN lineage_edges edge
                  ON edge.from_node_id=revision_node.id
                 AND edge.to_node_id=dataset_node.id
                 AND edge.relation='version_of'
                WHERE r.build_state='ready' AND edge.id IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM workflow_executions execution
                      WHERE execution.output_revision_id=r.id
                  )
                ORDER BY r.created_at DESC,r.id
                LIMIT ?
                """,
                (cap,),
            ).fetchall()
        output: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["source_run_ids"] = json.loads(str(item.pop("source_run_ids_json")))
                item["schema"] = json.loads(str(item.pop("schema_json")))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                LOGGER.error("Skipping corrupt ready revision during lineage scan: %s", exc)
                continue
            output.append(item)
        return output

    def get_workflow_node_executions(self, execution_id: str) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM workflow_node_executions WHERE execution_id=? ORDER BY node_id",
                    (execution_id,),
                )
            ]

    def checkpoint_workflow_execution(
        self,
        execution_id: str,
        *,
        last_input_identity: str,
        processed_delta: int,
        output_delta: int,
        error_delta: int,
        node_deltas: dict[str, dict[str, int | str]],
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        if processed_delta < 0 or output_delta < 0 or error_delta < 0:
            raise ValueError("workflow checkpoint deltas must be non-negative")
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT state FROM workflow_executions WHERE id=?", (execution_id,)
            ).fetchone()
            if row is None:
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW",
                    context={"execution_id": execution_id},
                )
            if str(row[0]) != "running":
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_STATE_CONFLICT",
                    "当前工作流执行状态不能写入检查点。",
                    domain="WORKFLOW",
                    context={"execution_id": execution_id, "state": str(row[0])},
                )
            connection.execute(
                """
                UPDATE workflow_executions SET
                    state='running',updated_at=?,last_input_identity=?,
                    processed_inputs=processed_inputs+?,staged_outputs=staged_outputs+?,
                    error_count=error_count+?,checkpoint_json=?,error_code=NULL,error_message=NULL
                WHERE id=?
                """,
                (
                    now, last_input_identity, int(processed_delta), int(output_delta), int(error_delta),
                    json.dumps(checkpoint or {}, ensure_ascii=False, sort_keys=True, default=str), execution_id,
                ),
            )
            for node_id, delta in node_deltas.items():
                connection.execute(
                    """
                    INSERT INTO workflow_node_executions(
                        execution_id,node_id,input_count,output_count,error_count,state
                    ) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(execution_id,node_id) DO UPDATE SET
                        input_count=workflow_node_executions.input_count+excluded.input_count,
                        output_count=workflow_node_executions.output_count+excluded.output_count,
                        error_count=workflow_node_executions.error_count+excluded.error_count,
                        state=excluded.state
                    """,
                    (
                        execution_id, str(node_id), int(delta.get("input_count", 0)),
                        int(delta.get("output_count", 0)), int(delta.get("error_count", 0)),
                        str(delta.get("state", "completed"))[:32],
                    ),
                )

    def finish_workflow_execution(
        self,
        execution_id: str,
        *,
        state: str,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> None:
        if state not in {"completed", "completed_with_errors", "failed", "cancelled", "interrupted"}:
            raise ValueError("unsupported workflow execution state")
        now = utc_now()
        finished = now if state in {"completed", "completed_with_errors", "failed", "cancelled"} else None
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE workflow_executions SET state=?,updated_at=?,finished_at=?,error_code=?,error_message=?
                WHERE id=?
                """,
                (
                    state, now, finished, error_code,
                    None if error_message is None else str(error_message)[:500], execution_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ArenyxaError(
                    "WORKFLOW_EXECUTION_NOT_FOUND", "找不到工作流执行记录。", domain="WORKFLOW",
                    context={"execution_id": execution_id},
                )

    def save_visualization(self, visualization: dict[str, Any]) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO visualizations(id,name,dataset_ref,chart_type,config_json,created_at,updated_at,schema_version)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name,dataset_ref=excluded.dataset_ref,
                    chart_type=excluded.chart_type,config_json=excluded.config_json,updated_at=excluded.updated_at,
                    schema_version=excluded.schema_version
                """,
                (
                    visualization["id"],
                    visualization["name"],
                    visualization["dataset_ref"],
                    visualization["chart_type"],
                    json.dumps(visualization["config"], ensure_ascii=False),
                    visualization.get("created_at", now),
                    now,
                    visualization.get("schema_version", 6),
                ),
            )

    def list_visualizations(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM visualizations ORDER BY updated_at DESC").fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["config"] = json.loads(item.pop("config_json"))
            result.append(item)
        return result

    def index_object(self, object_type: str, object_id: str, title: str, url: str, content: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM local_search WHERE object_type=? AND object_id=?", (object_type, object_id)
            )
            connection.execute(
                "INSERT INTO local_search(object_type,object_id,title,url,content) VALUES(?,?,?,?,?)",
                (object_type, object_id, title, url, content),
            )

    def search(self, query: str, limit: int = 100) -> list[dict[str, Any]]:
        import re

        sanitized = " ".join(f'"{token}"*' for token in re.findall(r"[\w]+", query, flags=re.UNICODE))
        if not sanitized:
            return []
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT object_type,object_id,title,url,snippet(local_search,4,'<b>','</b>','…',18) AS snippet "
                "FROM local_search WHERE local_search MATCH ? ORDER BY rank LIMIT ?",
                (sanitized, max(1, min(1_000, int(limit)))),
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_metrics(self) -> dict[str, Any]:
        with self.connect() as connection:
                                                                                                
                                                                                             
                                                  
            row = connection.execute(
                """SELECT
                   (SELECT count(*) FROM tasks WHERE status NOT IN ('deleted','archived')) AS tasks,
                   (SELECT count(*) FROM runs) AS runs,
                   (SELECT count(*) FROM result_records) AS records,
                   (SELECT count(*) FROM runs WHERE status IN ('queued','running','paused')) AS active,
                   (SELECT count(*) FROM capture_sessions) AS captures,
                   (SELECT count(*) FROM runs WHERE status='failed') AS errors"""
            ).fetchone()
        assert row is not None
        return {
            "tasks": int(row["tasks"]),
            "runs": int(row["runs"]),
            "records": int(row["records"]),
            "active": int(row["active"]),
            "captures": int(row["captures"]),
            "errors": int(row["errors"]),
            "database_bytes": self.path.stat().st_size if self.path.exists() else 0,
        }

    @staticmethod
    def _task_from_dict(data: dict[str, Any]) -> Task:
        if not isinstance(data, dict):
            raise TypeError("task definition root must be an object")
        request_items = data.get("requests", [])
        field_items = data.get("fields", [])
        if not isinstance(request_items, list) or not isinstance(field_items, list):
            raise TypeError("task requests/fields must be arrays")

        requests: list[RequestSpec] = []
        for item in request_items:
            if not isinstance(item, dict):
                raise TypeError("task request must be an object")
            raw = dict(item)
            retry_value = raw.pop("retry", {})
            if not isinstance(retry_value, dict):
                raise TypeError("retry policy must be an object")
            requests.append(RequestSpec(**raw, retry=RetryPolicy(**dict(retry_value))))

        fields: list[FieldSpec] = []
        from arenyxa.domain.models import CleanerStep, ValidationRule

        for item in field_items:
            if not isinstance(item, dict):
                raise TypeError("task field must be an object")
            raw = dict(item)
            cleaner_items = raw.pop("cleaners", [])
            validator_items = raw.pop("validators", [])
            if not isinstance(cleaner_items, list) or not isinstance(validator_items, list):
                raise TypeError("field cleaners/validators must be arrays")
            cleaners = []
            for cleaner in cleaner_items:
                if not isinstance(cleaner, dict):
                    raise TypeError("cleaner must be an object")
                cleaners.append(CleanerStep(**dict(cleaner)))
            validators = []
            for validator in validator_items:
                if not isinstance(validator, dict):
                    raise TypeError("validator must be an object")
                validators.append(ValidationRule(**dict(validator)))
            fields.append(FieldSpec(**raw, cleaners=cleaners, validators=validators))

        if not isinstance(data.get("name"), str) or not isinstance(data.get("id"), str):
            raise TypeError("task name/id must be strings")
        return Task(
            name=data["name"],
            requests=requests,
            fields=fields,
            id=data["id"],
            status=TaskStatus(str(data.get("status", "draft"))),
            tags=list(data.get("tags", [])) if isinstance(data.get("tags", []), list) else [],
            parser_hint=str(data.get("parser_hint", "auto")),
            created_at=str(data.get("created_at", utc_now())),
            updated_at=str(data.get("updated_at", utc_now())),
            schema_version=int(data.get("schema_version", 1)),
        )
