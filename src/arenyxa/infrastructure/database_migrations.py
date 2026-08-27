"""SQLite schema migrations for the Arenyxa local persistence store.

Kept out of database.py so the runtime facade stays small and maintainable.
"""
from __future__ import annotations

from arenyxa.infrastructure.database_jobs import PLATFORM_JOB_MIGRATION

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
    """,
    PLATFORM_JOB_MIGRATION,

)