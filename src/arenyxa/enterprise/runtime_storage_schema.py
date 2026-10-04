"""Additive SQLite/PostgreSQL distributed storage schema contracts."""

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS distributed_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS distributed_workers(
    worker_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    identity_algorithm TEXT NOT NULL DEFAULT 'ED25519',
    identity_metadata_json TEXT NOT NULL DEFAULT '{}',
    protocol_min INTEGER NOT NULL,
    protocol_max INTEGER NOT NULL,
    negotiated_protocol INTEGER NOT NULL,
    app_compat_version TEXT NOT NULL,
    resources_json TEXT NOT NULL,
    max_slots INTEGER NOT NULL,
    active_leases INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    heartbeat_at REAL NOT NULL,
    revoked_at TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS distributed_jobs(
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    traceparent TEXT NOT NULL DEFAULT '',
    tracestate TEXT NOT NULL DEFAULT '',
    resource_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    side_effect_mode TEXT NOT NULL,
    side_effect_state TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL,
    protocol_version INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    lease_worker_id TEXT NOT NULL DEFAULT '',
    lease_token_sha256 TEXT NOT NULL DEFAULT '',
    lease_expires_at REAL NOT NULL DEFAULT 0,
    checkpoint_json TEXT NOT NULL DEFAULT '{}',
    checkpoint_seq INTEGER NOT NULL DEFAULT 0,
    result_json TEXT NOT NULL DEFAULT '{}',
    result_sha256 TEXT NOT NULL DEFAULT '',
    terminal_worker_id TEXT NOT NULL DEFAULT '',
    terminal_lease_token_sha256 TEXT NOT NULL DEFAULT '',
    terminal_at TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS distributed_job_idempotency(
    idempotency_key TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    side_effect_mode TEXT NOT NULL,
    terminal_state TEXT NOT NULL,
    terminal_receipt TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    terminal_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_distributed_idempotency_retention
    ON distributed_job_idempotency(side_effect_mode,terminal_at,idempotency_key);
CREATE INDEX IF NOT EXISTS idx_distributed_idempotency_job
    ON distributed_job_idempotency(job_id);
CREATE TABLE IF NOT EXISTS distributed_job_events(
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    worker_id TEXT NOT NULL DEFAULT '',
    code TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(job_id) REFERENCES distributed_jobs(job_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_distributed_job_events_job
    ON distributed_job_events(job_id,event_id DESC);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_state_priority
    ON distributed_jobs(state, priority DESC, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_distributed_jobs_worker
    ON distributed_jobs(lease_worker_id, state);
"""

_POSTGRES_SCHEMA = (
    _SQLITE_SCHEMA.replace(
        "event_id INTEGER PRIMARY KEY AUTOINCREMENT", "event_id BIGSERIAL PRIMARY KEY"
    )
    # SQLite REAL is an 8-byte IEEE-754 value, while PostgreSQL REAL is only 4 bytes.
    # Epoch timestamps need float8 precision so short leases and heartbeats are not rounded
    # by roughly a minute at contemporary epoch values.
    .replace("heartbeat_at REAL", "heartbeat_at DOUBLE PRECISION")
    .replace("lease_expires_at REAL", "lease_expires_at DOUBLE PRECISION")
)

_POSTGRES_EPOCH_MIGRATIONS = (
    (
        "distributed_workers",
        "heartbeat_at",
        (
            "ALTER TABLE distributed_workers ALTER COLUMN heartbeat_at TYPE DOUBLE PRECISION "
            "USING heartbeat_at::DOUBLE PRECISION"
        ),
    ),
    (
        "distributed_jobs",
        "lease_expires_at",
        (
            "ALTER TABLE distributed_jobs ALTER COLUMN lease_expires_at TYPE DOUBLE PRECISION "
            "USING lease_expires_at::DOUBLE PRECISION"
        ),
    ),
)
