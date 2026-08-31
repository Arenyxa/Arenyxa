from __future__ import annotations


class PostgreSQLFastSqlMixin:
    def lease_next_fast_sql(self) -> str:
        return """
            WITH eligible_worker AS (
                SELECT worker_id,protocol_min,protocol_max
                FROM distributed_workers
                WHERE worker_id=? AND state='active' AND active_leases<max_slots
            ), candidate AS (
                SELECT j.*
                FROM distributed_jobs AS j
                JOIN eligible_worker AS w
                  ON j.protocol_version BETWEEN w.protocol_min AND w.protocol_max
                WHERE j.state='queued'
                ORDER BY j.priority DESC,j.created_at ASC
                LIMIT 1
                FOR UPDATE OF j SKIP LOCKED
            ), claimed_worker AS (
                UPDATE distributed_workers AS w
                SET active_leases=w.active_leases+1,heartbeat_at=GREATEST(w.heartbeat_at,?,EXTRACT(EPOCH FROM clock_timestamp())),updated_at=?
                FROM candidate AS c
                WHERE w.worker_id=? AND w.state='active' AND w.active_leases<w.max_slots
                RETURNING w.worker_id
            ), leased AS (
                UPDATE distributed_jobs AS j
                SET state='leased',attempt=j.attempt+1,lease_worker_id=?,lease_token_sha256=?,
                    lease_expires_at=EXTRACT(EPOCH FROM clock_timestamp())+?,error_code='',updated_at=?
                FROM candidate AS c
                CROSS JOIN claimed_worker AS w
                WHERE j.job_id=c.job_id AND j.state='queued'
                RETURNING j.*
            ), event AS (
                INSERT INTO distributed_job_events(
                    job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
                )
                SELECT job_id,'leased','queued','leased',?,?,
                       json_build_object('attempt',attempt,'lease_seconds',?)::text,?
                FROM leased
                RETURNING job_id
            ), trimmed AS (
                DELETE FROM distributed_job_events
                WHERE job_id=(SELECT job_id FROM event)
                  AND event_id NOT IN (
                      SELECT event_id FROM distributed_job_events
                      WHERE job_id=(SELECT job_id FROM event)
                      ORDER BY event_id DESC LIMIT ?
                  )
            )
            SELECT * FROM leased
        """

    def start_job_fast_sql(self) -> str:
        return """
            WITH candidate AS (
                SELECT job_id,state
                FROM distributed_jobs
                WHERE job_id=? AND state='leased' AND lease_worker_id=?
                  AND lease_token_sha256=? AND lease_expires_at>GREATEST(?,EXTRACT(EPOCH FROM clock_timestamp()))
                FOR UPDATE
            ), updated AS (
                UPDATE distributed_jobs AS j
                SET state='running',updated_at=?
                FROM candidate AS c
                WHERE j.job_id=c.job_id
                RETURNING j.job_id
            ), event AS (
                INSERT INTO distributed_job_events(
                    job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
                )
                SELECT c.job_id,'started',c.state,'running',?,?,?,?
                FROM candidate AS c
                JOIN updated AS u ON u.job_id=c.job_id
                RETURNING job_id
            ), trimmed AS (
                DELETE FROM distributed_job_events
                WHERE job_id=(SELECT job_id FROM event)
                  AND event_id NOT IN (
                      SELECT event_id FROM distributed_job_events
                      WHERE job_id=(SELECT job_id FROM event)
                      ORDER BY event_id DESC LIMIT ?
                  )
            )
            SELECT * FROM updated
        """

    def complete_fast_sql(self) -> str:
        return """
            WITH candidate AS (
                SELECT job_id,state,side_effect_state,idempotency_key,kind,payload_sha256,
                       resource_id,permission,side_effect_mode,created_at
                FROM distributed_jobs
                WHERE job_id=? AND state IN ('leased','running')
                  AND lease_worker_id=? AND lease_token_sha256=? AND lease_expires_at>GREATEST(?,EXTRACT(EPOCH FROM clock_timestamp()))
                FOR UPDATE
            ), tombstone AS (
                INSERT INTO distributed_job_idempotency(
                    idempotency_key,job_id,kind,payload_sha256,resource_id,permission,
                    side_effect_mode,terminal_state,created_at,terminal_at,updated_at
                )
                SELECT c.idempotency_key,c.job_id,c.kind,c.payload_sha256,c.resource_id,c.permission,
                       c.side_effect_mode,'completed',c.created_at,?,?
                FROM candidate AS c
                ON CONFLICT (idempotency_key) DO UPDATE SET
                    terminal_state=EXCLUDED.terminal_state,
                    terminal_at=EXCLUDED.terminal_at,
                    updated_at=EXCLUDED.updated_at
                WHERE distributed_job_idempotency.job_id=EXCLUDED.job_id
                  AND distributed_job_idempotency.kind=EXCLUDED.kind
                  AND distributed_job_idempotency.payload_sha256=EXCLUDED.payload_sha256
                  AND distributed_job_idempotency.resource_id=EXCLUDED.resource_id
                  AND distributed_job_idempotency.permission=EXCLUDED.permission
                  AND distributed_job_idempotency.side_effect_mode=EXCLUDED.side_effect_mode
                RETURNING idempotency_key,terminal_at,updated_at
            ), updated AS (
                UPDATE distributed_jobs AS j
                SET state='completed',result_json=?,result_sha256=?,
                    side_effect_state=CASE WHEN c.side_effect_state='started' THEN 'completed'
                                           ELSE c.side_effect_state END,
                    terminal_worker_id=?,terminal_lease_token_sha256=?,terminal_at=t.terminal_at,
                    lease_worker_id='',lease_token_sha256='',lease_expires_at=0,
                    error_code='',updated_at=t.updated_at
                FROM candidate AS c
                JOIN tombstone AS t ON t.idempotency_key=c.idempotency_key
                WHERE j.job_id=c.job_id
                RETURNING j.job_id,j.terminal_at,j.updated_at
            ), worker_updated AS (
                UPDATE distributed_workers AS w
                SET active_leases=GREATEST(0,w.active_leases-1),heartbeat_at=GREATEST(w.heartbeat_at,?,EXTRACT(EPOCH FROM clock_timestamp())),updated_at=?
                WHERE w.worker_id=? AND EXISTS (SELECT 1 FROM updated)
                RETURNING w.worker_id
            ), event AS (
                INSERT INTO distributed_job_events(
                    job_id,event_type,from_state,to_state,worker_id,code,details_json,created_at
                )
                SELECT c.job_id,'completed',c.state,'completed',?,?,?,?
                FROM candidate AS c
                JOIN updated AS u ON u.job_id=c.job_id
                RETURNING job_id
            ), trimmed AS (
                DELETE FROM distributed_job_events
                WHERE job_id=(SELECT job_id FROM event)
                  AND event_id NOT IN (
                      SELECT event_id FROM distributed_job_events
                      WHERE job_id=(SELECT job_id FROM event)
                      ORDER BY event_id DESC LIMIT ?
                  )
            )
            SELECT c.state AS previous_state
            FROM candidate AS c
            JOIN updated AS u ON u.job_id=c.job_id
        """
