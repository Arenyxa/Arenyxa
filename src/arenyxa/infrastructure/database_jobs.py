from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Any

from arenyxa.domain.models import utc_now

PLATFORM_JOB_MIGRATION = """
CREATE TABLE IF NOT EXISTS platform_jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    surface TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'queued','running','succeeded','failed','cancelled','timed_out','interrupted'
    )),
    progress REAL NOT NULL DEFAULT 0.0 CHECK(progress >= 0.0 AND progress <= 1.0),
    message TEXT NOT NULL DEFAULT '',
    result_json TEXT NOT NULL DEFAULT 'null',
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    timeout_seconds REAL NOT NULL CHECK(timeout_seconds > 0.0 AND timeout_seconds <= 86400.0),
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_platform_jobs_state_created
    ON platform_jobs(state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_platform_jobs_kind_created
    ON platform_jobs(kind, created_at DESC);
"""


class PlatformJobStoreMixin:
    """Durable repository operations for the bounded v8 platform Job System."""

    _JOB_STATES = frozenset(
        {"queued", "running", "succeeded", "failed", "cancelled", "timed_out", "interrupted"}
    )

    @classmethod
    def _validate_job_state(cls, state: str) -> str:
        normalized = str(state).strip().casefold()
        if normalized not in cls._JOB_STATES:
            raise ValueError(f"invalid platform job state: {state}")
        return normalized

    def create_platform_job(self, row: Mapping[str, Any]) -> None:
        state = self._validate_job_state(str(row.get("state", "queued")))
        job_id = str(row.get("id", "")).strip()
        kind = str(row.get("kind", "")).strip()
        surface = str(row.get("surface", "")).strip()
        if not job_id or len(job_id) > 160:
            raise ValueError("platform job id must contain 1-160 characters")
        if not kind or len(kind) > 128 or not surface or len(surface) > 64:
            raise ValueError("platform job kind/surface is invalid")
        created_at = str(row.get("created_at") or utc_now())
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO platform_jobs(
                    id,kind,surface,state,progress,message,result_json,error_code,error_message,
                    actor,correlation_id,timeout_seconds,created_at,started_at,finished_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    job_id,
                    kind,
                    surface,
                    state,
                    float(row.get("progress", 0.0)),
                    str(row.get("message", ""))[:1024],
                    json.dumps(row.get("result"), ensure_ascii=False, separators=(",", ":")),
                    str(row.get("error_code", ""))[:128],
                    str(row.get("error_message", ""))[:4096],
                    str(row.get("actor", ""))[:256],
                    str(row.get("correlation_id", ""))[:256],
                    float(row.get("timeout_seconds", 0.0)),
                    created_at,
                    row.get("started_at"),
                    row.get("finished_at"),
                    str(row.get("updated_at") or created_at),
                ),
            )

    def update_platform_job(
        self,
        job_id: str,
        *,
        state: str | None = None,
        progress: float | None = None,
        message: str | None = None,
        result: Any = None,
        result_present: bool = False,
        error_code: str | None = None,
        error_message: str | None = None,
        started_at: str | None = None,
        finished_at: str | None = None,
        expected_states: tuple[str, ...] | None = None,
    ) -> bool:
        assignments = ["updated_at=?"]
        parameters: list[Any] = [utc_now()]
        if state is not None:
            assignments.append("state=?")
            parameters.append(self._validate_job_state(state))
        if progress is not None:
            assignments.append("progress=?")
            parameters.append(max(0.0, min(1.0, float(progress))))
        if message is not None:
            assignments.append("message=?")
            parameters.append(str(message)[:1024])
        if result_present:
            encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"), default=str)
            if len(encoded.encode("utf-8")) > 1024 * 1024:
                raise ValueError("platform job result exceeds the 1 MiB persistence budget")
            assignments.append("result_json=?")
            parameters.append(encoded)
        if error_code is not None:
            assignments.append("error_code=?")
            parameters.append(str(error_code)[:128])
        if error_message is not None:
            assignments.append("error_message=?")
            parameters.append(str(error_message)[:4096])
        if started_at is not None:
            assignments.append("started_at=?")
            parameters.append(str(started_at))
        if finished_at is not None:
            assignments.append("finished_at=?")
            parameters.append(str(finished_at))
        sql = "UPDATE platform_jobs SET " + ",".join(assignments) + " WHERE id=?"
        parameters.append(str(job_id))
        if expected_states:
            normalized = tuple(self._validate_job_state(item) for item in expected_states)
            sql += " AND state IN (" + ",".join("?" for _ in normalized) + ")"
            parameters.extend(normalized)
        with self.transaction() as connection:
            cursor = connection.execute(sql, parameters)
        return int(cursor.rowcount) == 1

    @staticmethod
    def _platform_job_row(row: sqlite3.Row) -> dict[str, Any]:
        payload = dict(row)
        try:
            payload["result"] = json.loads(str(payload.pop("result_json")))
        except (json.JSONDecodeError, TypeError, UnicodeError):
            payload.pop("result_json", None)
            payload["result"] = None
            payload["error_code"] = payload.get("error_code") or "JOB_RESULT_CORRUPT"
        payload["progress"] = float(payload.get("progress", 0.0))
        payload["timeout_seconds"] = float(payload.get("timeout_seconds", 0.0))
        return payload

    def get_platform_job(self, job_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM platform_jobs WHERE id=?", (str(job_id),)).fetchone()
        return None if row is None else self._platform_job_row(row)

    def list_platform_jobs(self, *, limit: int = 100, state: str = "") -> list[dict[str, Any]]:
        bounded_limit = max(1, min(1000, int(limit)))
        normalized_state = str(state).strip().casefold()
        with self.connect() as connection:
            if normalized_state:
                self._validate_job_state(normalized_state)
                rows = connection.execute(
                    "SELECT * FROM platform_jobs WHERE state=? ORDER BY created_at DESC LIMIT ?",
                    (normalized_state, bounded_limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM platform_jobs ORDER BY created_at DESC LIMIT ?", (bounded_limit,)
                ).fetchall()
        return [self._platform_job_row(row) for row in rows]

    def recover_platform_jobs(self) -> int:
        recovered_at = utc_now()
        with self.transaction() as connection:
            cursor = connection.execute(
                """
                UPDATE platform_jobs
                SET state='interrupted',progress=MIN(progress,0.99),
                    error_code='JOB_PROCESS_INTERRUPTED',
                    error_message='The owning Arenyxa process stopped before this job reached a terminal state.',
                    finished_at=?,updated_at=?
                WHERE state IN ('queued','running')
                """,
                (recovered_at, recovered_at),
            )
        return max(0, int(cursor.rowcount))
