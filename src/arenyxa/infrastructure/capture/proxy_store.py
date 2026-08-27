from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import utc_now
from arenyxa.infrastructure.capture.proxy_models import ProxyFlow
from arenyxa.infrastructure.capture.proxy_transport import _header, _parse_raw_message


LOGGER = logging.getLogger(__name__)


class ProxyHistoryStore:
    """Crash-safe WAL history for the professional proxy workbench.

    The live engine still keeps a small in-memory window for low-latency UI updates.
    This store owns the durable, pageable history and can scale independently from
    that window. Exact raw messages are retained so Repeater and forensic exports do
    not need to reconstruct a request from lossy projections.
    """

    SCHEMA_VERSION = 1
    MAX_PAGE_SIZE = 1_000

    def __init__(self, path: Path, *, body_limit: int = 32 * 1024 * 1024) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.body_limit = max(64 * 1024, min(int(body_limit), 256 * 1024 * 1024))
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.path,
            timeout=15.0,
            check_same_thread=False,
            isolation_level=None,
        )
        self._connection.row_factory = sqlite3.Row
        self._closed = False
        self._configure()
        self._migrate()

    def _configure(self) -> None:
        with self._lock:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA busy_timeout=15000")
            self._connection.execute("PRAGMA temp_store=MEMORY")
            self._connection.execute("PRAGMA wal_autocheckpoint=2000")

    def _migrate(self) -> None:
        script = """
        BEGIN IMMEDIATE;
        CREATE TABLE IF NOT EXISTS proxy_schema (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS proxy_sessions (
            id TEXT PRIMARY KEY,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            state TEXT NOT NULL CHECK(state IN ('running','completed','interrupted')),
            bind_host TEXT NOT NULL,
            bind_port INTEGER NOT NULL,
            flow_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0,
            request_bytes INTEGER NOT NULL DEFAULT 0,
            response_bytes INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS proxy_flows (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES proxy_sessions(id) ON DELETE CASCADE,
            sequence INTEGER NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            client TEXT NOT NULL,
            scheme TEXT NOT NULL,
            protocol TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL,
            target TEXT NOT NULL,
            status INTEGER,
            reason TEXT NOT NULL,
            request_headers_json TEXT NOT NULL,
            request_cookies_json TEXT NOT NULL,
            request_raw BLOB NOT NULL,
            request_size INTEGER NOT NULL,
            response_headers_json TEXT NOT NULL,
            response_raw BLOB NOT NULL,
            response_content_type TEXT NOT NULL,
            response_size INTEGER NOT NULL,
            latency_ms REAL NOT NULL,
            tls_intercepted INTEGER NOT NULL,
            tunnel INTEGER NOT NULL,
            dropped INTEGER NOT NULL,
            error_code TEXT NOT NULL,
            error_message TEXT NOT NULL,
            rewrite_rule_ids_json TEXT NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_flows_session_sequence
            ON proxy_flows(session_id, sequence);
        CREATE INDEX IF NOT EXISTS idx_proxy_flows_started
            ON proxy_flows(started_at DESC, id DESC);
        CREATE INDEX IF NOT EXISTS idx_proxy_flows_host_started
            ON proxy_flows(host, started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_proxy_flows_method_started
            ON proxy_flows(method, started_at DESC);
        CREATE INDEX IF NOT EXISTS idx_proxy_flows_status_started
            ON proxy_flows(status, started_at DESC);
        INSERT OR IGNORE INTO proxy_schema(version, applied_at) VALUES(1, 'bootstrap');
        COMMIT;
        """
        with self._lock:
            try:
                self._connection.executescript(script)
            except sqlite3.DatabaseError as exc:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.DatabaseError:
                    record_current_exception(__name__, 'ProxyHistoryStore._migrate:126')
                raise ArenyxaError(
                    "PROXY_HISTORY_MIGRATION_FAILED",
                    "Proxy history database migration failed.",
                    domain="PROXY",
                    context={"path": str(self.path)},
                ) from exc

    def start_session(self, session_id: str, host: str, port: int, *, started_at: str | None = None) -> None:
        with self._lock:
            self._connection.execute(
                "INSERT INTO proxy_sessions(id,started_at,state,bind_host,bind_port) VALUES(?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET state='running',finished_at=NULL,bind_host=excluded.bind_host,"
                "bind_port=excluded.bind_port",
                (str(session_id), started_at or utc_now(), "running", str(host), int(port)),
            )

    def finish_session(self, session_id: str, *, state: str = "completed") -> None:
        if state not in {"completed", "interrupted"}:
            raise ValueError("invalid proxy session terminal state")
        with self._lock:
            self._connection.execute(
                "UPDATE proxy_sessions SET state=?,finished_at=COALESCE(finished_at,?) WHERE id=?",
                (state, utc_now(), str(session_id)),
            )

    def recover_interrupted(self) -> int:
        with self._lock:
            cursor = self._connection.execute(
                "UPDATE proxy_sessions SET state='interrupted',finished_at=COALESCE(finished_at,?) "
                "WHERE state='running'",
                (utc_now(),),
            )
            return max(0, int(cursor.rowcount))

    @staticmethod
    def _message_metadata(raw: bytes) -> tuple[list[tuple[str, str]], bytes]:
        if not raw:
            return [], b""
        try:
            _line, headers, body = _parse_raw_message(raw)
            return headers, body
        except ValueError:
            return [], b""

    @staticmethod
    def _cookies(headers: Iterable[tuple[str, str]]) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for name, value in headers:
            if str(name).casefold() != "cookie":
                continue
            for item in str(value).split(";")[:256]:
                key, separator, _secret = item.strip().partition("=")
                if key:
                    rows.append({"name": key[:128], "value": "[REDACTED]" if separator else ""})
        return rows

    def _flow_values(self, session_id: str, flow: ProxyFlow) -> tuple[Any, ...]:
        request_headers, _request_body = self._message_metadata(flow.request_raw)
        response_headers, _response_body = self._message_metadata(flow.response_raw)
        protocol = "HTTP/2" if any(
            str(value).casefold() == "h2" for name, value in response_headers if str(name).casefold() == "x-arenyxa-alpn"
        ) else "HTTP/1.1"
        content_type = _header(response_headers, "Content-Type")
        error_code = "PROXY_FLOW_ERROR" if flow.error else ""
        return (
            flow.id,
            str(session_id),
            int(flow.sequence),
            str(flow.started_at),
            str(flow.completed_at or utc_now()),
            str(flow.client),
            str(flow.scheme),
            protocol,
            str(flow.method),
            flow.url,
            str(flow.host),
            int(flow.port),
            str(flow.target),
            flow.status,
            str(flow.reason),
            json.dumps(request_headers, ensure_ascii=False, separators=(",", ":")),
            json.dumps(self._cookies(request_headers), ensure_ascii=False, separators=(",", ":")),
            sqlite3.Binary(flow.request_raw),
            int(flow.request_bytes),
            json.dumps(response_headers, ensure_ascii=False, separators=(",", ":")),
            sqlite3.Binary(flow.response_raw),
            str(content_type),
            int(flow.response_bytes),
            float(flow.duration_ms),
            int(bool(flow.tls_intercepted)),
            int(bool(flow.tunnel)),
            int(bool(flow.dropped)),
            error_code,
            str(flow.error),
            json.dumps(list(flow.rewrite_rule_ids), ensure_ascii=False, separators=(",", ":")),
        )

    def store(self, session_id: str, flow: ProxyFlow) -> None:
        if len(flow.request_raw) > self.body_limit or len(flow.response_raw) > self.body_limit:
            raise ArenyxaError(
                "PROXY_HISTORY_BODY_LIMIT",
                "Proxy message exceeds the durable history body limit.",
                domain="PROXY",
                context={"flow_id": flow.id, "limit": self.body_limit},
            )
        values = self._flow_values(session_id, flow)
        statement = """
            INSERT INTO proxy_flows(
                id,session_id,sequence,started_at,completed_at,client,scheme,protocol,method,url,host,port,
                target,status,reason,request_headers_json,request_cookies_json,request_raw,request_size,
                response_headers_json,response_raw,response_content_type,response_size,latency_ms,
                tls_intercepted,tunnel,dropped,error_code,error_message,rewrite_rule_ids_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                completed_at=excluded.completed_at,status=excluded.status,reason=excluded.reason,
                request_headers_json=excluded.request_headers_json,
                request_cookies_json=excluded.request_cookies_json,request_raw=excluded.request_raw,
                request_size=excluded.request_size,
                response_headers_json=excluded.response_headers_json,response_raw=excluded.response_raw,
                response_content_type=excluded.response_content_type,response_size=excluded.response_size,
                latency_ms=excluded.latency_ms,dropped=excluded.dropped,error_code=excluded.error_code,
                error_message=excluded.error_message,rewrite_rule_ids_json=excluded.rewrite_rule_ids_json
        """
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                existing = self._connection.execute(
                    "SELECT session_id,error_code,request_size,response_size FROM proxy_flows WHERE id=?",
                    (flow.id,),
                ).fetchone()
                if existing is not None and str(existing["session_id"]) != str(session_id):
                    raise sqlite3.IntegrityError("proxy flow id already belongs to another session")
                self._connection.execute(statement, values)
                is_new = existing is None
                previous_error = 0 if is_new else int(bool(existing["error_code"]))
                previous_request_bytes = 0 if is_new else int(existing["request_size"])
                previous_response_bytes = 0 if is_new else int(existing["response_size"])
                self._connection.execute(
                    "UPDATE proxy_sessions SET flow_count=flow_count+?,error_count=error_count+?,"
                    "request_bytes=request_bytes+?,response_bytes=response_bytes+? WHERE id=?",
                    (
                        int(is_new),
                        int(bool(flow.error)) - previous_error,
                        int(flow.request_bytes) - previous_request_bytes,
                        int(flow.response_bytes) - previous_response_bytes,
                        str(session_id),
                    ),
                )
                self._connection.execute("COMMIT")
            except sqlite3.DatabaseError as exc:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.DatabaseError:
                    record_current_exception(__name__, 'ProxyHistoryStore.store:280')
                raise ArenyxaError(
                    "PROXY_HISTORY_WRITE_FAILED",
                    "Proxy history could not be committed.",
                    domain="PROXY",
                    context={"flow_id": flow.id, "path": str(self.path)},
                ) from exc

    @staticmethod
    def _flow(row: sqlite3.Row) -> ProxyFlow:
        try:
            rewrite_ids = json.loads(str(row["rewrite_rule_ids_json"] or "[]"))
        except (TypeError, json.JSONDecodeError):
            rewrite_ids = []
        return ProxyFlow(
            id=str(row["id"]),
            sequence=int(row["sequence"]),
            started_at=str(row["started_at"]),
            client=str(row["client"]),
            scheme=str(row["scheme"]),
            method=str(row["method"]),
            host=str(row["host"]),
            port=int(row["port"]),
            target=str(row["target"]),
            request_raw=bytes(row["request_raw"] or b""),
            response_raw=bytes(row["response_raw"] or b""),
            status=None if row["status"] is None else int(row["status"]),
            reason=str(row["reason"]),
            duration_ms=float(row["latency_ms"]),
            request_bytes=int(row["request_size"]),
            response_bytes=int(row["response_size"]),
            tls_intercepted=bool(row["tls_intercepted"]),
            tunnel=bool(row["tunnel"]),
            dropped=bool(row["dropped"]),
            error=str(row["error_message"]),
            completed_at=str(row["completed_at"]),
            rewrite_rule_ids=[str(value) for value in rewrite_ids if isinstance(value, str)],
        )

    def get(self, flow_id: str) -> ProxyFlow | None:
        with self._lock:
            row = self._connection.execute("SELECT * FROM proxy_flows WHERE id=?", (str(flow_id),)).fetchone()
        return None if row is None else self._flow(row)

    def page(
        self,
        *,
        page: int = 1,
        page_size: int = 100,
        query: str = "",
        session_id: str = "",
    ) -> dict[str, Any]:
        bounded_page = max(1, int(page))
        bounded_size = max(1, min(int(page_size), self.MAX_PAGE_SIZE))
        clauses: list[str] = []
        values: list[Any] = []
        if session_id:
            clauses.append("session_id=?")
            values.append(str(session_id))
        needle = str(query).strip()
        if needle:
            clauses.append("(host LIKE ? ESCAPE '\\' OR url LIKE ? ESCAPE '\\' OR method LIKE ? ESCAPE '\\')")
            escaped = needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            values.extend([f"%{escaped}%"] * 3)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        offset = (bounded_page - 1) * bounded_size
        with self._lock:
            total = int(self._connection.execute("SELECT count(*) FROM proxy_flows" + where, values).fetchone()[0])
            rows = self._connection.execute(
                "SELECT * FROM proxy_flows" + where + " ORDER BY started_at DESC,id DESC LIMIT ? OFFSET ?",
                (*values, bounded_size, offset),
            ).fetchall()
        return {
            "page": bounded_page,
            "page_size": bounded_size,
            "total": total,
            "has_next": offset + len(rows) < total,
            "items": [self._flow(row) for row in rows],
        }

    def recent(self, limit: int) -> list[ProxyFlow]:
        result = self.page(page=1, page_size=max(1, min(int(limit), self.MAX_PAGE_SIZE)))
        return list(reversed(result["items"]))

    def sessions(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 10_000))
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM proxy_sessions ORDER BY started_at DESC,id DESC LIMIT ?", (bounded,)
            ).fetchall()
        return [dict(row) for row in rows]

    def cleanup(self, *, max_records: int = 1_000_000, batch_size: int = 5_000) -> int:
        retained = max(10_000, min(int(max_records), 10_000_000))
        batch = max(100, min(int(batch_size), 50_000))
        with self._lock:
            total = int(self._connection.execute("SELECT count(*) FROM proxy_flows").fetchone()[0])
            excess = max(0, total - retained)
            if not excess:
                return 0
            remove = min(excess, batch)
            cursor = self._connection.execute(
                "DELETE FROM proxy_flows WHERE id IN (SELECT id FROM proxy_flows ORDER BY started_at,id LIMIT ?)",
                (remove,),
            )
            return max(0, int(cursor.rowcount))

    def health_check(self) -> dict[str, Any]:
        with self._lock:
            row = self._connection.execute("PRAGMA quick_check(1)").fetchone()
            mode = self._connection.execute("PRAGMA journal_mode").fetchone()
            flows = int(self._connection.execute("SELECT count(*) FROM proxy_flows").fetchone()[0])
        return {
            "ok": bool(row and str(row[0]).casefold() == "ok"),
            "journal_mode": "" if mode is None else str(mode[0]).casefold(),
            "flows": flows,
            "path": str(self.path),
        }

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.DatabaseError:
                LOGGER.exception("Proxy history WAL checkpoint failed during shutdown")
            self._connection.close()
            self._closed = True


__all__ = ["ProxyHistoryStore"]
