from __future__ import annotations

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
from arenyxa.security.sql_safety import sqlite_wal_checkpoint

LOGGER = logging.getLogger(__name__)

class NetworkStoreMixin:
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
        consecutive_empty = 0
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
                    # A corrupted record must not block the entire backfill process.
                    # Record the error and try to mark the event as processed even though it is corrupted.
                    event_id = str(item.get("id", ""))
                    LOGGER.error("Skipping corrupted network event %s: %s", event_id, exc)
                    with self.transaction() as connection:
                        connection.execute(
                            "INSERT OR IGNORE INTO network_projection_events(event_id,projected_at) VALUES(?,?)",
                            (event_id, utc_now()),
                        )
                    continue
            
            if not events:
                consecutive_empty += 1
                if consecutive_empty > 5: # Prevent corrupted records from causing an infinite loop.
                    break
                continue
            
            consecutive_empty = 0
            with self.transaction() as connection:
                batch_projected = self._append_network_core(connection, events)
                if batch_projected == 0:
                    # If no records were projected (for example because of conflicts), break the loop defensively.
                    # Normally _append_network_core handles insertion conflicts.
                    consecutive_empty += 1
                    if consecutive_empty > 5:
                        break
                else:
                    projected += batch_projected
        return projected

    @staticmethod
    def _append_network_core(connection: sqlite3.Connection, events: list[NetworkEvent]) -> int:
        projected = 0
        
        # Prepare batch data.
        bodies_data = []
        flows_data = []
        requests_data = []
        responses_data = []
        dns_data = []
        tls_data = []
        ws_channels_data = []
        ws_messages_data = []
        
        for event in events:
            # Claim each event first so that projection remains unique.
            # Execute claims one by one so the projected count remains accurate.
            claimed = connection.execute(
                "INSERT OR IGNORE INTO network_projection_events(event_id,projected_at) VALUES(?,?)",
                (event.id, utc_now()),
            )
            if int(claimed.rowcount) == 0:
                continue
            
            projected += 1
            bundle = NetworkNormalizer.normalize(event)
            
            for body in bundle.body_artifacts:
                bodies_data.append((
                    body.id, body.session_id, body.sha256, body.stored_sha256, body.byte_size, body.stored_size, body.content_type,
                    body.encoding, body.storage_kind, body.storage_ref, int(body.truncated), int(body.sensitive),
                    body.created_at or event.timestamp,
                ))
            
            flow = bundle.flow
            flows_data.append((
                flow.id, flow.session_id, flow.source_type, flow.protocol, flow.transport,
                flow.local_address, flow.remote_address, flow.process_ref, flow.first_seen,
                flow.last_seen, flow.event_count, flow.bytes_seen,
                json.dumps(flow.metadata, ensure_ascii=False, default=str),
            ))
            
            request = bundle.request
            if request is not None:
                requests_data.append((
                    request.id, request.event_id, request.session_id, request.flow_id, request.timestamp,
                    request.method, request.url, request.host, json.dumps(request.query, ensure_ascii=False),
                    json.dumps(request.headers, ensure_ascii=False), request.body_ref, request.initiator,
                ))
            
            response = bundle.response
            if response is not None:
                responses_data.append((
                    response.id, response.request_id, response.event_id, response.session_id,
                    response.timestamp, response.status, json.dumps(response.headers, ensure_ascii=False),
                    response.body_ref, response.content_type, response.size,
                    json.dumps(response.timing, ensure_ascii=False),
                ))
            
            dns = bundle.dns
            if dns is not None:
                dns_data.append((
                    dns.id, dns.event_id, dns.session_id, dns.timestamp, dns.query_name, dns.query_type,
                    json.dumps(dns.answers, ensure_ascii=False), dns.elapsed_ms, dns.error,
                ))
            
            tls = bundle.tls
            if tls is not None:
                tls_data.append((
                    tls.id, tls.event_id, tls.session_id, tls.flow_id, tls.timestamp, tls.host,
                    tls.version, tls.cipher, tls.alpn, tls.certificate_ref,
                    json.dumps(tls.metadata, ensure_ascii=False, default=str),
                ))
            
            channel = bundle.websocket_channel
            if channel is not None:
                ws_channels_data.append((
                    channel.id, channel.session_id, channel.flow_id, channel.url, channel.host,
                    channel.opened_at, channel.closed_at, channel.message_count, channel.bytes_seen,
                ))
            
            message = bundle.websocket_message
            if message is not None:
                ws_messages_data.append((
                    message.id, message.channel_id, message.event_id, message.timestamp, message.direction,
                    message.opcode, message.size, message.payload_ref,
                    json.dumps(message.metadata, ensure_ascii=False, default=str),
                ))

        # Execute the batch insert.
        if bodies_data:
            connection.executemany(
                """
                INSERT INTO network_bodies(id,session_id,sha256,stored_sha256,byte_size,stored_size,content_type,encoding,
                    storage_kind,storage_ref,truncated,sensitive,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET sha256=excluded.sha256,stored_sha256=excluded.stored_sha256,byte_size=excluded.byte_size,
                    stored_size=excluded.stored_size,content_type=excluded.content_type,encoding=excluded.encoding,
                    storage_kind=excluded.storage_kind,storage_ref=excluded.storage_ref,truncated=excluded.truncated,
                    sensitive=MAX(network_bodies.sensitive,excluded.sensitive)
                """,
                bodies_data
            )
        
        if flows_data:
            connection.executemany(
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
                flows_data
            )
            
        if requests_data:
            connection.executemany(
                """
                INSERT INTO http_requests(id,event_id,session_id,flow_id,timestamp,method,url,host,
                    query_json,headers_json,body_ref,initiator) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET flow_id=excluded.flow_id,timestamp=excluded.timestamp,
                    method=excluded.method,url=excluded.url,host=excluded.host,query_json=excluded.query_json,
                    headers_json=excluded.headers_json,body_ref=excluded.body_ref,initiator=excluded.initiator
                """,
                requests_data
            )
            
        if responses_data:
            connection.executemany(
                """
                INSERT INTO http_responses(id,request_id,event_id,session_id,timestamp,status,headers_json,
                    body_ref,content_type,size,timing_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(request_id) DO UPDATE SET event_id=excluded.event_id,timestamp=excluded.timestamp,
                    status=excluded.status,headers_json=excluded.headers_json,body_ref=excluded.body_ref,
                    content_type=excluded.content_type,size=excluded.size,timing_json=excluded.timing_json
                """,
                responses_data
            )
            
        if dns_data:
            connection.executemany(
                """
                INSERT INTO dns_transactions(id,event_id,session_id,timestamp,query_name,query_type,
                    answers_json,elapsed_ms,error) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(event_id) DO UPDATE SET timestamp=excluded.timestamp,query_name=excluded.query_name,
                    query_type=excluded.query_type,answers_json=excluded.answers_json,
                    elapsed_ms=excluded.elapsed_ms,error=excluded.error
                """,
                dns_data
            )
            
        if tls_data:
            connection.executemany(
                """
                INSERT INTO tls_handshakes(id,event_id,session_id,flow_id,timestamp,host,version,cipher,
                    alpn,certificate_ref,metadata_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(event_id) DO UPDATE SET flow_id=excluded.flow_id,timestamp=excluded.timestamp,
                    host=excluded.host,version=excluded.version,cipher=excluded.cipher,alpn=excluded.alpn,
                    certificate_ref=excluded.certificate_ref,metadata_json=excluded.metadata_json
                """,
                tls_data
            )
            
        if ws_channels_data:
            connection.executemany(
                """
                INSERT INTO websocket_channels(id,session_id,flow_id,url,host,opened_at,closed_at,
                    message_count,bytes_seen) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET closed_at=COALESCE(excluded.closed_at,websocket_channels.closed_at),
                    message_count=websocket_channels.message_count+excluded.message_count,
                    bytes_seen=websocket_channels.bytes_seen+excluded.bytes_seen
                """,
                ws_channels_data
            )
            
        if ws_messages_data:
            connection.executemany(
                """
                INSERT INTO websocket_messages(id,channel_id,event_id,timestamp,direction,opcode,size,
                    payload_ref,metadata_json) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(event_id) DO UPDATE SET timestamp=excluded.timestamp,direction=excluded.direction,
                    opcode=excluded.opcode,size=excluded.size,payload_ref=excluded.payload_ref,
                    metadata_json=excluded.metadata_json
                """,
                ws_messages_data
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

