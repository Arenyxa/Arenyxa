from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import psycopg

from src.arenyxa.enterprise.distributed_queue import DurableDistributedQueue


def _close(obj: Any) -> None:
    close = getattr(obj, "close", None)
    if callable(close):
        close()


def _assert_postgresql(queue: DurableDistributedQueue) -> None:
    backend = str(getattr(queue, "storage_capabilities", {}).get("backend", ""))
    if backend != "postgresql":
        raise RuntimeError(f"diagnostic precondition backend mismatch: {backend!r}")


def catalog_only(dsn: str) -> dict[str, Any]:
    queue = DurableDistributedQueue(dsn)
    try:
        _assert_postgresql(queue)
        with psycopg.connect(dsn, autocommit=True, application_name="arenyxa-phase3-catalog") as conn:
            rels = conn.execute(
                """
                SELECT c.relname,c.relkind,count(a.attnum) FILTER (WHERE a.attnum>0 AND NOT a.attisdropped) AS columns
                FROM pg_class c
                JOIN pg_namespace n ON n.oid=c.relnamespace
                LEFT JOIN pg_attribute a ON a.attrelid=c.oid
                WHERE n.nspname=current_schema() AND c.relname LIKE 'distributed_%'
                GROUP BY c.relname,c.relkind
                ORDER BY c.relname
                """
            ).fetchall()
            idx = conn.execute(
                """
                SELECT t.relname AS table_name,i.relname AS index_name,pg_get_indexdef(i.oid)
                FROM pg_class t
                JOIN pg_index x ON x.indrelid=t.oid
                JOIN pg_class i ON i.oid=x.indexrelid
                JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname=current_schema() AND t.relname LIKE 'distributed_%'
                ORDER BY t.relname,i.relname
                """
            ).fetchall()
        return {
            "mode": "catalog",
            "relations": [[str(x) for x in row] for row in rels],
            "indexes": [[str(x) for x in row] for row in idx],
        }
    finally:
        _close(queue)


def relation_touch(dsn: str) -> dict[str, Any]:
    base = catalog_only(dsn)
    probes: list[dict[str, Any]] = []
    with psycopg.connect(dsn, autocommit=True, application_name="arenyxa-phase3-relation-touch") as conn:
        statements = [
            ("jobs_pk", "SELECT job_id FROM distributed_jobs WHERE job_id=%s", ("phase3-no-row",)),
            ("workers_pk", "SELECT worker_id FROM distributed_workers WHERE worker_id=%s", ("phase3-no-worker",)),
            ("events_job", "SELECT event_id FROM distributed_job_events WHERE job_id=%s ORDER BY event_id DESC LIMIT 1", ("phase3-no-row",)),
            ("meta_pk", "SELECT meta_key FROM distributed_meta WHERE meta_key=%s", ("phase3-no-meta",)),
            ("jobs_queue", "SELECT job_id FROM distributed_jobs WHERE state='queued' AND protocol_version BETWEEN %s AND %s ORDER BY priority DESC,created_at ASC LIMIT 1", (1, 1)),
        ]
        for name, sql, params in statements:
            t0 = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            rows = conn.execute(sql, params).fetchall()
            probes.append({"name": name, "rows": len(rows), "started_at": str(t0)})
    return {**base, "mode": "relation_touch", "probes": probes}


def planner_only(dsn: str) -> dict[str, Any]:
    base = catalog_only(dsn)
    plans: list[dict[str, Any]] = []
    with psycopg.connect(dsn, autocommit=True, application_name="arenyxa-phase3-planner") as conn:
        statements = [
            ("jobs_pk", "EXPLAIN SELECT * FROM distributed_jobs WHERE job_id='phase3-no-row'"),
            ("workers_pk", "EXPLAIN SELECT * FROM distributed_workers WHERE worker_id='phase3-no-worker'"),
            ("jobs_queue", "EXPLAIN SELECT * FROM distributed_jobs WHERE state='queued' AND protocol_version BETWEEN 1 AND 1 ORDER BY priority DESC,created_at ASC LIMIT 1"),
            ("events_job", "EXPLAIN SELECT event_id FROM distributed_job_events WHERE job_id='phase3-no-row' ORDER BY event_id DESC LIMIT 256"),
            ("job_lock_shape", "EXPLAIN SELECT * FROM distributed_jobs WHERE job_id='phase3-no-row' FOR UPDATE"),
        ]
        for name, sql in statements:
            rows = conn.execute(sql).fetchall()
            plans.append({"name": name, "plan": [str(r[0]) for r in rows]})
    return {**base, "mode": "planner", "plans": plans}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--mode", choices=("catalog", "relation", "planner"), required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    if args.mode == "catalog":
        payload = catalog_only(args.dsn)
    elif args.mode == "relation":
        payload = relation_touch(args.dsn)
    else:
        payload = planner_only(args.dsn)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
