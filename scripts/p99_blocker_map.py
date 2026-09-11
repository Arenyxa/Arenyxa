from __future__ import annotations

from collections import Counter
import os

import psutil
import psycopg

from scripts import p99_ci_probe_v2 as v2


def _kind(query: str) -> str:
    text = " ".join(str(query).split()).casefold()
    if "with eligible_worker as" in text:
        return "lease_fast_cte"
    if "set state='running'" in text or "set state=$" in text and "event_type" in text and "started" in text:
        return "start_fast_cte"
    if "side_effect_state" in text and "terminal_worker_id" in text:
        return "complete_fast_cte"
    if "update distributed_workers" in text and "active_leases=active_leases+" in text:
        return "worker_slot_increment"
    if "update distributed_workers" in text and "greatest" in text:
        return "worker_slot_decrement"
    if "arenyxa_pool_health" in text:
        return "pool_health"
    if "distributed_jobs" in text:
        return "jobs_other"
    if "distributed_workers" in text:
        return "workers_other"
    return text[:160] or "<empty>"


class BlockingProbe(v2.Probe):
    def __init__(self, dsn: str, *, observe: bool, sample_ms: int) -> None:
        super().__init__(dsn, observe=observe, sample_ms=sample_ms)
        self.blocked_pairs: Counter[str] = Counter()
        self.blocked_waits: Counter[str] = Counter()

    def _sample(self) -> None:
        process = psutil.Process(os.getpid())
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                observer_pid = conn.info.backend_pid
                while not self.stop.wait(self.sample_s):
                    activity = conn.execute(
                        """
                        SELECT state,COALESCE(wait_event_type,''),COALESCE(wait_event,''),count(*)
                        FROM pg_stat_activity
                        WHERE datname=current_database() AND pid<>%s
                        GROUP BY 1,2,3
                        """, (observer_pid,),
                    ).fetchall()
                    locks = conn.execute(
                        """
                        SELECT l.locktype,l.mode,l.granted,count(*)
                        FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
                        WHERE a.datname=current_database() AND a.pid<>%s
                        GROUP BY 1,2,3
                        """, (observer_pid,),
                    ).fetchall()
                    blockers = conn.execute(
                        """
                        SELECT a.wait_event_type,a.wait_event,a.query,b.query
                        FROM pg_stat_activity AS a
                        CROSS JOIN LATERAL unnest(pg_blocking_pids(a.pid)) AS bp(blocker_pid)
                        JOIN pg_stat_activity AS b ON b.pid=bp.blocker_pid
                        WHERE a.datname=current_database() AND a.pid<>%s
                        """, (observer_pid,),
                    ).fetchall()
                    with self.lock:
                        for state, wet, we, count in activity:
                            self.activity[str(state)] += int(count)
                            if wet or we:
                                self.waits[f"{state}|{wet}|{we}"] += int(count)
                        for locktype, mode, granted, count in locks:
                            if not bool(granted):
                                self.lock_waits[f"{locktype}|{mode}"] += int(count)
                        for wet, we, blocked_query, blocker_query in blockers:
                            blocked = _kind(str(blocked_query))
                            blocker = _kind(str(blocker_query))
                            self.blocked_pairs[f"{blocked} <- {blocker}"] += 1
                            self.blocked_waits[f"{wet or ''}|{we or ''}|{blocked}"] += 1
                        self.host.append({
                            "cpu": float(psutil.cpu_percent(interval=None)),
                            "load1": float(os.getloadavg()[0]),
                            "ctx": int(psutil.cpu_stats().ctx_switches),
                            "threads": int(process.num_threads()),
                        })
        except BaseException:
            return

    def report(self):
        out = super().report()
        out["blocked_query_pairs"] = dict(self.blocked_pairs.most_common())
        out["blocked_waits"] = dict(self.blocked_waits.most_common())
        return out


v2.Probe = BlockingProbe

if __name__ == "__main__":
    raise SystemExit(v2.main())
