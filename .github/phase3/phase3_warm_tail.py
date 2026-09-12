from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import threading
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psutil
import psycopg

from scripts import postgresql_32_worker_gate as gate
from arenyxa.enterprise.runtime_storage import PostgreSQLDistributedRuntimeStorage, _ConnectionFacade


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    return round(float(gate._percentile(list(values), q)), 3)


def proc_sched() -> tuple[int, int]:
    ctxt = running = 0
    with open('/proc/stat', 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('ctxt '): ctxt = int(line.split()[1])
            elif line.startswith('procs_running '): running = int(line.split()[1])
    return ctxt, running


def pg_processes() -> list[psutil.Process]:
    out = []
    for p in psutil.process_iter(['name']):
        try:
            if str(p.info.get('name') or '').lower().startswith('postgres'):
                out.append(p)
        except psutil.Error:
            pass
    return out


def sql_class(sql: str) -> str:
    q = ' '.join(str(sql).lower().split())
    if 'arenyxa_pool_health' in q: return 'health_check'
    if 'with eligible_worker' in q and 'distributed_jobs' in q: return 'lease'
    if "'started'" in q and 'distributed_jobs' in q: return 'start'
    if "'completed'" in q and 'distributed_job_idempotency' in q: return 'complete'
    if 'update distributed_workers' in q and 'active_leases' in q: return 'worker_update'
    if 'insert into distributed_job_events' in q: return 'event_insert'
    if 'distributed_jobs' in q: return 'jobs_other'
    if 'distributed_workers' in q: return 'workers_other'
    return 'other'


class WarmTrace:
    def __init__(self) -> None:
        self.active = False
        self.run_no = 0
        self.local = threading.local()
        self.lock = threading.Lock()
        self.cycles: list[dict[str, Any]] = []
        self.conn_generations: dict[int, int] = {}
        self.next_generation = 1
        self.orig_lease = gate.DurableDistributedQueue.lease_next
        self.orig_start = gate.DurableDistributedQueue.start_job
        self.orig_complete = gate.DurableDistributedQueue.complete
        self.orig_connection = PostgreSQLDistributedRuntimeStorage.connection
        self.orig_execute = _ConnectionFacade.execute

    def _current(self) -> dict[str, Any] | None:
        return getattr(self.local, 'current', None)

    def _next_attempt(self) -> int:
        n = int(getattr(self.local, 'attempt_seq', 0)) + 1
        self.local.attempt_seq = n
        return n

    def install(self) -> None:
        owner = self
        orig_lease, orig_start, orig_complete = self.orig_lease, self.orig_start, self.orig_complete
        orig_connection, orig_execute = self.orig_connection, self.orig_execute

        def lease_next(obj, worker_id, *args, **kwargs):
            t0, w0 = time.monotonic(), time.time()
            attempt = owner._next_attempt()
            cur = {
                'run': owner.run_no, 'native_tid': threading.get_native_id(), 'attempt_seq': attempt,
                'worker_id': str(worker_id), 'queue_client': hex(id(obj)),
                'cycle_start_mono': t0, 'cycle_start_wall': w0,
                'lease_start_mono': t0, 'phase': 'lease',
                'checkouts': [], 'statements': [], 'backend_pids': {'lease': [], 'start': [], 'complete': []},
            }
            if owner.active: owner.local.current = cur
            try:
                result = orig_lease(obj, worker_id, *args, **kwargs)
            finally:
                if owner.active:
                    cur['lease_end_mono'] = time.monotonic()
            if owner.active and result is not None:
                cur['job_id'] = str(result.job_id)
                cur['lease_token_digest'] = hashlib.sha256(str(result.lease_token).encode()).hexdigest()[:16]
            elif owner.active:
                owner.local.current = None
            return result

        def start_job(obj, job_id, worker_id, lease_token, *args, **kwargs):
            cur = owner._current(); t0 = time.monotonic()
            if cur is not None: cur['phase'] = 'start'; cur['start_start_mono'] = t0
            try:
                return orig_start(obj, job_id, worker_id, lease_token, *args, **kwargs)
            finally:
                if cur is not None: cur['start_end_mono'] = time.monotonic()

        def complete(obj, job_id, worker_id, lease_token, result, *args, **kwargs):
            cur = owner._current(); t0 = time.monotonic()
            if cur is not None: cur['phase'] = 'complete'; cur['complete_start_mono'] = t0
            try:
                return orig_complete(obj, job_id, worker_id, lease_token, result, *args, **kwargs)
            finally:
                if owner.active and cur is not None:
                    t1 = time.monotonic(); cur['complete_end_mono'] = t1; cur['cycle_end_mono'] = t1
                    cur['cycle_end_wall'] = time.time(); cur['cycle_ms'] = (t1-cur['cycle_start_mono'])*1000
                    cur['lease_ms'] = (cur['lease_end_mono']-cur['lease_start_mono'])*1000
                    cur['start_ms'] = (cur.get('start_end_mono',t0)-cur.get('start_start_mono',t0))*1000
                    cur['complete_ms'] = (t1-t0)*1000
                    cur.pop('phase', None)
                    with owner.lock: owner.cycles.append(dict(cur))
                    owner.local.current = None

        @contextmanager
        def connection(storage):
            cur = owner._current(); phase = None if cur is None else cur.get('phase')
            t0 = time.monotonic()
            cm = orig_connection(storage)
            with cm as facade:
                acquired = time.monotonic()
                if owner.active and cur is not None and phase in ('lease','start','complete'):
                    raw = facade.raw; raw_id = id(raw)
                    with owner.lock:
                        gen = owner.conn_generations.get(raw_id)
                        if gen is None:
                            gen = owner.next_generation; owner.next_generation += 1; owner.conn_generations[raw_id] = gen
                    pid = int(getattr(getattr(raw, 'info', None), 'backend_pid', 0) or 0)
                    cur['checkouts'].append({'phase': phase, 'start_mono': t0, 'end_mono': acquired,
                                             'checkout_ms': (acquired-t0)*1000, 'backend_pid': pid,
                                             'connection_generation': gen})
                    if pid and pid not in cur['backend_pids'][phase]: cur['backend_pids'][phase].append(pid)
                yield facade

        def execute(facade, sql, params=()):
            cur = owner._current(); phase = None if cur is None else cur.get('phase')
            t0 = time.monotonic()
            try:
                return orig_execute(facade, sql, params)
            finally:
                if owner.active and cur is not None and phase in ('lease','start','complete'):
                    t1 = time.monotonic(); pid = int(getattr(getattr(facade.raw,'info',None),'backend_pid',0) or 0)
                    cur['statements'].append({'phase': phase, 'class': sql_class(sql), 'backend_pid': pid,
                                              'start_mono': t0, 'end_mono': t1, 'client_execute_ms': (t1-t0)*1000})

        gate.DurableDistributedQueue.lease_next = lease_next
        gate.DurableDistributedQueue.start_job = start_job
        gate.DurableDistributedQueue.complete = complete
        PostgreSQLDistributedRuntimeStorage.connection = connection
        _ConnectionFacade.execute = execute

    def restore(self) -> None:
        gate.DurableDistributedQueue.lease_next = self.orig_lease
        gate.DurableDistributedQueue.start_job = self.orig_start
        gate.DurableDistributedQueue.complete = self.orig_complete
        PostgreSQLDistributedRuntimeStorage.connection = self.orig_connection
        _ConnectionFacade.execute = self.orig_execute


class Observer:
    def __init__(self, dsn: str, interval: float) -> None:
        self.dsn = dsn; self.interval = interval; self.stop = threading.Event(); self.samples: list[dict[str, Any]]=[]; self.errors=[]
        self.python = psutil.Process(os.getpid()); self.thread = threading.Thread(target=self._run, daemon=True, name='phase3-warm-observer')
    def start(self):
        psutil.cpu_percent(None); self.python.cpu_percent(None)
        for p in pg_processes():
            try: p.cpu_percent(None)
            except psutil.Error: pass
        self.thread.start()
    def close(self): self.stop.set(); self.thread.join(timeout=10)
    def _run(self):
        last_t=time.monotonic(); last_ctxt,_=proc_sched()
        try:
            with psycopg.connect(self.dsn, autocommit=True, application_name='arenyxa-phase3-warm-observer') as conn:
                me=conn.info.backend_pid
                while not self.stop.wait(self.interval):
                    mono=time.monotonic(); wall=time.time(); ctxt,runnable=proc_sched(); dt=max(mono-last_t,1e-9); ctx_rate=(ctxt-last_ctxt)/dt; last_t,last_ctxt=mono,ctxt
                    rows=conn.execute("""
                        SELECT pid,state,COALESCE(wait_event_type,''),COALESCE(wait_event,''),backend_type,
                               pg_blocking_pids(pid),
                               CASE
                                 WHEN query ILIKE '%arenyxa_pool_health%' THEN 'health_check'
                                 WHEN query ILIKE '%eligible_worker%' AND query ILIKE '%distributed_jobs%' THEN 'lease'
                                 WHEN query ILIKE '%distributed_job_idempotency%' AND query ILIKE '%completed%' THEN 'complete'
                                 WHEN query ILIKE '%distributed_jobs%' AND query ILIKE '%started%' THEN 'start'
                                 WHEN query ILIKE '%distributed_workers%' THEN 'worker_or_lease'
                                 WHEN query ILIKE '%distributed_jobs%' THEN 'jobs_other'
                                 ELSE 'other' END AS query_class
                        FROM pg_stat_activity WHERE datname=current_database() AND pid<>%s
                    """,(me,)).fetchall()
                    activity=[]
                    for pid,state,wet,we,bt,blockers,qc in rows:
                        activity.append({'pid':int(pid),'state':str(state),'wait_event_type':str(wet),'wait_event':str(we),
                                         'backend_type':str(bt),'blocking_pids':[int(x) for x in (blockers or [])],'query_class':str(qc)})
                    pgps=pg_processes(); pgcpu=0.0
                    for p in pgps:
                        try: pgcpu += float(p.cpu_percent(None))
                        except psutil.Error: pass
                    self.samples.append({'mono':mono,'wall':wall,'cpu_total':float(psutil.cpu_percent(None)),
                                         'runnable':runnable,'ctx_per_s':ctx_rate,'python_cpu':float(self.python.cpu_percent(None)),
                                         'python_threads':self.python.num_threads(),'postgres_cpu':pgcpu,
                                         'backend_count':len(activity),'active_backend_count':sum(1 for x in activity if x['state']=='active'),
                                         'activity':activity})
        except BaseException as exc: self.errors.append(f'{type(exc).__name__}:{exc}')


def run_unprofiled(dsn: str) -> dict[str, Any]:
    return gate.run_gate(dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)


def run_profiled(dsn: str, run_no: int, interval: float) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    trace=WarmTrace(); trace.run_no=run_no; trace.active=True; trace.install(); obs=Observer(dsn,interval); obs.start()
    try: result=run_unprofiled(dsn)
    finally: obs.close(); trace.restore()
    if obs.errors: raise RuntimeError(f'observer errors: {obs.errors}')
    return result, list(trace.cycles), list(obs.samples)


def calibration_ok(off: list[dict[str, Any]], on: list[dict[str, Any]]) -> dict[str, Any]:
    offp=statistics.median(float(x['latency_ms']['p99']) for x in off); onp=statistics.median(float(x['latency_ms']['p99']) for x in on)
    offt=statistics.median(float(x['throughput_jobs_per_second']) for x in off); ont=statistics.median(float(x['throughput_jobs_per_second']) for x in on)
    intrusive = onp > offp*1.15 and onp-offp > 50.0 or ont < offt*0.85
    return {'off_p99_median':offp,'on_p99_median':onp,'off_throughput_median':offt,'on_throughput_median':ont,
            'p99_ratio':onp/max(offp,1e-9),'throughput_ratio':ont/max(offt,1e-9),'intrusive':intrusive}


def phase_window(c: dict[str, Any], phase: str) -> tuple[float,float]:
    if phase=='lease': return float(c['lease_start_mono']),float(c['lease_end_mono'])
    if phase=='start': return float(c.get('start_start_mono',0)),float(c.get('start_end_mono',0))
    return float(c.get('complete_start_mono',0)),float(c.get('complete_end_mono',0))


def correlate_cycle(c: dict[str, Any], samples: list[dict[str, Any]], interval: float) -> dict[str, Any]:
    out=dict(c); out['phase_evidence']={}
    for phase in ('lease','start','complete'):
        a,b=phase_window(c,phase); pids=set(int(x) for x in c.get('backend_pids',{}).get(phase,[]))
        relevant=[s for s in samples if a <= float(s['mono']) <= b]
        waits=Counter(); blockers=Counter(); qclasses=Counter(); active_obs=0
        for s in relevant:
            amap={int(x['pid']):x for x in s['activity']}
            for pid in pids:
                row=amap.get(pid)
                if not row: continue
                if row['state']=='active': active_obs+=1
                if row['wait_event_type'] or row['wait_event']: waits[f"{row['wait_event_type']}|{row['wait_event']}"]+=1
                qclasses[row['query_class']]+=1
                for bp in row['blocking_pids']:
                    br=amap.get(int(bp)); blockers[f"{bp}:{'' if br is None else br['query_class']}"]+=1
        stm=[x for x in c.get('statements',[]) if x['phase']==phase]
        chk=[x for x in c.get('checkouts',[]) if x['phase']==phase]
        phase_ms=float(c.get(f'{phase}_ms',0.0))
        execute_ms=sum(float(x['client_execute_ms']) for x in stm); checkout_ms=sum(float(x['checkout_ms']) for x in chk)
        out['phase_evidence'][phase]={
            'backend_pids':sorted(pids),'sample_count':len(relevant),'wait_samples':dict(waits),'blocker_samples':dict(blockers),
            'query_class_samples':dict(qclasses),'server_active_observed_ms':round(active_obs*interval*1000,3),
            'statement_client_wall_ms':round(execute_ms,3),'checkout_wall_ms':round(checkout_ms,3),
            'unattributed_client_wall_ms':round(max(0.0,phase_ms-execute_ms-checkout_ms),3),
            'statement_classes':dict(Counter(x['class'] for x in stm)),
        }
    relevant=[s for s in samples if float(c['cycle_start_mono']) <= float(s['mono']) <= float(c['cycle_end_mono'])]
    def vals(k): return [float(x[k]) for x in relevant]
    out['scheduler_window']={
        'samples':len(relevant), 'runq_avg':statistics.fmean(vals('runnable')) if relevant else None,
        'runq_peak':max(vals('runnable')) if relevant else None, 'cpu_avg':statistics.fmean(vals('cpu_total')) if relevant else None,
        'postgres_cpu_avg':statistics.fmean(vals('postgres_cpu')) if relevant else None,
        'python_cpu_avg':statistics.fmean(vals('python_cpu')) if relevant else None,
        'active_backends_avg':statistics.fmean(vals('active_backend_count')) if relevant else None,
        'ctx_per_s_avg':statistics.fmean(vals('ctx_per_s')) if relevant else None,
    }
    return out


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument('--dsn',required=True); ap.add_argument('--out',type=Path,required=True); ap.add_argument('--max-runs',type=int,default=30)
    args=ap.parse_args(); args.out.mkdir(parents=True,exist_ok=True)
    warm=run_unprofiled(args.dsn)
    if str((warm.get('storage') or {}).get('backend',''))!='postgresql': raise RuntimeError('warmup backend mismatch')
    (args.out/'warmup.json').write_text(json.dumps(warm,indent=2,sort_keys=True,default=str),encoding='utf-8')

    calibration={'attempts':[]}; chosen=None
    for interval in (0.1,0.25):
        off=[]; on=[]
        off.append(run_unprofiled(args.dsn)); r,c,s=run_profiled(args.dsn,-1,interval); on.append(r)
        off.append(run_unprofiled(args.dsn)); r,c,s=run_profiled(args.dsn,-2,interval); on.append(r)
        verdict=calibration_ok(off,on); verdict['interval_s']=interval; calibration['attempts'].append(verdict)
        if not verdict['intrusive']: chosen=interval; break
    calibration['chosen_interval_s']=chosen
    (args.out/'observer-calibration.json').write_text(json.dumps(calibration,indent=2,sort_keys=True),encoding='utf-8')
    if chosen is None: return 8

    runs=[]; failures=0; all_cycles=[]; all_samples=[]
    for run_no in range(1,args.max_runs+1):
        result,cycles,samples=run_profiled(args.dsn,run_no,chosen)
        if str((result.get('storage') or {}).get('backend',''))!='postgresql': raise RuntimeError('warm profile backend mismatch')
        p99=float(result['latency_ms']['p99']); failed=p99>500.0; failures += int(failed)
        top=sorted(cycles,key=lambda x:float(x.get('cycle_ms',0)),reverse=True)[:20] if failed else []
        enriched=[correlate_cycle(c,samples,chosen) for c in top]
        row={'run':run_no,'p50':result['latency_ms']['p50'],'p95':result['latency_ms']['p95'],'p99':p99,
             'max':result['latency_ms']['max'],'lease_p99':result['latency_ms']['phases']['lease_next']['p99'],
             'start_p99':result['latency_ms']['phases']['start_job']['p99'],'complete_p99':result['latency_ms']['phases']['complete']['p99'],
             'throughput':result['throughput_jobs_per_second'],'failed_p99':failed,'errors':result['errors'],'completed':result['completed'],
             'top20':enriched}
        runs.append(row); all_cycles.extend(cycles); all_samples.extend(samples)
        (args.out/f'run-{run_no:02d}.json').write_text(json.dumps({'result':result,'row':row},indent=2,sort_keys=True,default=str),encoding='utf-8')
        print(json.dumps({k:row[k] for k in ('run','p99','lease_p99','throughput','failed_p99')},sort_keys=True),flush=True)
        if run_no>=20 and failures>=5: break

    global_top=sorted(all_cycles,key=lambda x:float(x.get('cycle_ms',0)),reverse=True)[:20]
    global_enriched=[correlate_cycle(c,all_samples,chosen) for c in global_top]
    summary={'schema':'arenyxa.phase3-warm-tail/v1','observer_calibration':calibration,'run_count':len(runs),'failure_count':failures,
             'runs':runs,'global_top20':global_enriched,'all_correctness_pass':all(not x['errors'] and x['completed']==1024 for x in runs)}
    (args.out/'warm-tail-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True,default=str),encoding='utf-8')
    return 0 if summary['all_correctness_pass'] else 9


if __name__=='__main__': raise SystemExit(main())
