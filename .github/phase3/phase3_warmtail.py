from __future__ import annotations

import argparse
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
from arenyxa.enterprise.distributed import DurableDistributedQueue
from arenyxa.enterprise.runtime_storage import _ConnectionFacade, PostgreSQLDistributedRuntimeStorage


def qclass(sql: str) -> str:
    q = " ".join(str(sql).lower().split())
    if "arenyxa_pool_health" in q: return "health"
    if "with eligible_worker" in q and "distributed_jobs" in q: return "lease_fast"
    if "'started'" in q and "distributed_job_events" in q: return "start_fast"
    if "'completed'" in q and "distributed_job_events" in q: return "complete_fast"
    if "recover" in q or ("lease_expires_at" in q and "state in ('leased','running')" in q): return "recovery"
    if "distributed_workers" in q: return "workers"
    if "distributed_jobs" in q: return "jobs"
    if "distributed_job_events" in q: return "events"
    return "other"


def dist(vals: list[float]) -> dict[str, Any]:
    if not vals: return {"count":0,"mean":None,"min":None,"p50":None,"p95":None,"p99":None,"max":None}
    s=sorted(vals)
    def p(q: float): return s[min(len(s)-1,max(0,round((len(s)-1)*q)))]
    return {"count":len(vals),"mean":statistics.fmean(vals),"min":min(vals),"p50":p(.5),"p95":p(.95),"p99":p(.99),"max":max(vals)}


def read_sched() -> tuple[int,int]:
    ctxt=runq=0
    with open('/proc/stat','r',encoding='utf-8') as f:
        for line in f:
            if line.startswith('ctxt '): ctxt=int(line.split()[1])
            elif line.startswith('procs_running '): runq=int(line.split()[1])
    return ctxt,runq


def pg_processes() -> list[psutil.Process]:
    out=[]
    for p in psutil.process_iter(['name']):
        try:
            if str(p.info.get('name') or '').lower().startswith('postgres'): out.append(p)
        except psutil.Error: pass
    return out


class TraceState:
    def __init__(self) -> None:
        self.capture=False; self.workload_active=False; self.window_start=None; self.window_end=None
        self.tls=threading.local(); self.calls=[]; self.execs=[]; self.checkouts=[]; self.cycles=[]; self.samples=[]
        self.seq=0; self.seq_lock=threading.Lock(); self.sampler_stop=threading.Event(); self.sampler_thread=None
        self.interval=.1; self.dsn=''; self.pyproc=psutil.Process(os.getpid())
    def next_id(self) -> int:
        with self.seq_lock: self.seq+=1; return self.seq
    def reset_run(self, capture: bool, dsn: str, interval: float) -> None:
        self.capture=capture; self.workload_active=False; self.window_start=self.window_end=None
        self.calls=[]; self.execs=[]; self.checkouts=[]; self.cycles=[]; self.samples=[]; self.interval=interval; self.dsn=dsn
        self.sampler_stop=threading.Event(); self.sampler_thread=None
    def begin_call(self, phase: str, **meta: Any) -> dict[str,Any] | None:
        if not (self.capture and self.workload_active): return None
        rec={"call_id":self.next_id(),"phase":phase,"start":time.perf_counter(),**meta}
        self.tls.call=rec; return rec
    def end_call(self, rec: dict[str,Any] | None, **meta: Any) -> None:
        if rec is None: return
        rec.update(meta); rec['end']=time.perf_counter(); rec['client_ms']=(rec['end']-rec['start'])*1000.0
        self.calls.append(rec); self.tls.call=None
    def start_sampler(self) -> None:
        if not self.capture: return
        self.sampler_thread=threading.Thread(target=self._sample_loop,daemon=True,name='p3-warmtail-sampler'); self.sampler_thread.start()
    def stop_sampler(self) -> None:
        if not self.capture: return
        self.sampler_stop.set()
        if self.sampler_thread: self.sampler_thread.join(timeout=5)
    def _sample_loop(self) -> None:
        psutil.cpu_percent(interval=None); self.pyproc.cpu_percent(interval=None)
        for p in pg_processes():
            try: p.cpu_percent(interval=None)
            except psutil.Error: pass
        last_t=time.perf_counter(); last_ctxt,_=read_sched(); n=0
        try:
            with psycopg.connect(self.dsn,autocommit=True,application_name='arenyxa-p3-warmtail-observer') as conn:
                observer_pid=conn.info.backend_pid
                while not self.sampler_stop.wait(self.interval):
                    now=time.perf_counter(); wall=time.time(); ctxt,runq=read_sched(); dt=max(now-last_t,1e-6); ctx=(ctxt-last_ctxt)/dt; last_t=now; last_ctxt=ctxt
                    rows=conn.execute("""SELECT pid,state,backend_type,coalesce(wait_event_type,''),coalesce(wait_event,''),pg_blocking_pids(pid),query
                      FROM pg_stat_activity WHERE datname=current_database() AND pid<>%s""",(observer_pid,)).fetchall()
                    acts=[]
                    for pid,state,btype,wet,we,blockers,query in rows:
                        acts.append({"pid":int(pid),"state":str(state),"backend_type":str(btype),"wait_type":str(wet),"wait_event":str(we),"blockers":[int(x) for x in blockers],"query_class":qclass(str(query))})
                    locks=conn.execute("""SELECT pid,locktype,mode,coalesce(relation::regclass::text,''),coalesce(transactionid::text,'')
                      FROM pg_locks WHERE NOT granted""").fetchall()
                    pgcpu=None
                    if n%2==0:
                        vals=[]
                        for p in pg_processes():
                            try: vals.append(float(p.cpu_percent(interval=None)))
                            except psutil.Error: pass
                        pgcpu=sum(vals) if vals else 0.0
                    n+=1
                    self.samples.append({"mono":now,"wall":wall,"cpu":float(psutil.cpu_percent(interval=None)),"runq":runq,"ctx_s":ctx,"python_cpu":float(self.pyproc.cpu_percent(interval=None)),"pg_cpu":pgcpu,"activities":acts,"ungranted_locks":[{"pid":int(x[0]),"locktype":str(x[1]),"mode":str(x[2]),"relation":str(x[3]),"xid":str(x[4])} for x in locks]})
        except Exception as exc:
            self.samples.append({"mono":time.perf_counter(),"observer_error":f"{type(exc).__name__}: {exc}"})

STATE=TraceState()


def install_hooks() -> dict[str,Any]:
    orig={"lease":DurableDistributedQueue.lease_next,"start":DurableDistributedQueue.start_job,"complete":DurableDistributedQueue.complete,"execute":_ConnectionFacade.execute,"connection":PostgreSQLDistributedRuntimeStorage.connection,"executor":gate.ThreadPoolExecutor}
    def lease(self, worker_id: str, *, lease_seconds: int=60):
        rec=STATE.begin_call('lease',worker_id=str(worker_id)); result=None
        try:
            result=orig['lease'](self,worker_id,lease_seconds=lease_seconds); return result
        finally:
            jid=None if result is None else str(result.job_id)
            STATE.end_call(rec,job_id=jid,returned=jid is not None)
            if rec is not None and result is not None:
                STATE.tls.cycle={"cycle_id":STATE.next_id(),"job_id":jid,"worker_id":str(worker_id),"start":rec['start'],"lease_call_id":rec['call_id'],"lease_ms":rec.get('client_ms')}
    def start(self, job_id, worker_id, lease_token):
        rec=STATE.begin_call('start',job_id=str(job_id),worker_id=str(worker_id))
        try: return orig['start'](self,job_id,worker_id,lease_token)
        finally:
            STATE.end_call(rec)
            cyc=getattr(STATE.tls,'cycle',None)
            if cyc is not None and str(job_id)==cyc.get('job_id') and rec is not None:
                cyc['start_call_id']=rec['call_id']; cyc['start_ms']=rec.get('client_ms')
    def complete(self, job_id, worker_id, lease_token, result):
        rec=STATE.begin_call('complete',job_id=str(job_id),worker_id=str(worker_id))
        try: return orig['complete'](self,job_id,worker_id,lease_token,result)
        finally:
            STATE.end_call(rec)
            cyc=getattr(STATE.tls,'cycle',None)
            if cyc is not None and str(job_id)==cyc.get('job_id') and rec is not None:
                cyc['complete_call_id']=rec['call_id']; cyc['complete_ms']=rec.get('client_ms'); cyc['end']=rec.get('end'); cyc['total_ms']=(cyc['end']-cyc['start'])*1000.0; STATE.cycles.append(cyc); STATE.tls.cycle=None
    def execute(self, sql, params=()):
        call=getattr(STATE.tls,'call',None)
        if not (STATE.capture and STATE.workload_active and call is not None): return orig['execute'](self,sql,params)
        st=time.perf_counter(); pid=int(getattr(getattr(self.raw,'info',None),'backend_pid',0) or 0); ok=False
        try:
            x=orig['execute'](self,sql,params); ok=True; return x
        finally:
            en=time.perf_counter(); STATE.execs.append({"call_id":call['call_id'],"phase":call['phase'],"class":qclass(str(sql)),"pid":pid,"start":st,"end":en,"elapsed_ms":(en-st)*1000.0,"ok":ok})
    @contextmanager
    def connection(self):
        call=getattr(STATE.tls,'call',None); st=time.perf_counter()
        with orig['connection'](self) as c:
            en=time.perf_counter()
            if STATE.capture and STATE.workload_active and call is not None:
                pid=int(getattr(getattr(c.raw,'info',None),'backend_pid',0) or 0); STATE.checkouts.append({"call_id":call['call_id'],"phase":call['phase'],"pid":pid,"start":st,"end":en,"elapsed_ms":(en-st)*1000.0})
            yield c
    class Exec(orig['executor']):
        def __enter__(self):
            if STATE.capture: STATE.workload_active=True; STATE.window_start=time.perf_counter()
            return super().__enter__()
        def __exit__(self, et, ev, tb):
            try: return super().__exit__(et,ev,tb)
            finally:
                if STATE.capture: STATE.window_end=time.perf_counter(); STATE.workload_active=False
    DurableDistributedQueue.lease_next=lease; DurableDistributedQueue.start_job=start; DurableDistributedQueue.complete=complete; _ConnectionFacade.execute=execute; PostgreSQLDistributedRuntimeStorage.connection=connection; gate.ThreadPoolExecutor=Exec
    return orig


def restore_hooks(o: dict[str,Any]) -> None:
    DurableDistributedQueue.lease_next=o['lease']; DurableDistributedQueue.start_job=o['start']; DurableDistributedQueue.complete=o['complete']; _ConnectionFacade.execute=o['execute']; PostgreSQLDistributedRuntimeStorage.connection=o['connection']; gate.ThreadPoolExecutor=o['executor']


def run_gate(dsn: str, capture: bool, interval: float) -> tuple[dict[str,Any],dict[str,Any]]:
    STATE.reset_run(capture,dsn,interval); STATE.start_sampler()
    try: result=gate.run_gate(dsn,workers=64,concurrency=128,jobs=1024,p99_budget_ms=500.0)
    finally: STATE.stop_sampler()
    return result, trace_summary(result)


def slice_samples(start: float, end: float) -> list[dict[str,Any]]:
    return [s for s in STATE.samples if start <= float(s.get('mono',-1)) <= end and 'observer_error' not in s]


def enrich_call(call: dict[str,Any]) -> dict[str,Any]:
    cid=call['call_id']; ex=[x for x in STATE.execs if x['call_id']==cid]; co=[x for x in STATE.checkouts if x['call_id']==cid]
    pids=sorted({x['pid'] for x in ex+co if x.get('pid')})
    sam=slice_samples(call['start'],call['end']); waits=Counter(); blocker_edges=Counter(); ungranted=[]
    for s in sam:
        amap={a['pid']:a for a in s.get('activities',[])}
        for pid in pids:
            a=amap.get(pid)
            if not a: continue
            if a['wait_type'] or a['wait_event']: waits[f"{a['wait_type']}|{a['wait_event']}"]+=1
            for b in a['blockers']:
                blocker_edges[f"{pid}->{b}:{(amap.get(b) or {}).get('query_class','unknown')}"]+=1
        for l in s.get('ungranted_locks',[]):
            if l['pid'] in pids: ungranted.append(l)
    sched={k:dist([float(s[k]) for s in sam if s.get(k) is not None]) for k in ('cpu','runq','ctx_s','python_cpu','pg_cpu')}
    db_ms=sum(float(x['elapsed_ms']) for x in ex); checkout_ms=sum(float(x['elapsed_ms']) for x in co)
    return {**call,"backend_pids":pids,"db_execute_wall_ms":db_ms,"checkout_wall_ms":checkout_ms,"client_residual_ms":float(call['client_ms'])-db_ms-checkout_ms,"statement_classes":dict(Counter(x['class'] for x in ex)),"wait_samples":dict(waits),"blocker_edges":dict(blocker_edges),"ungranted_locks":ungranted,"scheduler":sched}


def trace_summary(result: dict[str,Any]) -> dict[str,Any]:
    callmap={c['call_id']:c for c in STATE.calls}; top=sorted(STATE.cycles,key=lambda x:float(x.get('total_ms',0)),reverse=True)[:20]
    enriched=[]
    for cyc in top:
        row=dict(cyc); row['lease']=enrich_call(callmap[cyc['lease_call_id']]); row['start_phase']=enrich_call(callmap[cyc['start_call_id']]); row['complete_phase']=enrich_call(callmap[cyc['complete_call_id']]); enriched.append(row)
    all_calls=[enrich_call(c) for c in STATE.calls if c['phase']=='lease' and c.get('returned')]
    return {"official":result,"window":{"start":STATE.window_start,"end":STATE.window_end},"cycle_count":len(STATE.cycles),"top20":enriched,"lease_calls":all_calls,"samples":STATE.samples,"observer_errors":[s['observer_error'] for s in STATE.samples if s.get('observer_error')]}


def precondition(dsn: str) -> dict[str,Any]:
    r=gate.run_gate(dsn,workers=64,concurrency=128,jobs=1024,p99_budget_ms=500.0)
    assert (r.get('storage') or {}).get('backend')=='postgresql' and r.get('completed')==1024 and not r.get('errors')
    return r


def compact(r: dict[str,Any]) -> dict[str,Any]:
    lat=r['latency_ms']; ph=lat['phases']; return {"p50":lat['p50'],"p95":lat['p95'],"p99":lat['p99'],"max":lat['max'],"lease_p99":ph['lease_next']['p99'],"start_p99":ph['start_job']['p99'],"complete_p99":ph['complete']['p99'],"throughput":r['throughput_jobs_per_second'],"passed":r['passed']}


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument('--dsn',required=True); ap.add_argument('--out',type=Path,required=True); args=ap.parse_args(); args.out.mkdir(parents=True,exist_ok=True)
    with psycopg.connect(args.dsn,autocommit=True) as c:
        vals=c.execute("SELECT current_setting('server_version_num'),current_setting('max_connections'),current_setting('fsync'),current_setting('synchronous_commit')").fetchone()
        assert tuple(map(str,vals))==('160015','256','on','on')
    warm=precondition(args.dsn); (args.out/'precondition.json').write_text(json.dumps(warm,indent=2,sort_keys=True),encoding='utf-8')
    hooks=install_hooks()
    try:
        off=[]; on=[]
        for i in range(2):
            r,_=run_gate(args.dsn,False,.1); off.append(compact(r))
        for i in range(2):
            r,t=run_gate(args.dsn,True,.1); on.append(compact(r)); (args.out/f'cal-on-{i+1}.json').write_text(json.dumps(t,indent=2,sort_keys=True,default=str),encoding='utf-8')
        off_p=statistics.median([x['p99'] for x in off]); on_p=statistics.median([x['p99'] for x in on]); off_t=statistics.median([x['throughput'] for x in off]); on_t=statistics.median([x['throughput'] for x in on])
        intrusive=on_p>off_p*1.20 or on_t<off_t*.85; interval=.25 if intrusive else .1
        calibration={"off":off,"on100ms":on,"off_p99_median":off_p,"on_p99_median":on_p,"off_throughput_median":off_t,"on_throughput_median":on_t,"intrusive":intrusive,"chosen_interval_s":interval}
        (args.out/'observer-calibration.json').write_text(json.dumps(calibration,indent=2,sort_keys=True),encoding='utf-8')
        runs=[]; failures=0
        for i in range(1,31):
            r,t=run_gate(args.dsn,True,interval); c=compact(r); c['run']=i; c['trace_file']=f'run-{i:02d}.json'; runs.append(c)
            if float(c['p99'])>500.0: failures+=1
            (args.out/c['trace_file']).write_text(json.dumps(t,indent=2,sort_keys=True,default=str),encoding='utf-8')
            print(json.dumps(c,sort_keys=True),flush=True)
            if i>=20 and failures>=5: break
        summary={"calibration":calibration,"warm_runs":runs,"warm_failures":failures,"run_count":len(runs),"old_run8_maintenance_hypothesis":"REJECTED_BY_TIMED_WINDOW_EVIDENCE"}
        (args.out/'phase3b-summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True),encoding='utf-8')
    finally: restore_hooks(hooks)
    return 0

if __name__=='__main__': raise SystemExit(main())
