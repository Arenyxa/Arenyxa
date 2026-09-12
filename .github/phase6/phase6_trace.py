"""Phase 6 diagnostic only: existing-call timing, zero SQL polling.

OFF uses original production methods except two integer recovery counters.
ON adds nested timings and exact observations of the gate's existing clock reads.
No source, query, result, exception, sleep, retry or workload is rewritten.
"""
from __future__ import annotations
import argparse
import ast
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import statistics
import sys
import threading
import time
from types import SimpleNamespace

from phase6_math import distribution, ledger

HASHES = {
 'src/arenyxa/enterprise/runtime_storage.py':'5702ee19406e72525c96d848eeb7b909141872e0d8c0ebdb29c149b4d596594a',
 'src/arenyxa/enterprise/distributed_queue.py':'8d34fef8df28b3ef7521dd2c465aa2bdf8a6217244635f151c6f752d704c2ccd',
 'scripts/postgresql_32_worker_gate.py':'1dcb09ea7490abebb8e73546178415530adc852422a0346b8d72de56e5322657',
 'scripts/postgresql_64_worker_128_concurrency_gate.py':'ba766b7e02b0f511c1e721628e8e0d615adada27b24918762a73bc1ef7762588',
}
PC=time.perf_counter
MISSING=object()

def verify(root):
    actual={p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in HASHES}
    if actual!=HASHES:
        raise RuntimeError('FROZEN SOURCE IDENTITY MISMATCH: '+json.dumps(actual))
    return actual

def clock_sites(path):
    out={}
    for n in ast.walk(ast.parse(path.read_text())):
        if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
            name=n.targets[0].id
            if name in ('operation_start','elapsed') and 'perf_counter' in ast.unparse(n.value):
                out[name]=n.lineno
    if set(out)!= {'operation_start','elapsed'}:
        raise RuntimeError('Gate clock structure differs')
    return out

def thread_usage():
    u=resource.getrusage(resource.RUSAGE_THREAD)
    return (u.ru_utime+u.ru_stime,u.ru_nvcsw,u.ru_nivcsw)

class OSObserver:
    """Read-only /proc observer. No SQL or network calls. 250ms requested cadence."""
    def __init__(self):
        self.samples=[]; self.stop=threading.Event();self.thread=None
    def start(self):
        self.thread=threading.Thread(target=self.loop,name='phase6-os-observer',daemon=True)
        self.thread.start()
    def loop(self):
        import psutil
        while not self.stop.is_set():
            begin=PC()
            try:
                stat=Path('/proc/stat').read_text(); load=Path('/proc/loadavg').read_text()
                cpu=[int(x) for x in stat.splitlines()[0].split()[1:]]
                fields={x.split()[0]:x.split()[1:] for x in stat.splitlines() if x}
                pg_cpu=0.;pg_n=0
                for p in psutil.process_iter(['name','cpu_times'],ad_value=None):
                    if (p.info['name'] or '').startswith('postgres'):
                        ct=p.info['cpu_times']
                        if ct is not None: pg_cpu+=ct.user+ct.system;pg_n+=1
                py=psutil.Process().cpu_times()
                self.samples.append(dict(t=begin,end=PC(),cpu=cpu,ctxt=int(fields['ctxt'][0]),
                    runq=int(fields['procs_running'][0]),load=load.strip(),
                    python_cpu=py.user+py.system,pg_cpu=pg_cpu if pg_n else None,pg_processes=pg_n))
            except (OSError,ValueError,psutil.Error) as exc:
                self.samples.append(dict(t=begin,error=type(exc).__name__))
            self.stop.wait(max(0.,.25-(PC()-begin)))
    def finish(self):
        self.stop.set()
        if self.thread:self.thread.join(timeout=3)

class Recorder:
    def __init__(self,gate,rs,queue,psycopg,full):
        self.gate=gate;self.rs=rs;self.Q=queue;self.pg=psycopg;self.full=full
        self.tls=threading.local();self.active=False;self.cycles=[];self.tasks=[]
        self.recovery_count=0;self.originals=[];self.window={};self.os=OSObserver()
        self.sites=clock_sites(Path(gate.__file__))
        self.phase_values={};self.official_values=[];self.overflow=False
    def row(self):
        return getattr(self.tls,'row',None) if self.active else None
    def lease_row(self):
        return self.row() if getattr(self.tls,'phase','')=='lease' else None
    def span(self,kind,start,end):
        r=self.lease_row()
        if r is not None:
            if len(r['spans'])>=256:self.overflow=True
            else:r['spans'].append((kind,start,end))
    def patch(self,owner,name,value):
        original=owner.__dict__.get(name,MISSING) if isinstance(owner,type) else getattr(owner,name)
        self.originals.append((owner,name,original));setattr(owner,name,value)
        return original
    def install(self):
        R=self;Q=self.Q;rs=self.rs;Backend=rs.PostgreSQLDistributedRuntimeStorage
        old_executor=self.gate.ThreadPoolExecutor
        class Executor(old_executor):
            def __enter__(self):
                frame=sys._getframe(1)
                R.phase_values=frame.f_locals['phase_latencies_ms']
                R.official_values=frame.f_locals['latencies_ms']
                R.window['begin']=PC();R.active=True
                if R.full:R.os.start()
                return super().__enter__()
            def submit(self,fn,*args,**kwargs):
                if not R.full:return super().submit(fn,*args,**kwargs)
                submitted=PC();slot=int(args[0])
                def task():
                    started=PC();R.tls.task=(slot,submitted,started);R.tls.attempt=0
                    try:return fn(*args,**kwargs)
                    finally:R.tasks.append((slot,submitted,started,PC()))
                return super().submit(task)
            def __exit__(self,*args):
                try:return super().__exit__(*args)
                finally:
                    R.window['end']=PC();R.active=False
                    if R.full:R.os.finish()
        self.patch(self.gate,'ThreadPoolExecutor',Executor)
        for name in ('recover_stale_worker_leases','recover_expired_leases'):
            original=getattr(Q,name)
            def child(self,*args,_orig=original,_name=name,**kwargs):
                if R.active and _name=='recover_stale_worker_leases':R.recovery_count+=1
                r=R.lease_row();a=PC() if r is not None else None
                try:return _orig(self,*args,**kwargs)
                finally:
                    if r is not None:r['recovery'].append((_name,a,PC()))
            self.patch(Q,name,child)
        if not self.full:return
        real_time=self.gate.time
        class GateClock:
            def __getattr__(self,name):return getattr(real_time,name)
            def perf_counter(self):
                t=PC();f=sys._getframe(1)
                if R.active and f.f_code.co_name=='work':
                    if f.f_lineno==R.sites['operation_start']:
                        R.tls.attempt+=1
                        R.tls.row={'operation_start':t,'attempt':R.tls.attempt,
                            'task':R.tls.task,'tid':threading.get_native_id(),
                            'spans':[],'sql':[],'health':[],'recovery':[], 'success':False}
                    elif f.f_lineno==R.sites['elapsed']:
                        row=R.row()
                        if row is not None:
                            row['cycle_end']=t;row['cycle_ms']=(t-row['operation_start'])*1000.
                            R.cycles.append(row);R.tls.row=None
                return t
        self.patch(self.gate,'time',GateClock())
        old_lease=Q.lease_next
        def lease(self,*args,**kwargs):
            r=R.row()
            if r is None:return old_lease(self,*args,**kwargs)
            R.tls.phase='lease';r['client_id']=id(self);r['worker']=str(args[0])
            r['lease_begin']=PC();r['usage_before']=thread_usage()
            result=None
            try:
                result=old_lease(self,*args,**kwargs);return result
            finally:
                r['usage_after']=thread_usage();r['lease_end']=PC()
                r['success']=result is not None
                r['job_id']=str(result.job_id) if result is not None else None
                R.tls.phase=''
        self.patch(Q,'lease_next',lease)
        for name,label in [('start_job','start'),('complete','complete')]:
            original=getattr(Q,name)
            def phase(self,*args,_orig=original,_label=label,**kwargs):
                r=R.row()
                if r is None:return _orig(self,*args,**kwargs)
                r[_label+'_begin']=PC()
                try:return _orig(self,*args,**kwargs)
                finally:r[_label+'_end']=PC()
            self.patch(Q,name,phase)
        old_due=Q._recover_expired_leases_if_due
        def due(self,*args,**kwargs):
            r=R.lease_row()
            if r is None:return old_due(self,*args,**kwargs)
            a=PC();r['due_age']=time.monotonic()-self._last_expiry_scan_monotonic
            try:return old_due(self,*args,**kwargs)
            finally:R.span('due',a,PC())
        self.patch(Q,'_recover_expired_leases_if_due',due)
        old_conn=Backend.connection
        @contextlib.contextmanager
        def connection(self):
            r=R.lease_row()
            if r is None:
                with old_conn(self) as c:yield c
                return
            a=PC();exit_start=None
            try:
                with old_conn(self) as c:
                    R.span('checkout',a,PC())
                    r.setdefault('backend_pids',[]).append(c.raw.info.backend_pid)
                    try:yield c
                    finally:exit_start=PC()
            finally:
                if exit_start is not None:R.span('checkin',exit_start,PC())
        self.patch(Backend,'connection',connection)
        old_health=Backend.__dict__['_check_pool_connection'].__func__
        def health(cls,c):
            r=R.lease_row()
            if r is None:return old_health(cls,c)
            h={'begin':PC(),'idle_since':getattr(c,'_arenyxa_pool_idle_since',None),'probe':False}
            h['idle_age']=None if h['idle_since'] is None else time.monotonic()-h['idle_since']
            r['health'].append(h);R.tls.health=h
            try:return old_health(cls,c)
            finally:
                h['end']=PC();R.span('health',h['begin'],h['end']);R.tls.health=None
        self.patch(Backend,'_check_pool_connection',classmethod(health))
        real_select=rs.select
        class SelectProxy:
            def __getattr__(self,name):return getattr(real_select,name)
            def select(self,*args,**kwargs):
                h=getattr(R.tls,'health',None)
                try:
                    result=real_select.select(*args,**kwargs)
                    if h is not None:h['readable']=bool(result[0]);h['exceptional']=bool(result[2])
                    return result
                except BaseException:
                    if h is not None:h['fd_exception']=True
                    raise
        self.patch(rs,'select',SelectProxy())
        raw_execute=self.pg.Connection.execute
        def execute(self,query,*args,**kwargs):
            r=R.lease_row()
            if r is None:return raw_execute(self,query,*args,**kwargs)
            h=getattr(R.tls,'health',None)
            kind='health_probe' if h is not None else 'execute'
            sql_class=('health' if h is not None else 'lease_fast' if 'WITH eligible_worker AS' in str(query) else 'other_business')
            a=PC()
            try:return raw_execute(self,query,*args,**kwargs)
            finally:
                b=PC();R.span(kind,a,b)
                r['sql'].append((sql_class,a,b,self.info.backend_pid))
                if h is not None:h['probe']=True
        self.patch(self.pg.Connection,'execute',execute)
        facade=rs._ConnectionFacade.execute
        def facade_execute(self,*args,**kwargs):
            r=R.lease_row()
            if r is None:return facade(self,*args,**kwargs)
            a=PC()
            try:return facade(self,*args,**kwargs)
            finally:R.span('facade',a,PC())
        self.patch(rs._ConnectionFacade,'execute',facade_execute)
        for name in ('fetchone','fetchall'):
            original=getattr(rs._CursorFacade,name)
            def fetch(self,*args,_orig=original,**kwargs):
                if R.lease_row() is None:return _orig(self,*args,**kwargs)
                a=PC()
                try:return _orig(self,*args,**kwargs)
                finally:R.span('fetch',a,PC())
            self.patch(rs._CursorFacade,name,fetch)
        old_materialize=Q._lease_from_row
        def materialize(*args,**kwargs):
            if R.lease_row() is None:return old_materialize(*args,**kwargs)
            a=PC()
            try:return old_materialize(*args,**kwargs)
            finally:R.span('postprocess',a,PC())
        self.patch(Q,'_lease_from_row',staticmethod(materialize))
    def restore(self):
        self.active=False;self.os.finish()
        for obj,name,value in reversed(self.originals):
            if value is MISSING:delattr(obj,name)
            else:setattr(obj,name,value)
    def result(self):
        rows=[]
        for r in self.cycles:
            r=dict(r);r['recovery_yes']=bool(r['recovery'])
            r['lease_ms']=(r['lease_end']-r['lease_begin'])*1000.
            for p in ('start','complete'):r[p+'_ms']=(r[p+'_end']-r[p+'_begin'])*1000.
            r['ledger']=ledger(r['lease_begin'],r['lease_end'],r['spans'])
            r['checkout_inclusive_ms']=sum((b-a)*1000 for k,a,b in r['spans'] if k=='checkout')
            r['health_probe_yes']=any(h['probe'] for h in r['health'])
            r['client_nonexecute_ms']=r['lease_ms']-r['ledger']['execute_ms']
            r['thread_cpu_ms']=(r['usage_after'][0]-r['usage_before'][0])*1000
            r['thread_vcsw']=r['usage_after'][1]-r['usage_before'][1]
            r['thread_ivcsw']=r['usage_after'][2]-r['usage_before'][2]
            rows.append(r)
        match=(len(rows)==len(self.official_values) and
               sorted(round(r['cycle_ms'],6) for r in rows)==sorted(round(x,6) for x in self.official_values)) if self.full else None
        return dict(cycles=rows,window=self.window,tasks=self.tasks,os_samples=self.os.samples,
                    exact_cycle_multiset_matches_gate=match,overflow=self.overflow,
                    timed_recovery_invocations=self.recovery_count,
                    phase_distributions={k:distribution(v) for k,v in self.phase_values.items()},
                    cycle_distribution=distribution(self.official_values))

def compact(result,trace):
    lat=result['latency_ms'];pm=result['pool']['metrics']
    return dict(p50=lat['p50'],p95=lat['p95'],p99=lat['p99'],max=lat['max'],
        throughput=result['throughput_jobs_per_second'],passed=result['passed'],
        lease_p99=lat['phases']['lease_next']['p99'],start_p99=lat['phases']['start_job']['p99'],
        complete_p99=lat['phases']['complete']['p99'],recovery_calls=trace['timed_recovery_invocations'],
        pool_wait_ms=sum(x.get('requests_wait_ms',0) for x in pm))

def correct(r):
    return (r['storage']['backend']=='postgresql' and r['completed']==1024 and r['non_completed']==0
        and not r['errors'] and r['fencing_probe']['passed'] and not any(r['state_invariants'].values())
        and r['active_leases_after']==0 and r['pool']['connection_storm_free'])

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dsn',required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--runs',type=int,default=40);args=ap.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    root=Path(os.environ.get('GITHUB_WORKSPACE',Path.cwd()));verify(root)
    import psycopg
    from scripts import postgresql_32_worker_gate as gate
    from arenyxa.enterprise import runtime_storage as rs
    from arenyxa.enterprise.distributed import DurableDistributedQueue as Q
    with psycopg.connect(args.dsn,autocommit=True) as c:
        settings=c.execute("SELECT current_setting('server_version_num'),current_setting('max_connections'),current_setting('fsync'),current_setting('synchronous_commit'),pg_postmaster_start_time()::text").fetchone()
    if tuple(map(str,settings[:4]))!=('160015','256','on','on'):raise RuntimeError('PostgreSQL contract mismatch')
    (args.out/'settings.json').write_text(json.dumps(settings))
    def save(name,payload):
        (args.out/(name+'.json')).write_text(json.dumps(payload,separators=(',',':')),encoding='utf-8')
    # Existing gate first run is retained, not redefined as a release pass.
    first=gate.run_gate(args.dsn,workers=64,concurrency=128,jobs=1024,p99_budget_ms=500.)
    save('first-run',first)
    if not correct(first):raise RuntimeError('First run correctness failure')
    def run(name,full):
        verify(root);rec=Recorder(gate,rs,Q,psycopg,full);rec.install()
        try:r=gate.run_gate(args.dsn,workers=64,concurrency=128,jobs=1024,p99_budget_ms=500.)
        finally:rec.restore()
        trace=rec.result();payload={'official':r,'trace':trace};save(name,payload);verify(root)
        if not correct(r):raise RuntimeError('Correctness failure: '+name)
        if full and (trace['overflow'] or not trace['exact_cycle_multiset_matches_gate']):
            raise RuntimeError('Observer identity/count failure: '+name)
        v=compact(r,trace);v['name']=name;v['full']=full;print(json.dumps(v),flush=True);return v
    calibration=[run('cal-'+str(i+1),bool(i%2)) for i in range(4)]
    off=[x for x in calibration if not x['full']];on=[x for x in calibration if x['full']]
    ratios={k:statistics.median(x[k] for x in on)/statistics.median(x[k] for x in off) for k in ('p50','p95','p99','throughput')}
    recovery_delta=abs(statistics.mean(x['recovery_calls'] for x in on)-statistics.mean(x['recovery_calls'] for x in off))
    accepted=(max(ratios[k] for k in ('p50','p95','p99'))<=1.10 and ratios['throughput']>=.95 and recovery_delta<=6.)
    cal={'runs':calibration,'ratios':ratios,'recovery_calls_absolute_delta':recovery_delta,
         'accepted':accepted,'limits':{'latency_ratio_max':1.10,'throughput_ratio_min':.95,'recovery_call_delta_max':6}}
    save('calibration',cal)
    if not accepted:
        save('verdict',{'status':'INTRUSIVE','warm_runs':0});return 3
    runs=[]
    for i in range(1,args.runs+1):
        runs.append(run(f'warm-{i:02}',True));save('summary',{'calibration':cal,'runs':runs})
    with psycopg.connect(args.dsn,autocommit=True) as c:
        final=c.execute("SELECT current_setting('server_version_num'),current_setting('max_connections'),current_setting('fsync'),current_setting('synchronous_commit'),pg_postmaster_start_time()::text").fetchone()
    save('settings-final',final)
    if settings!=final:raise RuntimeError('PostgreSQL instance/settings changed')
    save('hashes-final',verify(root));save('verdict',{'status':'CAPTURE_COMPLETE','warm_runs':len(runs),'warm_failures':sum(x['p99']>500 for x in runs)})
    return 0

if __name__=='__main__':raise SystemExit(main())
