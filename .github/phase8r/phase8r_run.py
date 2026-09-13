from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Any, Callable

import phase6_minimal
import phase6_trace as p6
from phase6_math import distribution
from phase8_core import paired_boundary_calibration
from phase8r_core import (MAX_WORKERS_FROZEN, WARM_RUNS, expected_worker_registry_count,
                          assert_phase8r_worker_budget, expected_pool_geometry)
from phase8_observe import combined_snapshot

WORKERS=64
CONCURRENCY=128
JOBS=1024
CLIENTS=16
P99_BUDGET=500.0
PG_IMAGE='postgres:16.15'
CAL_PATTERN=('OFF','ON','ON','OFF','OFF','ON','ON','OFF')


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,ensure_ascii=False,indent=2,sort_keys=True),encoding='utf-8')


def write_gz(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    with gzip.open(path,'wt',encoding='utf-8',compresslevel=6) as f:
        json.dump(obj,f,separators=(',',':'))


def sh(cmd: list[str], *, check: bool=True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,check=check)


def stop_container(name: str) -> None:
    subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def start_container(name: str, port: int, out: Path) -> tuple[str,dict[str,Any]]:
    stop_container(name)
    cp=sh(['docker','run','-d','--name',name,'-p',f'127.0.0.1:{port}:5432',
           '-e','POSTGRES_USER=arenyxa','-e','POSTGRES_PASSWORD=arenyxa_ci','-e','POSTGRES_DB=arenyxa_ci',
           PG_IMAGE,'-c','max_connections=256'])
    container_id=cp.stdout.strip()
    dsn=f'postgresql://arenyxa:arenyxa_ci@127.0.0.1:{port}/arenyxa_ci'
    import psycopg
    deadline=time.monotonic()+45
    last=None
    while time.monotonic()<deadline:
        try:
            with psycopg.connect(dsn,connect_timeout=2,autocommit=True) as conn:
                with conn.cursor() as cur:
                    vals={k:cur.execute(f'SHOW {k}').fetchone()[0] for k in ('server_version','max_connections','fsync','synchronous_commit')}
                    postmaster=cur.execute("SELECT extract(epoch from pg_postmaster_start_time())").fetchone()[0]
            break
        except Exception as exc:
            last=exc;time.sleep(.5)
    else:
        logs=sh(['docker','logs',name],check=False).stdout
        raise RuntimeError(f'PostgreSQL did not become ready: {last}\n{logs[-4000:]}')
    if not str(vals['server_version']).startswith('16.15'):
        raise RuntimeError('server_version mismatch: '+str(vals))
    if str(vals['max_connections'])!='256' or str(vals['fsync']).lower()!='on' or str(vals['synchronous_commit']).lower()!='on':
        raise RuntimeError('PostgreSQL safety contract mismatch: '+str(vals))
    image_digest=sh(['docker','image','inspect',PG_IMAGE,'--format','{{json .RepoDigests}}'],check=False).stdout.strip()
    meta={'container_name':name,'container_id':container_id,'port':port,'dsn_redacted':f'postgresql://arenyxa:***@127.0.0.1:{port}/arenyxa_ci',
          'started_wall_ns':time.time_ns(),'started_perf':time.perf_counter(),'postmaster_start_epoch':float(postmaster),
          'settings':vals,'image':PG_IMAGE,'image_repo_digests':image_digest}
    write_json(out/'instance.json',meta)
    return dsn,meta


def target_rows(trace: dict[str,Any]) -> list[dict[str,Any]]:
    out=[]
    for r in trace['cycles']:
        sql=r.get('sql') or []
        lf=sum(1 for x in sql if x[0]=='lease_fast')
        fallback=any(x[0]=='other_business' for x in sql)
        if r.get('success') and not r.get('recovery_yes') and lf==1 and not fallback:
            out.append(r)
    return out


def compact_run(official: dict[str,Any], trace: dict[str,Any], *, name: str,
                instance_meta: dict[str,Any], warm_index: int|None) -> dict[str,Any]:
    target=target_rows(trace)
    lease=[r['lease_ms'] for r in target]
    execute=[r['ledger']['execute_ms'] for r in target]
    lat=official['latency_ms']; pool=official['pool']['metrics']
    acq=sum(int(x.get('acquisition_failures',0) or 0) for x in pool)
    result={
      'name':name,'warm_index':warm_index,
      'elapsed_since_container_start_s':time.perf_counter()-float(instance_meta['started_perf']),
      'elapsed_since_postmaster_start_s':time.time()-float(instance_meta['postmaster_start_epoch']),
      'cumulative_gate_jobs':None if warm_index is None else warm_index*JOBS,
      'p50':lat['p50'],'p95':lat['p95'],'p99':lat['p99'],'p999':trace['cycle_distribution']['p999'],'max':lat['max'],
      'throughput':official['throughput_jobs_per_second'],'duration_seconds':official['duration_seconds'],
      'lease_p50':distribution(lease)['p50'],'lease_p95':distribution(lease)['p95'],'lease_p99':distribution(lease)['p99'],'lease_p999':distribution(lease)['p999'],
      'execute_p99_existing_phase6':distribution(execute)['p99'],
      'start_p99':lat['phases']['start_job']['p99'],'complete_p99':lat['phases']['complete']['p99'],
      'recovery_calls':trace['timed_recovery_invocations'],
      'health_probe_count':sum(bool(r.get('health_probe_yes')) for r in target),
      'ordinary_target_count':len(target),
      'pool_total_size':official['pool']['total_pool_size_observed'],'pool_max_size':official['pool']['max_pool_size_observed'],
      'pool_wait_ms':sum(float(x.get('requests_wait_ms',0) or 0) for x in pool),
      'acquisition_failures':acq,'connection_storm_free':official['pool']['connection_storm_free'],
      'completed':official['completed'],'non_completed':official['non_completed'],'errors':official['errors'],
      'fencing_pass':bool(official['fencing_probe']['passed']),'invariants':official['state_invariants'],
      'active_leases_after':official['active_leases_after'],'official_passed':official['passed'],
      'trace_cycle_identity_match':trace['exact_cycle_multiset_matches_gate'],'trace_overflow':trace['overflow'],
    }
    return result


def correctness(summary: dict[str,Any]) -> bool:
    return (summary['completed']==JOBS and summary['non_completed']==0 and not summary['errors'] and summary['fencing_pass']
            and not any(summary['invariants'].values()) and summary['active_leases_after']==0
            and summary['acquisition_failures']==0 and summary['connection_storm_free']
            and summary['trace_cycle_identity_match'] and not summary['trace_overflow'])


def run_gate_off(dsn: str, root: Path, out: Path, *, name: str,
                 instance_meta: dict[str,Any], warm_index: int|None, expected_workers: int) -> dict[str,Any]:
    p6.verify(root)
    import psycopg
    from scripts import postgresql_32_worker_gate as gate
    from arenyxa.enterprise import runtime_storage as rs
    from arenyxa.enterprise.distributed import DurableDistributedQueue as Q
    p6.OSObserver=phase6_minimal.NoPolling
    rec=phase6_minimal.MinimalRecorder(gate,rs,Q,psycopg,True)
    # Capture worker_count from the gate's EXISTING post-timed health() call.
    # This wrapper performs no SQL and returns the production result unchanged.
    health_captures=[]
    original_health=Q.health
    def capture_health(self,*args,**kwargs):
        result=original_health(self,*args,**kwargs)
        cap=dict(result.get('capacity') or {})
        health_captures.append({'worker_count':int(cap.get('worker_count',-1)),
                                'total_worker_slots':int(cap.get('total_worker_slots',-1)),
                                'active_leases':int(cap.get('active_leases',-1))})
        return result
    Q.health=capture_health
    rec.install()
    try:
        official=gate.run_gate(dsn,workers=WORKERS,concurrency=CONCURRENCY,jobs=JOBS,p99_budget_ms=P99_BUDGET)
    finally:
        rec.restore();Q.health=original_health
    trace=rec.result();p6.verify(root)
    summary=compact_run(official,trace,name=name,instance_meta=instance_meta,warm_index=warm_index)
    if not health_captures:
        raise RuntimeError('existing gate health() call was not observed')
    summary['worker_registry_count']=health_captures[-1]['worker_count']
    summary['worker_total_slots']=health_captures[-1]['total_worker_slots']
    summary['health_active_leases']=health_captures[-1]['active_leases']
    summary['worker_registry_expected_count']=int(expected_workers)
    summary['worker_registry_count_matches_expected']=(summary['worker_registry_count']==int(expected_workers))
    geom=expected_pool_geometry()
    metrics=official['pool']['metrics']
    summary['pool_geometry_ok']=(official['workers']==WORKERS and official['concurrency']==CONCURRENCY and
        official['independent_clients']==CLIENTS and official['jobs']==JOBS and
        official['pool']['instances']==geom['instances'] and official['pool']['total_pool_size_observed']==geom['total_pool_size'] and
        all(int(m.get('pool_min',-1))==geom['pool_min'] and int(m.get('pool_max',-1))==geom['pool_max'] for m in metrics))
    write_gz(out/f'{name}.json.gz',{'official':official,'trace':trace,'summary':summary,'observer':'PHASE6_MINIMAL_OFF_ONLY'})
    if not summary['worker_registry_count_matches_expected']:
        raise RuntimeError(f"worker registry count mismatch: observed={summary['worker_registry_count']} expected={expected_workers}")
    if not summary['pool_geometry_ok']:
        raise RuntimeError('frozen pool geometry mismatch')
    if not correctness(summary):
        write_json(out/f'{name}-CORRECTNESS-FAIL.json',summary)
        raise RuntimeError('correctness hard gate failure: '+name)
    return summary


def run_snapshot_calibration(root: Path, out: Path, *, name: str, port: int,
                             enable_os: bool, enable_pg: bool) -> dict[str,Any]:
    inst_dir=out/name; inst_dir.mkdir(parents=True,exist_ok=True)
    container='p8r-'+name.replace('_','-')
    dsn,meta=start_container(container,port,inst_dir)
    try:
        first=run_gate_off(dsn,root,inst_dir,name='first-run-retained',instance_meta=meta,warm_index=None,expected_workers=expected_worker_registry_count(1))
        records=[];actions=[]
        for idx,mode in enumerate(CAL_PATTERN,1):
            action=None
            if mode=='ON':
                action=combined_snapshot(dsn=dsn,container_name=container,enable_os=enable_os,enable_pg=enable_pg)
            actions.append({'index':idx,'mode':mode,'snapshot':action})
            s=run_gate_off(dsn,root,inst_dir,name=f'probe-{idx:02d}-{mode.lower()}',instance_meta=meta,warm_index=None,expected_workers=expected_worker_registry_count(idx+1))
            s['mode']=mode;records.append(s)
        verdict=paired_boundary_calibration(records)
        verdict['snapshot_errors']=sum(1 for a in actions if a['snapshot'] and (
            (enable_pg and not (a['snapshot'].get('postgres') or {}).get('ok',False)) or
            (enable_os and 'error' in (a['snapshot'].get('host',{}).get('postgres_container') or {}))))
        if verdict['snapshot_errors']:
            verdict['accepted']=False
        payload={'name':name,'enable_os':enable_os,'enable_pg':enable_pg,'pattern':list(CAL_PATTERN),
                 'first_run':first,'runs':records,'actions':actions,'verdict':verdict}
        write_json(inst_dir/'calibration.json',payload)
        return payload
    finally:
        stop_container(container)


def select_snapshot_profile(root: Path, out: Path, *, port: int) -> dict[str,Any]:
    oscal=run_snapshot_calibration(root,out,name='cal_os_only',port=port,enable_os=True,enable_pg=False)
    if oscal['verdict']['accepted']:
        combined=run_snapshot_calibration(root,out,name='cal_os_pg',port=port,enable_os=True,enable_pg=True)
        if combined['verdict']['accepted']:
            sel={'enable_os':True,'enable_pg':True,'reason':'combined OS+PG boundary snapshot calibration accepted',
                 'os_calibration':oscal['verdict'],'final_calibration':combined['verdict']}
        else:
            sel={'enable_os':True,'enable_pg':False,'reason':'OS accepted; combined OS+PG rejected, so PG snapshots disabled',
                 'os_calibration':oscal['verdict'],'final_calibration':combined['verdict']}
    else:
        pgcal=run_snapshot_calibration(root,out,name='cal_pg_only',port=port,enable_os=False,enable_pg=True)
        if pgcal['verdict']['accepted']:
            sel={'enable_os':False,'enable_pg':True,'reason':'OS boundary snapshot rejected; PG-only accepted',
                 'os_calibration':oscal['verdict'],'final_calibration':pgcal['verdict']}
        else:
            sel={'enable_os':False,'enable_pg':False,'reason':'both available run-boundary snapshot profiles rejected; timing-only Phase8',
                 'os_calibration':oscal['verdict'],'final_calibration':pgcal['verdict']}
    write_json(out/'observer-selection.json',sel)
    return sel


def run_series(root: Path,out: Path,*,series_name: str,port: int,runs: int,
               snapshot_profile: dict[str,Any],pause_every: int=0,pause_seconds: float=0.0) -> dict[str,Any]:
    d=out/series_name; d.mkdir(parents=True,exist_ok=True)
    container='p8r-'+series_name.replace('_','-')
    dsn,meta=start_container(container,port,d)
    try:
        first=run_gate_off(dsn,root,d,name='first-run-retained',instance_meta=meta,warm_index=None,expected_workers=expected_worker_registry_count(1))
        enable_os=bool(snapshot_profile['enable_os']);enable_pg=bool(snapshot_profile['enable_pg'])
        current=combined_snapshot(dsn=dsn,container_name=container,enable_os=enable_os,enable_pg=enable_pg) if (enable_os or enable_pg) else None
        write_json(d/'boundary-initial.json',current)
        summaries=[];pauses=[]
        for i in range(1,runs+1):
            pre=current
            s=run_gate_off(dsn,root,d,name=f'warm-{i:03d}',instance_meta=meta,warm_index=i,expected_workers=expected_worker_registry_count(i+1))
            post=combined_snapshot(dsn=dsn,container_name=container,enable_os=enable_os,enable_pg=enable_pg) if (enable_os or enable_pg) else None
            s['pre_boundary_snapshot']=pre;s['post_boundary_snapshot']=post
            summaries.append(s);current=post
            write_json(d/'warm-summary-progress.json',{'series':series_name,'first_run':first,'runs':summaries,'pauses':pauses})
            if pause_every and i < runs and i % pause_every==0:
                p={'after_run':i,'pause_seconds':pause_seconds,'before_pause_snapshot':post,'pause_started_wall_ns':time.time_ns()}
                time.sleep(pause_seconds)
                p['pause_ended_wall_ns']=time.time_ns()
                current=combined_snapshot(dsn=dsn,container_name=container,enable_os=enable_os,enable_pg=enable_pg) if (enable_os or enable_pg) else None
                p['after_pause_snapshot']=current;pauses.append(p);write_json(d/f'pause-after-{i:03d}.json',p)
        payload={'series':series_name,'first_run':first,'runs':summaries,'pauses':pauses,
                 'snapshot_profile':{'enable_os':enable_os,'enable_pg':enable_pg},
                 'warm_run_count':len(summaries),'warm_failure_count':sum(s['p99']>P99_BUDGET for s in summaries),
                 'failure_runs':[s['warm_index'] for s in summaries if s['p99']>P99_BUDGET],
                 'source_hashes_final':p6.verify(root)}
        write_json(d/'series-summary.json',payload)
        return payload
    finally:
        stop_container(container)


def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--runs',type=int,default=WARM_RUNS)
    ap.add_argument('--replicas',type=int,default=3)
    ap.add_argument('--idle-replica',action='store_true')
    ap.add_argument('--pause-every',type=int,default=10)
    ap.add_argument('--pause-seconds',type=float,default=30.0)
    ap.add_argument('--port',type=int,default=55432)
    args=ap.parse_args(); args.out.mkdir(parents=True,exist_ok=True)
    assert_phase8r_worker_budget(warm_runs=args.runs)
    root=Path(os.environ.get('GITHUB_WORKSPACE',Path.cwd()))
    source_hashes=p6.verify(root)
    env={'python':'.'.join(map(str,sys.version_info[:3])),'source_hashes':source_hashes,
         'workers':WORKERS,'concurrency':CONCURRENCY,'jobs':JOBS,'clients':CLIENTS,'p99_budget_ms':P99_BUDGET,
         'postgres_image':PG_IMAGE,'new_hot_path_observer':False,'extra_sql_in_timed_window':False,
         'phase6_minimal_off_baseline_reused':True,'phase8r_admissible_horizon':True,'calibration_pattern':list(CAL_PATTERN),
         'runs_predeclared':args.runs,'replicas_predeclared':args.replicas,'idle_replica':args.idle_replica,
         'pause_every':args.pause_every,'pause_seconds':args.pause_seconds,
         'worker_budget':assert_phase8r_worker_budget(warm_runs=args.runs)}
    write_json(args.out/'environment.json',env)
    subprocess.run(['docker','pull',PG_IMAGE],check=True)
    profile=select_snapshot_profile(root,args.out,port=args.port)
    results=[]
    for i in range(1,args.replicas+1):
        results.append(run_series(root,args.out,series_name=f'continuous-{i:02d}',port=args.port,runs=args.runs,snapshot_profile=profile))
    if args.idle_replica:
        results.append(run_series(root,args.out,series_name='idle-pause',port=args.port,runs=args.runs,snapshot_profile=profile,
                                  pause_every=args.pause_every,pause_seconds=args.pause_seconds))
    write_json(args.out/'capture-verdict.json',{'status':'CAPTURE_COMPLETE','series':[r['series'] for r in results],
              'snapshot_profile':profile,'source_hashes_final':p6.verify(root)})
    return 0


if __name__=='__main__':
    raise SystemExit(main())
