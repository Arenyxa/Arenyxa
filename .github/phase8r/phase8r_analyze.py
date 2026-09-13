from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path
import statistics
from typing import Any

from phase8_core import best_l1_change_point, classify_replication_axis, rolling_robust
from phase8r_core import WARM_RUNS, EXPECTED_FINAL_WORKERS


def load(path: Path): return json.loads(path.read_text(encoding='utf-8'))
def num(v):
    if v is None: return None
    try:return float(v)
    except (TypeError,ValueError):return None

def delta(a,b):
    x=num(a);y=num(b)
    if x is None or y is None or y < x:return None
    return y-x

def med(xs):
    v=[float(x) for x in xs if x is not None and math.isfinite(float(x))]
    return statistics.median(v) if v else None

def mad(xs):
    v=[float(x) for x in xs if x is not None and math.isfinite(float(x))]
    if not v:return None
    m=statistics.median(v);return statistics.median(abs(x-m) for x in v)


def cpu_delta(pre,post):
    a=((pre or {}).get('host') or {}).get('proc_stat',{}).get('cpu',{})
    b=((post or {}).get('host') or {}).get('proc_stat',{}).get('cpu',{})
    keys=('user','nice','system','idle','iowait','irq','softirq','steal')
    ds={k:delta(a.get(k),b.get(k)) for k in keys}
    if any(v is None for v in ds.values()):return {}
    total=sum(ds.values())
    if total<=0:return {}
    busy=ds['user']+ds['nice']+ds['system']+ds['irq']+ds['softirq']+ds['steal']
    return {'host_cpu_busy_pct':100*busy/total,'host_cpu_steal_pct':100*ds['steal']/total,
            'host_cpu_iowait_pct':100*ds['iowait']/total,'host_cpu_total_jiffies':total}


def dict_delta(pre: dict[str,Any],post: dict[str,Any],keys, prefix):
    out={}
    for k in keys:
        v=delta(pre.get(k),post.get(k))
        if v is not None:out[prefix+k]=v
    return out


def table_aggregate(snap):
    pg=(snap or {}).get('postgres') or {}
    tabs=pg.get('tables') or []
    idx=pg.get('indexes') or []
    return {
      'table_total_bytes':sum(num(x.get('total_bytes')) or 0 for x in tabs),
      'table_heap_bytes':sum(num(x.get('heap_bytes')) or 0 for x in tabs),
      'n_live_tup':sum(num(x.get('n_live_tup')) or 0 for x in tabs),
      'n_dead_tup':sum(num(x.get('n_dead_tup')) or 0 for x in tabs),
      'autovacuum_count':sum(num(x.get('autovacuum_count')) or 0 for x in tabs),
      'autoanalyze_count':sum(num(x.get('autoanalyze_count')) or 0 for x in tabs),
      'vacuum_count':sum(num(x.get('vacuum_count')) or 0 for x in tabs),
      'analyze_count':sum(num(x.get('analyze_count')) or 0 for x in tabs),
      'index_bytes':sum(num(x.get('index_bytes')) or 0 for x in idx),
      'idx_scan':sum(num(x.get('idx_scan')) or 0 for x in idx),
    }


def run_features(run: dict[str,Any]) -> dict[str,float]:
    pre=run.get('pre_boundary_snapshot');post=run.get('post_boundary_snapshot')
    out={}
    if pre and post:
        out.update(cpu_delta(pre,post))
        hp=((pre.get('host') or {}).get('proc_stat') or {});hq=((post.get('host') or {}).get('proc_stat') or {})
        for k in ('ctxt','processes'):
            v=delta(hp.get(k),hq.get(k))
            if v is not None:out['host_'+k+'_delta']=v
        for point,label in ((pre,'pre'),(post,'post')):
            h=(point.get('host') or {})
            la=h.get('loadavg') or {};ps=h.get('proc_stat') or {};mi=h.get('meminfo_kb') or {}
            for k in ('load1','load5','runnable'):
                v=num(la.get(k));
                if v is not None:out[f'host_{label}_{k}']=v
            for k in ('procs_running','procs_blocked'):
                v=num(ps.get(k));
                if v is not None:out[f'host_{label}_{k}']=v
            for k in ('MemAvailable','Dirty','Writeback'):
                v=num(mi.get(k));
                if v is not None:out[f'host_{label}_{k}_kb']=v
        prepy=((pre.get('host') or {}).get('python_process') or {}); postpy=((post.get('host') or {}).get('python_process') or {})
        for k in ('cpu_user_s','cpu_system_s','vcsw','ivcsw','read_bytes','write_bytes'):
            v=delta(prepy.get(k),postpy.get(k))
            if v is not None:out['python_'+k+'_delta']=v
        for k in ('rss','threads'):
            v=num(postpy.get(k));
            if v is not None:out['python_post_'+k]=v
        prec=((pre.get('host') or {}).get('postgres_container') or {}); postc=((post.get('host') or {}).get('postgres_container') or {})
        out.update(dict_delta(prec.get('cpu_stat') or {},postc.get('cpu_stat') or {},('usage_usec','user_usec','system_usec','nr_periods','nr_throttled','throttled_usec'),'pg_cgroup_'))
        for k in ('memory_current','memory_peak'):
            v=num(postc.get(k));
            if v is not None:out['pg_cgroup_post_'+k]=v
        out.update(dict_delta(prec.get('memory_stat') or {},postc.get('memory_stat') or {},('pgfault','pgmajfault'),'pg_cgroup_'))
        out.update(dict_delta(prec.get('io_stat') or {},postc.get('io_stat') or {},('rbytes','wbytes','rios','wios'),'pg_cgroup_'))

        pred=(pre.get('postgres') or {}).get('database') or {}; postd=(post.get('postgres') or {}).get('database') or {}
        out.update(dict_delta(pred,postd,('xact_commit','xact_rollback','blks_read','blks_hit','tup_returned','tup_fetched','tup_inserted','tup_updated','tup_deleted','conflicts','temp_files','temp_bytes','deadlocks','blk_read_time','blk_write_time','session_time','active_time','idle_in_transaction_time','sessions','sessions_abandoned','sessions_fatal','sessions_killed'),'db_'))
        prew=(pre.get('postgres') or {}).get('wal') or {};postw=(post.get('postgres') or {}).get('wal') or {}
        out.update(dict_delta(prew,postw,('wal_records','wal_fpi','wal_bytes','wal_buffers_full','wal_write','wal_sync','wal_write_time','wal_sync_time'),'wal_'))
        preb=(pre.get('postgres') or {}).get('bgwriter') or {};postb=(post.get('postgres') or {}).get('bgwriter') or {}
        out.update(dict_delta(preb,postb,('checkpoints_timed','checkpoints_req','checkpoint_write_time','checkpoint_sync_time','buffers_checkpoint','buffers_clean','maxwritten_clean','buffers_backend','buffers_backend_fsync','buffers_alloc'),'bg_'))
        ta=table_aggregate(pre);tb=table_aggregate(post)
        for k in ('n_live_tup','n_dead_tup','autovacuum_count','autoanalyze_count','vacuum_count','analyze_count','idx_scan'):
            v=delta(ta.get(k),tb.get(k))
            if v is not None:out['tables_'+k+'_delta']=v
        for k in ('table_total_bytes','table_heap_bytes','index_bytes','n_live_tup','n_dead_tup'):
            v=num(tb.get(k));
            if v is not None:out['tables_post_'+k]=v
        for k in ('snapshot_duration_ms',):
            v=num(post.get(k));
            if v is not None:out['boundary_post_'+k]=v
    return out


def rank(vals):
    order=sorted(range(len(vals)),key=lambda i:vals[i]);r=[0.0]*len(vals);i=0
    while i<len(order):
        j=i+1
        while j<len(order) and vals[order[j]]==vals[order[i]]:j+=1
        avg=(i+j-1)/2+1
        for k in range(i,j):r[order[k]]=avg
        i=j
    return r

def pearson(x,y):
    if len(x)<3:return None
    mx=statistics.fmean(x);my=statistics.fmean(y)
    dx=[a-mx for a in x];dy=[b-my for b in y]
    den=(sum(a*a for a in dx)*sum(b*b for b in dy))**.5
    return sum(a*b for a,b in zip(dx,dy))/den if den else None

def spearman(x,y):return pearson(rank(x),rank(y)) if len(x)==len(y) else None


def feature_effects(rows, split_index):
    feats=[r['_features'] for r in rows]
    names=sorted({k for f in feats for k in f})
    out=[]
    for n in names:
        a=[f.get(n) for f in feats[:split_index] if f.get(n) is not None]
        b=[f.get(n) for f in feats[split_index:] if f.get(n) is not None]
        if len(a)<3 or len(b)<3:continue
        am=med(a);bm=med(b);scale=mad(a+b) or 0.0
        effect=(bm-am)/(scale+1e-12)
        ratio=bm/am if am not in (None,0) else None
        pairs=[(float(r['p99']),float(r['_features'][n])) for r in rows if n in r['_features']]
        rho=spearman([x for x,_ in pairs],[y for _,y in pairs]) if len(pairs)>=3 else None
        out.append({'feature':n,'pre_median':am,'post_median':bm,'post_over_pre':ratio,'robust_effect_mad':effect,'spearman_vs_p99':rho,'n_pre':len(a),'n_post':len(b)})
    return sorted(out,key=lambda x:abs(x['robust_effect_mad']),reverse=True)


def analyze_series(path: Path):
    p=load(path/'series-summary.json');rows=p['runs']
    for r in rows:r['_features']=run_features(r)
    p99=[r['p99'] for r in rows]
    primary=best_l1_change_point(p99,min_segment=8,permutations=1000,seed=20260913)
    metrics={}
    for key in ('p99','p999','throughput','lease_p99','start_p99','complete_p99'):
        metrics[key]=best_l1_change_point([r[key] for r in rows],min_segment=8,permutations=300,seed=20260913+len(key))
    roll=rolling_robust(p99,window=5)
    effects=feature_effects(rows,primary['split_index']) if primary.get('split_index') else []
    tr=None
    if primary.get('meaningful'):
        k=primary['split_index'];first_post=rows[k]
        tr={'transition_run':int(first_post['warm_index']),'transition_elapsed_s':first_post['elapsed_since_postmaster_start_s'],
            'transition_cumulative_jobs':int(first_post['warm_index'])*1024,'direction':primary['direction']}
    return {'series':p['series'],'first_run':p['first_run'],'warm_failure_count':p['warm_failure_count'],'failure_runs':p['failure_runs'],
            'primary_p99_change_point':primary,'metric_change_points':metrics,'rolling_p99':roll,
            'feature_effects_at_p99_split':effects,'transition':tr,
            'snapshot_profile':p['snapshot_profile'],'runs':rows,'pauses':p.get('pauses') or []}


def write_run_csv(path, analyses):
    rows=[]
    for a in analyses:
        for r in a['runs']:
            row={k:v for k,v in r.items() if not k.startswith('_') and not isinstance(v,(dict,list))}
            row['series']=a['series'];row.update(r['_features']);rows.append(row)
    if not rows:return
    fields=sorted({k for r in rows for k in r})
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dir',type=Path,required=True);args=ap.parse_args();d=args.dir
    series_dirs=sorted(p.parent for p in d.glob('*/series-summary.json'))
    analyses=[analyze_series(p) for p in series_dirs]
    incomplete=[a['series'] for a in analyses if len(a['runs'])!=WARM_RUNS]
    registry_bad=[]
    for a in analyses:
        if len(a['runs'])==WARM_RUNS:
            last=a['runs'][-1]
            if int(last.get('worker_registry_count',-1))!=EXPECTED_FINAL_WORKERS:
                registry_bad.append({'series':a['series'],'observed':last.get('worker_registry_count')})
    continuous=[a for a in analyses if a['series'].startswith('continuous-')]
    valid_cont=[a for a in continuous if len(a['runs'])==WARM_RUNS and a['primary_p99_change_point'].get('meaningful')]
    directions={str(a['primary_p99_change_point'].get('direction')) for a in valid_cont}
    reproduced=(len(valid_cont)>=2 and len(directions)==1)
    reps=[a['transition'] for a in valid_cont if a.get('transition')]
    axis=classify_replication_axis(reps) if reps else {'most_stable_axis':None}
    idle=next((a for a in analyses if a['series']=='idle-pause'),None)
    idle_complete=bool(idle and len(idle['runs'])==WARM_RUNS)
    if incomplete or registry_bad:
        initial='E_INCONCLUSIVE_INCOMPLETE_PROTOCOL'
    elif not reproduced:
        initial='E_NO_REPRODUCIBLE_REGIME'
    else:
        stable=axis.get('most_stable_axis')
        if stable in ('run_index','cumulative_jobs'):
            initial='A_REPRODUCIBLE_DB_WORKLOAD_STATE_REGIME'
        elif stable=='elapsed_time':
            initial='C_REPRODUCIBLE_TIME_STATE_REGIME'
        else:
            initial='D_REPRODUCIBLE_REGIME_AXIS_UNRESOLVED'
    summary={'series_count':len(analyses),'continuous_count':len(continuous),'incomplete_series':incomplete,
             'worker_registry_mismatches':registry_bad,'valid_continuous_change_points':len(valid_cont),
             'valid_continuous_directions':sorted(directions),'reproducible_same_host_regime':reproduced,
             'replication_axis':axis,'idle_complete':idle_complete,
             'idle_transition':None if idle is None else idle.get('transition'),
             'observer_selection':load(d/'observer-selection.json') if (d/'observer-selection.json').exists() else None,
             'series':[ {k:v for k,v in a.items() if k not in ('runs','rolling_p99','feature_effects_at_p99_split')} for a in analyses],
             'initial_phase8r_verdict':initial}
    (d/'PHASE8R_NUMERIC_SUMMARY.json').write_text(json.dumps(summary,indent=2,sort_keys=True),encoding='utf-8')
    for a in analyses:
        slim={k:v for k,v in a.items() if k!='runs'}
        (d/f"PHASE8R_{a['series']}_ANALYSIS.json").write_text(json.dumps(slim,indent=2,sort_keys=True),encoding='utf-8')
    write_run_csv(d/'PHASE8R_ALL_RUNS_FEATURES.csv',analyses)
    print(json.dumps({'analysis':'complete','series':len(analyses),'initial':initial,'reproduced':reproduced,'axis':axis.get('most_stable_axis')},separators=(',',':')))
    return 0

if __name__=='__main__':raise SystemExit(main())
