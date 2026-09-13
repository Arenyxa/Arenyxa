from __future__ import annotations

import argparse
import csv
import gzip
import json
from pathlib import Path
import statistics

from phase7_lite_core import distribution, quantile_nearest


def correlation(xs, ys):
    pairs = [(float(x), float(y)) for x,y in zip(xs,ys) if x is not None and y is not None]
    if len(pairs) < 3: return None
    x,y = zip(*pairs)
    if statistics.pstdev(x) == 0 or statistics.pstdev(y) == 0: return None
    return statistics.correlation(x,y)


def one_lease_fast(row):
    sql = row.get('sql') or []
    return sum(1 for x in sql if x[0]=='lease_fast') == 1 and not any(x[0]=='other_business' for x in sql)


def flatten(run_no, run_p99, row):
    calls = row.get('phase7_lite_calls') or []
    if len(calls) != 1 or 'summary' not in calls[0]: return None
    call = calls[0]; s = call['summary']
    if not s.get('decomposition_valid'): return None
    task = row.get('task') or [None,None,None]; slot = task[0]
    cid = f"P7L-R{run_no:03d}-S{int(slot):03d}-A{int(row.get('attempt',0)):03d}" if slot is not None else f"P7L-R{run_no:03d}-T{row.get('tid')}-A{row.get('attempt')}"
    kinds = '+'.join(s.get('send_kinds') or [])
    return {
        'run':run_no,'run_p99_ms':run_p99,'run_gate':'FAIL' if run_p99>500 else 'PASS',
        'cycle_id':cid,'client_id':row.get('client_id'),'worker':row.get('worker'),'job_id':row.get('job_id'),
        'tid':row.get('tid'),'attempt':row.get('attempt'),'backend_pid':call.get('backend_pid'),
        'lease_ms':row.get('lease_ms'),'execute_ms':s.get('execute_ms'),'pre_send_ms':s.get('pre_send_ms'),
        'send_enqueue_ms':s.get('send_enqueue_ms'),'send_begin_to_full_result_ms':s.get('send_begin_to_full_result_ms'),
        'pre_result_ms':s.get('pre_result_ms'),'post_result_ms':s.get('post_result_ms'),
        'pre_result_share':s.get('pre_result_share'),'post_result_share':s.get('post_result_share'),
        'send_count':s.get('send_count'),'send_kinds':kinds,
        'strict_prepared_boundary': kinds in ('prepared_query','prepare+prepared_query'),
        'lease_thread_cpu_ms':row.get('thread_cpu_ms'),'lease_thread_vcsw':row.get('thread_vcsw'),'lease_thread_ivcsw':row.get('thread_ivcsw'),
        'health_probe_yes':bool(row.get('health_probe_yes')),'recovery_yes':bool(row.get('recovery_yes')),
        'conservation_error_ms':s.get('conservation_error_ms'),'anomaly_count':len(call.get('anomalies') or []),
    }


def dist(rows, field): return distribution(r[field] for r in rows if r.get(field) is not None)


def aggregate(rows):
    fields = ('lease_ms','execute_ms','pre_send_ms','send_enqueue_ms','send_begin_to_full_result_ms','pre_result_ms','post_result_ms','pre_result_share','post_result_share','lease_thread_cpu_ms','lease_thread_vcsw','lease_thread_ivcsw')
    execute_sum = sum(r['execute_ms'] for r in rows if r.get('execute_ms') is not None)
    pre_sum = sum(r['pre_result_ms'] for r in rows if r.get('pre_result_ms') is not None)
    post_sum = sum(r['post_result_ms'] for r in rows if r.get('post_result_ms') is not None)
    return {
        'n':len(rows),'metrics':{f:dist(rows,f) for f in fields},
        'sum_execute_ms':execute_sum,'sum_pre_result_ms':pre_sum,'sum_post_result_ms':post_sum,
        'aggregate_pre_result_share':pre_sum/execute_sum if execute_sum else None,
        'aggregate_post_result_share':post_sum/execute_sum if execute_sum else None,
        'health_probe_rate':sum(r['health_probe_yes'] for r in rows)/len(rows) if rows else None,
        'strict_prepared_rate':sum(r['strict_prepared_boundary'] for r in rows)/len(rows) if rows else None,
        'send_kind_counts':{k:sum(r['send_kinds']==k for r in rows) for k in sorted({r['send_kinds'] for r in rows})},
    }


def write_csv(path, rows):
    if not rows: path.write_text('', encoding='utf-8'); return
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--dir',type=Path,required=True); args=ap.parse_args(); d=args.dir
    vp=d/'verdict.json'
    if not vp.exists(): raise SystemExit('verdict.json missing')
    verdict=json.loads(vp.read_text())
    if verdict.get('status')!='CAPTURE_COMPLETE':
        (d/'PHASE7_LITE_ANALYSIS_STATUS.json').write_text(json.dumps({'status':'NOT_ANALYZED','capture_verdict':verdict},indent=2),encoding='utf-8'); return 0

    rows=[]; recovery=[]; runs=[]
    for path in sorted(d.glob('warm-*.json.gz')):
        run_no=int(path.name.split('-')[1].split('.')[0])
        with gzip.open(path,'rt',encoding='utf-8') as f: p=json.load(f)
        official=p['official']; trace=p['trace']; rp99=float(official['latency_ms']['p99'])
        runs.append({'run':run_no,'p50':official['latency_ms']['p50'],'p95':official['latency_ms']['p95'],'p99':rp99,'max':official['latency_ms']['max'],'throughput':official['throughput_jobs_per_second'],'lease_p99':official['latency_ms']['phases']['lease_next']['p99'],'start_p99':official['latency_ms']['phases']['start_job']['p99'],'complete_p99':official['latency_ms']['phases']['complete']['p99'],'gate':'FAIL' if rp99>500 else 'PASS'})
        for row in trace['cycles']:
            if not row.get('success') or not one_lease_fast(row): continue
            flat=flatten(run_no,rp99,row)
            if flat is None: continue
            (recovery if row.get('recovery_yes') else rows).append(flat)

    write_csv(d/'PHASE7_LITE_RUN_SUMMARY.csv',runs); write_csv(d/'PHASE7_LITE_ORDINARY_ALL.csv',rows); write_csv(d/'PHASE7_LITE_RECOVERY_CONTROL.csv',recovery)
    vals=[r['execute_ms'] for r in rows]; q50=quantile_nearest(vals,.5); q99=quantile_nearest(vals,.99); q999=quantile_nearest(vals,.999)
    groups={
        'FAST_P0_P50':[r for r in rows if r['execute_ms']<=q50],
        'MID_P50_P99':[r for r in rows if q50<r['execute_ms']<=q99],
        'TOP1':[r for r in rows if r['execute_ms']>q99],
        'TOP0.1':[r for r in rows if r['execute_ms']>q999],
    }
    top100=sorted(rows,key=lambda r:r['execute_ms'],reverse=True)[:100]; fast100=sorted(rows,key=lambda r:r['execute_ms'])[:100]
    write_csv(d/'PHASE7_LITE_TOP100_SLOW_EXECUTES.csv',top100); write_csv(d/'PHASE7_LITE_FASTEST100_CONTROLS.csv',fast100)
    write_csv(d/'PHASE7_LITE_TOP1.csv',sorted(groups['TOP1'],key=lambda r:r['execute_ms'],reverse=True)); write_csv(d/'PHASE7_LITE_TOP0_1.csv',sorted(groups['TOP0.1'],key=lambda r:r['execute_ms'],reverse=True))

    fail=[r for r in rows if r['run_gate']=='FAIL']; passed=[r for r in rows if r['run_gate']=='PASS']
    fail_top=[r for r in groups['TOP1'] if r['run_gate']=='FAIL']; pass_top=[r for r in groups['TOP1'] if r['run_gate']=='PASS']
    hp=[r for r in rows if r['health_probe_yes']]; nohp=[r for r in rows if not r['health_probe_yes']]
    strict=[r for r in rows if r['strict_prepared_boundary']]
    controls={
        'FAST_vs_TOP1':{'FAST':aggregate(groups['FAST_P0_P50']),'TOP1':aggregate(groups['TOP1'])},
        'PASS_vs_FAIL_all':{'PASS':aggregate(passed),'FAIL':aggregate(fail)},
        'PASS_vs_FAIL_TOP1':{'PASS_TOP1':aggregate(pass_top),'FAIL_TOP1':aggregate(fail_top)},
        'health_probe_vs_no_probe':{'probe':aggregate(hp),'no_probe':aggregate(nohp)},
        'ordinary_vs_recovery':{'ordinary':aggregate(rows),'recovery':aggregate(recovery)},
        'strict_prepared_subset':aggregate(strict),
    }
    (d/'PHASE7_LITE_COUNTERFACTUALS.json').write_text(json.dumps(controls,indent=2),encoding='utf-8')

    corr_fields=('pre_result_ms','post_result_ms','pre_send_ms','send_enqueue_ms','lease_thread_cpu_ms','lease_thread_vcsw','lease_thread_ivcsw')
    correlations={f:correlation([r['execute_ms'] for r in rows],[r.get(f) for r in rows]) for f in corr_fields}
    errors=[abs(r['conservation_error_ms']) for r in rows]
    top1agg=aggregate(groups['TOP1']); top01agg=aggregate(groups['TOP0.1'])
    if verdict.get('tail_reproduction')!='SUFFICIENT_GENUINE_WARM_FAILURES': candidate='D — INCONCLUSIVE (INSUFFICIENT TAIL REPRODUCTION)'
    elif top1agg['aggregate_pre_result_share'] is not None and top1agg['aggregate_pre_result_share']>=.90 and top1agg['aggregate_post_result_share']<=.10: candidate='A — PRE-RESULT DOMINANT CANDIDATE'
    elif top1agg['aggregate_post_result_share'] is not None and top1agg['aggregate_post_result_share']>=.90: candidate='B — POST-RESULT DOMINANT CANDIDATE'
    else: candidate='C — MIXED CANDIDATE'
    summary={
        'capture_verdict':verdict,'ordinary_n':len(rows),'recovery_control_n':len(recovery),'strict_prepared_n':len(strict),
        'failure_runs':[r['run'] for r in runs if r['gate']=='FAIL'],'execute_thresholds_ms':{'q50':q50,'q99':q99,'q999':q999},
        'groups':{k:aggregate(v) for k,v in groups.items()},'top100':aggregate(top100),'fastest100':aggregate(fast100),
        'strict_prepared':aggregate(strict),'correlations_execute_vs_component':correlations,
        'max_abs_conservation_error_ms':max(errors) if errors else None,
        't2':'NOT DIRECTLY OBSERVABLE','t3':'NOT DIRECTLY OBSERVABLE','t4':'NOT DIRECTLY OBSERVABLE',
        'mechanical_initial_candidate_before_adversarial_review':candidate,
        'top1_aggregate_pre_result_share':top1agg['aggregate_pre_result_share'],'top1_aggregate_post_result_share':top1agg['aggregate_post_result_share'],
        'top0_1_aggregate_pre_result_share':top01agg['aggregate_pre_result_share'],'top0_1_aggregate_post_result_share':top01agg['aggregate_post_result_share'],
    }
    (d/'PHASE7_LITE_NUMERIC_SUMMARY.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    (d/'PHASE7_LITE_ANALYSIS_STATUS.json').write_text(json.dumps({'status':'ANALYZED','summary':'PHASE7_LITE_NUMERIC_SUMMARY.json'},indent=2),encoding='utf-8')
    print(json.dumps({'analysis':'complete','ordinary':len(rows),'fail_runs':summary['failure_runs'],'candidate':candidate},separators=(',',':')))
    return 0

if __name__=='__main__': raise SystemExit(main())
