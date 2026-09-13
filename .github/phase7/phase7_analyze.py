from __future__ import annotations

import argparse
import csv
import gzip
import json
from pathlib import Path
import statistics

from phase7_core import distribution, quantile_nearest


def correlation(xs, ys):
    pairs = [(float(x), float(y)) for x, y in zip(xs, ys) if x is not None and y is not None]
    if len(pairs) < 3:
        return None
    x, y = zip(*pairs)
    if statistics.pstdev(x) == 0 or statistics.pstdev(y) == 0:
        return None
    return statistics.correlation(x, y)


def one_lease_fast(row):
    sql = row.get('sql') or []
    return sum(1 for x in sql if x[0] == 'lease_fast') == 1 and not any(x[0] == 'other_business' for x in sql)


def flatten_call(run_no, run_p99, row):
    calls = row.get('phase7_calls') or []
    if len(calls) != 1:
        return None
    call = calls[0]; s = call['summary']
    task = row.get('task') or [None, None, None]
    slot = task[0]
    cycle_id = f"P7-R{run_no:03d}-S{int(slot):03d}-A{int(row.get('attempt', 0)):03d}" if slot is not None else f"P7-R{run_no:03d}-T{row.get('tid')}-A{row.get('attempt')}"
    waits = [w for seg in call.get('segments', []) for w in seg.get('waits', [])]
    wait_wall_ms = sum((w['ready_at'] - w['wait_begin']) * 1000.0 for w in waits)
    progress_wall_ms = sum((w['driver_progress_end'] - w['ready_at']) * 1000.0 for w in waits)
    send_total = None
    if s.get('enqueue_ms') is not None and s.get('flush_ms') is not None:
        send_total = s['enqueue_ms'] + s['flush_ms']
    sched_cpu = s.get('sched_cpu_ms')
    rq = s.get('runqueue_wait_ms')
    blocked_other = None
    if sched_cpu is not None and rq is not None:
        blocked_other = s['execute_ms'] - sched_cpu - rq
    return {
        'run': run_no,
        'run_p99_ms': run_p99,
        'run_gate': 'FAIL' if run_p99 > 500.0 else 'PASS',
        'cycle_id': cycle_id,
        'client_id': row.get('client_id'),
        'worker': row.get('worker'),
        'job_id': row.get('job_id'),
        'tid': row.get('tid'),
        'attempt': row.get('attempt'),
        'backend_pid': call.get('backend_pid'),
        'lease_ms': row.get('lease_ms'),
        'execute_ms': s.get('execute_ms'),
        'send_total_ms': send_total,
        'pre_send_ms': s.get('pre_send_ms'),
        'enqueue_ms': s.get('enqueue_ms'),
        'flush_ms': s.get('flush_ms'),
        'time_to_first_readable_ms': s.get('time_to_first_readable_ms'),
        'flush_to_full_result_ms': s.get('response_to_full_ms'),
        'first_readable_to_full_result_ms': s.get('post_first_readable_to_full_ms'),
        'full_result_to_return_ms': s.get('post_full_result_ms'),
        'thread_cpu_ms': s.get('thread_cpu_ms'),
        'sched_cpu_ms': sched_cpu,
        'runqueue_wait_ms': rq,
        'blocked_or_sleeping_other_ms': blocked_other,
        'thread_vcsw': s.get('thread_vcsw'),
        'thread_ivcsw': s.get('thread_ivcsw'),
        'sched_timeslices': s.get('sched_timeslices'),
        'wait_wall_ms': wait_wall_ms,
        'post_ready_driver_progress_wall_ms': progress_wall_ms,
        'wait_count': len(waits),
        'health_probe_yes': bool(row.get('health_probe_yes')),
        'recovery_yes': bool(row.get('recovery_yes')),
        'segment_count': s.get('segment_count'),
        'segment_kinds': '+'.join(str(x) for x in s.get('segment_kinds', [])),
        'first_readable_relation': s.get('first_readable_relation'),
        'ledger_error_ms': s.get('ledger_error_ms'),
        'anomaly_count': len(call.get('anomalies') or []),
    }


def dist_fields(rows, field):
    return distribution(r[field] for r in rows if r.get(field) is not None)


def group_summary(rows):
    fields = (
        'lease_ms','execute_ms','pre_send_ms','send_total_ms','enqueue_ms','flush_ms',
        'time_to_first_readable_ms','flush_to_full_result_ms','first_readable_to_full_result_ms',
        'full_result_to_return_ms','thread_cpu_ms','sched_cpu_ms','runqueue_wait_ms',
        'blocked_or_sleeping_other_ms','wait_wall_ms','post_ready_driver_progress_wall_ms',
        'thread_vcsw','thread_ivcsw','sched_timeslices',
    )
    return {
        'n': len(rows),
        'metrics': {f: dist_fields(rows, f) for f in fields},
        'health_probe_rate': sum(r['health_probe_yes'] for r in rows) / len(rows) if rows else None,
        'recovery_rate': sum(r['recovery_yes'] for r in rows) / len(rows) if rows else None,
        'readable_observed_rate': sum(r['time_to_first_readable_ms'] is not None for r in rows) / len(rows) if rows else None,
        'readable_before_flush_rate': sum(r['first_readable_relation'] == 'BEFORE_FLUSH_COMPLETE' for r in rows) / len(rows) if rows else None,
        'segment_kind_counts': {k: sum(r['segment_kinds'] == k for r in rows) for k in sorted({r['segment_kinds'] for r in rows})},
    }


def write_csv(path, rows):
    if not rows:
        path.write_text('')
        return
    with path.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--dir', type=Path, required=True); args = ap.parse_args()
    d = args.dir
    verdict_path = d / 'verdict.json'
    if not verdict_path.exists():
        raise SystemExit('verdict.json missing')
    verdict = json.loads(verdict_path.read_text())
    if verdict.get('status') != 'CAPTURE_COMPLETE':
        (d/'PHASE7_ANALYSIS_STATUS.json').write_text(json.dumps({'status':'NOT_ANALYZED','capture_verdict':verdict}, indent=2))
        return 0

    all_rows = []
    recovery_rows = []
    run_summaries = []
    for path in sorted(d.glob('warm-*.json.gz')):
        run_no = int(path.name.split('-')[1].split('.')[0])
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            p = json.load(f)
        official = p['official']; trace = p['trace']; rp99 = float(official['latency_ms']['p99'])
        run_summaries.append({
            'run':run_no, 'p50':official['latency_ms']['p50'], 'p95':official['latency_ms']['p95'],
            'p99':rp99, 'max':official['latency_ms']['max'], 'throughput':official['throughput_jobs_per_second'],
            'lease_p99':official['latency_ms']['phases']['lease_next']['p99'],
            'start_p99':official['latency_ms']['phases']['start_job']['p99'],
            'complete_p99':official['latency_ms']['phases']['complete']['p99'],
            'gate':'FAIL' if rp99 > 500.0 else 'PASS',
        })
        for row in trace['cycles']:
            if not row.get('success') or not one_lease_fast(row):
                continue
            flat = flatten_call(run_no, rp99, row)
            if flat is None:
                continue
            if row.get('recovery_yes'):
                recovery_rows.append(flat)
            else:
                all_rows.append(flat)

    write_csv(d/'PHASE7_RUN_SUMMARY.csv', run_summaries)
    write_csv(d/'PHASE7_ORDINARY_ALL.csv', all_rows)
    write_csv(d/'PHASE7_RECOVERY_CONTROL.csv', recovery_rows)

    single = [r for r in all_rows if r['segment_count'] == 1 and r['ledger_error_ms'] is not None and r['anomaly_count'] == 0]
    execute_vals = [r['execute_ms'] for r in single]
    q50 = quantile_nearest(execute_vals, .5); q99 = quantile_nearest(execute_vals, .99); q999 = quantile_nearest(execute_vals, .999)
    groups = {
        'FAST_P0_P50': [r for r in single if r['execute_ms'] <= q50],
        'MID_P50_P99': [r for r in single if q50 < r['execute_ms'] <= q99],
        'TOP1': [r for r in single if r['execute_ms'] > q99],
        'TOP0.1': [r for r in single if r['execute_ms'] > q999],
    }
    for name, rows in groups.items():
        for r in rows:
            r['analysis_group'] = name
    write_csv(d/'PHASE7_TOP1.csv', sorted(groups['TOP1'], key=lambda r:r['execute_ms'], reverse=True))
    write_csv(d/'PHASE7_TOP0_1.csv', sorted(groups['TOP0.1'], key=lambda r:r['execute_ms'], reverse=True))
    top100 = sorted(single, key=lambda r:r['execute_ms'], reverse=True)[:100]
    fastest100 = sorted(single, key=lambda r:r['execute_ms'])[:100]
    write_csv(d/'PHASE7_TOP100_SLOW_EXECUTES.csv', top100)
    write_csv(d/'PHASE7_FASTEST100_CONTROLS.csv', fastest100)

    fail_rows = [r for r in single if r['run_gate']=='FAIL']
    pass_rows = [r for r in single if r['run_gate']=='PASS']
    fail_top = [r for r in groups['TOP1'] if r['run_gate']=='FAIL']
    pass_top = [r for r in groups['TOP1'] if r['run_gate']=='PASS']
    health_yes = [r for r in single if r['health_probe_yes']]
    health_no = [r for r in single if not r['health_probe_yes']]

    controls = {
        'FAST_vs_TOP1': {'FAST': group_summary(groups['FAST_P0_P50']), 'TOP1': group_summary(groups['TOP1'])},
        'PASS_vs_FAIL_all_ordinary': {'PASS': group_summary(pass_rows), 'FAIL': group_summary(fail_rows)},
        'PASS_vs_FAIL_TOP1': {'PASS_TOP1': group_summary(pass_top), 'FAIL_TOP1': group_summary(fail_top)},
        'health_probe_vs_no_probe': {'probe': group_summary(health_yes), 'no_probe': group_summary(health_no)},
        'ordinary_vs_recovery_control': {'ordinary': group_summary(single), 'recovery': group_summary(recovery_rows)},
    }
    (d/'PHASE7_COUNTERFACTUALS.json').write_text(json.dumps(controls, indent=2), encoding='utf-8')

    corr_fields = (
        'send_total_ms','time_to_first_readable_ms','flush_to_full_result_ms','full_result_to_return_ms',
        'thread_cpu_ms','sched_cpu_ms','runqueue_wait_ms','wait_wall_ms','thread_vcsw','thread_ivcsw',
    )
    correlations = {f: correlation([r['execute_ms'] for r in single], [r.get(f) for r in single]) for f in corr_fields}

    ledger_errors = [abs(r['ledger_error_ms']) for r in single]
    summary = {
        'capture_verdict': verdict,
        'ordinary_exactly_one_lease_fast_no_fallback_n': len(all_rows),
        'ordinary_single_protocol_segment_n': len(single),
        'ordinary_multi_or_anomalous_n': len(all_rows)-len(single),
        'recovery_control_n': len(recovery_rows),
        'run_failures': [r['run'] for r in run_summaries if r['gate']=='FAIL'],
        'execute_group_thresholds_ms': {'q50':q50,'q99':q99,'q999':q999},
        'groups': {k:group_summary(v) for k,v in groups.items()},
        'top100': group_summary(top100),
        'fastest100': group_summary(fastest100),
        'max_abs_conservation_error_ms': max(ledger_errors) if ledger_errors else None,
        'correlations_execute_vs_component': correlations,
        'first_readable_not_observed_n': sum(r['time_to_first_readable_ms'] is None for r in single),
        'first_readable_before_flush_n': sum(r['first_readable_relation']=='BEFORE_FLUSH_COMPLETE' for r in single),
        'schedstat_available_n': sum(r['runqueue_wait_ms'] is not None for r in single),
        't4_directly_observed': False,
    }
    (d/'PHASE7_NUMERIC_SUMMARY.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (d/'PHASE7_ANALYSIS_STATUS.json').write_text(json.dumps({'status':'ANALYZED','summary':'PHASE7_NUMERIC_SUMMARY.json'}, indent=2))
    print(json.dumps({'analysis':'complete','ordinary':len(all_rows),'single':len(single),'fail_runs':summary['run_failures']}, separators=(',',':')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
