from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path
import statistics

import phase6_minimal
import phase6_trace as p6
from phase7_lite_core import distribution
from phase7_lite_observer import BoundaryLiteRecorder


def is_target_row(row):
    sql = row.get('sql') or []
    lease_fast = sum(1 for x in sql if x[0] == 'lease_fast')
    fallback = any(x[0] == 'other_business' for x in sql)
    return bool(row.get('success')) and not row.get('recovery_yes') and lease_fast == 1 and not fallback


def trace_metrics(trace, lite_enabled):
    target = [r for r in trace['cycles'] if is_target_row(r)]
    lease = [r['lease_ms'] for r in target]
    execute = [r['ledger']['execute_ms'] for r in target]
    out = {
        'ordinary_target_count': len(target),
        'ordinary_lease': distribution(lease),
        'execute': distribution(execute),
        'health_probe_count': sum(bool(r.get('health_probe_yes')) for r in target),
        'lease_thread_cpu': distribution(r['thread_cpu_ms'] for r in target),
        'lease_thread_vcsw': distribution(r['thread_vcsw'] for r in target),
        'lease_thread_ivcsw': distribution(r['thread_ivcsw'] for r in target),
    }
    samples = {'lease': lease, 'execute': execute}
    if lite_enabled:
        calls = []
        missing = 0
        invalid = 0
        for r in target:
            c = r.get('phase7_lite_calls') or []
            if len(c) != 1 or 'summary' not in c[0]:
                missing += 1
                continue
            calls.append(c[0])
            if not c[0]['summary']['decomposition_valid']:
                invalid += 1
        summaries = [c['summary'] for c in calls if c['summary']['decomposition_valid']]
        errors = [abs(s['conservation_error_ms']) for s in summaries]
        out.update({
            'phase7_lite_call_count': len(calls),
            'phase7_lite_missing': missing,
            'phase7_lite_invalid': invalid,
            'max_abs_conservation_error_ms': max(errors) if errors else None,
            'pre_send': distribution(s['pre_send_ms'] for s in summaries if s['pre_send_ms'] is not None),
            'send_enqueue': distribution(s['send_enqueue_ms'] for s in summaries if s['send_enqueue_ms'] is not None),
            'send_begin_to_full_result': distribution(s['send_begin_to_full_result_ms'] for s in summaries if s['send_begin_to_full_result_ms'] is not None),
            'pre_result': distribution(s['pre_result_ms'] for s in summaries),
            'post_result': distribution(s['post_result_ms'] for s in summaries),
            'pre_result_share': distribution(s['pre_result_share'] for s in summaries),
            'post_result_share': distribution(s['post_result_share'] for s in summaries),
            'send_count': distribution(s['send_count'] for s in summaries),
            'prepared_query_only_count': sum(s['send_kinds'] == ['prepared_query'] for s in summaries),
            'prepare_plus_query_count': sum(s['send_kinds'] == ['prepare','prepared_query'] for s in summaries),
            'unprepared_query_count': sum(s['send_kinds'] == ['query'] for s in summaries),
        })
    return out, samples


def compact(official, trace, lite_enabled, name, mode):
    base = p6.compact(official, trace)
    tm, samples = trace_metrics(trace, lite_enabled)
    base.update({'name': name, 'mode': mode, 'trace_metrics': tm})
    return base, samples


def med_ratio(on, off, key):
    a = statistics.median(float(x[key]) for x in on)
    b = statistics.median(float(x[key]) for x in off)
    return a / b if b else None


def pooled_dist(records, sample_key):
    vals = []
    for x in records:
        vals.extend(x['_samples'].get(sample_key, []))
    return distribution(vals)


def calibration_verdict(records):
    off = [x for x in records if x['mode'] == 'OFF']
    on = [x for x in records if x['mode'] == 'ON']
    ratios = {k: med_ratio(on, off, k) for k in ('p50','p95','p99','throughput')}
    off_lease = pooled_dist(off, 'lease'); on_lease = pooled_dist(on, 'lease')
    off_exec = pooled_dist(off, 'execute'); on_exec = pooled_dist(on, 'execute')
    tail = {
        'ordinary_lease_p99_ratio': on_lease['p99'] / off_lease['p99'],
        'ordinary_lease_p999_ratio': on_lease['p999'] / off_lease['p999'],
        'execute_p99_ratio': on_exec['p99'] / off_exec['p99'],
        'execute_p999_ratio': on_exec['p999'] / off_exec['p999'],
    }
    recovery_delta = abs(statistics.mean(x['recovery_calls'] for x in on) - statistics.mean(x['recovery_calls'] for x in off))
    coverage_ok = all(x['trace_metrics'].get('phase7_lite_missing', 1) == 0 and x['trace_metrics'].get('phase7_lite_invalid', 1) == 0 for x in on)
    conservation_ok = all((x['trace_metrics'].get('max_abs_conservation_error_ms') or 0.0) <= 1e-5 for x in on)
    primary_gate = max(ratios[k] for k in ('p50','p95','p99')) <= 1.10 and ratios['throughput'] >= .95 and recovery_delta <= 6.
    tail_gate = all(0.80 <= v <= 1.20 for v in tail.values())
    off_order = [x for x in records if x['mode'] == 'OFF']
    on_order = [x for x in records if x['mode'] == 'ON']
    temporal = {
        'off2_over_off1_p99': off_order[1]['p99'] / off_order[0]['p99'],
        'off2_over_off1_throughput': off_order[1]['throughput'] / off_order[0]['throughput'],
        'on2_over_on1_p99': on_order[1]['p99'] / on_order[0]['p99'],
        'on2_over_on1_throughput': on_order[1]['throughput'] / on_order[0]['throughput'],
        'note': 'diagnostic temporal-regime evidence only; not used to relax observer gates',
    }
    return {
        'accepted': bool(primary_gate and tail_gate and coverage_ok and conservation_ok),
        'primary_ratios': ratios,
        'tail_ratios': tail,
        'recovery_calls_absolute_delta': recovery_delta,
        'coverage_ok': coverage_ok,
        'conservation_ok': conservation_ok,
        'temporal_order_evidence': temporal,
        'limits': {
            'latency_ratio_max': 1.10,
            'throughput_ratio_min': .95,
            'recovery_call_delta_max': 6,
            'tail_two_sided_ratio_range': [0.80, 1.20],
            'conservation_error_abs_ms_max': 1e-5,
        },
        'off_pooled': {'ordinary_lease': off_lease, 'execute': off_exec},
        'on_pooled': {'ordinary_lease': on_lease, 'execute': on_exec},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dsn', required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--runs', type=int, default=80)
    args = ap.parse_args(); args.out.mkdir(parents=True, exist_ok=True)
    root = Path(os.environ.get('GITHUB_WORKSPACE', Path.cwd()))
    p6.verify(root)

    import psycopg
    from scripts import postgresql_32_worker_gate as gate
    from arenyxa.enterprise import runtime_storage as rs
    from arenyxa.enterprise.distributed import DurableDistributedQueue as Q

    p6.OSObserver = phase6_minimal.NoPolling

    def save_json(name, payload):
        (args.out / (name + '.json')).write_text(json.dumps(payload, separators=(',', ':')), encoding='utf-8')

    def save_payload(name, payload):
        with gzip.open(args.out / (name + '.json.gz'), 'wt', encoding='utf-8', compresslevel=6) as f:
            json.dump(payload, f, separators=(',', ':'))

    env = {
        'python': '.'.join(map(str, __import__('sys').version_info[:3])),
        'psycopg': psycopg.__version__, 'pq_impl': getattr(psycopg.pq, '__impl__', None),
        'libpq_version': psycopg.pq.version(), 'phase7_zero_extra_sql': True,
        'observer': 'BOUNDARY_LITE', 'warm_runs_predeclared': args.runs,
        'source_hashes': p6.verify(root),
        'unobserved': ['T2_PQFLUSH_COMPLETE','T3_SOCKET_FIRST_READABLE','T4_PQCONSUMEINPUT_PROGRESS'],
    }
    save_json('phase7-lite-environment', env)
    print(json.dumps({'environment': env}, separators=(',', ':')), flush=True)

    first = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.)
    save_json('first-run-retained-not-attributed', first)
    if not p6.correct(first): raise RuntimeError('first run correctness failure')

    def run(name, mode):
        p6.verify(root)
        rec = phase6_minimal.MinimalRecorder(gate, rs, Q, psycopg, True) if mode == 'OFF' else BoundaryLiteRecorder(gate, rs, Q, psycopg, True)
        rec.install()
        try:
            official = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.)
        finally:
            rec.restore()
        trace = rec.result()
        save_payload(name, {'official': official, 'trace': trace, 'phase7_mode': mode, 'observer':'BOUNDARY_LITE'})
        p6.verify(root)
        if not p6.correct(official): raise RuntimeError('correctness failure: ' + name)
        if trace['overflow'] or not trace['exact_cycle_multiset_matches_gate']:
            raise RuntimeError('observer identity/count failure: ' + name)
        c, samples = compact(official, trace, mode == 'ON', name, mode); c['_samples'] = samples
        print(json.dumps({k:v for k,v in c.items() if k != '_samples'}, separators=(',', ':')), flush=True)
        return c

    cal = []
    for i, mode in enumerate(('OFF','ON','OFF','ON'), 1):
        cal.append(run(f'lite-cal-{i}-{mode.lower()}', mode))
    verdict = calibration_verdict(cal)
    save_json('lite-calibration', {'sequence':['OFF','ON','OFF','ON'], 'runs':[{k:v for k,v in x.items() if k!='_samples'} for x in cal], 'verdict':verdict})
    print(json.dumps({'calibration':'BOUNDARY_LITE', **verdict}, separators=(',', ':')), flush=True)
    if not verdict['accepted']:
        save_json('verdict', {'status':'INTRUSIVE_BOUNDARY_LITE','warm_runs':0,'calibration':verdict,'final_classification':'D — INCONCLUSIVE'})
        return 3

    summaries = []
    for i in range(1, args.runs + 1):
        c = run(f'warm-{i:03d}', 'ON'); c.pop('_samples', None); summaries.append(c)
        save_json('warm-summary-progress', {'runs': summaries})
    failures = [x for x in summaries if x['p99'] > 500.0]
    save_json('verdict', {
        'status':'CAPTURE_COMPLETE','warm_runs':len(summaries),'warm_failures':len(failures),
        'failure_run_names':[x['name'] for x in failures],
        'tail_reproduction':'SUFFICIENT_GENUINE_WARM_FAILURES' if len(failures)>=2 else 'INSUFFICIENT_TAIL_REPRODUCTION',
        'observer':'BOUNDARY_LITE','source_hashes_final':p6.verify(root),
    })
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
