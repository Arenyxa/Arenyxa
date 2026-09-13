from __future__ import annotations

import argparse
import gzip
import json
import os
from pathlib import Path
import statistics

import phase6_minimal
import phase6_trace as p6
from phase7_core import distribution
from phase7_observer import Phase7Recorder


def is_target_row(row):
    sql = row.get('sql') or []
    lease_fast = sum(1 for x in sql if x[0] == 'lease_fast')
    fallback = any(x[0] == 'other_business' for x in sql)
    return bool(row.get('success')) and not row.get('recovery_yes') and lease_fast == 1 and not fallback


def trace_metrics(trace, phase7_enabled):
    target = [r for r in trace['cycles'] if is_target_row(r)]
    lease = [r['lease_ms'] for r in target]
    execute = [r['ledger']['execute_ms'] for r in target]
    out = {
        'ordinary_target_count': len(target),
        'ordinary_lease': distribution(lease),
        'execute': distribution(execute),
        'health_probe_count': sum(bool(r.get('health_probe_yes')) for r in target),
        'lease_thread_vcsw': distribution(r['thread_vcsw'] for r in target),
        'lease_thread_ivcsw': distribution(r['thread_ivcsw'] for r in target),
    }
    samples = {'lease': lease, 'execute': execute}
    if phase7_enabled:
        calls = []
        missing = 0
        for r in target:
            c = r.get('phase7_calls') or []
            if len(c) != 1:
                missing += 1
            else:
                calls.append(c[0])
        summaries = [c['summary'] for c in calls]
        valid_single = [s for s in summaries if s.get('segment_count') == 1 and s.get('ledger_error_ms') is not None]
        ledger_errors = [abs(s['ledger_error_ms']) for s in valid_single]
        out.update({
            'phase7_call_count': len(calls),
            'phase7_missing_or_multiple': missing,
            'single_segment_count': len(valid_single),
            'multi_segment_count': sum(s.get('segment_count', 0) != 1 for s in summaries),
            'max_abs_ledger_error_ms': max(ledger_errors) if ledger_errors else None,
            'p7_execute': distribution(s['execute_ms'] for s in summaries),
            'pre_send': distribution(s['pre_send_ms'] for s in valid_single if s.get('pre_send_ms') is not None),
            'enqueue': distribution(s['enqueue_ms'] for s in valid_single if s.get('enqueue_ms') is not None),
            'flush': distribution(s['flush_ms'] for s in valid_single if s.get('flush_ms') is not None),
            'flush_to_full_result': distribution(s['response_to_full_ms'] for s in valid_single if s.get('response_to_full_ms') is not None),
            'full_result_to_return': distribution(s['post_full_result_ms'] for s in valid_single if s.get('post_full_result_ms') is not None),
            'time_to_first_readable': distribution(s['time_to_first_readable_ms'] for s in valid_single if s.get('time_to_first_readable_ms') is not None),
            'runqueue_wait': distribution(s['runqueue_wait_ms'] for s in summaries if s.get('runqueue_wait_ms') is not None),
            'execute_thread_cpu': distribution(s['thread_cpu_ms'] for s in summaries if s.get('thread_cpu_ms') is not None),
            'execute_vcsw': distribution(s['thread_vcsw'] for s in summaries if s.get('thread_vcsw') is not None),
            'execute_ivcsw': distribution(s['thread_ivcsw'] for s in summaries if s.get('thread_ivcsw') is not None),
            'first_readable_before_flush_count': sum(s.get('first_readable_relation') == 'BEFORE_FLUSH_COMPLETE' for s in summaries),
        })
        samples['p7_execute'] = [s['execute_ms'] for s in summaries]
    return out, samples


def compact(official, trace, phase7_enabled, name, mode):
    base = p6.compact(official, trace)
    tm, samples = trace_metrics(trace, phase7_enabled)
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
    coverage_ok = all(x['trace_metrics'].get('phase7_missing_or_multiple', 1) == 0 for x in on)
    conservation_ok = all((x['trace_metrics'].get('max_abs_ledger_error_ms') or 0.0) <= 1e-5 for x in on)
    primary_gate = (max(ratios[k] for k in ('p50','p95','p99')) <= 1.10 and ratios['throughput'] >= .95 and recovery_delta <= 6.)
    tail_gate = all(0.80 <= v <= 1.20 for v in tail.values())
    accepted = bool(primary_gate and tail_gate and coverage_ok and conservation_ok)
    return {
        'accepted': accepted,
        'primary_ratios': ratios,
        'tail_ratios': tail,
        'recovery_calls_absolute_delta': recovery_delta,
        'coverage_ok': coverage_ok,
        'conservation_ok': conservation_ok,
        'limits': {
            'latency_ratio_max': 1.10,
            'throughput_ratio_min': .95,
            'recovery_call_delta_max': 6,
            'tail_two_sided_ratio_range': [0.80, 1.20],
            'ledger_error_abs_ms_max': 1e-5,
        },
        'off_pooled': {'ordinary_lease': off_lease, 'execute': off_exec},
        'on_pooled': {'ordinary_lease': on_lease, 'execute': on_exec},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dsn', required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--runs', type=int, default=80)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
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
        'psycopg': psycopg.__version__,
        'pq_impl': getattr(psycopg.pq, '__impl__', None),
        'libpq_version': psycopg.pq.version(),
        'phase7_zero_extra_sql': True,
        'warm_runs_predeclared': args.runs,
        'source_hashes': p6.verify(root),
    }
    save_json('phase7-environment', env)
    print(json.dumps({'environment': env}, separators=(',', ':')), flush=True)

    first = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.)
    save_json('first-run-retained-not-attributed', first)
    if not p6.correct(first):
        raise RuntimeError('first run correctness failure')

    def run(name, mode, use_schedstat):
        p6.verify(root)
        if mode == 'OFF':
            rec = phase6_minimal.MinimalRecorder(gate, rs, Q, psycopg, True)
            phase7_enabled = False
        else:
            rec = Phase7Recorder(gate, rs, Q, psycopg, True, use_schedstat=use_schedstat)
            phase7_enabled = True
        rec.install()
        try:
            official = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.)
        finally:
            rec.restore()
        trace = rec.result()
        payload = {'official': official, 'trace': trace, 'phase7_mode': mode, 'use_schedstat': use_schedstat}
        save_payload(name, payload)
        p6.verify(root)
        if not p6.correct(official):
            raise RuntimeError('correctness failure: ' + name)
        if trace['overflow'] or not trace['exact_cycle_multiset_matches_gate']:
            raise RuntimeError('observer identity/count failure: ' + name)
        c, samples = compact(official, trace, phase7_enabled, name, mode)
        c['_samples'] = samples
        printable = {k:v for k,v in c.items() if k != '_samples'}
        print(json.dumps(printable, separators=(',', ':')), flush=True)
        return c

    def calibrate(label, use_schedstat):
        seq = []
        for i, mode in enumerate(('OFF','ON','OFF','ON'), 1):
            seq.append(run(f'{label}-cal-{i}-{mode.lower()}', mode, use_schedstat))
        verdict = calibration_verdict(seq)
        save_json(label + '-calibration', {
            'runs': [{k:v for k,v in x.items() if k != '_samples'} for x in seq],
            'verdict': verdict,
            'sequence': ['OFF','ON','OFF','ON'],
            'off_semantics': 'accepted Phase6 minimal observer',
            'on_semantics': 'Phase6 minimal + Phase7 internal protocol observer' + (' + schedstat' if use_schedstat else ''),
        })
        print(json.dumps({'calibration': label, **verdict}, separators=(',', ':')), flush=True)
        return verdict

    rejected = []
    sched_cal = calibrate('schedstat', True)
    if sched_cal['accepted']:
        selected_schedstat = True
        selected_calibration = 'schedstat'
    else:
        rejected.append({'observer': 'protocol+schedstat', 'calibration': sched_cal})
        protocol_cal = calibrate('protocol-only', False)
        if not protocol_cal['accepted']:
            rejected.append({'observer': 'protocol-only', 'calibration': protocol_cal})
            save_json('verdict', {
                'status': 'INTRUSIVE_OBSERVER', 'warm_runs': 0, 'rejected_observers': rejected,
                'final_classification': 'D — INCONCLUSIVE',
            })
            return 3
        selected_schedstat = False
        selected_calibration = 'protocol-only'

    save_json('observer-selection', {
        'selected_calibration': selected_calibration,
        'use_schedstat': selected_schedstat,
        'rejected_observers': rejected,
    })

    summaries = []
    for i in range(1, args.runs + 1):
        c = run(f'warm-{i:03}', 'ON', selected_schedstat)
        c.pop('_samples', None)
        summaries.append(c)
        save_json('warm-summary-progress', {'runs': summaries})

    failures = [x for x in summaries if x['p99'] > 500.0]
    save_json('verdict', {
        'status': 'CAPTURE_COMPLETE',
        'warm_runs': len(summaries),
        'warm_failures': len(failures),
        'failure_run_names': [x['name'] for x in failures],
        'tail_reproduction': 'SUFFICIENT_GENUINE_WARM_FAILURES' if len(failures) >= 2 else 'INSUFFICIENT_TAIL_REPRODUCTION',
        'observer': selected_calibration,
        'use_schedstat': selected_schedstat,
        'source_hashes_final': p6.verify(root),
    })
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
