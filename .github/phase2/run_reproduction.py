import json
import os
import time
from pathlib import Path
from scripts import postgresql_32_worker_gate as gate

DSN = os.environ['ARENYXA_POSTGRES_TEST_DSN']
OUT = Path('phase2_artifacts')
OUT.mkdir(exist_ok=True)

def correctness(result):
    inv = result.get('state_invariants') or {}
    return (
        not result.get('errors')
        and result.get('completed') == result.get('jobs') == 1024
        and result.get('non_completed') == 0
        and bool((result.get('fencing_probe') or {}).get('passed'))
        and all(int(inv.get(k, 1)) == 0 for k in ('inconsistent_lease_rows','unreceipted_completed_jobs','implausible_future_leases'))
        and result.get('active_leases_after') == 0
        and bool((result.get('pool') or {}).get('connection_storm_free'))
    )

all_summaries = []
for round_no in range(1, 4):
    captured = {'cycle': None}
    original_percentile = gate._percentile
    first_p99 = {'seen': False}
    def capturing_percentile(values, percentile):
        if percentile == 0.99 and not first_p99['seen']:
            first_p99['seen'] = True
            captured['cycle'] = list(values)
        return original_percentile(values, percentile)
    gate._percentile = capturing_percentile
    started = time.perf_counter()
    try:
        result = gate.run_gate(DSN, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    finally:
        gate._percentile = original_percentile
    wall = time.perf_counter() - started
    values = captured['cycle'] or []
    p999 = round(original_percentile(values, 0.999), 3) if values else None
    metrics = list((result.get('pool') or {}).get('metrics') or [])
    extras = {
        'round': round_no,
        'wall_duration_seconds_external': round(wall, 3),
        'cycle_p99_9_ms': p999,
        'pool_requests_wait_ms_total': round(sum(float(x.get('requests_wait_ms', 0.0) or 0.0) for x in metrics), 3),
        'pool_requests_waiting_final': sum(int(x.get('requests_waiting', 0) or 0) for x in metrics),
        'pool_acquisitions_total': sum(int(x.get('acquisitions', 0) or 0) for x in metrics),
        'pool_acquisition_failures_total': sum(int(x.get('acquisition_failures', 0) or 0) for x in metrics),
        'pool_size_total_final': sum(int(x.get('pool_size', 0) or 0) for x in metrics),
        'pool_available_total_final': sum(int(x.get('pool_available', 0) or 0) for x in metrics),
        'correctness_pass': correctness(result),
    }
    result['reproduction_extras'] = extras
    (OUT / f'reproduction-run-{round_no}.json').write_text(json.dumps(result, indent=2, sort_keys=True), encoding='utf-8')
    lat = result['latency_ms']
    summary = {
        'round': round_no,
        'p50': lat['p50'], 'p95': lat['p95'], 'p99': lat['p99'], 'p999': p999, 'max': lat['max'],
        'duration_seconds': result['duration_seconds'], 'throughput': result['throughput_jobs_per_second'],
        'lease_p99': lat['phases']['lease_next']['p99'], 'start_p99': lat['phases']['start_job']['p99'], 'complete_p99': lat['phases']['complete']['p99'],
        'completed': result['completed'], 'non_completed': result['non_completed'], 'errors': result['errors'],
        'fencing': result['fencing_probe']['passed'], 'state_invariants': result['state_invariants'],
        'active_leases_after': result['active_leases_after'], 'connection_storm_free': result['pool']['connection_storm_free'],
        **extras,
    }
    all_summaries.append(summary)
    print(json.dumps(summary, sort_keys=True), flush=True)

payload = {'schema': 'arenyxa.phase2-reproduction/v1', 'rounds': all_summaries}
(OUT / 'reproduction-summary.json').write_text(json.dumps(payload, indent=2, sort_keys=True), encoding='utf-8')
if not all(x['correctness_pass'] for x in all_summaries):
    raise SystemExit('correctness failure in reproduction gate')
