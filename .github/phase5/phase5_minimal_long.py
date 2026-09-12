from __future__ import annotations

import argparse
import importlib.util
import json
import os
import statistics
from pathlib import Path

import psycopg

from scripts import postgresql_32_worker_gate as gate

ROOT = Path(os.environ.get('GITHUB_WORKSPACE', os.getcwd()))


def load_recovery_probe():
    path = ROOT / '.github/phase3/phase3_recovery_probe.py'
    spec = importlib.util.spec_from_file_location('phase3_recovery_probe', path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--dsn', required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--max-runs', type=int, default=60)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    probe = load_recovery_probe()
    with psycopg.connect(args.dsn, autocommit=True) as c:
        vals = c.execute("SELECT current_setting('server_version_num'),current_setting('max_connections'),current_setting('fsync'),current_setting('synchronous_commit')").fetchone()
        assert tuple(map(str, vals)) == ('160015','256','on','on')

    first = gate.run_gate(args.dsn, workers=64, concurrency=128, jobs=1024, p99_budget_ms=500.0)
    assert first['completed'] == 1024 and not first['errors'] and (first.get('storage') or {}).get('backend') == 'postgresql'
    (args.out / 'diagnostic-first-run.json').write_text(json.dumps(first, indent=2, sort_keys=True), encoding='utf-8')

    hooks = probe.install_hooks()
    try:
        cal = []
        for idx, enabled in enumerate((False, True, False, True), 1):
            r, t = probe.run_once(args.dsn, enabled)
            row = {'step': idx, 'enabled': enabled, **probe.compact(r)}
            cal.append(row)
            (args.out / f'cal-{idx}.json').write_text(json.dumps({'summary': row, 'trace': t}, indent=2, sort_keys=True), encoding='utf-8')
        off = [x for x in cal if not x['enabled']]
        on = [x for x in cal if x['enabled']]
        calibration = {
            'sequence': cal,
            'off_p99_median': statistics.median([x['p99'] for x in off]),
            'on_p99_median': statistics.median([x['p99'] for x in on]),
            'off_throughput_median': statistics.median([x['throughput'] for x in off]),
            'on_throughput_median': statistics.median([x['throughput'] for x in on]),
        }
        calibration['p99_ratio'] = calibration['on_p99_median'] / calibration['off_p99_median']
        calibration['throughput_ratio'] = calibration['on_throughput_median'] / calibration['off_throughput_median']
        calibration['intrusive'] = calibration['p99_ratio'] > 1.05 or calibration['throughput_ratio'] < 0.95
        (args.out / 'calibration.json').write_text(json.dumps(calibration, indent=2, sort_keys=True), encoding='utf-8')
        if calibration['intrusive']:
            raise RuntimeError(f'minimal tracer intrusive: {calibration}')

        runs = []
        failures = 0
        all_successful = []
        for i in range(1, max(40, args.max_runs) + 1):
            r, t = probe.run_once(args.dsn, True)
            c = probe.compact(r)
            successful = [x for x in t['lease_calls'] if x['returned']]
            recovery = [x for x in successful if x['recovery_children']]
            ordinary = [x for x in successful if not x['recovery_children']]

            def dist(rows):
                vals = sorted(float(x['client_ms']) for x in rows)
                if not vals:
                    return {'count': 0, 'median': None, 'p95': None, 'p99': None, 'max': None}
                pick = lambda q: vals[min(len(vals)-1, max(0, round((len(vals)-1)*q)))]
                return {'count': len(vals), 'median': statistics.median(vals), 'p95': pick(.95), 'p99': pick(.99), 'max': max(vals)}

            top20 = sorted(successful, key=lambda x: float(x['client_ms']), reverse=True)[:20]
            entry = {
                'run': i,
                **c,
                'genuine_failure': float(c['p99']) > 500.0,
                'successful_leases': len(successful),
                'recovery_calls': len(recovery),
                'recovery_incidence_pct': 100.0 * len(recovery) / max(1, len(successful)),
                'ordinary': dist(ordinary),
                'recovery': dist(recovery),
                'top20_recovery': sum(1 for x in top20 if x['recovery_children']),
                'top20': top20,
            }
            failures += int(entry['genuine_failure'])
            runs.append(entry)
            all_successful.extend({**x, 'run': i} for x in successful)
            (args.out / f'warm-run-{i:02d}.json').write_text(json.dumps({'summary': entry, 'trace': t}, indent=2, sort_keys=True), encoding='utf-8')
            print(json.dumps({k:v for k,v in entry.items() if k != 'top20'}, sort_keys=True), flush=True)
            if i >= 40 and failures >= 5:
                break
            if i >= args.max_runs:
                break

        top100 = sorted(all_successful, key=lambda x: float(x['client_ms']), reverse=True)[:100]
        summary = {
            'calibration': calibration,
            'runs': runs,
            'warm_runs': len(runs),
            'warm_failures': failures,
            'global_top100': top100,
            'global_top100_recovery_fraction': sum(1 for x in top100 if x['recovery_children']) / max(1, len(top100)),
        }
        (args.out / 'phase5-minimal-summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True), encoding='utf-8')
    finally:
        probe.restore(hooks)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
