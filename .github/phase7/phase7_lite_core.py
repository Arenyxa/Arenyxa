from __future__ import annotations

from typing import Any, Iterable


def quantile_nearest(values: Iterable[float], q: float) -> float | None:
    vals = sorted(float(x) for x in values)
    if not vals:
        return None
    if not 0.0 <= q <= 1.0:
        raise ValueError('q out of range')
    return vals[min(len(vals) - 1, max(0, round((len(vals) - 1) * q)))]


def distribution(values: Iterable[float]) -> dict[str, float | int | None]:
    vals = [float(x) for x in values]
    return {
        'count': len(vals),
        'p50': quantile_nearest(vals, .5),
        'p95': quantile_nearest(vals, .95),
        'p99': quantile_nearest(vals, .99),
        'p999': quantile_nearest(vals, .999),
        'max': max(vals) if vals else None,
    }


def summarize_lite_call(call: dict[str, Any]) -> dict[str, Any]:
    t0 = float(call['t0']); t6 = float(call['t6'])
    if t6 < t0:
        raise ValueError('negative execute interval')
    sends = list(call.get('send_marks') or [])
    ready = list(call.get('result_ready_marks') or [])
    out: dict[str, Any] = {
        'execute_ms': (t6 - t0) * 1000.0,
        'send_count': len(sends),
        'send_kinds': [s.get('kind') for s in sends],
        'result_ready_count': len(ready),
        'full_result_ready_at': ready[0] if len(ready) == 1 else None,
        'decomposition_valid': len(ready) == 1,
        'pre_send_ms': None,
        'send_enqueue_ms': None,
        'send_begin_to_full_result_ms': None,
        'pre_result_ms': None,
        'post_result_ms': None,
        'pre_result_share': None,
        'post_result_share': None,
        'conservation_error_ms': None,
    }
    if len(ready) != 1:
        return out
    t5 = float(ready[0])
    if not t0 <= t5 <= t6:
        raise ValueError('result-ready mark outside execute interval')
    out['pre_result_ms'] = (t5 - t0) * 1000.0
    out['post_result_ms'] = (t6 - t5) * 1000.0
    out['conservation_error_ms'] = out['execute_ms'] - out['pre_result_ms'] - out['post_result_ms']
    if out['execute_ms'] > 0:
        out['pre_result_share'] = out['pre_result_ms'] / out['execute_ms']
        out['post_result_share'] = out['post_result_ms'] / out['execute_ms']
    if sends:
        first = sends[0]
        t1 = float(first['begin'])
        out['pre_send_ms'] = (t1 - t0) * 1000.0
        out['send_begin_to_full_result_ms'] = (t5 - t1) * 1000.0
        if len(sends) == 1 and first.get('end') is not None:
            out['send_enqueue_ms'] = (float(first['end']) - t1) * 1000.0
    return out
