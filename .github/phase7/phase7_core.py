from __future__ import annotations

from dataclasses import dataclass
import math
import os
import time
from typing import Any, Callable, Generator, Iterable


@dataclass(frozen=True)
class SchedStat:
    cpu_ns: int
    runqueue_ns: int
    timeslices: int

    @classmethod
    def parse(cls, text: str) -> 'SchedStat':
        parts = text.strip().split()
        if len(parts) < 3:
            raise ValueError('schedstat requires at least three fields')
        return cls(*(int(x) for x in parts[:3]))


@dataclass(frozen=True)
class SchedDelta:
    cpu_ns: int
    runqueue_ns: int
    timeslices: int


def sched_delta(before: SchedStat, after: SchedStat) -> SchedDelta:
    vals = (after.cpu_ns - before.cpu_ns,
            after.runqueue_ns - before.runqueue_ns,
            after.timeslices - before.timeslices)
    if any(x < 0 for x in vals):
        raise ValueError('schedstat counters moved backwards')
    return SchedDelta(*vals)


class ThreadSchedReader:
    """Per-thread read-only schedstat reader. Opens the thread-self fd lazily."""
    def __init__(self) -> None:
        self.fd: int | None = None
        self.error: str | None = None

    def snapshot(self) -> SchedStat | None:
        if self.error is not None:
            return None
        try:
            if self.fd is None:
                self.fd = os.open('/proc/thread-self/schedstat', os.O_RDONLY | os.O_CLOEXEC)
            return SchedStat.parse(os.pread(self.fd, 160, 0).decode('ascii', 'strict'))
        except (OSError, ValueError, UnicodeError) as exc:
            self.error = type(exc).__name__
            return None


def proxy_generator(gen: Generator[Any, Any, Any], callback: Callable[[dict[str, Any]], None],
                    *, clock: Callable[[], float] = time.perf_counter,
                    context: Callable[[], Any] | None = None) -> Generator[Any, Any, Any]:
    """Transparent proxy around psycopg's wait generator.

    It never polls or reads the fd itself. The outer, original wait implementation
    receives the yielded readiness mask and sends the readiness result back here.
    """
    try:
        requested = next(gen)
    except StopIteration as ex:
        return ex.value
    while True:
        wait_context = context() if context is not None else None
        wait_begin = clock()
        ready = yield requested
        ready_at = clock()
        try:
            requested_next = gen.send(ready)
        except StopIteration as ex:
            progress_end = clock()
            callback(dict(requested=int(requested), ready=int(ready),
                          wait_begin=wait_begin, ready_at=ready_at,
                          driver_progress_end=progress_end, terminal=True, context=wait_context))
            return ex.value
        else:
            progress_end = clock()
            callback(dict(requested=int(requested), ready=int(ready),
                          wait_begin=wait_begin, ready_at=ready_at,
                          driver_progress_end=progress_end, terminal=False, context=wait_context))
            requested = requested_next


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


def summarize_call(call: dict[str, Any]) -> dict[str, Any]:
    t0 = float(call['t0']); t6 = float(call['t6'])
    if t6 < t0:
        raise ValueError('negative execute interval')
    segments = call.get('segments') or []
    out: dict[str, Any] = {
        'execute_ms': (t6 - t0) * 1000.0,
        'segment_count': len(segments),
        'segment_kinds': [s.get('kind') for s in segments],
        'pre_send_ms': None, 'enqueue_ms': None, 'flush_ms': None,
        'time_to_first_readable_ms': None,
        'post_first_readable_to_full_ms': None,
        'response_to_full_ms': None,
        'post_full_result_ms': None,
        'ledger_error_ms': None,
        'first_readable_relation': 'NOT_OBSERVED',
    }
    if not segments:
        return out
    first = segments[0]; last = segments[-1]
    t1 = first.get('t1'); enqueue_return = first.get('enqueue_return')
    t2 = first.get('t2'); t5 = last.get('t5')
    if t1 is not None:
        out['pre_send_ms'] = (float(t1) - t0) * 1000.0
    if t1 is not None and enqueue_return is not None:
        out['enqueue_ms'] = (float(enqueue_return) - float(t1)) * 1000.0
    if enqueue_return is not None and t2 is not None:
        out['flush_ms'] = (float(t2) - float(enqueue_return)) * 1000.0
    if t2 is not None and t5 is not None:
        out['response_to_full_ms'] = (float(t5) - float(t2)) * 1000.0
    if t5 is not None:
        out['post_full_result_ms'] = (t6 - float(t5)) * 1000.0

    read_events = []
    for seg in segments:
        read_events.extend(e for e in seg.get('waits', []) if int(e.get('ready', 0)) & 1)
    if read_events:
        first_ready = min(read_events, key=lambda e: e['ready_at'])
        tr = float(first_ready['ready_at'])
        if t2 is not None:
            out['time_to_first_readable_ms'] = (tr - float(t2)) * 1000.0
            out['first_readable_relation'] = 'AT_OR_AFTER_FLUSH' if tr >= float(t2) else 'BEFORE_FLUSH_COMPLETE'
        if t5 is not None:
            out['post_first_readable_to_full_ms'] = (float(t5) - tr) * 1000.0
        out['first_readable_at'] = tr

    parts = [out[k] for k in ('pre_send_ms','enqueue_ms','flush_ms','response_to_full_ms','post_full_result_ms')]
    if all(x is not None for x in parts):
        out['ledger_error_ms'] = out['execute_ms'] - sum(float(x) for x in parts)
        if not math.isclose(out['ledger_error_ms'], 0.0, abs_tol=1e-5):
            raise ValueError('execute timeline fails conservation')
    return out
