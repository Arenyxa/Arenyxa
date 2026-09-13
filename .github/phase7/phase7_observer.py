"""Phase 7 diagnostic-only observer for lease_fast execute internals.

No SQL is issued by this module. It delegates all protocol reads/writes to the
same psycopg/libpq machinery and only timestamps existing generator boundaries.
"""
from __future__ import annotations

from dataclasses import asdict

import phase6_minimal
import phase6_trace as p6
from phase7_core import ThreadSchedReader, proxy_generator, sched_delta, summarize_call


class Phase7Recorder(phase6_minimal.MinimalRecorder):
    def __init__(self, gate, rs, queue, psycopg, full=True, *, use_schedstat=True):
        super().__init__(gate, rs, queue, psycopg, full)
        self.use_schedstat = bool(use_schedstat)
        self.protocol_patch_active = False
        self.wait_patch_active = False

    def _call(self):
        return getattr(self.tls, 'p7_call', None)

    def _segment_context(self):
        call = self._call()
        seg = getattr(self.tls, 'p7_segment', None)
        return {
            'call_active': call is not None,
            'segment_index': None if seg is None else seg.get('index'),
            'phase': None if seg is None else seg.get('phase'),
        }

    def _sched_reader(self):
        reader = getattr(self.tls, 'p7_sched_reader', None)
        if reader is None:
            reader = ThreadSchedReader()
            self.tls.p7_sched_reader = reader
        return reader

    def install(self):
        super().install()
        if not self.full:
            return

        R = self
        import psycopg._cursor_base as cb
        import psycopg.generators as gens
        import psycopg.waiting as waiting

        native_protocol_execute = cb.execute
        native_send = gens.send
        native_fetch_many = gens.fetch_many
        old_wait = waiting.wait

        for method_name, kind in (
            ('_execute_send', 'query'),
            ('_send_prepare', 'prepare'),
            ('_send_query_prepared', 'prepared_query'),
        ):
            original = getattr(cb.BaseCursor, method_name)

            def send_method(cur, *args, _orig=original, _kind=kind, **kwargs):
                call = R._call()
                if call is None:
                    return _orig(cur, *args, **kwargs)
                pending = getattr(R.tls, 'p7_pending_segments', None)
                if pending is None:
                    pending = []
                    R.tls.p7_pending_segments = pending
                seg = {
                    'index': len(call['segments']) + len(pending),
                    'kind': _kind,
                    't1': p6.PC(),
                    'enqueue_return': None,
                    't2': None,
                    't5': None,
                    'phase': 'enqueue',
                    'waits': [],
                    'cursor_id': id(cur),
                }
                pending.append(seg)
                try:
                    return _orig(cur, *args, **kwargs)
                finally:
                    seg['enqueue_return'] = p6.PC()

            self.patch(cb.BaseCursor, method_name, send_method)

        def protocol_execute(pgconn):
            call = R._call()
            if call is None:
                return (yield from native_protocol_execute(pgconn))
            pending = getattr(R.tls, 'p7_pending_segments', None)
            if pending:
                seg = pending.pop(0)
            else:
                seg = {
                    'index': len(call['segments']),
                    'kind': 'unknown_internal_protocol',
                    't1': None,
                    'enqueue_return': None,
                    't2': None,
                    't5': None,
                    'phase': 'unknown',
                    'waits': [],
                    'cursor_id': None,
                }
                call['anomalies'].append('protocol_execute_without_send_hook')
            seg['index'] = len(call['segments'])
            call['segments'].append(seg)
            previous = getattr(R.tls, 'p7_segment', None)
            R.tls.p7_segment = seg
            try:
                seg['phase'] = 'flush'
                yield from native_send(pgconn)
                seg['t2'] = p6.PC()
                seg['phase'] = 'fetch'
                rv = yield from native_fetch_many(pgconn)
                seg['t5'] = p6.PC()
                seg['phase'] = 'result_ready'
                return rv
            finally:
                R.tls.p7_segment = previous

        self.patch(cb, 'execute', protocol_execute)
        self.protocol_patch_active = True

        def wait(gen, fileno, interval=0.0):
            call = R._call()
            if call is None:
                return old_wait(gen, fileno, interval=interval)

            def on_event(event):
                ctx = event.get('context') or {}
                idx = ctx.get('segment_index')
                event['phase'] = ctx.get('phase')
                event.pop('context', None)
                if idx is not None and 0 <= idx < len(call['segments']):
                    call['segments'][idx]['waits'].append(event)
                else:
                    pending = getattr(R.tls, 'p7_pending_segments', None) or []
                    target = next((s for s in pending if s.get('index') == idx), None)
                    if target is not None:
                        target['waits'].append(event)
                    else:
                        call['unscoped_waits'].append(event)

            proxied = proxy_generator(gen, on_event, clock=p6.PC, context=R._segment_context)
            return old_wait(proxied, fileno, interval=interval)

        self.patch(waiting, 'wait', wait)
        self.wait_patch_active = True

        old_execute = self.pg.Connection.execute

        def connection_execute(conn, query, *args, **kwargs):
            row = R.lease_row()
            is_target = row is not None and 'WITH eligible_worker AS' in str(query)
            if not is_target or R._call() is not None:
                return old_execute(conn, query, *args, **kwargs)

            usage_before = p6.thread_usage()
            sched_before = R._sched_reader().snapshot() if R.use_schedstat else None
            call = {
                't0': p6.PC(),
                't6': None,
                'backend_pid': conn.info.backend_pid,
                'thread_usage_before': usage_before,
                'thread_usage_after': None,
                'sched_before': asdict(sched_before) if sched_before is not None else None,
                'sched_after': None,
                'sched_error': None,
                'segments': [],
                'unscoped_waits': [],
                'anomalies': [],
            }
            R.tls.p7_call = call
            R.tls.p7_pending_segments = []
            try:
                return old_execute(conn, query, *args, **kwargs)
            finally:
                call['t6'] = p6.PC()
                call['thread_usage_after'] = p6.thread_usage()
                sched_after = R._sched_reader().snapshot() if R.use_schedstat else None
                call['sched_after'] = asdict(sched_after) if sched_after is not None else None
                reader = getattr(R.tls, 'p7_sched_reader', None)
                if reader is not None and reader.error is not None:
                    call['sched_error'] = reader.error
                pending = getattr(R.tls, 'p7_pending_segments', None) or []
                if pending:
                    call['anomalies'].append('unconsumed_send_segments:%d' % len(pending))
                    call['pending_segments'] = pending
                row.setdefault('phase7_calls', []).append(call)
                R.tls.p7_call = None
                R.tls.p7_segment = None
                R.tls.p7_pending_segments = []

        self.patch(self.pg.Connection, 'execute', connection_execute)

    def result(self):
        result = super().result()
        sched_available = False
        call_count = 0
        for row in result['cycles']:
            calls = row.get('phase7_calls') or []
            for call in calls:
                call_count += 1
                call['summary'] = summarize_call(call)
                ub = call.get('thread_usage_before'); ua = call.get('thread_usage_after')
                if ub is not None and ua is not None:
                    call['summary']['thread_cpu_ms'] = (ua[0] - ub[0]) * 1000.0
                    call['summary']['thread_vcsw'] = ua[1] - ub[1]
                    call['summary']['thread_ivcsw'] = ua[2] - ub[2]
                sb = call.get('sched_before'); sa = call.get('sched_after')
                if sb is not None and sa is not None:
                    try:
                        from phase7_core import SchedStat
                        d = sched_delta(SchedStat(**sb), SchedStat(**sa))
                        call['summary']['sched_cpu_ms'] = d.cpu_ns / 1_000_000.0
                        call['summary']['runqueue_wait_ms'] = d.runqueue_ns / 1_000_000.0
                        call['summary']['sched_timeslices'] = d.timeslices
                        sched_available = True
                    except ValueError as exc:
                        call['anomalies'].append(type(exc).__name__)
        result['phase7'] = {
            'call_count': call_count,
            'protocol_patch_active': self.protocol_patch_active,
            'wait_patch_active': self.wait_patch_active,
            'schedstat_requested': self.use_schedstat,
            'schedstat_available': sched_available,
            't4_directly_observed': False,
            'socket_observation_semantics': 'driver-observed Ready.R returned by original psycopg wait function',
            't2_semantics': 'libpq output queue flush complete (PQflush==0), not server receipt',
            't5_semantics': 'native fetch_many returned after PGresult collection/terminal result state',
        }
        return result
