"""Phase 7 boundary-lite observer.

Adds no SQL, no socket reads/polls, no wait-generator proxy, no schedstat and no
extra per-execute rusage calls. It reuses Phase6-minimal T0/T6 execute spans.
The only new hot-path observations are cursor send-method timestamps and the
BaseCursor._check_results() entry, which occurs after the query's libpq execute
generator has returned its PGresult list.
"""
from __future__ import annotations

import phase6_minimal
import phase6_trace as p6
from phase7_lite_core import summarize_lite_call


LEASE_TOKEN = b'WITH eligible_worker AS'


def _query_bytes(pgq):
    q = getattr(pgq, 'query', b'')
    if isinstance(q, bytes):
        return q
    if isinstance(q, bytearray):
        return bytes(q)
    try:
        return bytes(q)
    except Exception:
        return str(q).encode('utf-8', 'replace')


class BoundaryLiteRecorder(phase6_minimal.MinimalRecorder):
    def _active_lite_call(self):
        return getattr(self.tls, 'p7lite_call', None)

    def _begin_or_get_call(self, row):
        call = self._active_lite_call()
        if call is None or call.get('row_identity') != id(row) or call.get('result_ready_marks'):
            call = {
                'row_identity': id(row),
                'send_marks': [],
                'result_ready_marks': [],
                'anomalies': [],
            }
            row.setdefault('phase7_lite_calls', []).append(call)
            self.tls.p7lite_call = call
        return call

    def install(self):
        super().install()
        if not self.full:
            return

        R = self
        import psycopg._cursor_base as cb

        def patch_send(method_name, kind, pgq_pos):
            original = getattr(cb.BaseCursor, method_name)

            def wrapped(cur, *args, **kwargs):
                row = R.lease_row()
                pgq = args[pgq_pos] if len(args) > pgq_pos else kwargs.get('query') or kwargs.get('pgq')
                target = row is not None and pgq is not None and LEASE_TOKEN in _query_bytes(pgq)
                if not target:
                    return original(cur, *args, **kwargs)
                call = R._begin_or_get_call(row)
                mark = {'kind': kind, 'begin': p6.PC(), 'end': None}
                call['send_marks'].append(mark)
                try:
                    return original(cur, *args, **kwargs)
                finally:
                    mark['end'] = p6.PC()

            R.patch(cb.BaseCursor, method_name, wrapped)

        patch_send('_execute_send', 'query', 0)
        patch_send('_send_prepare', 'prepare', 1)
        patch_send('_send_query_prepared', 'prepared_query', 1)

        original_check = cb.BaseCursor._check_results

        def check_results(cur, results):
            call = R._active_lite_call()
            row = R.lease_row()
            if call is not None and row is not None and call.get('row_identity') == id(row):
                call['result_ready_marks'].append(p6.PC())
                R.tls.p7lite_call = None
            return original_check(cur, results)

        self.patch(cb.BaseCursor, '_check_results', check_results)

    def result(self):
        result = super().result()
        call_count = 0
        valid_count = 0
        for row in result['cycles']:
            calls = row.get('phase7_lite_calls') or []
            lease_sql = [x for x in row.get('sql', []) if x[0] == 'lease_fast']
            if len(calls) == 1 and len(lease_sql) == 1:
                call = calls[0]
                _, t0, t6, backend_pid = lease_sql[0]
                call['t0'] = t0
                call['t6'] = t6
                call['backend_pid'] = backend_pid
                call.pop('row_identity', None)
                call['summary'] = summarize_lite_call(call)
                call_count += 1
                if call['summary']['decomposition_valid']:
                    valid_count += 1
            elif calls:
                for call in calls:
                    call.pop('row_identity', None)
                    call.setdefault('anomalies', []).append(
                        f'identity_mismatch:calls={len(calls)}:lease_fast={len(lease_sql)}'
                    )
        result['phase7_lite'] = {
            'call_count': call_count,
            'valid_decomposition_count': valid_count,
            't0_semantics': 'Phase6-minimal existing Connection.execute lease_fast span begin',
            't1_semantics': 'cursor send method entry; not libpq flush complete',
            't2': 'NOT DIRECTLY OBSERVABLE',
            't3': 'NOT DIRECTLY OBSERVABLE',
            't4': 'NOT DIRECTLY OBSERVABLE',
            't5_semantics': 'BaseCursor._check_results entry after main query execute(pgconn) returned PGresults; prepared-cache validate may precede it only when key is non-None',
            't6_semantics': 'Phase6-minimal existing Connection.execute lease_fast span end',
            'socket_consumed_by_observer': False,
            'extra_sql': False,
            'wait_generator_wrapped': False,
            'schedstat': False,
            'extra_execute_rusage': False,
        }
        return result
