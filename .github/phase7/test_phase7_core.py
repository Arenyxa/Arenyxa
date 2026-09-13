from phase7_core import (
    SchedStat,
    sched_delta,
    proxy_generator,
    quantile_nearest,
    summarize_call,
)


def test_schedstat_parse_and_delta():
    before = SchedStat.parse('100 200 3\n')
    after = SchedStat.parse('250 650 8\n')
    d = sched_delta(before, after)
    assert d.cpu_ns == 150
    assert d.runqueue_ns == 450
    assert d.timeslices == 5


def test_proxy_generator_preserves_wait_protocol_and_return_value():
    events = []
    ticks = iter([1.0, 2.0, 2.5, 3.0, 4.0, 4.5])

    def clock():
        return next(ticks)

    def source():
        ready = yield 1
        assert ready == 1
        ready = yield 2
        assert ready == 2
        return 'done'

    p = proxy_generator(source(), lambda e: events.append(e), clock=clock)
    assert next(p) == 1
    assert p.send(1) == 2
    try:
        p.send(2)
    except StopIteration as ex:
        assert ex.value == 'done'
    else:
        raise AssertionError('proxy must preserve StopIteration return value')

    assert len(events) == 2
    assert events[0]['requested'] == 1
    assert events[0]['ready'] == 1
    assert events[0]['terminal'] is False
    assert events[1]['requested'] == 2
    assert events[1]['ready'] == 2
    assert events[1]['terminal'] is True
    assert events[0]['wait_begin'] < events[0]['ready_at'] <= events[0]['driver_progress_end']


def test_nearest_quantile_matches_gate_style_indexing():
    xs = list(range(1, 101))
    assert quantile_nearest(xs, 0.50) == 51
    assert quantile_nearest(xs, 0.95) == 95
    assert quantile_nearest(xs, 0.99) == 99


def test_summarize_call_conserves_execute_wall():
    call = {
        't0': 1.0,
        't6': 1.100,
        'segments': [
            {'kind': 'query', 't1': 1.010, 'enqueue_return': 1.011, 't2': 1.020, 't5': 1.090,
             'waits': [
                 {'phase': 'fetch', 'requested': 1, 'ready': 1, 'wait_begin': 1.021,
                  'ready_at': 1.070, 'driver_progress_end': 1.075, 'terminal': False},
             ]},
        ],
    }
    s = summarize_call(call)
    assert abs(s['execute_ms'] - 100.0) < 1e-9
    assert abs(s['pre_send_ms'] - 10.0) < 1e-9
    assert abs(s['enqueue_ms'] - 1.0) < 1e-9
    assert abs(s['flush_ms'] - 9.0) < 1e-9
    assert abs(s['post_full_result_ms'] - 10.0) < 1e-9
    assert abs(s['ledger_error_ms']) < 1e-9


def test_proxy_generator_captures_context_at_wait_yield_not_after_resume():
    events = []
    state = {'phase': 'send'}
    ticks = iter([1.0, 2.0, 2.5])

    def source():
        ready = yield 3
        state['phase'] = 'fetch'
        assert ready == 1
        return 'ok'

    p = proxy_generator(source(), events.append, clock=lambda: next(ticks), context=lambda: dict(state))
    assert next(p) == 3
    try:
        p.send(1)
    except StopIteration:
        pass
    assert events[0]['context']['phase'] == 'send'
