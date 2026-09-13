from phase7_lite_core import summarize_lite_call, quantile_nearest


def test_lite_conservation_and_boundaries():
    call = {
        't0': 1.0,
        't6': 1.100,
        'send_marks': [{'kind': 'query', 'begin': 1.010, 'end': 1.012}],
        'result_ready_marks': [1.090],
    }
    s = summarize_lite_call(call)
    assert abs(s['execute_ms'] - 100.0) < 1e-9
    assert abs(s['pre_send_ms'] - 10.0) < 1e-9
    assert abs(s['send_enqueue_ms'] - 2.0) < 1e-9
    assert abs(s['send_begin_to_full_result_ms'] - 80.0) < 1e-9
    assert abs(s['pre_result_ms'] - 90.0) < 1e-9
    assert abs(s['post_result_ms'] - 10.0) < 1e-9
    assert abs(s['conservation_error_ms']) < 1e-9


def test_lite_preserves_prepare_plus_query_send_information():
    call = {
        't0': 2.0,
        't6': 2.200,
        'send_marks': [
            {'kind': 'prepare', 'begin': 2.010, 'end': 2.011},
            {'kind': 'prepared_query', 'begin': 2.050, 'end': 2.051},
        ],
        'result_ready_marks': [2.190],
    }
    s = summarize_lite_call(call)
    assert s['send_count'] == 2
    assert s['send_kinds'] == ['prepare', 'prepared_query']
    assert s['result_ready_count'] == 1
    assert s['full_result_ready_at'] == 2.190
    assert s['send_enqueue_ms'] is None


def test_lite_refuses_missing_or_multiple_result_ready_marks():
    missing = summarize_lite_call({'t0': 1.0, 't6': 1.1, 'send_marks': [], 'result_ready_marks': []})
    multi = summarize_lite_call({'t0': 1.0, 't6': 1.1, 'send_marks': [], 'result_ready_marks': [1.05, 1.06]})
    assert missing['decomposition_valid'] is False
    assert multi['decomposition_valid'] is False


def test_nearest_quantile_gate_style():
    xs = list(range(1, 101))
    assert quantile_nearest(xs, .50) == 51
    assert quantile_nearest(xs, .99) == 99
