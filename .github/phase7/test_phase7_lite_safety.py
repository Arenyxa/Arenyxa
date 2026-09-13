# RED regression: observer faults must never alter business semantics.
import pytest

from phase7_lite_observer import _invoke_business_safely
from phase7_lite_run import calibration_verdict, is_target_row


def test_observer_before_failure_cannot_change_business_result_or_arguments():
    query = object()
    params = object()
    seen = {}
    sentinel = object()

    def business(cur, q, p=None):
        seen['cur'] = cur
        seen['query'] = q
        seen['params'] = p
        return sentinel

    def broken_before():
        raise RuntimeError('observer-before-failure')

    cur = object()
    result = _invoke_business_safely(
        business,
        cur,
        (query, params),
        {},
        before=broken_before,
    )
    assert result is sentinel
    assert seen == {'cur': cur, 'query': query, 'params': params}


def test_observer_after_failure_cannot_replace_original_business_exception():
    class BusinessFailure(ValueError):
        pass

    original = BusinessFailure('business-failure')

    def business(cur):
        raise original

    def broken_after():
        raise RuntimeError('observer-after-failure')

    with pytest.raises(BusinessFailure) as caught:
        _invoke_business_safely(business, object(), (), {}, after=broken_after)
    assert caught.value is original


def test_phase7_fields_do_not_change_ordinary_recovery_classification():
    ordinary = {
        'success': True,
        'recovery_yes': False,
        'sql': [('lease_fast', 1.0, 2.0, 123)],
        'phase7_lite_calls': [{'arbitrary': 'diagnostic-only'}],
    }
    recovery = dict(ordinary, recovery_yes=True)
    assert is_target_row(ordinary) is True
    assert is_target_row(recovery) is False


def _cal_record(mode, p50, p95, p99, p999, throughput, lease, execute):
    return {
        'mode': mode,
        'p50': p50,
        'p95': p95,
        'p99': p99,
        'p999': p999,
        'throughput': throughput,
        'recovery_calls': 0,
        'trace_metrics': {
            'phase7_lite_missing': 0,
            'phase7_lite_invalid': 0,
            'max_abs_conservation_error_ms': 0.0,
        },
        '_samples': {'lease': lease, 'execute': execute},
    }


def test_calibration_tail_gate_includes_cycle_p999():
    records = [
        _cal_record('OFF', 100, 200, 300, 400, 500, [100, 200, 300, 400], [90, 190, 290, 390]),
        _cal_record('ON', 101, 202, 303, 404, 498, [101, 202, 303, 404], [91, 191, 291, 391]),
        _cal_record('OFF', 102, 204, 306, 408, 496, [102, 204, 306, 408], [92, 192, 292, 392]),
        _cal_record('ON', 103, 206, 309, 412, 494, [103, 206, 309, 412], [93, 193, 293, 393]),
    ]
    verdict = calibration_verdict(records)
    assert 'cycle_p999_ratio' in verdict['tail_ratios']
    assert 0.80 <= verdict['tail_ratios']['cycle_p999_ratio'] <= 1.20
