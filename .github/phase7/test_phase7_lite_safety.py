import pytest

from phase7_lite_observer import _invoke_business_safely
from phase7_lite_run import is_target_row


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
