from __future__ import annotations

import inspect

import pytest

# RED by design: these modules do not exist on the Phase 6 baseline yet.
from phase7b_lite_core import summarize_call
from phase7b_lite_observer import invoke_business_preserving
from phase7b_lite_run import is_target_row


def test_psycopg_335_t5_semantics_and_prepare_threshold():
    import psycopg
    import psycopg._cursor_base as cb
    from psycopg._preparing import PrepareManager

    assert psycopg.__version__ == "3.3.5"
    src = inspect.getsource(cb.BaseCursor._maybe_prepare_gen)
    i_execute = src.index("results = yield from execute(self._pgconn)")
    i_validate = src.index("self._conn._prepared.validate")
    i_check = src.index("self._check_results(results)")
    i_set = src.index("self._set_results(results)")
    assert i_execute < i_validate < i_check < i_set
    assert PrepareManager.prepare_threshold == 5


def test_t0_t1_t5_t6_order_and_conservation_single_segment():
    call = {
        "t0": 1.000,
        "t6": 1.100,
        "send_marks": [{"kind": "query", "begin": 1.010, "end": 1.012}],
        "result_ready_marks": [1.090],
    }
    s = summarize_call(call)
    assert s["decomposition_valid"] is True
    assert s["send_count"] == 1
    assert s["send_kinds"] == ["query"]
    assert s["event_order_valid"] is True
    assert s["execute_ms"] == pytest.approx(100.0)
    assert s["pre_result_ms"] == pytest.approx(90.0)
    assert s["post_result_ms"] == pytest.approx(10.0)
    assert s["conservation_error_ms"] == pytest.approx(0.0, abs=1e-9)


def test_prepared_multi_segment_is_preserved_not_collapsed():
    call = {
        "t0": 2.000,
        "t6": 2.200,
        "send_marks": [
            {"kind": "prepare", "begin": 2.010, "end": 2.011},
            {"kind": "prepared_query", "begin": 2.050, "end": 2.051},
        ],
        "result_ready_marks": [2.190],
    }
    s = summarize_call(call)
    assert s["decomposition_valid"] is True
    assert s["send_count"] == 2
    assert s["send_kinds"] == ["prepare", "prepared_query"]
    assert s["segment_class"] == "PREPARE_PLUS_PREPARED_QUERY"
    assert s["post_result_ms"] == pytest.approx(10.0)


def test_bad_event_order_is_rejected_instead_of_repaired():
    call = {
        "t0": 1.0,
        "t6": 1.1,
        "send_marks": [{"kind": "query", "begin": 0.99, "end": 1.01}],
        "result_ready_marks": [1.09],
    }
    s = summarize_call(call)
    assert s["decomposition_valid"] is False
    assert s["event_order_valid"] is False


def test_missing_or_multiple_t5_marks_are_invalid():
    base = {"t0": 1.0, "t6": 1.1, "send_marks": [{"kind": "query", "begin": 1.01, "end": 1.02}]}
    assert summarize_call({**base, "result_ready_marks": []})["decomposition_valid"] is False
    assert summarize_call({**base, "result_ready_marks": [1.08, 1.09]})["decomposition_valid"] is False


def test_phase7_fields_do_not_change_ordinary_recovery_classification():
    ordinary = {
        "success": True,
        "recovery_yes": False,
        "sql": [("lease_fast", 1.0, 2.0, 123)],
        "phase7b_calls": [{"diagnostic": True}],
    }
    recovery = dict(ordinary, recovery_yes=True)
    fallback = dict(ordinary, sql=ordinary["sql"] + [("other_business", 2.1, 2.2, 123)])
    assert is_target_row(ordinary) is True
    assert is_target_row(recovery) is False
    assert is_target_row(fallback) is False


def test_observer_does_not_modify_query_params_or_result():
    query = object()
    params = object()
    sentinel = object()
    seen = {}

    def business(cur, q, p=None):
        seen.update(cur=cur, q=q, p=p)
        return sentinel

    cur = object()
    result = invoke_business_preserving(
        business,
        cur,
        (query, params),
        {},
        before=lambda: None,
        after=lambda: None,
    )
    assert result is sentinel
    assert seen == {"cur": cur, "q": query, "p": params}


def test_observer_faults_cannot_change_business_result_or_exception():
    sentinel = object()

    def broken_observer():
        raise RuntimeError("diagnostic failure")

    def success(cur):
        return sentinel

    assert invoke_business_preserving(
        success, object(), (), {}, before=broken_observer, after=broken_observer
    ) is sentinel

    original = ValueError("business failure")

    def failure(cur):
        raise original

    with pytest.raises(ValueError) as caught:
        invoke_business_preserving(
            failure, object(), (), {}, before=broken_observer, after=broken_observer
        )
    assert caught.value is original
