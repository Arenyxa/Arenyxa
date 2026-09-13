from __future__ import annotations

from types import SimpleNamespace

from phase7b_lite_observer import install_boundary_hooks
from phase7b_lite_run import calibration_verdict


class FakePgq:
    def __init__(self, query: bytes):
        self.query = query


class FakeCursor:
    def __init__(self):
        self.calls = []

    def _execute_send(self, pgq, *, binary=None):
        self.calls.append(("query", pgq, binary))
        return "QUERY_RETURN"

    def _send_prepare(self, name, pgq):
        self.calls.append(("prepare", name, pgq))
        return "PREPARE_RETURN"

    def _send_query_prepared(self, name, pgq, *, binary=None):
        self.calls.append(("prepared_query", name, pgq, binary))
        return "PREPARED_RETURN"

    def _check_results(self, results):
        self.calls.append(("check", results))
        return "CHECK_RETURN"


class FakeRecorder:
    def __init__(self):
        self.tls = SimpleNamespace()
        self.row = {"phase7b_calls": []}
        self.originals = []

    def lease_row(self):
        return self.row

    def patch(self, owner, name, value):
        original = getattr(owner, name)
        self.originals.append((owner, name, original))
        setattr(owner, name, value)
        return original

    def begin_or_get_boundary_call(self, row):
        call = getattr(self.tls, "phase7b_call", None)
        if call is None or call.get("row_identity") != id(row) or call.get("result_ready_marks"):
            call = {
                "row_identity": id(row),
                "send_marks": [],
                "result_ready_marks": [],
                "anomalies": [],
            }
            row["phase7b_calls"].append(call)
            self.tls.phase7b_call = call
        return call

    def restore(self):
        for owner, name, original in reversed(self.originals):
            setattr(owner, name, original)
        self.originals.clear()


def _clock():
    value = [10.0]
    def now():
        value[0] += 0.001
        return value[0]
    return now


def test_installed_hook_preserves_single_segment_result_and_records_t1_t5():
    rec = FakeRecorder()
    install_boundary_hooks(rec, FakeCursor, _clock())
    try:
        cur = FakeCursor(); pgq = FakePgq(b"WITH eligible_worker AS SELECT 1")
        assert cur._execute_send(pgq, binary=False) == "QUERY_RETURN"
        results = [object()]
        assert cur._check_results(results) == "CHECK_RETURN"
        assert cur.calls == [("query", pgq, False), ("check", results)]
        calls = rec.row["phase7b_calls"]
        assert len(calls) == 1
        assert [x["kind"] for x in calls[0]["send_marks"]] == ["query"]
        assert len(calls[0]["result_ready_marks"]) == 1
    finally:
        rec.restore()


def test_installed_hook_preserves_prepare_plus_query_segments():
    rec = FakeRecorder()
    install_boundary_hooks(rec, FakeCursor, _clock())
    try:
        cur = FakeCursor(); pgq = FakePgq(b"WITH eligible_worker AS SELECT 1")
        assert cur._send_prepare(b"p", pgq) == "PREPARE_RETURN"
        assert cur._send_query_prepared(b"p", pgq, binary=False) == "PREPARED_RETURN"
        assert cur._check_results([object()]) == "CHECK_RETURN"
        call = rec.row["phase7b_calls"][0]
        assert [x["kind"] for x in call["send_marks"]] == ["prepare", "prepared_query"]
        assert len(call["result_ready_marks"]) == 1
    finally:
        rec.restore()


def test_non_target_query_is_not_recorded():
    rec = FakeRecorder()
    install_boundary_hooks(rec, FakeCursor, _clock())
    try:
        cur = FakeCursor(); pgq = FakePgq(b"SELECT 1")
        assert cur._execute_send(pgq) == "QUERY_RETURN"
        assert cur._check_results([object()]) == "CHECK_RETURN"
        assert rec.row["phase7b_calls"] == []
    finally:
        rec.restore()


def _record(mode, *, p50=100, p95=200, p99=300, p999=400, throughput=500, recovery=1,
            lease=(100, 200, 300, 400), execute=(90, 190, 290, 390), missing=0, invalid=0, error=0.0):
    return {
        "mode": mode,
        "p50": p50, "p95": p95, "p99": p99, "p999": p999,
        "throughput": throughput, "recovery_calls": recovery,
        "trace_metrics": {
            "phase7b_missing": missing,
            "phase7b_invalid": invalid,
            "max_abs_conservation_error_ms": error,
        },
        "_samples": {"lease": list(lease), "execute": list(execute)},
    }


def test_calibration_accepts_only_predeclared_safe_window():
    records = [
        _record("OFF"),
        _record("ON", p50=102, p95=204, p99=306, p999=404, throughput=490,
                lease=(101, 201, 301, 401), execute=(91, 191, 291, 391)),
        _record("OFF", p50=101, p95=201, p99=301, p999=401, throughput=495,
                lease=(102, 202, 302, 402), execute=(92, 192, 292, 392)),
        _record("ON", p50=103, p95=205, p99=307, p999=405, throughput=488,
                lease=(103, 203, 303, 403), execute=(93, 193, 293, 393)),
    ]
    verdict = calibration_verdict(records)
    assert verdict["accepted"] is True
    assert verdict["limits"]["throughput_ratio_min"] == 0.95
    assert verdict["limits"]["tail_two_sided_ratio_range"] == [0.80, 1.20]


def test_calibration_rejects_throughput_or_tail_pollution():
    throughput_bad = [
        _record("OFF"), _record("ON", throughput=460),
        _record("OFF"), _record("ON", throughput=460),
    ]
    assert calibration_verdict(throughput_bad)["accepted"] is False

    tail_bad = [
        _record("OFF", p999=400), _record("ON", p999=520),
        _record("OFF", p999=400), _record("ON", p999=520),
    ]
    verdict = calibration_verdict(tail_bad)
    assert verdict["accepted"] is False
    assert verdict["tail_ratios"]["cycle_p999_ratio"] > 1.20
