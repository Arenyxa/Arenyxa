from __future__ import annotations

import json
import logging

from arenyxa.infrastructure.observability import JsonFormatter, Redactor


def test_json_formatter_preserves_correlation_fields_and_redacts_context() -> None:
    formatter = JsonFormatter(Redactor())
    record = logging.LogRecord("arenyxa.test", logging.ERROR, __file__, 1, "boom", (), None)
    record.run_id = "run-1"
    record.execution_id = "exec-1"
    record.worker_id = "worker-1"
    record.job_id = "job-1"
    record.correlation_id = "corr-1"
    record.error_code = "TEST_FAILURE"
    record.context = {"authorization": "Bearer super-secret", "resource": "workflow:x"}
    payload = json.loads(formatter.format(record))
    assert payload["run_id"] == "run-1"
    assert payload["execution_id"] == "exec-1"
    assert payload["worker_id"] == "worker-1"
    assert payload["job_id"] == "job-1"
    assert payload["correlation_id"] == "corr-1"
    assert payload["error_code"] == "TEST_FAILURE"
    assert payload["context"]["authorization"] == "••••••••"
