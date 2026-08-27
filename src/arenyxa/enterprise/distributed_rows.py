from __future__ import annotations

from typing import Any

from arenyxa.enterprise.distributed_protocol import MAX_CHECKPOINT_BYTES, MAX_RESULT_BYTES, _load_json


def distributed_job_row(row: Any) -> dict[str, Any]:
    """Project one durable job row into the bounded public/operator view."""
    keys = row.keys()
    return {
        "job_id": str(row["job_id"]), "kind": str(row["kind"]), "state": str(row["state"]),
        "payload_sha256": str(row["payload_sha256"]),
        "traceparent": str(row["traceparent"]) if "traceparent" in keys else "",
        "tracestate": str(row["tracestate"]) if "tracestate" in keys else "",
        "resource_id": str(row["resource_id"]), "permission": str(row["permission"]),
        "idempotency_key": str(row["idempotency_key"]), "side_effect_mode": str(row["side_effect_mode"]),
        "side_effect_state": str(row["side_effect_state"]), "attempt": int(row["attempt"]),
        "max_attempts": int(row["max_attempts"]), "protocol_version": int(row["protocol_version"]),
        "priority": int(row["priority"]), "lease_worker_id": str(row["lease_worker_id"]),
        "lease_expires_at": float(row["lease_expires_at"]),
        "checkpoint": _load_json(str(row["checkpoint_json"]), MAX_CHECKPOINT_BYTES, "job checkpoint"),
        "checkpoint_seq": int(row["checkpoint_seq"]),
        "result": _load_json(str(row["result_json"]), MAX_RESULT_BYTES, "job result"),
        "result_sha256": str(row["result_sha256"]), "terminal_worker_id": str(row["terminal_worker_id"]),
        "terminal_at": str(row["terminal_at"]), "error_code": str(row["error_code"]),
        "created_at": str(row["created_at"]), "updated_at": str(row["updated_at"]),
    }
