"""Job-scoped ownership facade (Design A).

Production ``DurableDistributedQueue`` APIs stay checkout-per-method.
This module is the supported way to run lease + start + complete without
holding a PostgreSQL connection across application work.

``ClaimedJob`` is frozen token data. It has no connection, pool, or pin.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from arenyxa.enterprise.distributed_protocol import DEFAULT_LEASE_SECONDS
from arenyxa.enterprise.distributed_queue import DurableDistributedQueue


@dataclass(frozen=True, slots=True)
class ClaimedJob:
    job_id: str
    worker_id: str
    lease_token: str
    lease_expires_at: float
    kind: str
    payload: Mapping[str, Any]
    attempt: int
    max_attempts: int

    def connection(self) -> None:
        raise RuntimeError("ClaimedJob does not own a database connection")


class JobLifecycle:
    """Queue-owned checkouts. Every public method releases before return."""

    def __init__(self, queue: DurableDistributedQueue) -> None:
        self._queue = queue

    def acquire_job(self, worker_id: str, *, lease_seconds: int = DEFAULT_LEASE_SECONDS) -> ClaimedJob | None:
        lease = self._queue.lease_next(worker_id, lease_seconds=lease_seconds)
        if lease is None:
            return None
        try:
            self._queue.start_job(lease.job_id, worker_id, lease.lease_token)
        except Exception:
            # Lease already committed; release via fail so the job is not orphaned
            # without a ClaimedJob handle. Best-effort: still surface start_job error.
            try:
                self._queue.fail(
                    lease.job_id,
                    worker_id,
                    lease.lease_token,
                    "JOB_START_FAILED",
                    retryable=True,
                )
            except Exception:
                pass
            raise
        return ClaimedJob(
            job_id=lease.job_id,
            worker_id=str(worker_id),
            lease_token=lease.lease_token,
            lease_expires_at=float(lease.lease_expires_at),
            kind=str(lease.kind),
            payload=lease.payload,
            attempt=int(lease.attempt),
            max_attempts=int(lease.max_attempts),
        )

    def complete_job(self, claimed: ClaimedJob, result: Mapping[str, Any]) -> None:
        self._queue.complete(claimed.job_id, claimed.worker_id, claimed.lease_token, result)

    def fail_job(self, claimed: ClaimedJob, error_code: str, *, retryable: bool = True) -> str:
        return self._queue.fail(
            claimed.job_id,
            claimed.worker_id,
            claimed.lease_token,
            error_code,
            retryable=retryable,
        )

    def recover_expired_leases(self, now: float | None = None) -> int:
        return self._queue.recover_expired_leases(now=now)
