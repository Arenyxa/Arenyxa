from __future__ import annotations

"""Bounded asynchronous persistence for the Proxy Suite hot path.

The network handler must not synchronously perform SQLite + per-flow file + JSONL fsync work
for every completed flow.  This pipeline moves durable persistence onto one ordered writer,
keeps memory bounded, exposes explicit backpressure, and drains before session shutdown.
"""

import copy
import logging
import queue
import threading
import time
from typing import Any, Callable

from arenyxa.infrastructure.capture.proxy_models import ProxyFlow

LOGGER = logging.getLogger(__name__)

PersistenceErrorCallback = Callable[[str, ProxyFlow, BaseException], None]


class ProxyPersistencePipeline:
    """Single-writer, bounded persistence queue for completed proxy flows.

    Ordering is intentional: the SQLite history store has a unique `(session_id, sequence)`
    constraint and the legacy JSONL archive is append-oriented.  A single writer preserves flow
    ordering and removes SQLite write contention from request-handler threads.

    When the queue is saturated the producer performs a synchronous fallback rather than dropping
    forensic evidence.  That fallback is counted as explicit backpressure and is therefore visible
    in diagnostics instead of becoming silent data loss.
    """

    _STOP = object()

    def __init__(
        self,
        history_store: Any,
        archive: Any,
        *,
        capacity: int = 1024,
        error_callback: PersistenceErrorCallback | None = None,
    ) -> None:
        self.history_store = history_store
        self.archive = archive
        self.capacity = max(16, min(10000, int(capacity)))
        self.error_callback = error_callback
        self._queue: queue.Queue[object] = queue.Queue(maxsize=self.capacity)
        self._lock = threading.RLock()
        self._closed = False
        self._enqueued = 0
        self._persisted = 0
        self._history_failures = 0
        self._archive_failures = 0
        self._sync_fallbacks = 0
        self._max_queue_depth = 0
        self._last_error = ""
        self._last_persisted_at = 0.0
        self._thread = threading.Thread(
            target=self._run,
            name="arenyxa-proxy-persistence",
            daemon=True,
        )
        self._thread.start()

    def enqueue(self, session_id: str, flow: ProxyFlow) -> str:
        """Queue a completed flow, or synchronously persist it under bounded backpressure."""
        persisted_flow = copy.deepcopy(flow)
        item = (str(session_id), persisted_flow)
        with self._lock:
            if self._closed:
                raise RuntimeError("Proxy persistence pipeline is closed")
        try:
            self._queue.put_nowait(item)
        except queue.Full:
            with self._lock:
                self._sync_fallbacks += 1
            self._persist(str(session_id), persisted_flow)
            return "synchronous_fallback"
        with self._lock:
            self._enqueued += 1
            self._max_queue_depth = max(self._max_queue_depth, self._queue.qsize())
        return "queued"

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._STOP:
                    return
                session_id, flow = item  # type: ignore[misc]
                self._persist(str(session_id), flow)
            finally:
                self._queue.task_done()

    def _persist(self, session_id: str, flow: ProxyFlow) -> None:
        history_ok = True
        archive_ok = True
        try:
            self.history_store.store(session_id, flow)
        except Exception as exc:  # broad-exception-boundary: persistence worker must survive one failed flow
            LOGGER.exception("Proxy persistence history sink failed")
            history_ok = False
            self._record_error("history", flow, exc)
        try:
            self.archive.store(flow)
        except Exception as exc:  # broad-exception-boundary: legacy archive is isolated from durable history
            LOGGER.exception("Proxy persistence archive sink failed")
            archive_ok = False
            self._record_error("archive", flow, exc)
        with self._lock:
            if history_ok and archive_ok:
                self._persisted += 1
            self._last_persisted_at = time.time()

    def _record_error(self, sink: str, flow: ProxyFlow, exc: BaseException) -> None:
        with self._lock:
            if sink == "history":
                self._history_failures += 1
            else:
                self._archive_failures += 1
            self._last_error = f"{sink}:{type(exc).__name__}: {exc}"[:512]
        callback = self.error_callback
        if callback is not None:
            try:
                callback(sink, flow, exc)
            except Exception:  # broad-exception-boundary: diagnostics callback cannot kill writer
                LOGGER.exception("Proxy persistence error callback failed")
        LOGGER.error(
            "Proxy persistence %s sink failed for flow %s",
            sink,
            getattr(flow, "id", "unknown"),
            exc_info=(type(exc), exc, exc.__traceback__),
        )

    def flush(self, timeout: float = 5.0) -> bool:
        """Wait for all currently queued writes to finish within a bounded time budget."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        while True:
            # Queue.unfinished_tasks is protected by all_tasks_done's lock.  Reading it under the
            # same condition avoids relying on an unprotected implementation detail.
            with self._queue.all_tasks_done:
                pending = int(self._queue.unfinished_tasks)
            if pending <= 0:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def close(self, timeout: float = 5.0) -> bool:
        """Drain queued evidence and stop the writer.  Returns whether the drain completed."""
        with self._lock:
            if self._closed:
                return not self._thread.is_alive()
            self._closed = True
        drained = self.flush(timeout)
        remaining = max(0.0, float(timeout))
        try:
            self._queue.put(self._STOP, timeout=remaining)
        except queue.Full:
            return False
        if self._thread is not threading.current_thread():
            self._thread.join(remaining)
        return drained and not self._thread.is_alive()

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "schema": "arenyxa.proxy-persistence/v1",
                "capacity": self.capacity,
                "queue_depth": self._queue.qsize(),
                "unfinished": int(self._queue.unfinished_tasks),
                "enqueued": self._enqueued,
                "persisted": self._persisted,
                "sync_fallbacks": self._sync_fallbacks,
                "history_failures": self._history_failures,
                "archive_failures": self._archive_failures,
                "max_queue_depth": self._max_queue_depth,
                "last_error": self._last_error,
                "last_persisted_at": self._last_persisted_at,
                "writer_alive": self._thread.is_alive(),
                "closed": self._closed,
                "bounded": True,
            }
