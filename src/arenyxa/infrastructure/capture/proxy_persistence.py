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
from collections.abc import Callable
from typing import Any, cast

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
    _OPEN = "open"
    _CLOSING = "closing"
    _CLOSED = "closed"

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
        self._lifecycle = threading.Condition(self._lock)
        self._close_lock = threading.Lock()
        self._state = self._OPEN
        self._active_admissions = 0
        self._stop_enqueued = False
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
        with self._lifecycle:
            if self._state != self._OPEN:
                raise RuntimeError("Proxy persistence pipeline is closing or closed")
            self._active_admissions += 1
        try:
            try:
                self._queue.put_nowait(item)
            except queue.Full:
                with self._lock:
                    self._sync_fallbacks += 1
                self._persist(str(session_id), persisted_flow)
                return "synchronous_fallback"
            depth = self._queue.qsize()
            with self._lock:
                self._enqueued += 1
                self._max_queue_depth = max(self._max_queue_depth, depth)
            return "queued"
        finally:
            with self._lifecycle:
                self._active_admissions -= 1
                self._lifecycle.notify_all()

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is self._STOP:
                    break
                session_id, flow = cast(tuple[str, ProxyFlow], item)
                self._persist(str(session_id), flow)
            finally:
                self._queue.task_done()
        with self._lifecycle:
            self._state = self._CLOSED
            self._lifecycle.notify_all()

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
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._queue.all_tasks_done.wait(remaining)
        return True

    def close(self, timeout: float = 5.0) -> bool:
        """Drain queued evidence and stop the writer.  Returns whether the drain completed."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        if not self._close_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            with self._lifecycle:
                return self._state == self._CLOSED
        try:
            with self._lifecycle:
                if self._state == self._CLOSED:
                    return True
                if self._state == self._OPEN:
                    self._state = self._CLOSING
                    self._lifecycle.notify_all()
                while self._active_admissions:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    self._lifecycle.wait(remaining)

            remaining = max(0.0, deadline - time.monotonic())
            if not self.flush(remaining):
                return False

            if not self._stop_enqueued:
                try:
                    self._queue.put_nowait(self._STOP)
                except queue.Full:
                    return False
                self._stop_enqueued = True

            remaining = max(0.0, deadline - time.monotonic())
            if self._thread is not threading.current_thread():
                self._thread.join(remaining)
            with self._lifecycle:
                return self._state == self._CLOSED
        finally:
            self._close_lock.release()

    def status(self) -> dict[str, Any]:
        with self._queue.all_tasks_done:
            queue_depth = len(self._queue.queue)
            unfinished = int(self._queue.unfinished_tasks)
        with self._lifecycle:
            return {
                "schema": "arenyxa.proxy-persistence/v1",
                "capacity": self.capacity,
                "queue_depth": queue_depth,
                "unfinished": unfinished,
                "enqueued": self._enqueued,
                "persisted": self._persisted,
                "sync_fallbacks": self._sync_fallbacks,
                "history_failures": self._history_failures,
                "archive_failures": self._archive_failures,
                "max_queue_depth": self._max_queue_depth,
                "last_error": self._last_error,
                "last_persisted_at": self._last_persisted_at,
                "writer_alive": self._thread.is_alive(),
                "state": self._state,
                "active_admissions": self._active_admissions,
                "closed": self._state == self._CLOSED,
                "bounded": True,
            }
