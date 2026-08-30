from __future__ import annotations
from arenyxa.recoverable import record_current_exception

import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Protocol, cast

from arenyxa.domain.enums import CaptureState
from arenyxa.domain.errors import ArenyxaError
from arenyxa.domain.models import CaptureSession, NetworkEvent, utc_now
from arenyxa.infrastructure.capture.filtering import FilterEngine
from arenyxa.infrastructure.database import SQLiteStore

LOGGER = logging.getLogger(__name__)


class CaptureAdapter(Protocol):
    """Lifecycle contract implemented by capture source adapters."""

    def start(self, session: CaptureSession, emit: Callable[[NetworkEvent], None]) -> None:
        """Start the capture source and emit events into the controller."""
        ...

    def stop(self) -> None:
        """Stop the capture source and release source-owned resources."""
        ...

    def pause(self) -> None:
        """Pause capture event production when supported."""
        ...

    def resume(self) -> None:
        """Resume capture event production after a pause."""
        ...


class CaptureController:
    def __init__(
        self, store: SQLiteStore, queue_capacity: int = 50_000, flush_size: int = 500,
        *, enterprise_operations: object | None = None,
    ) -> None:
        self.store = store
        self._enterprise_operations = enterprise_operations
                                                                                                
                                                                                               
                                                                                               
                                                                                                 
        self.queue_capacity = max(1, int(queue_capacity))
        self.flush_size = min(self.queue_capacity, max(1, int(flush_size)))
        self.session: CaptureSession | None = None
        self.adapter: CaptureAdapter | None = None
        self._queue: queue.Queue[NetworkEvent] = queue.Queue(maxsize=self.queue_capacity)
        self._writer: threading.Thread | None = None
        self._stopping = threading.Event()
        self._filter: Callable[[NetworkEvent], bool] = lambda _event: True
        self._listeners: list[Callable[[list[NetworkEvent]], None]] = []
        self._finalization_listeners: list[Callable[[CaptureSession], None]] = []
        self._finalization_notified_session: CaptureSession | None = None
        self._writer_error: Exception | None = None
        self._source_error: Exception | None = None
        self._state_lock = threading.RLock()
        self._lifecycle_lock = threading.RLock()
        self._accepting_stop_tail = False

    def add_listener(self, callback: Callable[[list[NetworkEvent]], None]) -> None:
        """Register a listener for committed capture batches."""
        with self._state_lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[list[NetworkEvent]], None]) -> None:
        """Remove a previously registered capture listener."""
        with self._state_lock:
            try:
                self._listeners.remove(callback)
            except ValueError:
                record_current_exception(__name__, 'CaptureController.remove_listener:75')

    def add_finalization_listener(self, callback: Callable[[CaptureSession], None]) -> None:
        with self._state_lock:
            if callback not in self._finalization_listeners:
                self._finalization_listeners.append(callback)

    def remove_finalization_listener(self, callback: Callable[[CaptureSession], None]) -> None:
        with self._state_lock:
            try:
                self._finalization_listeners.remove(callback)
            except ValueError:
                return

    def _notify_finalized(self, session: CaptureSession) -> None:
        with self._state_lock:
            if self._finalization_notified_session is session:
                return
            self._finalization_notified_session = session
            listeners = tuple(self._finalization_listeners)
        for callback in listeners:
            try:
                callback(session)
            except Exception:
                LOGGER.exception("Capture finalization listener failed for session %s", session.id)

    def _drain_queue(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                return

    def prepare(self, session: CaptureSession, adapter: CaptureAdapter) -> None:
                                                                                                
                                                                                              
                                                                                      
        """Validate and prepare a capture session before source startup."""
        with self._lifecycle_lock:
            active_states = {
                CaptureState.PREPARING,
                CaptureState.CAPTURING,
                CaptureState.PAUSED,
                CaptureState.FINALIZING,
            }
            if self.session and self.session.state in active_states:
                raise ArenyxaError("CAPTURE_ALREADY_ACTIVE", "已有捕获会话正在运行。", domain="CAPTURE")
            if self._writer and self._writer.is_alive():
                raise ArenyxaError("CAPTURE_WRITER_ACTIVE", "捕获写入线程尚未结束。", domain="CAPTURE")

                                                                                                
                                                                                               
                                                                           
            compiled_filter = FilterEngine().compile(session.filter_expression)
            previous_state = session.state
            session.state = CaptureState.PREPARING
            try:
                self.store.save_capture(session)
            except Exception:
                session.state = previous_state
                raise

            self._drain_queue()
            self._writer_error = None
            self._source_error = None
            self._stopping.clear()
            self._accepting_stop_tail = False
                                                                                                 
                                                                                               
                                                               
            with self._state_lock:
                self.session = session
                self.adapter = adapter
                self._filter = compiled_filter
                self._finalization_notified_session = None

    def start(self) -> None:
        """Start capture source and durable writer processing."""
        with self._lifecycle_lock:
            if not self.session or not self.adapter or self.session.state is not CaptureState.PREPARING:
                raise ArenyxaError("CAPTURE_NOT_PREPARED", "捕获会话尚未准备。", domain="CAPTURE")
            if self._enterprise_operations is not None:
                self._enterprise_operations.authorize_if_bound(
                    "capture", self.session.id, "enterprise.capture.run",
                    correlation_id=f"capture-start:{self.session.id}",
                )
            self._stopping.clear()
            self._writer_error = None
            self._source_error = None
            self._accepting_stop_tail = False
            self.session.state = CaptureState.CAPTURING
            previous_started_at = self.session.started_at
            self.session.started_at = utc_now()
            try:
                self.store.save_capture(self.session)
            except Exception:
                self.session.state = CaptureState.PREPARING
                self.session.started_at = previous_started_at
                raise
            self._writer = threading.Thread(target=self._writer_loop, name="arenyxa-traffic-writer", daemon=True)
            writer_started = False
            adapter_start_attempted = False
            try:
                self._writer.start()
                writer_started = True
                adapter_start_attempted = True
                self.adapter.start(self.session, self.emit)
            except Exception:
                                                                                          
                                                                                                
                                                                                         
                self._stopping.set()
                if adapter_start_attempted:
                    try:
                        self.adapter.stop()
                    except Exception:
                        LOGGER.exception("Capture adapter cleanup after failed start also failed")
                if writer_started:
                    self._writer.join(timeout=5)
                else:
                                                                                              
                                                                                       
                    self._writer = None
                self.session.state = CaptureState.FAILED
                self.session.finished_at = utc_now()
                try:
                    self.store.save_capture(self.session)
                except Exception:
                                                                                             
                                                                                              
                                                                                               
                    LOGGER.exception("Failed to persist capture start failure")
                self._notify_finalized(self.session)
                raise

    def emit(self, event: NetworkEvent) -> None:
                                                                                          
                                                                                       
        """Accept one event into the bounded capture pipeline."""
        session = self.session
        if session is None:
            return
                                                                                                  
                                                                                             
        if event.session_id != session.id:
            return
                                                                                              
                                                                                             
                                
        accepting_tail = self._accepting_stop_tail
        if session.state is not CaptureState.CAPTURING and not accepting_tail:
            return
        if self._writer_error is not None or self._source_error is not None:
            return
        if self._stopping.is_set() and not accepting_tail:
            return
        try:
            accepted = self._filter(event)
        except Exception as exc:                                                       
                                                                                           
                                                                                         
            with self._state_lock:
                if self.session is not session or event.session_id != session.id:
                    return
                accepting_tail = self._accepting_stop_tail
                if session.state is not CaptureState.CAPTURING and not accepting_tail:
                    return
                if self._stopping.is_set() and not accepting_tail:
                    return
                self._source_error = ArenyxaError(
                    "CAPTURE_FILTER_FAILED",
                    "捕获过滤器执行失败。",
                    domain="CAPTURE",
                    context={"details": str(exc)},
                )
                self._stopping.set()
                session.state = CaptureState.FAILED
                session.finished_at = utc_now()
            return
        if not accepted:
            return
                                                                                               
                                                                                             
                                                                 
        with self._state_lock:
            current = self.session
            if current is not session or current is None or event.session_id != current.id:
                return
            accepting_tail = self._accepting_stop_tail
            if current.state is not CaptureState.CAPTURING and not accepting_tail:
                return
            if self._writer_error is not None or self._source_error is not None:
                return
            if self._stopping.is_set() and not accepting_tail:
                return
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                                                                                               
                                                                                             
                current.dropped_events += 1

    def pause(self) -> None:
        """Pause an active capture session without discarding state."""
        with self._lifecycle_lock:
            if self.session and self.adapter and self.session.state is CaptureState.CAPTURING:
                self.adapter.pause()
                self.session.state = CaptureState.PAUSED
                try:
                    self.store.save_capture(self.session)
                except Exception:
                                                                                                
                                                                                              
                                                        
                    try:
                        self.adapter.resume()
                    except Exception as rollback_error:
                        LOGGER.exception("Capture pause rollback failed")
                        self._source_error = rollback_error
                        self._stopping.set()
                        self.session.state = CaptureState.FAILED
                        self.session.finished_at = utc_now()
                    else:
                        self.session.state = CaptureState.CAPTURING
                    raise

    def resume(self) -> None:
        """Resume a previously paused capture session."""
        with self._lifecycle_lock:
            if self.session and self.adapter and self.session.state is CaptureState.PAUSED:
                self.adapter.resume()
                self.session.state = CaptureState.CAPTURING
                try:
                    self.store.save_capture(self.session)
                except Exception:
                                                                                               
                    try:
                        self.adapter.pause()
                    except Exception as rollback_error:
                        LOGGER.exception("Capture resume rollback failed")
                        self._source_error = rollback_error
                        self._stopping.set()
                        self.session.state = CaptureState.FAILED
                        self.session.finished_at = utc_now()
                    else:
                        self.session.state = CaptureState.PAUSED
                    raise

    def stop(self, cancelled: bool = False) -> CaptureSession:
                                                                                            
                                                                                             
                                                    
        """Finalize capture source, writer, chunks, and durable session state."""
        with self._lifecycle_lock:
            return self._stop_locked(cancelled)

    def _stop_locked(self, cancelled: bool = False) -> CaptureSession:
        with self._state_lock:
            session = self.session
            if session is None:
                raise ArenyxaError("CAPTURE_NOT_ACTIVE", "没有活动捕获会话。", domain="CAPTURE")
            if session.state in {CaptureState.COMPLETED, CaptureState.CANCELLED}:
                return session

        adapter_error: Exception | None = None
        adapter = self.adapter
        with self._state_lock:
            should_stop_adapter = adapter is not None and session.state in {
                CaptureState.PREPARING,
                CaptureState.CAPTURING,
                CaptureState.PAUSED,
                CaptureState.FAILED,
            }
                                                                                               
                                                                                                
                                                                                           
            self._accepting_stop_tail = should_stop_adapter and session.state in {
                CaptureState.CAPTURING,
                CaptureState.PAUSED,
            }
        if should_stop_adapter and adapter is not None:
            try:
                adapter.stop()
            except Exception as exc:                                     
                adapter_error = exc
                LOGGER.exception("Capture adapter stop failed")

                                                                                            
                                                                                          
                                                                                             
                                                                                           
        with self._state_lock:
            self._accepting_stop_tail = False
            session.state = CaptureState.FINALIZING
            self._stopping.set()
        if self._writer and self._writer is not threading.current_thread():
            self._writer.join(timeout=10)
        writer_stuck = bool(self._writer and self._writer.is_alive())

        chunk_error: Exception | None = None
        chunks_method = getattr(self.adapter, "committed_chunks", None) if self.adapter else None
        if callable(chunks_method):
            try:
                chunks = cast(Callable[[], List[Dict[str, Any]]], chunks_method)()
                self.store.save_capture_chunks(session.id, chunks)
            except Exception as exc:
                chunk_error = exc
                LOGGER.exception("Capture chunk metadata persistence failed")

        failure = self._writer_error or self._source_error or adapter_error or chunk_error
        if writer_stuck and failure is None:
            failure = RuntimeError("capture writer thread did not stop within 10 seconds")

        session.finished_at = utc_now()
        session.state = (
            CaptureState.FAILED if failure is not None else (CaptureState.CANCELLED if cancelled else CaptureState.COMPLETED)
        )
        try:
            self.store.save_capture(session)
        except Exception as exc:                                                
            if failure is None:
                failure = exc
            LOGGER.exception("Failed to persist final capture state")

        self._notify_finalized(session)
        if failure is not None:
            if self._writer_error is not None:
                code = "CAPTURE_STORAGE_FAILED"
            elif self._source_error is not None:
                code = "CAPTURE_SOURCE_LOST"
            else:
                code = "CAPTURE_FINALIZATION_FAILED"
            raise ArenyxaError(
                code,
                "捕获数据源、写入或结束处理失败；会话已标记为失败，请检查日志、磁盘和数据库。",
                domain="CAPTURE",
                context={"session_id": session.id, "details": str(failure)},
            ) from failure
        return session

    def health_snapshot(self) -> dict[str, Any]:
        """Return bounded, non-blocking capture runtime health for the control plane."""
        with self._state_lock:
            session = self.session
            writer_error = self._writer_error
            source_error = self._source_error
            writer = self._writer
            accepting_stop_tail = self._accepting_stop_tail
        state = None if session is None else session.state.value
        queue_size = int(self._queue.qsize())
        capacity = int(self.queue_capacity)
        pressure = 0.0 if capacity <= 0 else min(1.0, queue_size / capacity)
        degraded = writer_error is not None or source_error is not None
        return {
            "healthy": not degraded,
            "active": session is not None and state in {"preparing", "capturing", "paused", "finalizing"},
            "state": state,
            "session": None if session is None else {
                "id": session.id,
                "name": session.name,
                "state": state,
                "event_count": int(session.event_count),
                "bytes_captured": int(session.bytes_captured),
            },
            "queue": {
                "size": queue_size,
                "capacity": capacity,
                "pressure": round(pressure, 6),
                "backpressure": pressure >= 0.8,
            },
            "writer_alive": bool(writer is not None and writer.is_alive()),
            "accepting_stop_tail": bool(accepting_stop_tail),
            "writer_error": None if writer_error is None else type(writer_error).__name__,
            "source_error": None if source_error is None else type(source_error).__name__,
        }

    def _writer_loop(self) -> None:
        batch: list[NetworkEvent] = []
        last_notify = time.monotonic()
        try:
            while not self._stopping.is_set() or not self._queue.empty():
                source_failure = self._adapter_failure()
                if source_failure is not None and not self._stopping.is_set():
                                                                                         
                                                                                           
                                                                                 
                    self._source_error = source_failure
                    self._stopping.set()
                    if self.session is not None:
                        self.session.state = CaptureState.FAILED
                        self.session.finished_at = utc_now()
                try:
                    event = self._queue.get(timeout=0.1)
                    batch.append(event)
                except queue.Empty:
                    record_current_exception(__name__, 'CaptureController._writer_loop:443')
                if batch and (len(batch) >= self.flush_size or time.monotonic() - last_notify >= 0.2):
                    self._commit_batch(batch)
                    last_notify = time.monotonic()
            if batch:
                self._commit_batch(batch)
            if self._source_error is not None and self.session is not None:
                                                                                              
                                                                                            
                                                           
                self.store.save_capture(self.session)
        except Exception as exc:
            if self._source_error is None:
                self._writer_error = exc
                LOGGER.exception("Capture writer terminated after a persistence failure")
            else:
                LOGGER.error("Capture source failed asynchronously: %s", self._source_error)
            self._stopping.set()
            if self.session:
                self.session.state = CaptureState.FAILED
                self.session.finished_at = utc_now()
                try:
                    self.store.save_capture(self.session)
                except Exception:
                    LOGGER.exception("Unable to persist asynchronous capture failure")

    def _adapter_failure(self) -> Exception | None:
        if self.adapter is None:
            return None
        failure_method = getattr(self.adapter, "failure", None)
        if not callable(failure_method):
            return None
        try:
            failure = failure_method()
        except Exception as exc:                                                         
            return exc
        return failure if isinstance(failure, Exception) else None

    def _commit_batch(self, batch: list[NetworkEvent]) -> None:
        if not batch:
            return
        snapshot = batch.copy()
                                                                                            
                                                                                           
                                                                                           
        if self.session:
            old_count = self.session.event_count
            old_bytes = self.session.bytes_captured
            self.session.event_count += len(snapshot)
            self.session.bytes_captured += sum(event.size for event in snapshot)
            atomic_append = getattr(self.store, "append_capture_events", None)
            try:
                if callable(atomic_append):
                    atomic_append(self.session, snapshot)
                else:
                    self.store.append_network_events(snapshot)
                    self.store.save_capture(self.session)
            except Exception:
                                                                                          
                                                                                           
                self.session.event_count = old_count
                self.session.bytes_captured = old_bytes
                raise
        else:
            self.store.append_network_events(snapshot)
        batch.clear()
        with self._state_lock:
            listeners = tuple(self._listeners)
        for listener in listeners:
            try:
                listener(snapshot)
            except Exception:
                                                                                         
                                                                       
                LOGGER.exception("Capture listener failed")
