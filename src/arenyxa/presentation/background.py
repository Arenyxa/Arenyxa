from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from arenyxa.qt_compat.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

LOGGER = logging.getLogger(__name__)
_ACTIVE_JOBS: set[BackgroundJob] = set()
_SHUTTING_DOWN = False


class JobSignals(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()


class JobCallbacks(QObject):
    def __init__(
        self,
        on_success: Callable[[Any], None],
        on_error: Callable[[str], None],
        on_finished: Callable[[], None] | None = None,
    ) -> None:
        super().__init__()
        self._on_success = on_success
        self._on_error = on_error
        self._on_finished = on_finished
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    @Slot(object)
    def success(self, value: Any) -> None:
        if not self._enabled:
            return
        try:
            self._on_success(value)
        except Exception:
                                                                                          
                                                                                         
                                      
            LOGGER.exception("Background success callback failed")

    @Slot(str)
    def error(self, message: str) -> None:
        if not self._enabled:
            return
        try:
            self._on_error(message)
        except Exception:
            LOGGER.exception("Background error callback failed")

    @Slot()
    def finished(self) -> None:
        if self._on_finished is not None:
            try:
                self._on_finished()
            except Exception:
                LOGGER.exception("Background cleanup callback failed")


class BackgroundJob(QRunnable):
    

    def __init__(self, function: Callable[[], Any]) -> None:
        super().__init__()
        self.function = function
        self.signals = JobSignals()
        self.callbacks: JobCallbacks | None = None
        self.setAutoDelete(False)

    @Slot()
    def run(self) -> None:
        try:
            self.signals.succeeded.emit(self.function())
        except Exception as exc:                                                     
            LOGGER.exception("Background UI job failed")
            self.signals.failed.emit(str(exc))
        finally:
            self.signals.finished.emit()


def run_background(
    function: Callable[[], Any],
    on_success: Callable[[Any], None],
    on_error: Callable[[str], None],
) -> BackgroundJob:
    job = BackgroundJob(function)
    if _SHUTTING_DOWN:
                                                                                           
                                                                                              
        LOGGER.debug("Ignoring background job submitted during application shutdown")
        return job

    def cleanup() -> None:
                                                                                   
                                                                                      
                                                                          
        _ACTIVE_JOBS.discard(job)
        job.callbacks = None

    callbacks = JobCallbacks(on_success, on_error, cleanup)
    job.callbacks = callbacks
    _ACTIVE_JOBS.add(job)
    job.signals.succeeded.connect(callbacks.success)
    job.signals.failed.connect(callbacks.error)
    job.signals.finished.connect(callbacks.finished)
    QThreadPool.globalInstance().start(job)
    return job


def begin_background_shutdown(timeout_ms: int = 2500) -> bool:
    





    global _SHUTTING_DOWN
    _SHUTTING_DOWN = True
    pool = QThreadPool.globalInstance()
    for job in tuple(_ACTIVE_JOBS):
        callbacks = job.callbacks
        if callbacks is not None:
            callbacks.disable()
        try:
            removed = pool.tryTake(job)
        except (AttributeError, RuntimeError):
            removed = False
        if removed:
            _ACTIVE_JOBS.discard(job)
            job.callbacks = None
    try:
        return bool(pool.waitForDone(max(0, int(timeout_ms))))
    except RuntimeError:
        return False


def active_background_job_count() -> int:
    return len(_ACTIVE_JOBS)
