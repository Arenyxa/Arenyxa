from __future__ import annotations

import logging
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from collections.abc import Callable
from dataclasses import field
from arenyxa.application.future_callbacks import WeakMethodFutureCallback
from arenyxa.compat import dataclass, shutdown_executor
from datetime import datetime, timedelta
from arenyxa.compat import UTC
from arenyxa.compat import ZoneInfo, ZoneInfoNotFoundError

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class ScheduleRule:
    kind: str = "interval"
    interval_minutes: int = 60
    hour: int = 2
    minute: int = 0
    weekdays: tuple[int, ...] = field(default_factory=lambda: tuple(range(7)))
    timezone: str = "Asia/Shanghai"

    def validate(self) -> None:
        if self.kind not in {"interval", "daily", "weekly"}:
            raise ValueError(f"不支持的计划类型：{self.kind}")
        if not isinstance(self.interval_minutes, int) or not 1 <= self.interval_minutes <= 525_600:
            raise ValueError("计划间隔必须位于 1 到 525600 分钟。")
        if not isinstance(self.hour, int) or not 0 <= self.hour <= 23:
            raise ValueError("计划小时必须位于 0 到 23。")
        if not isinstance(self.minute, int) or not 0 <= self.minute <= 59:
            raise ValueError("计划分钟必须位于 0 到 59。")
        if not isinstance(self.weekdays, tuple):
            raise ValueError("weekdays 必须为 tuple。")
        if any(not isinstance(day, int) or day < 0 or day > 6 for day in self.weekdays):
            raise ValueError("weekdays 只能包含 0 到 6。")
        if self.kind == "weekly" and not self.weekdays:
            raise ValueError("每周计划至少需要选择一天。")
        try:
            ZoneInfo(self.timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"未知时区：{self.timezone}。Windows 源码环境必须安装 tzdata。") from exc

    def next_after(self, moment: datetime) -> datetime:
        self.validate()
        zone = ZoneInfo(self.timezone)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)

                                                                                          
                                                              
        if self.kind == "interval":
            return (moment.astimezone(UTC) + timedelta(minutes=self.interval_minutes)).astimezone(zone)

        local = moment.astimezone(zone)
        selected = set(self.weekdays) if self.kind == "weekly" else None
                                                                                          
                                                                                        
                                                                                           
                                                                                  
        for offset in range(0, 8):
            day = local.date() + timedelta(days=offset)
            if selected is not None and day.weekday() not in selected:
                continue
            candidate = datetime(
                day.year, day.month, day.day, self.hour, self.minute, tzinfo=zone, fold=0
            )
            candidate = candidate.astimezone(UTC).astimezone(zone)
            if candidate.astimezone(UTC) > local.astimezone(UTC):
                return candidate
        raise RuntimeError("无法计算下一次计划运行时间。")


class SchedulerService:
    





    def __init__(
        self,
        on_reschedule: Callable[[str, datetime], None] | None = None,
        *,
        on_executed: Callable[[str, datetime], None] | None = None,
        max_callback_workers: int = 4,
    ) -> None:
        self._condition = threading.Condition()
        self._jobs: dict[str, tuple[ScheduleRule, datetime, Callable[[], None], bool]] = {}
                                                                                             
                                                                                            
                                                                                   
        self._job_generations: dict[str, int] = {}
        self._generation_counter = 0
                                                                                            
                                                                                             
                                             
        self._definition_io_lock = threading.RLock()
        self._running: set[str] = set()
        self._callback_futures: dict[str, Future[None]] = {}
        self._stopping = False
        self._on_reschedule = on_reschedule
        self._on_executed = on_executed
        self._callback_executor = ThreadPoolExecutor(
            max_workers=max(1, int(max_callback_workers)),
            thread_name_prefix="arenyxa-schedule",
        )
        self._thread = threading.Thread(target=self._run, name="arenyxa-scheduler", daemon=True)

    def start(self) -> None:
        with self._condition:
            if self._stopping:
                raise RuntimeError("SchedulerService 已停止，不能再次启动。")
            if not self._thread.is_alive():
                self._thread.start()

    def add(
        self,
        schedule_id: str,
        rule: ScheduleRule,
        callback: Callable[[], None],
        enabled: bool = True,
        next_run: datetime | None = None,
    ) -> None:
        if not schedule_id:
            raise ValueError("schedule_id 不能为空。")
        rule.validate()
        cancel_future: Future[None] | None = None
        replacing = False
        due_at = next_run or rule.next_after(datetime.now(UTC))
        if due_at.tzinfo is None:
            due_at = due_at.replace(tzinfo=UTC)
        with self._definition_io_lock:
            with self._condition:
                                                                                            
                                                                                                
                                                                                        
                replacing = schedule_id in self._jobs
                if replacing:
                    cancel_future = self._callback_futures.get(schedule_id)
                self._jobs[schedule_id] = (rule, due_at, callback, bool(enabled))
                self._job_generations[schedule_id] = self._next_generation_locked()
                self._condition.notify_all()
                                                                                           
                                                                                              
                                                                                            
            if replacing and self._on_reschedule:
                try:
                    self._on_reschedule(schedule_id, due_at)
                except Exception:
                    LOGGER.exception("Failed to persist replacement schedule %s", schedule_id)
        if cancel_future is not None:
            cancel_future.cancel()

    def set_enabled(self, schedule_id: str, enabled: bool) -> None:
        rescheduled: datetime | None = None
        cancel_future: Future[None] | None = None
        with self._definition_io_lock:
            with self._condition:
                if schedule_id not in self._jobs:
                    raise KeyError(schedule_id)
                rule, next_run, callback, was_enabled = self._jobs[schedule_id]
                desired = bool(enabled)
                                                                                            
                                                                                              
                if desired and not was_enabled:
                    next_run = rule.next_after(datetime.now(UTC))
                    rescheduled = next_run
                if not desired and was_enabled:
                                                                                               
                                                                                                
                                                                                       
                    cancel_future = self._callback_futures.get(schedule_id)
                if desired != was_enabled:
                    self._job_generations[schedule_id] = self._next_generation_locked()
                self._jobs[schedule_id] = (rule, next_run, callback, desired)
                self._condition.notify_all()
            if rescheduled is not None and self._on_reschedule:
                try:
                    self._on_reschedule(schedule_id, rescheduled)
                except Exception:
                    LOGGER.exception("Failed to persist re-enabled schedule %s", schedule_id)
        if cancel_future is not None:
            cancel_future.cancel()

    def snapshot(self) -> list[dict[str, object]]:
        





        with self._condition:
            rows: list[dict[str, object]] = []
            for schedule_id, (rule, next_run, _callback, enabled) in self._jobs.items():
                future = self._callback_futures.get(schedule_id)
                rows.append({
                    "id": schedule_id,
                    "kind": rule.kind,
                    "timezone": rule.timezone,
                    "enabled": bool(enabled),
                    "next_run_at": next_run.isoformat(),
                    "running": schedule_id in self._running,
                    "callback_pending": bool(future is not None and not future.done()),
                })
        rows.sort(key=lambda item: (str(item["next_run_at"]), str(item["id"])))
        return rows

    def remove(self, schedule_id: str) -> None:
        cancel_future: Future[None] | None = None
        with self._definition_io_lock:
            with self._condition:
                self._jobs.pop(schedule_id, None)
                self._job_generations.pop(schedule_id, None)
                cancel_future = self._callback_futures.get(schedule_id)
                self._condition.notify_all()
        if cancel_future is not None:
            cancel_future.cancel()

    def stop(self) -> None:
        with self._condition:
            if self._stopping:
                return
            self._stopping = True
            self._condition.notify_all()
        if self._thread.is_alive() and self._thread is not threading.current_thread():
            self._thread.join(timeout=5)
                                                                                         
                                                                                         
                                                                                       
        current_name = threading.current_thread().name
        wait_callbacks = not current_name.startswith("arenyxa-schedule")
        with self._condition:
            callback_futures = list(self._callback_futures.values())
        for future in callback_futures:
            future.cancel()
        shutdown_executor(self._callback_executor, wait=wait_callbacks, cancel_futures=True)

    def _run(self) -> None:
        while True:
            callbacks: list[tuple[str, Callable[[], None], datetime, int]] = []
            rescheduled: list[tuple[str, datetime, int]] = []
            with self._condition:
                if self._stopping:
                    return
                now = datetime.now(UTC)
                wake_seconds = 60.0
                for schedule_id, (rule, next_run, callback, enabled) in list(self._jobs.items()):
                    if not enabled:
                        continue
                    generation = self._job_generations[schedule_id]
                    try:
                        due = next_run.astimezone(UTC) <= now
                    except (ValueError, OverflowError) as exc:
                        LOGGER.exception("Invalid next_run for schedule %s", schedule_id)
                        self._jobs[schedule_id] = (rule, next_run, callback, False)
                        self._job_generations[schedule_id] = self._next_generation_locked()
                        continue
                    if due:
                        try:
                            following = rule.next_after(now)
                        except (ValueError, OverflowError) as exc:
                            LOGGER.error("Disabling invalid schedule %s: %s", schedule_id, exc)
                            self._jobs[schedule_id] = (rule, next_run, callback, False)
                            self._job_generations[schedule_id] = self._next_generation_locked()
                            continue
                        self._jobs[schedule_id] = (rule, following, callback, enabled)
                        if schedule_id in self._running:
                                                                                            
                                                                                         
                            rescheduled.append((schedule_id, following, generation))
                            LOGGER.warning("Skipping overlapping invocation of schedule %s", schedule_id)
                        else:
                            self._running.add(schedule_id)
                                                                                              
                                                                                             
                                                                                           
                                                                               
                            callbacks.append((schedule_id, callback, following, generation))
                    else:
                        wake_seconds = min(
                            wake_seconds, max(0.05, (next_run.astimezone(UTC) - now).total_seconds())
                        )
                if not callbacks and not rescheduled:
                    self._condition.wait(timeout=wake_seconds)
                    continue
            if self._on_reschedule:
                for schedule_id, next_run, generation in rescheduled:
                    self._persist_reschedule_if_current(schedule_id, generation, next_run)
            for schedule_id, callback, following, generation in callbacks:
                try:
                    future = self._callback_executor.submit(
                        self._execute_callback, schedule_id, callback, following, generation
                    )
                    with self._condition:
                        self._callback_futures[schedule_id] = future
                    future.add_done_callback(
                        WeakMethodFutureCallback(self, "_callback_done", prefix=(schedule_id,))
                    )
                except RuntimeError:
                                                                                            
                                                                                        
                    with self._condition:
                        self._running.discard(schedule_id)
                    if not self._stopping:
                        LOGGER.exception("Unable to submit scheduled callback %s", schedule_id)

    def _execute_callback(
        self,
        schedule_id: str,
        callback: Callable[[], None],
        next_run: datetime,
        generation: int,
    ) -> None:
                                                                                       
                                                                             
        with self._condition:
            current = self._jobs.get(schedule_id)
            if (
                self._stopping
                or current is None
                or not current[3]
                or current[2] is not callback
                or self._job_generations.get(schedule_id) != generation
            ):
                return
        attempted_at = datetime.now(UTC)
        try:
            callback()
        except Exception:
            LOGGER.exception("Scheduled callback %s failed", schedule_id)
        finally:
                                                                                         
                                                                                             
                                                                                            
            with self._definition_io_lock:
                with self._condition:
                    current = self._jobs.get(schedule_id)
                    is_current = (
                        current is not None
                        and current[3]
                        and current[2] is callback
                        and self._job_generations.get(schedule_id) == generation
                    )
                                                                                            
                                                                                           
                                                                                            
                                                                                        
                    persisted_next_run = current[1] if is_current and current is not None else next_run
                if is_current:
                    if self._on_executed:
                        try:
                            self._on_executed(schedule_id, attempted_at)
                        except Exception:
                            LOGGER.exception("Failed to persist execution time for %s", schedule_id)
                    if self._on_reschedule:
                        try:
                            self._on_reschedule(schedule_id, persisted_next_run)
                        except Exception:
                                                                                                  
                                                                                                   
                            LOGGER.exception("Failed to persist next run after %s", schedule_id)

    def _next_generation_locked(self) -> int:
        self._generation_counter += 1
        return self._generation_counter

    def _persist_reschedule_if_current(
        self, schedule_id: str, generation: int, next_run: datetime
    ) -> None:
        if self._on_reschedule is None:
            return
        with self._definition_io_lock:
            with self._condition:
                current = self._jobs.get(schedule_id)
                if current is None or self._job_generations.get(schedule_id) != generation:
                    return
            try:
                self._on_reschedule(schedule_id, next_run)
            except Exception:
                                                                            
                LOGGER.exception("Failed to persist rescheduled job %s", schedule_id)

    def _callback_done(self, schedule_id: str, future: Future[None]) -> None:
        with self._condition:
            if self._callback_futures.get(schedule_id) is future:
                self._callback_futures.pop(schedule_id, None)
                self._running.discard(schedule_id)
                self._condition.notify_all()
