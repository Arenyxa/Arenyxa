from __future__ import annotations

import json
import logging
import queue
import threading
from collections import deque
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Iterable

from arenyxa.compat import dataclass
from arenyxa.domain.models import utc_now

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StreamEnvelope:
    sequence: int
    topic: str
    timestamp: str
    payload: dict[str, Any]

    def snapshot(self) -> dict[str, Any]:
        return asdict(self)


class EventStreamSubscription:
    """Bounded, non-blocking queue subscription for asynchronous consumers."""

    def __init__(self, token: int, owner: "BoundedEventStream", buffer: "queue.Queue[StreamEnvelope]") -> None:
        self.token = int(token)
        self._owner = owner
        self._buffer = buffer
        self._closed = False

    def poll(self, timeout: float | None = None) -> StreamEnvelope | None:
        if self._closed:
            return None
        try:
            if timeout is None:
                return self._buffer.get_nowait()
            return self._buffer.get(timeout=max(0.0, float(timeout)))
        except queue.Empty:
            return None

    def drain(self, limit: int = 1000) -> list[StreamEnvelope]:
        result: list[StreamEnvelope] = []
        for _ in range(max(0, min(100_000, int(limit)))):
            item = self.poll()
            if item is None:
                break
            result.append(item)
        return result

    def close(self) -> None:
        if not self._closed:
            self._owner.unsubscribe(self.token)
            self._closed = True

    def __enter__(self) -> "EventStreamSubscription":
        return self

    def __exit__(self, _exc_type: object | None, _exc: object | None, _tb: object | None) -> None:
        self.close()


class BoundedEventStream:
    """Process-local, bounded event bus with replay and optional JSONL durability.

    This is not presented as a Kafka replacement. It gives Arenyxa a safe streaming
    contract that can be bridged to a broker later without coupling capture hot paths
    to a network dependency.
    """

    def __init__(self, capacity: int = 20_000, *, journal_path: Path | None = None) -> None:
        self.capacity = max(128, min(1_000_000, int(capacity)))
        self.journal_path = Path(journal_path) if journal_path is not None else None
        self._lock = threading.RLock()
        self._events: deque[StreamEnvelope] = deque(maxlen=self.capacity)
        self._subscribers: dict[int, tuple[str, Callable[[StreamEnvelope], None]]] = {}
        self._queue_subscribers: dict[int, tuple[str, queue.Queue[StreamEnvelope]]] = {}
        self._next_subscriber = 1
        self._sequence = 0
        self._published = 0
        self._dropped = 0
        self._subscriber_errors = 0

    def subscribe(self, callback: Callable[[StreamEnvelope], None], *, topic_prefix: str = "") -> int:
        if not callable(callback):
            raise TypeError("callback must be callable")
        with self._lock:
            token = self._next_subscriber
            self._next_subscriber += 1
            self._subscribers[token] = (str(topic_prefix or ""), callback)
            return token

    def subscribe_queue(self, *, topic_prefix: str = "", capacity: int = 1024) -> EventStreamSubscription:
        """Create a bounded asynchronous queue consumer without blocking publishers."""

        buffer: queue.Queue[StreamEnvelope] = queue.Queue(maxsize=max(1, min(100_000, int(capacity))))
        with self._lock:
            token = self._next_subscriber
            self._next_subscriber += 1
            self._queue_subscribers[token] = (str(topic_prefix or ""), buffer)
        return EventStreamSubscription(token, self, buffer)

    def unsubscribe(self, token: int) -> bool:
        with self._lock:
            key = int(token)
            callback_removed = self._subscribers.pop(key, None) is not None
            queue_removed = self._queue_subscribers.pop(key, None) is not None
            return callback_removed or queue_removed

    def publish(self, topic: str, payload: dict[str, Any]) -> StreamEnvelope:
        topic_value = str(topic or "").strip()
        if not topic_value or len(topic_value) > 256:
            raise ValueError("stream topic must be 1..256 characters")
        safe_payload = dict(payload)
        with self._lock:
            before = len(self._events)
            self._sequence += 1
            envelope = StreamEnvelope(self._sequence, topic_value, utc_now(), safe_payload)
            self._events.append(envelope)
            if before == self.capacity:
                self._dropped += 1
            self._published += 1
            subscribers = tuple(self._subscribers.values())
            queue_subscribers = tuple(self._queue_subscribers.values())
        self._journal(envelope)
        for prefix, callback in subscribers:
            if prefix and not topic_value.startswith(prefix):
                continue
            try:
                callback(envelope)
            except Exception:
                with self._lock:
                    self._subscriber_errors += 1
                LOGGER.exception("Event stream subscriber failed for topic %s", topic_value)
        for prefix, buffer in queue_subscribers:
            if prefix and not topic_value.startswith(prefix):
                continue
            try:
                buffer.put_nowait(envelope)
            except queue.Full:
                # Queue consumers are deliberately lossy under backpressure: capture hot paths
                # must not block because an observer is slow. The drop counter is observable.
                with self._lock:
                    self._dropped += 1
        return envelope

    def publish_many(self, topic: str, payloads: Iterable[dict[str, Any]]) -> int:
        count = 0
        for payload in payloads:
            self.publish(topic, payload)
            count += 1
        return count

    def replay(self, *, after_sequence: int = 0, topic_prefix: str = "", limit: int = 1000) -> list[dict[str, Any]]:
        bounded = max(1, min(100_000, int(limit)))
        prefix = str(topic_prefix or "")
        with self._lock:
            rows = tuple(self._events)
        result: list[dict[str, Any]] = []
        for item in rows:
            if item.sequence <= int(after_sequence):
                continue
            if prefix and not item.topic.startswith(prefix):
                continue
            result.append(item.snapshot())
            if len(result) >= bounded:
                break
        return result

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "capacity": self.capacity,
                "buffered": len(self._events),
                "published": self._published,
                "dropped_oldest": self._dropped,
                "subscriber_count": len(self._subscribers) + len(self._queue_subscribers),
                "callback_subscribers": len(self._subscribers),
                "queue_subscribers": len(self._queue_subscribers),
                "subscriber_errors": self._subscriber_errors,
                "last_sequence": self._sequence,
                "journal": str(self.journal_path) if self.journal_path is not None else "",
            }

    def _journal(self, envelope: StreamEnvelope) -> None:
        if self.journal_path is None:
            return
        line = json.dumps(envelope.snapshot(), ensure_ascii=False, separators=(",", ":"), default=str) + "\n"
        encoded = line.encode("utf-8")
        if len(encoded) > 2 * 1024 * 1024:
            LOGGER.warning("Skipping oversized event-stream journal record: %d bytes", len(encoded))
            return
        try:
            self.journal_path.parent.mkdir(parents=True, exist_ok=True)
            with self.journal_path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line)
        except OSError:
            LOGGER.exception("Event stream journal write failed")
