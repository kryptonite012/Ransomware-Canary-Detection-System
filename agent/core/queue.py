"""Bounded event queue with coalescing deduplication and backpressure.

Filesystem notification APIs frequently emit several events for a single
logical write (e.g. ``modified`` for every buffered ``write()`` call).  The
queue coalesces identical ``(type, src, dest)`` events that arrive within a
short window so that behavioural counters are not inflated, and it never
blocks the notification thread: when full it drops the event and counts it.
"""
from __future__ import annotations

import queue
import threading
import time
from collections import OrderedDict

from agent.core.events import FileEvent


class Deduplicator:
    """Tracks recently seen event keys; thread-safe."""

    def __init__(self, window_seconds: float, max_keys: int = 200_000):
        self.window = window_seconds
        self.max_keys = max_keys
        self._seen: OrderedDict[tuple, float] = OrderedDict()
        self._lock = threading.Lock()
        self.suppressed = 0

    def is_duplicate(self, key: tuple, now: float | None = None) -> bool:
        if self.window <= 0:
            return False
        now = time.monotonic() if now is None else now
        with self._lock:
            last = self._seen.get(key)
            if last is not None and now - last < self.window:
                self.suppressed += 1
                return True
            self._seen[key] = now
            self._seen.move_to_end(key)
            # Evict expired / excess keys from the old end.
            while self._seen:
                oldest_key, ts = next(iter(self._seen.items()))
                if now - ts >= self.window or len(self._seen) > self.max_keys:
                    self._seen.popitem(last=False)
                else:
                    break
            return False


class BoundedEventQueue:
    def __init__(self, maxsize: int, dedup_window_seconds: float = 0.4, high_watermark: float = 0.8):
        self._q: queue.Queue[FileEvent] = queue.Queue(maxsize=maxsize)
        self.maxsize = maxsize
        self.high_watermark = int(maxsize * high_watermark)
        self.dedup = Deduplicator(dedup_window_seconds)
        self.accepted = 0
        self.dropped = 0
        self._lock = threading.Lock()

    def put(self, event: FileEvent) -> bool:
        if self.dedup.is_duplicate(event.dedup_key(), event.monotonic):
            return False
        try:
            self._q.put_nowait(event)
        except queue.Full:
            with self._lock:
                self.dropped += 1
            return False
        with self._lock:
            self.accepted += 1
        return True

    def get(self, timeout: float | None = None) -> FileEvent | None:
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_batch(self, max_items: int, timeout: float) -> list[FileEvent]:
        first = self.get(timeout)
        if first is None:
            return []
        batch = [first]
        while len(batch) < max_items:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        return batch

    def qsize(self) -> int:
        return self._q.qsize()

    @property
    def under_pressure(self) -> bool:
        return self._q.qsize() >= self.high_watermark

    def stats(self) -> dict[str, int]:
        return {
            "depth": self.qsize(),
            "capacity": self.maxsize,
            "accepted": self.accepted,
            "dropped": self.dropped,
            "deduplicated": self.dedup.suppressed,
        }
