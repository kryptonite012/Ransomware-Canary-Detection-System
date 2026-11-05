"""Filesystem monitoring via watchdog.

watchdog selects the native notification API per platform:

* Linux   - inotify
* Windows - ReadDirectoryChangesW
* macOS   - FSEvents

The handler runs on watchdog's observer thread, so it does the minimum amount
of work: normalize the event and push it into the bounded queue.
"""
from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field

from watchdog.events import (
    DirCreatedEvent,
    DirDeletedEvent,
    DirMovedEvent,
    FileClosedEvent,
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileOpenedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from agent.core.events import EventType, FileEvent
from agent.core.queue import BoundedEventQueue
from agent.filesystem.exclusions import ExclusionRules, SelfWriteGuard

log = logging.getLogger("sentinel.filesystem")

_TYPE_MAP: dict[str, EventType] = {
    "created": EventType.CREATED,
    "modified": EventType.MODIFIED,
    "deleted": EventType.DELETED,
    "moved": EventType.MOVED,
    "opened": EventType.OPENED,
    "closed": EventType.CLOSED_WRITE,
}


def _decode(p: bytes | str) -> str:
    return os.fsdecode(p) if isinstance(p, bytes) else p


class _Handler(FileSystemEventHandler):
    def __init__(self, monitor: "FilesystemMonitor"):
        super().__init__()
        self.monitor = monitor

    def on_any_event(self, event: FileSystemEvent) -> None:  # noqa: D401 - watchdog API
        try:
            self.monitor.handle_raw(event)
        except Exception:  # never let the observer thread die
            log.exception("error handling filesystem event")


@dataclass
class WatchStatus:
    path: str
    recursive: bool
    state: str = "pending"  # active | error | missing
    detail: str | None = None
    watch: object | None = field(default=None, repr=False)


class FilesystemMonitor:
    def __init__(
        self,
        event_queue: BoundedEventQueue,
        exclusions: ExclusionRules,
        self_writes: SelfWriteGuard,
        detect_reads: bool = False,
    ):
        self.queue = event_queue
        self.exclusions = exclusions
        self.self_writes = self_writes
        self.detect_reads = detect_reads
        self.observer = Observer()
        self.handler = _Handler(self)
        self.watches: dict[str, WatchStatus] = {}
        self._lock = threading.Lock()
        self._started = False
        self.events_seen = 0
        self.events_excluded = 0
        self.read_paths_of_interest: set[str] = set()

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if not self._started:
            self.observer.daemon = True
            self.observer.start()
            self._started = True

    def stop(self, timeout: float = 5.0) -> None:
        if self._started:
            self.observer.stop()
            self.observer.join(timeout)
            self._started = False

    @property
    def alive(self) -> bool:
        return self._started and self.observer.is_alive()

    def _event_filter(self) -> list[type[FileSystemEvent]]:
        types: list[type[FileSystemEvent]] = [
            FileCreatedEvent, FileModifiedEvent, FileDeletedEvent, FileMovedEvent,
            DirCreatedEvent, DirDeletedEvent, DirMovedEvent, FileClosedEvent,
        ]
        if self.detect_reads:
            types.append(FileOpenedEvent)
        return types

    def add_directory(self, path: str, recursive: bool = True) -> WatchStatus:
        path = os.path.abspath(os.path.expanduser(path))
        with self._lock:
            existing = self.watches.get(path)
            if existing and existing.state == "active":
                return existing
            status = WatchStatus(path=path, recursive=recursive)
            self.watches[path] = status
        if not os.path.isdir(path):
            status.state, status.detail = "missing", "directory does not exist"
            log.warning("monitored directory missing: %s", path)
            return status
        if not os.access(path, os.R_OK | os.X_OK):
            status.state, status.detail = "error", "permission denied"
            log.warning("no permission to monitor %s", path)
            return status
        try:
            status.watch = self.observer.schedule(
                self.handler, path, recursive=recursive, event_filter=self._event_filter()
            )
            status.state, status.detail = "active", None
            log.info("monitoring %s (recursive=%s)", path, recursive)
        except OSError as exc:
            # e.g. inotify watch limit reached (ENOSPC) or permission errors in subtrees
            status.state, status.detail = "error", f"{exc.__class__.__name__}: {exc}"
            log.error("failed to monitor %s: %s", path, exc)
        return status

    def remove_directory(self, path: str) -> None:
        path = os.path.abspath(os.path.expanduser(path))
        with self._lock:
            status = self.watches.pop(path, None)
        if status and status.watch is not None:
            try:
                self.observer.unschedule(status.watch)
            except (KeyError, ValueError):
                pass
            log.info("stopped monitoring %s", path)

    def active_directories(self) -> list[str]:
        return [p for p, s in self.watches.items() if s.state == "active"]

    # ---------------------------------------------------------------- events
    def handle_raw(self, event: FileSystemEvent) -> None:
        etype = _TYPE_MAP.get(event.event_type)
        if etype is None:
            return
        src = _decode(event.src_path)
        dest = _decode(event.dest_path) if getattr(event, "dest_path", None) else None
        self.events_seen += 1

        if etype is EventType.OPENED:
            # Reads are only interesting for canary files (high noise otherwise).
            if src not in self.read_paths_of_interest:
                return
        if etype is EventType.CLOSED_WRITE and event.is_directory:
            return

        check_path = dest or src
        if self.self_writes.is_self_write(src) or (dest and self.self_writes.is_self_write(dest)):
            return
        src_excluded = self.exclusions.is_excluded(src)
        dest_excluded = self.exclusions.is_excluded(dest) if dest else src_excluded
        if src_excluded and dest_excluded:
            self.events_excluded += 1
            return
        if etype is EventType.MOVED and src_excluded and not dest_excluded:
            # e.g. editor writes "file.tmp" then renames to "file.docx": treat as a write.
            etype, src, dest = EventType.MODIFIED, dest, None
            check_path = src
        elif etype is EventType.MOVED and dest_excluded and not src_excluded:
            # Moved out of scope (e.g. into an excluded trash folder): treat as delete.
            etype, dest = EventType.DELETED, None
            check_path = src

        size = None
        if etype in (EventType.CREATED, EventType.MODIFIED, EventType.MOVED, EventType.CLOSED_WRITE) and not \
                event.is_directory:
            try:
                size = os.stat(check_path).st_size
            except OSError:
                size = None
        self.queue.put(
            FileEvent(event_type=etype, src_path=src, dest_path=dest, is_directory=event.is_directory, size=size)
        )
