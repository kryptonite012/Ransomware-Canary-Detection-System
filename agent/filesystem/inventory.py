"""Inventory scanner: enumerates monitored files to establish a baseline.

The scan runs in a background thread at low priority (it yields periodically)
and never follows symlinks, so a link pointing outside the monitored scope
cannot pull unrelated trees into the inventory.
"""
from __future__ import annotations

import logging
import os
import stat
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from agent.entropy.filetypes import category_for, extension_of
from agent.filesystem.exclusions import ExclusionRules

log = logging.getLogger("sentinel.inventory")


@dataclass(slots=True)
class InventoryEntry:
    path: str
    size: int
    mtime: float
    extension: str
    category: str


def iter_files(root: str, recursive: bool, exclusions: ExclusionRules,
               stop: threading.Event | None = None) -> Iterator[InventoryEntry]:
    stack = [root]
    while stack:
        if stop is not None and stop.is_set():
            return
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as exc:
            log.debug("cannot scan %s: %s", current, exc)
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                full = entry.path
                if exclusions.is_excluded(full):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if recursive:
                        stack.append(full)
                    continue
                st = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode):
                    continue
                yield InventoryEntry(
                    path=full,
                    size=st.st_size,
                    mtime=st.st_mtime,
                    extension=extension_of(full)[:32],
                    category=category_for(full).name,
                )
            except OSError:
                continue


class InventoryScanner:
    def __init__(self, exclusions: ExclusionRules, max_files: int,
                 on_batch: Callable[[list[InventoryEntry]], None], batch_size: int = 1000,
                 yield_every: int = 2000, yield_seconds: float = 0.01):
        self.exclusions = exclusions
        self.max_files = max_files
        self.on_batch = on_batch
        self.batch_size = batch_size
        self.yield_every = yield_every
        self.yield_seconds = yield_seconds
        self.files_scanned = 0
        self.last_duration: float | None = None
        self.truncated = False

    def scan(self, directories: list[tuple[str, bool]], stop: threading.Event | None = None) -> int:
        start = time.monotonic()
        self.files_scanned = 0
        self.truncated = False
        batch: list[InventoryEntry] = []
        for root, recursive in directories:
            for entry in iter_files(root, recursive, self.exclusions, stop):
                batch.append(entry)
                self.files_scanned += 1
                if len(batch) >= self.batch_size:
                    self.on_batch(batch)
                    batch = []
                if self.files_scanned % self.yield_every == 0:
                    time.sleep(self.yield_seconds)
                if self.files_scanned >= self.max_files:
                    self.truncated = True
                    log.warning("inventory limit of %d files reached; remaining files not baselined",
                                self.max_files)
                    break
            if self.truncated or (stop is not None and stop.is_set()):
                break
        if batch:
            self.on_batch(batch)
        self.last_duration = time.monotonic() - start
        log.info("inventory scan complete: %d files in %.2fs", self.files_scanned, self.last_duration)
        return self.files_scanned
