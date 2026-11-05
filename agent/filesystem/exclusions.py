"""Path exclusion rules and self-write suppression.

Two things must never feed back into detection:

1. The agent's own storage (database, logs, evidence vault, snapshots).
   Monitoring them would create a recursive loop where every write the agent
   performs produces another event.
2. Files the agent itself writes inside monitored directories (canary
   deployment / regeneration).  These are registered in ``SelfWriteGuard`` for
   a short window and ignored.
"""
from __future__ import annotations

import fnmatch
import os
import sys
import threading
import time
from collections.abc import Iterable

_CASE_INSENSITIVE = sys.platform in ("win32", "darwin")


def normalize(path: str) -> str:
    p = os.path.normpath(os.path.abspath(path))
    if _CASE_INSENSITIVE:
        p = p.lower()
    return p


def _to_match_form(path: str) -> str:
    p = path.replace("\\", "/")
    return p.lower() if _CASE_INSENSITIVE else p


class ExclusionRules:
    def __init__(self, patterns: Iterable[str], directories: Iterable[str]):
        self.patterns = [_to_match_form(p) for p in patterns]
        self.directories = sorted({normalize(d) for d in directories if d})

    def add_directory(self, directory: str) -> None:
        d = normalize(directory)
        if d not in self.directories:
            self.directories.append(d)
            self.directories.sort()

    def is_excluded(self, path: str) -> bool:
        norm = normalize(path)
        for d in self.directories:
            if norm == d or norm.startswith(d + os.sep):
                return True
        match_form = _to_match_form(norm)
        base = match_form.rsplit("/", 1)[-1]
        for pat in self.patterns:
            if "/" in pat:
                if fnmatch.fnmatchcase(match_form, pat):
                    return True
            elif fnmatch.fnmatchcase(base, pat):
                return True
        return False


class SelfWriteGuard:
    """Registry of paths the agent is about to touch."""

    def __init__(self, ttl_seconds: float = 3.0):
        self.ttl = ttl_seconds
        self._paths: dict[str, float] = {}
        self._lock = threading.Lock()

    def register(self, path: str, ttl: float | None = None) -> None:
        with self._lock:
            self._paths[normalize(path)] = time.monotonic() + (ttl if ttl is not None else self.ttl)

    def is_self_write(self, path: str) -> bool:
        now = time.monotonic()
        key = normalize(path)
        with self._lock:
            expiry = self._paths.get(key)
            if expiry is None:
                return False
            if expiry < now:
                del self._paths[key]
                return False
            return True

    def purge(self) -> None:
        now = time.monotonic()
        with self._lock:
            for k in [k for k, v in self._paths.items() if v < now]:
                del self._paths[k]


def is_within(path: str, root: str) -> bool:
    p, r = normalize(path), normalize(root)
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)
