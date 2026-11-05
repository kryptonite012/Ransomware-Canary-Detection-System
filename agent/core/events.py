"""Normalized event model used throughout the agent pipeline."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(str, Enum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"
    OPENED = "opened"
    CLOSED_WRITE = "closed_write"


# Event types that change file content or namespace ("destructive" operations
# from a ransomware perspective).  OPENED is informational only.
CHANGE_TYPES = frozenset({EventType.CREATED, EventType.MODIFIED, EventType.DELETED, EventType.MOVED,
                          EventType.CLOSED_WRITE})


@dataclass(slots=True)
class FileEvent:
    event_type: EventType
    src_path: str
    dest_path: str | None = None
    is_directory: bool = False
    timestamp: float = field(default_factory=time.time)
    monotonic: float = field(default_factory=time.monotonic)
    pid: int | None = None
    process_name: str | None = None
    attribution: str | None = None  # "audit", "io_correlation", None
    size: int | None = None
    coalesced: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def path(self) -> str:
        """The path that now holds the content (dest for moves)."""
        return self.dest_path or self.src_path

    @property
    def extension(self) -> str:
        return os.path.splitext(self.path)[1].lower()

    def dedup_key(self) -> tuple[str, str, str | None]:
        return (self.event_type.value, self.src_path, self.dest_path)
