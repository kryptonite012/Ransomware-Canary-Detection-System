"""Process telemetry and attribution.

Most cross-platform filesystem notification APIs (inotify, FSEvents,
ReadDirectoryChangesW) do **not** report which process caused an event.  Getting
the true PID per event requires privileged, OS-specific facilities (Linux
``fanotify``/audit, Windows ETW/minifilter, macOS Endpoint Security).  SENTINEL
uses those when a platform adapter reports they are available; otherwise it
falls back to **I/O correlation**:

* A sampling thread tracks every process's ``write_bytes`` and the set of
  directories it has open, via :mod:`psutil`.
* When a change event arrives, the most likely author is the running process
  with the highest recent disk-write rate (optionally confirmed by an open
  handle in the event's directory tree).

I/O correlation is a heuristic - results are tagged ``attribution="io_correlation"``
so the UI never presents a guess as ground truth.  It is still valuable: during
a real mass-encryption event one process dominates disk writes, and that is
exactly what this surfaces.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import psutil
from sqlalchemy import select, update

from agent.core.events import FileEvent
from backend.database import utcnow
from backend.models import Process

log = logging.getLogger("sentinel.telemetry")


@dataclass
class ProcInfo:
    pid: int
    name: str
    exe: str | None
    cmdline: str | None
    ppid: int | None
    username: str | None
    create_time: float
    last_write_bytes: int = 0
    write_rate: float = 0.0  # bytes/sec
    total_write: int = 0
    files_modified: int = 0
    last_activity: float = field(default=0.0)
    suspicious: bool = False
    reasons: list[str] = field(default_factory=list)
    db_id: int | None = None
    dirty: bool = True


class ProcessMonitor:
    def __init__(self, agent, coordinator, sample_interval: float = 2.0):
        self.agent = agent
        self.coordinator = coordinator
        self.sample_interval = sample_interval
        self.endpoint_id = agent.endpoint_id
        self._procs: dict[int, ProcInfo] = {}
        self._recent_writers: deque[tuple[float, int, float]] = deque(maxlen=50)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._have_io = hasattr(psutil.Process(), "io_counters")
        self.samples = 0
        self.protected_names = set(n.lower() for n in agent.config.response.protected_process_names)

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="sentinel-telemetry", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._flush_running_state()

    def _loop(self) -> None:
        # Prime io counters.
        self._sample()
        while not self._stop.wait(self.sample_interval):
            try:
                self._sample()
            except Exception:
                log.exception("process sampling error")

    # ------------------------------------------------------------------ sampling
    def _sample(self) -> None:
        now = time.monotonic()
        seen: set[int] = set()
        attrs = ["pid", "name", "ppid", "username", "create_time"]
        for proc in psutil.process_iter(attrs=attrs):
            try:
                info = proc.info
                pid = info["pid"]
                seen.add(pid)
                with self._lock:
                    pi = self._procs.get(pid)
                    if pi is None or pi.create_time != (info.get("create_time") or 0.0):
                        pi = self._make(proc, info)
                        self._procs[pid] = pi
                    if self._have_io:
                        try:
                            wb = proc.io_counters().write_bytes
                        except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError, OSError):
                            wb = pi.last_write_bytes
                        if pi.last_write_bytes and wb >= pi.last_write_bytes:
                            delta = wb - pi.last_write_bytes
                            pi.write_rate = delta / self.sample_interval
                            pi.total_write += delta
                            if pi.write_rate > 0:
                                self._recent_writers.append((now, pid, pi.write_rate))
                                pi.last_activity = now
                        pi.last_write_bytes = wb
                        if pi.write_rate > 0:
                            pi.dirty = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self.samples += 1
        self._mark_exited(seen)
        self._evaluate_suspicion()
        self._persist()

    def _make(self, proc: psutil.Process, info: dict) -> ProcInfo:
        exe = cmdline = None
        try:
            exe = proc.exe() or None
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass
        try:
            cl = proc.cmdline()
            cmdline = " ".join(cl)[:2000] if cl else None
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            pass
        return ProcInfo(
            pid=info["pid"], name=(info.get("name") or "?")[:255], exe=exe, cmdline=cmdline,
            ppid=info.get("ppid"), username=(info.get("username") or None),
            create_time=info.get("create_time") or 0.0, last_activity=time.monotonic())

    def _mark_exited(self, seen: set[int]) -> None:
        with self._lock:
            gone = [pid for pid in self._procs if pid not in seen]
            for pid in gone:
                pi = self._procs[pid]
                if pi.db_id is not None:
                    self.agent.store.run(lambda s, i=pi.db_id: s.execute(
                        update(Process).where(Process.id == i).values(
                            is_running=False, state="exited", last_seen=utcnow())))
                del self._procs[pid]

    # ------------------------------------------------------------------ suspicion
    def _evaluate_suspicion(self) -> None:
        b = self.agent.config.behavior
        with self._lock:
            procs = list(self._procs.values())
        for pi in procs:
            reasons: list[str] = []
            if pi.files_modified >= b.process_file_threshold:
                reasons.append(f"modified {pi.files_modified} files")
            if pi.write_rate >= b.process_write_rate_bytes:
                reasons.append(f"disk-write rate {pi.write_rate / 1e6:.1f} MB/s")
            if pi.name.lower() in self.protected_names:
                reasons = []  # never flag critical OS processes
            was = pi.suspicious
            pi.suspicious = bool(reasons)
            pi.reasons = reasons
            if pi.suspicious and not was and pi.name.lower() not in self.protected_names:
                pi.dirty = True
                self.coordinator.add_signal(
                    "suspicious_process",
                    f"process {pi.name} (pid {pi.pid}) {', '.join(reasons)}",
                    severity_hint="high",
                    evidence={"pid": pi.pid, "name": pi.name, "exe": pi.exe, "reasons": reasons,
                              "write_rate": round(pi.write_rate, 1), "files_modified": pi.files_modified})

    # ------------------------------------------------------------------ attribution
    def attribute(self, ev: FileEvent) -> dict[str, Any] | None:
        now = time.monotonic()
        with self._lock:
            candidates = [(t, pid, rate) for (t, pid, rate) in self._recent_writers if now - t <= 6.0]
        if not candidates:
            return None
        candidates.sort(key=lambda x: x[2], reverse=True)
        for _, pid, rate in candidates:
            with self._lock:
                pi = self._procs.get(pid)
            if pi is None or pi.name.lower() in self.protected_names:
                continue
            pi.files_modified += 1
            pi.dirty = True
            return {"pid": pid, "name": pi.name, "attribution": "io_correlation", "write_rate": rate}
        return None

    # ------------------------------------------------------------------ persistence
    def _persist(self) -> None:
        now = utcnow()
        with self._lock:
            dirty = [pi for pi in self._procs.values() if pi.dirty]
        for pi in dirty:
            self._persist_one(pi, now)

    def _persist_one(self, pi: ProcInfo, now: datetime) -> None:
        def _do(s):
            row = None
            if pi.db_id is not None:
                row = s.get(Process, pi.db_id)
            if row is None:
                row = s.scalar(select(Process).where(
                    Process.endpoint_id == self.endpoint_id, Process.process_id == pi.pid,
                    Process.create_time == pi.create_time))
            if row is None:
                row = Process(endpoint_id=self.endpoint_id, process_id=pi.pid, process_name=pi.name,
                              executable_path=pi.exe, command_line=pi.cmdline, parent_process_id=pi.ppid,
                              username=pi.username, create_time=pi.create_time, first_seen=now)
                s.add(row)
            row.last_seen = now
            row.is_running = True
            row.state = "running"
            row.write_bytes_rate = round(pi.write_rate, 1)
            row.total_write_bytes = pi.total_write
            row.files_modified = pi.files_modified
            row.suspicious = pi.suspicious
            row.suspicion_reasons = pi.reasons or None
            s.flush()
            return row.id

        try:
            pi.db_id = self.agent.store.run(_do)
            pi.dirty = False
        except Exception:
            log.exception("failed to persist process %s", pi.pid)

    def _flush_running_state(self) -> None:
        with self._lock:
            ids = [pi.db_id for pi in self._procs.values() if pi.db_id]
        if ids:
            self.agent.store.run(lambda s: s.execute(
                update(Process).where(Process.id.in_(ids)).values(last_seen=utcnow())))

    # ------------------------------------------------------------------ lookup / stats
    def get(self, pid: int) -> ProcInfo | None:
        with self._lock:
            return self._procs.get(pid)

    def suspicious_processes(self) -> list[ProcInfo]:
        with self._lock:
            return [pi for pi in self._procs.values() if pi.suspicious]

    def health(self) -> dict[str, Any]:
        with self._lock:
            return {"tracked_processes": len(self._procs), "samples": self.samples,
                    "io_counters": self._have_io,
                    "suspicious": sum(1 for p in self._procs.values() if p.suspicious)}
