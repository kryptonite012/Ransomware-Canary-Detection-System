"""Persistence layer used by the agent.

High-volume telemetry (file events, inventory updates, entropy history) is
buffered in memory and flushed in batches by a dedicated writer thread, so a
slow disk or a locked database never blocks event processing.  Low-volume,
high-value records (alerts, incidents, canary state) are written immediately.
"""
from __future__ import annotations

import logging
import platform
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import and_, delete, func, insert, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from agent.version import __version__
from backend.database import make_session_factory, session_scope, utcnow
from backend.models import (
    AgentCommand,
    Endpoint,
    EntropyHistory,
    FileEvent as FileEventRow,
    FileInventory,
    MonitoredDirectory,
    SystemConfiguration,
)

log = logging.getLogger("sentinel.store")


def _upsert(session: Session, model, rows: list[dict[str, Any]], keys: list[str], update_cols: list[str]) -> None:
    if not rows:
        return
    dialect = session.bind.dialect.name  # type: ignore[union-attr]
    if dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as d_insert
    elif dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as d_insert
    else:  # pragma: no cover - generic fallback
        for row in rows:
            session.merge(model(**row))
        return
    stmt = d_insert(model).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=keys, set_={c: getattr(stmt.excluded, c) for c in update_cols}
    )
    session.execute(stmt)


class AgentStore:
    def __init__(self, database_url: str, flush_interval: float = 1.0, batch_size: int = 500,
                 max_buffer: int = 200_000):
        self.database_url = database_url
        self.factory: sessionmaker[Session] = make_session_factory(database_url)
        self.flush_interval = flush_interval
        self.batch_size = batch_size
        self.max_buffer = max_buffer
        self.endpoint_id: int | None = None
        self._events: deque[dict[str, Any]] = deque()
        self._inventory: dict[str, dict[str, Any]] = {}
        self._entropy: deque[dict[str, Any]] = deque()
        self._buf_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.rows_written = 0
        self.rows_dropped = 0
        self.write_errors = 0
        self.last_flush_seconds = 0.0

    # ----------------------------------------------------------------- sessions
    def session(self):
        return session_scope(self.factory)

    def run(self, fn: Callable[[Session], Any], retries: int = 3) -> Any:
        """Execute ``fn`` in a transaction, retrying on transient lock errors."""
        delay = 0.2
        for attempt in range(retries):
            try:
                with self.session() as s:
                    return fn(s)
            except OperationalError as exc:
                if attempt == retries - 1 or "locked" not in str(exc).lower():
                    raise
                time.sleep(delay)
                delay *= 2
        return None

    # ----------------------------------------------------------------- endpoint
    def register_endpoint(self, hostname: str, capabilities: dict[str, Any]) -> int:
        os_name = f"{platform.system()} {platform.release()}".strip()

        def _do(s: Session) -> int:
            ep = s.scalar(select(Endpoint).where(Endpoint.hostname == hostname))
            now = utcnow()
            if ep is None:
                ep = Endpoint(hostname=hostname, operating_system=os_name, agent_version=__version__,
                              status="starting", last_seen=now, started_at=now, capabilities=capabilities)
                s.add(ep)
                s.flush()
            else:
                ep.operating_system = os_name
                ep.agent_version = __version__
                ep.status = "starting"
                ep.last_seen = now
                ep.started_at = now
                ep.capabilities = capabilities
            return ep.id

        self.endpoint_id = self.run(_do)
        return self.endpoint_id

    def heartbeat(self, status: str, health: dict[str, Any], risk_score: float | None = None,
                  risk_level: str | None = None, risk_details: dict[str, Any] | None = None,
                  policy_version: int | None = None) -> None:
        values: dict[str, Any] = {"status": status, "health": health, "last_seen": utcnow()}
        if risk_score is not None:
            values["current_risk_score"] = round(float(risk_score), 2)
        if risk_level is not None:
            values["current_risk_level"] = risk_level
        if risk_details is not None:
            values["risk_details"] = risk_details
        if policy_version is not None:
            values["policy_version"] = policy_version
        self.run(lambda s: s.execute(update(Endpoint).where(Endpoint.id == self.endpoint_id).values(**values)))

    # ----------------------------------------------------------------- config / dirs
    def latest_policy(self) -> SystemConfiguration | None:
        def _do(s: Session):
            row = s.scalar(select(SystemConfiguration).order_by(SystemConfiguration.version.desc()).limit(1))
            if row is not None:
                s.expunge(row)
            return row

        return self.run(_do)

    def monitored_directories(self) -> list[MonitoredDirectory]:
        def _do(s: Session):
            rows = list(s.scalars(select(MonitoredDirectory).where(
                MonitoredDirectory.endpoint_id == self.endpoint_id)))
            for r in rows:
                s.expunge(r)
            return rows

        return self.run(_do)

    def set_directory_status(self, dir_id: int, status: str, detail: str | None) -> None:
        self.run(lambda s: s.execute(update(MonitoredDirectory).where(MonitoredDirectory.id == dir_id)
                                     .values(status=status, status_detail=(detail or None) and detail[:500])))

    # ----------------------------------------------------------------- commands
    def pending_commands(self) -> list[AgentCommand]:
        def _do(s: Session):
            rows = list(s.scalars(select(AgentCommand).where(
                and_(AgentCommand.endpoint_id == self.endpoint_id, AgentCommand.status == "pending"))
                .order_by(AgentCommand.id).limit(20)))
            for r in rows:
                s.expunge(r)
            return rows

        return self.run(_do)

    def update_command(self, command_id: int, status: str, result: dict[str, Any] | None = None) -> None:
        values: dict[str, Any] = {"status": status}
        now = utcnow()
        if status == "running":
            values["started_at"] = now
        else:
            values["completed_at"] = now
        if result is not None:
            values["result"] = result
        self.run(lambda s: s.execute(update(AgentCommand).where(AgentCommand.id == command_id).values(**values)))

    # ----------------------------------------------------------------- buffered telemetry
    def add_file_event(self, row: dict[str, Any]) -> None:
        with self._buf_lock:
            if len(self._events) >= self.max_buffer:
                self.rows_dropped += 1
                return
            row.setdefault("endpoint_id", self.endpoint_id)
            self._events.append(row)

    def add_inventory(self, rows: Iterable[dict[str, Any]]) -> None:
        with self._buf_lock:
            for row in rows:
                row.setdefault("endpoint_id", self.endpoint_id)
                existing = self._inventory.get(row["file_path"])
                if existing:
                    existing.update(row)
                else:
                    self._inventory[row["file_path"]] = row

    def add_entropy_record(self, row: dict[str, Any]) -> None:
        with self._buf_lock:
            row.setdefault("endpoint_id", self.endpoint_id)
            self._entropy.append(row)

    def pending_rows(self) -> int:
        with self._buf_lock:
            return len(self._events) + len(self._inventory) + len(self._entropy)

    def flush(self) -> int:
        with self._buf_lock:
            events = [self._events.popleft() for _ in range(min(len(self._events), self.batch_size * 10))]
            inventory = list(self._inventory.values())
            self._inventory.clear()
            entropy = list(self._entropy)
            self._entropy.clear()
        if not (events or inventory or entropy):
            return 0
        start = time.monotonic()
        written = 0
        try:
            def _do(s: Session) -> None:
                nonlocal written
                for i in range(0, len(events), self.batch_size):
                    chunk = events[i: i + self.batch_size]
                    s.execute(insert(FileEventRow), chunk)
                    written += len(chunk)
                inv_cols = ["extension", "category", "size", "mtime", "entropy", "magic_ok", "last_scanned",
                            "last_modified_event", "deleted"]
                # Group by key-set so partial updates do not clobber unrelated columns.
                groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
                for r in inventory:
                    groups.setdefault(tuple(sorted(r.keys())), []).append(r)
                for keyset, rows in groups.items():
                    cols = [c for c in inv_cols if c in keyset]
                    for i in range(0, len(rows), self.batch_size):
                        _upsert(s, FileInventory, rows[i: i + self.batch_size], ["endpoint_id", "file_path"],
                                cols or ["deleted"])
                    written += len(rows)
                if entropy:
                    s.execute(insert(EntropyHistory), entropy)
                    written += len(entropy)

            self.run(_do)
            self.rows_written += written
        except Exception:
            self.write_errors += 1
            log.exception("failed to flush %d telemetry rows; re-queueing", len(events) + len(inventory))
            with self._buf_lock:
                # Put events back at the front (bounded) so a transient failure loses nothing.
                for row in reversed(events):
                    if len(self._events) < self.max_buffer:
                        self._events.appendleft(row)
                    else:
                        self.rows_dropped += 1
                for r in inventory:
                    self._inventory.setdefault(r["file_path"], r)
                self._entropy.extendleft(reversed(entropy))
        self.last_flush_seconds = time.monotonic() - start
        return written

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sentinel-db-writer", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.flush_interval):
            try:
                while self.flush() >= self.batch_size * 10:
                    pass
            except Exception:  # pragma: no cover - defensive
                log.exception("db writer loop error")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        # Final drain.
        for _ in range(100):
            if self.flush() == 0:
                break

    # ----------------------------------------------------------------- queries
    def inventory_snapshot(self) -> dict[str, tuple[int | None, float | None, float | None, bool | None]]:
        """path -> (size, mtime, entropy, magic_ok) for entropy baselines after restart."""
        def _do(s: Session):
            rows = s.execute(select(FileInventory.file_path, FileInventory.size, FileInventory.mtime,
                                    FileInventory.entropy, FileInventory.magic_ok)
                             .where(FileInventory.endpoint_id == self.endpoint_id,
                                    FileInventory.deleted.is_(False)))
            return {r[0]: (r[1], r[2], r[3], r[4]) for r in rows}

        return self.run(_do)

    def count_inventory(self) -> int:
        return self.run(lambda s: s.scalar(select(func.count()).select_from(FileInventory).where(
            FileInventory.endpoint_id == self.endpoint_id, FileInventory.deleted.is_(False)))) or 0

    def purge_older_than(self, model, column, days: int, extra_filter=None) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        def _do(s: Session) -> int:
            stmt = delete(model).where(column < cutoff)
            if extra_filter is not None:
                stmt = stmt.where(extra_filter)
            return s.execute(stmt).rowcount or 0

        return self.run(_do)
