"""SentinelAgent - the long-running endpoint service.

Thread layout::

    watchdog observer ──► BoundedEventQueue ──► pipeline thread ──► detectors / risk engine
                                                     │                   │
                                                     ▼                   ▼
                                                AgentStore (batched writer thread) ◄── response engine
    heartbeat thread  : endpoint health, risk decay, policy reload, retention
    command thread    : executes signed control-plane commands
    inventory thread  : background baseline scan

The agent works without the API/dashboard running and without network access:
everything it needs is local (configuration, public key, database).
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

import psutil

from agent.core.config import SentinelConfig
from agent.core.events import EventType, FileEvent
from agent.core.policy import PolicyManager
from agent.core.queue import BoundedEventQueue
from agent.core.signing import command_payload
from agent.core.store import AgentStore
from agent.filesystem.exclusions import ExclusionRules, SelfWriteGuard
from agent.filesystem.inventory import InventoryEntry, InventoryScanner
from agent.filesystem.monitor import FilesystemMonitor
from agent.version import __version__
from backend.database import run_migrations

log = logging.getLogger("sentinel.agent")

CommandHandler = Callable[[dict[str, Any]], dict[str, Any]]


class SentinelAgent:
    def __init__(self, config: SentinelConfig):
        self.base_config = config
        self.config = config
        self.policy_version: int | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.started_at: float | None = None
        self.events_processed = 0
        self.processing_errors = 0
        self._last_rate_sample = (time.monotonic(), 0)
        self.events_per_second = 0.0
        self.tamper_findings: list[str] = []
        self.command_handlers: dict[str, CommandHandler] = {}
        self.directory_ids: dict[str, int | None] = {}
        self._proc = psutil.Process()
        self._proc.cpu_percent(None)
        self.inventory_scanner: InventoryScanner | None = None
        self.engines: Any = None  # populated by agent.core.engines (detection components)
        self._register_builtin_commands()

    # ================================================================== lifecycle
    def start(self) -> None:
        cfg = self.config
        data = cfg.agent.data_path()
        for sub in ("", "secrets", "evidence", "snapshots", "state", "logs"):
            (data / sub).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(data, 0o700)
            os.chmod(data / "secrets", 0o700)
        except OSError:
            pass

        db_url = cfg.agent.resolved_database_url()
        log.info("starting PROJECT SENTINEL agent v%s (pid %d)", __version__, os.getpid())
        run_migrations(db_url)
        self.store = AgentStore(db_url, cfg.agent.db_flush_interval_seconds, cfg.agent.db_batch_size)
        self.store.register_endpoint(cfg.agent.resolved_endpoint_name(), self.capabilities())
        self.endpoint_id = self.store.endpoint_id

        self.policy = PolicyManager(self.base_config, self.store)
        state = self.policy.resolve()
        self.config = state.config
        self.policy_version = state.version
        self.tamper_findings.extend(state.tamper_findings)

        self.queue = BoundedEventQueue(
            self.config.agent.queue_size,
            self.config.monitoring.dedup_window_ms / 1000.0,
            self.config.agent.queue_high_watermark,
        )
        self.exclusions = self._build_exclusions()
        self.self_writes = SelfWriteGuard()
        self.monitor = FilesystemMonitor(self.queue, self.exclusions, self.self_writes,
                                         detect_reads=self.config.monitoring.detect_reads)

        # Detection engines are optional in phase 1; they are wired here when present.
        from agent.core.engines import build_engines  # local import keeps module graph acyclic
        self.engines = build_engines(self)

        self.store.start()
        self.monitor.start()
        self.started_at = time.time()
        self._apply_directories()

        self._spawn(self._pipeline_loop, "sentinel-pipeline")
        self._spawn(self._heartbeat_loop, "sentinel-heartbeat")
        self._spawn(self._command_loop, "sentinel-commands")
        if self.config.monitoring.inventory_scan_on_start:
            self._spawn(self._inventory_job, "sentinel-inventory")
        if self.engines is not None:
            self.engines.start()
        for finding in self.tamper_findings:
            self._report_tamper(finding)
        self.store.heartbeat("online", self.health())
        log.info("agent started; monitoring %d director(ies)", len(self.monitor.active_directories()))

    def _spawn(self, target: Callable[[], None], name: str) -> None:
        t = threading.Thread(target=self._guard(target, name), name=name, daemon=True)
        t.start()
        self._threads.append(t)

    def _guard(self, target: Callable[[], None], name: str) -> Callable[[], None]:
        """Restart a worker loop if it crashes unexpectedly (self-healing)."""
        def runner() -> None:
            backoff = 1.0
            while not self._stop.is_set():
                try:
                    target()
                    return
                except Exception:
                    log.exception("worker %s crashed; restarting in %.0fs", name, backoff)
                    if self._stop.wait(backoff):
                        return
                    backoff = min(backoff * 2, 60)
        return runner

    def stop(self) -> None:
        if self._stop.is_set():
            return
        log.info("stopping agent")
        self._stop.set()
        try:
            self.monitor.stop()
        except Exception:
            log.exception("error stopping monitor")
        if self.engines is not None:
            self.engines.stop()
        # Drain what is already queued (bounded time) so no telemetry is lost.
        deadline = time.monotonic() + 5
        while self.queue.qsize() and time.monotonic() < deadline:
            self._process_batch(self.queue.get_batch(500, 0.05))
        for t in self._threads:
            t.join(timeout=5)
        try:
            self.store.heartbeat("stopped", self.health())
        except Exception:
            log.exception("final heartbeat failed")
        self.store.stop()
        log.info("agent stopped")

    def run_forever(self) -> None:
        self.start()
        try:
            while not self._stop.wait(1.0):
                pass
        finally:
            self.stop()

    def request_stop(self) -> None:
        self._stop.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    # ================================================================== configuration
    def _build_exclusions(self) -> ExclusionRules:
        cfg = self.config
        rules = ExclusionRules(cfg.monitoring.exclude_patterns, cfg.monitoring.exclude_directories)
        # Never monitor our own storage (prevents recursive event loops).
        rules.add_directory(str(cfg.agent.data_path()))
        db_url = cfg.agent.resolved_database_url()
        if db_url.startswith("sqlite:///"):
            rules.add_directory(os.path.dirname(db_url.split("///", 1)[1]))
        if cfg.agent.log_file:
            rules.add_directory(os.path.dirname(os.path.abspath(cfg.agent.log_file)))
        return rules

    def _apply_directories(self) -> None:
        dirs, findings = self.policy.resolve_directories(self.config)
        for f in findings:
            if f not in self.tamper_findings:
                self.tamper_findings.append(f)
                self._report_tamper(f)
        wanted = {}
        data_dir = str(self.config.agent.data_path())
        for d, row_id in dirs:
            path = os.path.abspath(os.path.expanduser(d.path))
            if data_dir.startswith(path.rstrip(os.sep) + os.sep) or path == data_dir:
                log.warning("monitored directory %s contains the agent data directory; it stays excluded", path)
            wanted[path] = (d.recursive, row_id)
        for existing in list(self.monitor.watches):
            if existing not in wanted:
                self.monitor.remove_directory(existing)
                if self.engines is not None:
                    self.engines.on_directory_removed(existing)
        for path, (recursive, row_id) in wanted.items():
            status = self.monitor.add_directory(path, recursive)
            self.directory_ids[path] = row_id
            if row_id is not None:
                self.store.set_directory_status(row_id, status.state, status.detail)
            if status.state == "active" and self.engines is not None:
                self.engines.on_directory_added(path)

    def monitored_roots(self) -> list[tuple[str, bool]]:
        return [(p, s.recursive) for p, s in self.monitor.watches.items() if s.state == "active"]

    def reload_policy(self) -> bool:
        state = self.policy.resolve(self.policy_version)
        for f in state.tamper_findings:
            if f not in self.tamper_findings:
                self.tamper_findings.append(f)
                self._report_tamper(f)
        changed = state.source == "database" and state.version != self.policy_version
        if changed:
            log.info("applying signed policy v%s", state.version)
            self.config = state.config
            self.policy_version = state.version
            self.exclusions.patterns = ExclusionRules(self.config.monitoring.exclude_patterns, []).patterns
            for d in self.config.monitoring.exclude_directories:
                self.exclusions.add_directory(d)
            self.queue.dedup.window = self.config.monitoring.dedup_window_ms / 1000.0
            if self.engines is not None:
                self.engines.on_config_changed(self.config)
        self._apply_directories()
        return changed

    def _report_tamper(self, finding: str) -> None:
        log.error("integrity finding: %s", finding)
        if self.engines is not None:
            self.engines.report_tamper(finding)

    # ================================================================== pipeline
    def _pipeline_loop(self) -> None:
        while not self._stop.is_set():
            batch = self.queue.get_batch(500, 0.25)
            if batch:
                self._process_batch(batch)
            elif self.engines is not None:
                self.engines.idle_tick()

    def _process_batch(self, batch: list[FileEvent]) -> None:
        for ev in batch:
            try:
                self._process_event(ev)
            except Exception:
                self.processing_errors += 1
                log.exception("error processing event %s %s", ev.event_type, ev.src_path)
            self.events_processed += 1

    def _process_event(self, ev: FileEvent) -> None:
        if self.engines is not None:
            self.engines.enrich(ev)
        if ev.event_type is not EventType.CLOSED_WRITE and ev.event_type is not EventType.OPENED:
            self._persist_event(ev)
        if self.engines is not None:
            self.engines.process(ev)

    def _persist_event(self, ev: FileEvent) -> None:
        ts = datetime.fromtimestamp(ev.timestamp, timezone.utc)
        self.store.add_file_event({
            "file_path": ev.src_path[:2048],
            "dest_path": ev.dest_path[:2048] if ev.dest_path else None,
            "event_type": ev.event_type.value,
            "is_directory": ev.is_directory,
            "process_id": ev.pid,
            "process_name": ev.process_name,
            "attribution": ev.attribution,
            "file_size": ev.size,
            "timestamp": ts,
            "event_metadata": ev.metadata or None,
        })
        if ev.is_directory:
            return
        if ev.event_type is EventType.DELETED:
            self.store.add_inventory([{"file_path": ev.src_path, "deleted": True}])
        elif ev.event_type is EventType.MOVED:
            self.store.add_inventory([{"file_path": ev.src_path, "deleted": True}])
            self.store.add_inventory([{"file_path": ev.dest_path, "deleted": False, "size": ev.size,
                                       "last_modified_event": ts}])
        else:
            self.store.add_inventory([{"file_path": ev.src_path, "deleted": False, "size": ev.size,
                                       "last_modified_event": ts}])

    # ================================================================== inventory
    def _inventory_job(self) -> None:
        from agent.entropy.filetypes import extension_of, category_for

        def on_batch(entries: list[InventoryEntry]) -> None:
            now = datetime.now(timezone.utc)
            self.store.add_inventory([{
                "file_path": e.path, "extension": e.extension, "category": e.category, "size": e.size,
                "mtime": e.mtime, "last_scanned": now, "deleted": False,
            } for e in entries])
            if self.engines is not None:
                self.engines.on_inventory_batch(entries)

        _ = (extension_of, category_for)
        self.inventory_scanner = InventoryScanner(self.exclusions, self.config.monitoring.inventory_max_files,
                                                  on_batch)
        self.inventory_scanner.scan(self.monitored_roots(), self._stop)

    # ================================================================== heartbeat
    def _heartbeat_loop(self) -> None:
        last_policy = time.monotonic()
        last_inventory = time.monotonic()
        while not self._stop.wait(self.config.agent.heartbeat_interval_seconds):
            now = time.monotonic()
            if now - last_policy >= self.config.agent.config_poll_interval_seconds:
                last_policy = now
                try:
                    self.reload_policy()
                except Exception:
                    log.exception("policy reload failed")
            if now - last_inventory >= self.config.monitoring.inventory_rescan_hours * 3600:
                last_inventory = now
                self._spawn(self._inventory_job, "sentinel-inventory")
            self.self_writes.purge()
            risk = self.engines.risk_snapshot() if self.engines is not None else None
            status = "degraded" if (not self.monitor.alive or self.queue.dropped) else "online"
            try:
                self.store.heartbeat(
                    status, self.health(),
                    risk_score=risk["score"] if risk else None,
                    risk_level=risk["level"] if risk else None,
                    risk_details=risk,
                    policy_version=self.policy_version,
                )
            except Exception:
                log.exception("heartbeat failed")
            if self.engines is not None:
                self.engines.periodic()

    def health(self) -> dict[str, Any]:
        now = time.monotonic()
        last_t, last_n = self._last_rate_sample
        if now - last_t >= 1:
            self.events_per_second = round((self.events_processed - last_n) / (now - last_t), 2)
            self._last_rate_sample = (now, self.events_processed)
        try:
            mem = self._proc.memory_info().rss
            cpu = self._proc.cpu_percent(None)
            threads = self._proc.num_threads()
        except psutil.Error:
            mem, cpu, threads = None, None, None
        watches = {p: {"state": s.state, "detail": s.detail, "recursive": s.recursive}
                   for p, s in self.monitor.watches.items()}
        health: dict[str, Any] = {
            "agent_version": __version__,
            "pid": os.getpid(),
            "uptime_seconds": round(time.time() - self.started_at, 1) if self.started_at else 0,
            "cpu_percent": cpu,
            "memory_rss_bytes": mem,
            "threads": threads,
            "monitor_alive": self.monitor.alive,
            "watches": watches,
            "queue": self.queue.stats(),
            "events_seen": self.monitor.events_seen,
            "events_excluded": self.monitor.events_excluded,
            "events_processed": self.events_processed,
            "events_per_second": self.events_per_second,
            "processing_errors": self.processing_errors,
            "db_pending_rows": self.store.pending_rows(),
            "db_rows_written": self.store.rows_written,
            "db_write_errors": self.store.write_errors,
            "db_rows_dropped": self.store.rows_dropped,
            "policy_version": self.policy_version,
            "signed_instructions": self.policy.can_verify,
            "tamper_findings": self.tamper_findings[-10:],
            "inventory_files": self.inventory_scanner.files_scanned if self.inventory_scanner else 0,
            "inventory_truncated": self.inventory_scanner.truncated if self.inventory_scanner else False,
        }
        if self.engines is not None:
            health.update(self.engines.health())
        return health

    def capabilities(self) -> dict[str, Any]:
        from agent.telemetry.attribution import attribution_capabilities
        return {
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "filesystem_backend": _fs_backend_name(),
            "privileged": _is_privileged(),
            **attribution_capabilities(),
        }

    # ================================================================== commands
    def _register_builtin_commands(self) -> None:
        self.command_handlers["ping"] = lambda params: {"pong": True, "time": time.time()}
        self.command_handlers["reload_config"] = lambda params: {"changed": self.reload_policy(),
                                                                 "policy_version": self.policy_version}
        self.command_handlers["rescan_inventory"] = self._cmd_rescan

    def _cmd_rescan(self, params: dict[str, Any]) -> dict[str, Any]:
        self._spawn(self._inventory_job, "sentinel-inventory")
        return {"started": True}

    def _command_loop(self) -> None:
        while not self._stop.wait(self.config.agent.command_poll_interval_seconds):
            try:
                commands = self.store.pending_commands()
            except Exception:
                log.exception("cannot poll commands")
                continue
            for cmd in commands:
                self._execute_command(cmd)

    def _execute_command(self, cmd) -> None:
        payload = command_payload(cmd.id, cmd.endpoint_id, cmd.command, cmd.params or {})
        verifier = self.policy.verifier
        if verifier is None or not verifier.verify(payload, cmd.signature):
            msg = f"command #{cmd.id} ({cmd.command}) rejected: invalid or missing signature"
            self.store.update_command(cmd.id, "rejected", {"error": "invalid signature"})
            self._report_tamper(msg)
            return
        handler = self.command_handlers.get(cmd.command)
        if handler is None:
            self.store.update_command(cmd.id, "failed", {"error": f"unknown command {cmd.command}"})
            return
        self.store.update_command(cmd.id, "running")
        try:
            result = handler(cmd.params or {})
            self.store.update_command(cmd.id, "completed", result)
            log.info("command #%d %s completed", cmd.id, cmd.command)
        except Exception as exc:
            log.exception("command #%d %s failed", cmd.id, cmd.command)
            self.store.update_command(cmd.id, "failed", {"error": str(exc)[:500]})


def _fs_backend_name() -> str:
    from watchdog.observers import Observer
    return Observer.__name__


def _is_privileged() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return os.geteuid() == 0
