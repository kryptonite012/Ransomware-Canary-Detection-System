"""DetectionCoordinator - fuses the detection engines into the agent pipeline.

Responsibilities:

* Enrich each event with process attribution (best effort, platform dependent).
* Route events to the canary engine (immediate, synchronous - canary hits are
  the highest-value, lowest-latency signal).
* Route change events to the behaviour engine and feed resulting signals to the
  risk engine.
* Schedule entropy analysis on a **separate, rate-limited worker thread** so
  that reading file contents never blocks event processing.
* Expose a single ``on_detection`` callback so the protection layer (Phase 3)
  can turn risk/canary/behaviour signals into alerts, incidents and responses.
"""
from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent.behavior.detectors import BehaviorEngine, BehaviorSignal
from agent.canary.engine import CanaryEngine, CanaryTrigger
from agent.core.events import CHANGE_TYPES, EventType, FileEvent
from agent.detection.risk import RiskEngine, RiskUpdate
from agent.entropy.analyzer import EntropyAnalyzer, EntropyResult, RateLimiter

log = logging.getLogger("sentinel.detection")


@dataclass
class DetectionContext:
    kind: str  # "canary" | "behavior" | "entropy" | "tamper"
    risk: RiskUpdate
    canary: CanaryTrigger | None = None
    behavior: BehaviorSignal | None = None
    entropy: EntropyResult | None = None
    detail: str | None = None
    pid: int | None = None
    process_name: str | None = None


OnDetection = Callable[[DetectionContext], None]


class DetectionCoordinator:
    def __init__(self, agent, on_detection: OnDetection | None = None):
        self.agent = agent
        cfg = agent.config
        self.config = cfg
        self.on_detection = on_detection
        self.process_monitor = None  # set by engines.build_engines when telemetry is available

        self.entropy = EntropyAnalyzer(cfg.entropy)
        self.behavior = BehaviorEngine(cfg.behavior)
        self.risk = RiskEngine(cfg.risk)
        self.canary = CanaryEngine(agent.store, cfg.canary, agent.self_writes, agent.endpoint_id,
                                   on_trigger=self._on_canary_trigger)
        self._entropy_rl = RateLimiter(cfg.entropy.max_analyses_per_second)
        self._entropy_q: queue.Queue[str] = queue.Queue(maxsize=cfg.entropy.analysis_queue_size)
        self._entropy_inflight: set[str] = set()
        self._entropy_lock = threading.Lock()
        self._stop = threading.Event()
        self._entropy_thread: threading.Thread | None = None
        self.entropy_dropped = 0
        self.last_verify = 0.0
        self._deployed_dirs: set[str] = set()
        self._triggered_canaries: set[int] = set()

    # ================================================================= lifecycle
    def start(self) -> None:
        self.seed_baselines_from_store()
        self.canary.load_existing()
        self.canary.self_writes = self.agent.self_writes
        self._refresh_canary_watch_paths()
        if self.config.canary.enabled and self.config.canary.auto_deploy:
            self._deploy_pending()
        if self.config.entropy.enabled:
            self._entropy_thread = threading.Thread(target=self._entropy_loop, name="sentinel-entropy",
                                                    daemon=True)
            self._entropy_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._entropy_thread:
            self._entropy_thread.join(timeout=5)
        self.canary.shutdown()

    def _deploy_pending(self) -> None:
        for path in self.agent.monitor.active_directories():
            if path not in self._deployed_dirs:
                self.canary.deploy_to_directory(path)
                self._deployed_dirs.add(path)
        self._refresh_canary_watch_paths()

    def _refresh_canary_watch_paths(self) -> None:
        paths = set(self.canary.canary_paths())
        self.agent.monitor.read_paths_of_interest = (
            paths if self.config.canary.alert_on_read else set()
        )

    # ================================================================= directory hooks
    def on_directory_added(self, path: str) -> None:
        if self.config.canary.enabled and self.config.canary.auto_deploy and path not in self._deployed_dirs:
            self.canary.deploy_to_directory(path)
            self._deployed_dirs.add(path)
            self._refresh_canary_watch_paths()

    def on_directory_removed(self, path: str) -> None:
        self._deployed_dirs.discard(path)

    def on_config_changed(self, config) -> None:
        self.config = config
        self.risk.update_settings(config.risk)
        self.entropy.s = config.entropy
        self.behavior.s = config.behavior
        self.canary.s = config.canary

    # ================================================================= enrichment
    def enrich(self, ev: FileEvent) -> None:
        if self.process_monitor is not None and ev.pid is None and ev.event_type in CHANGE_TYPES:
            info = self.process_monitor.attribute(ev)
            if info is not None:
                ev.pid = info.get("pid")
                ev.process_name = info.get("name")
                ev.attribution = info.get("attribution")

    # ================================================================= processing
    def process(self, ev: FileEvent) -> None:
        # 1. Canary (synchronous, highest priority)
        trig = self.canary.handle_event(ev)
        # handle_event invokes _on_canary_trigger via callback for firing

        # 2. Behaviour
        if ev.event_type in CHANGE_TYPES and not ev.is_directory:
            for sig in self.behavior.observe(ev):
                self._on_behavior_signal(sig, ev)

        # 3. Entropy (async) - only for content-bearing writes
        if (self.config.entropy.enabled and not ev.is_directory
                and ev.event_type in (EventType.MODIFIED, EventType.CREATED, EventType.MOVED,
                                      EventType.CLOSED_WRITE)
                and not self.canary.is_canary(ev.path)):
            self._enqueue_entropy(ev.path)
        _ = trig

    def _enqueue_entropy(self, path: str) -> None:
        with self._entropy_lock:
            if path in self._entropy_inflight:
                return
            self._entropy_inflight.add(path)
        try:
            self._entropy_q.put_nowait(path)
        except queue.Full:
            with self._entropy_lock:
                self._entropy_inflight.discard(path)
            self.entropy_dropped += 1

    def _entropy_loop(self) -> None:
        while not self._stop.is_set():
            try:
                path = self._entropy_q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if not self._entropy_rl.allow():
                    time.sleep(0.01)
                result = self.entropy.analyze(path)
                if result is not None:
                    self.agent.store.add_entropy_record(result.to_history_row())
                    self.agent.store.add_inventory([{
                        "file_path": result.path, "entropy": round(result.entropy, 4),
                        "magic_ok": result.magic_ok, "deleted": False,
                    }])
                    if result.suspicious:
                        self._on_entropy(result)
            except Exception:
                log.exception("entropy analysis failed for %s", path)
            finally:
                with self._entropy_lock:
                    self._entropy_inflight.discard(path)

    # ================================================================= signal handlers
    def _on_canary_trigger(self, trig: CanaryTrigger, pid: int | None, process_name: str | None) -> None:
        signal_type = {
            "modified": "canary_modified", "deleted": "canary_deleted",
            "renamed": "canary_renamed", "accessed": "canary_accessed",
        }.get(trig.interaction, "canary_modified")
        desc = f"canary {trig.interaction}: {trig.path}"
        if trig.detail:
            desc += f" ({trig.detail})"
        update = self.risk.add_signal(signal_type, desc, severity_hint="high",
                                      evidence={"path": trig.path, "detected_by": trig.detected_by,
                                                "interaction": trig.interaction})
        # Multiple *distinct* canaries hit -> extra confidence signal.
        self._triggered_canaries.add(trig.canary_id)
        if len(self._triggered_canaries) >= 2:
            update = self.risk.add_signal(
                "multiple_canaries",
                f"{len(self._triggered_canaries)} distinct canaries interacted with",
                severity_hint="high", evidence={"distinct_canaries": len(self._triggered_canaries)})
        self._emit(DetectionContext("canary", update, canary=trig, pid=pid, process_name=process_name,
                                    detail=desc))

    def _on_behavior_signal(self, sig: BehaviorSignal, ev: FileEvent) -> None:
        update = self.risk.add_signal(sig.signal_type, sig.description, severity_hint=sig.severity_hint,
                                      evidence={**sig.evidence, "count": sig.count,
                                                "sample_paths": sig.sample_paths[:5],
                                                "directories": sig.directories[:5]})
        self._emit(DetectionContext("behavior", update, behavior=sig, pid=ev.pid,
                                    process_name=ev.process_name, detail=sig.description))

    def _on_entropy(self, result: EntropyResult) -> None:
        signal_type = "magic_mismatch" if result.magic_ok is False else "entropy_spike"
        update = self.risk.add_signal(signal_type, f"{result.reason} [{result.path}]",
                                      severity_hint="medium",
                                      evidence={"path": result.path, "entropy": round(result.entropy, 2),
                                                "category": result.category, "delta": result.delta,
                                                "magic_ok": result.magic_ok})
        self._emit(DetectionContext("entropy", update, entropy=result, detail=result.reason))

    def report_tamper(self, finding: str) -> None:
        update = self.risk.add_signal("configuration_tamper", finding, severity_hint="high",
                                      evidence={"finding": finding})
        self._emit(DetectionContext("tamper", update, detail=finding))

    def add_signal(self, signal_type: str, description: str, severity_hint: str = "medium",
                   evidence: dict[str, Any] | None = None) -> DetectionContext:
        update = self.risk.add_signal(signal_type, description, severity_hint, evidence)
        ctx = DetectionContext("signal", update, detail=description)
        self._emit(ctx)
        return ctx

    def _emit(self, ctx: DetectionContext) -> None:
        if self.on_detection is not None:
            try:
                self.on_detection(ctx)
            except Exception:
                log.exception("on_detection callback failed")

    # ================================================================= periodic
    def idle_tick(self) -> None:
        self._maybe_decay()

    def periodic(self) -> None:
        now = time.monotonic()
        self.behavior.prune(now)
        self._maybe_decay()
        if (self.config.canary.enabled
                and now - self.last_verify >= self.config.canary.verify_interval_seconds):
            self.last_verify = now
            try:
                self.canary.verify_all()
            except Exception:
                log.exception("canary verification failed")

    def _maybe_decay(self) -> None:
        update = self.risk.decay()
        if update is not None and update.changed_level:
            self._emit(DetectionContext("decay", update, detail="risk decayed"))

    # ================================================================= inventory / baselines
    def on_inventory_batch(self, entries) -> None:
        if not (self.config.entropy.enabled and self.config.entropy.baseline_on_inventory):
            return
        for e in entries:
            if e.size >= self.config.entropy.min_file_size:
                self._enqueue_entropy(e.path)

    def seed_baselines_from_store(self) -> None:
        if not self.config.entropy.enabled:
            return
        snapshot = self.agent.store.inventory_snapshot()
        for path, (_size, _mtime, entropy, magic_ok) in snapshot.items():
            self.entropy.seed_baseline(path, entropy, magic_ok)

    # ================================================================= reporting
    def risk_snapshot(self) -> dict[str, Any]:
        return self.risk.snapshot()

    def health(self) -> dict[str, Any]:
        return {
            "entropy": {**self.entropy.stats(), "queue_depth": self._entropy_q.qsize(),
                        "dropped": self.entropy_dropped},
            "behavior": self.behavior.stats(),
            "canary": self.canary.stats(),
            "risk": {"score": self.risk.score, "level": self.risk.level,
                     "peak_score": round(self.risk.peak_score, 1)},
            "process_telemetry": self.process_monitor.health() if self.process_monitor else {},
        }
