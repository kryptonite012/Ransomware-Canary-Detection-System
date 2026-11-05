"""Wiring of detection (and, in phase 3+, protection) engines into the agent."""
from __future__ import annotations

import logging

log = logging.getLogger("sentinel.engines")


def build_engines(agent):
    """Construct the detection coordinator and, when available, the protection
    manager, returning the object the agent drives through its lifecycle."""
    from agent.detection.coordinator import DetectionCoordinator

    coordinator = DetectionCoordinator(agent)

    # Process telemetry (attribution) - optional, enhances events with PID/name.
    try:
        from agent.telemetry.process_monitor import ProcessMonitor

        coordinator.process_monitor = ProcessMonitor(agent, coordinator)
    except Exception:  # pragma: no cover - telemetry is best-effort
        log.exception("process telemetry unavailable")

    # Protection layer (alerts / incidents / response).
    manager = None
    try:
        from agent.response.manager import ProtectionManager
    except ImportError:
        log.info("protection manager not installed; running detection only")
        ProtectionManager = None  # type: ignore
    if ProtectionManager is not None:
        try:
            manager = ProtectionManager(agent, coordinator)
            coordinator.on_detection = manager.handle_detection
        except Exception:
            log.exception("protection manager failed to initialize; running detection only")
            manager = None
    return _EngineBundle(coordinator, manager)


class _EngineBundle:
    """Adapter exposing the interface the agent expects over coordinator+manager."""

    def __init__(self, coordinator, manager):
        self.coordinator = coordinator
        self.manager = manager

    def start(self):
        if self.coordinator.process_monitor is not None:
            self.coordinator.process_monitor.start()
        self.coordinator.start()
        if self.manager is not None:
            self.manager.start()

    def stop(self):
        if self.manager is not None:
            self.manager.stop()
        self.coordinator.stop()
        if self.coordinator.process_monitor is not None:
            self.coordinator.process_monitor.stop()

    def enrich(self, ev):
        self.coordinator.enrich(ev)

    def process(self, ev):
        self.coordinator.process(ev)

    def idle_tick(self):
        self.coordinator.idle_tick()

    def periodic(self):
        self.coordinator.periodic()
        if self.manager is not None:
            self.manager.periodic()

    def on_directory_added(self, path):
        self.coordinator.on_directory_added(path)

    def on_directory_removed(self, path):
        self.coordinator.on_directory_removed(path)

    def on_config_changed(self, config):
        self.coordinator.on_config_changed(config)
        if self.manager is not None:
            self.manager.on_config_changed(config)

    def on_inventory_batch(self, entries):
        self.coordinator.on_inventory_batch(entries)

    def report_tamper(self, finding):
        self.coordinator.report_tamper(finding)

    def risk_snapshot(self):
        return self.coordinator.risk_snapshot()

    def health(self):
        h = self.coordinator.health()
        if self.manager is not None:
            h.update(self.manager.health())
        return h
