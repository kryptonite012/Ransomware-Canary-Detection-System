"""Data-retention enforcement.

Telemetry tables grow without bound on a busy endpoint.  The retention runner
deletes rows older than the configured horizon for each table, keeping the
database bounded while preserving high-value records (alerts, incidents,
evidence) for much longer than raw events.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.models import AgentCommand, EntropyHistory, FileEvent, Process, SecurityAlert

log = logging.getLogger("sentinel.retention")


def run_retention(store, settings) -> dict[str, int]:
    """Purge rows older than the configured retention horizons. Returns counts."""
    results: dict[str, int] = {}
    try:
        results["file_events"] = store.purge_older_than(
            FileEvent, FileEvent.timestamp, settings.file_events_days)
        results["entropy_history"] = store.purge_older_than(
            EntropyHistory, EntropyHistory.timestamp, settings.entropy_history_days)
        results["processes"] = store.purge_older_than(
            Process, Process.last_seen, settings.process_days, Process.is_running.is_(False))
        results["commands"] = store.purge_older_than(
            AgentCommand, AgentCommand.created_at, settings.commands_days,
            AgentCommand.status.in_(("completed", "failed", "rejected", "expired")))
        # Alerts are kept far longer; only purge resolved/false-positive ones past horizon.
        results["alerts"] = store.purge_older_than(
            SecurityAlert, SecurityAlert.timestamp, settings.alerts_days,
            SecurityAlert.status.in_(("resolved", "false_positive")))
    except Exception:
        log.exception("retention run failed")
        return results
    purged = {k: v for k, v in results.items() if v}
    if purged:
        log.info("retention purged rows: %s", purged)
    return results
