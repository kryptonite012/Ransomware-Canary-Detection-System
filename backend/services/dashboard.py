"""Aggregation queries that back the dashboard overview and statistics pages."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database import utcnow
from backend.models import (
    CanaryFile, Endpoint, FileEvent, FileInventory, Incident, MonitoredDirectory, Process,
    SecurityAlert,
)


def _endpoint_filter(stmt, column, endpoint_id: int | None):
    return stmt.where(column == endpoint_id) if endpoint_id else stmt


def overview(session: Session, endpoint_id: int | None = None) -> dict[str, Any]:
    now = utcnow()
    hour_ago = now - timedelta(hours=1)
    day_ago = now - timedelta(days=1)

    endpoints = list(session.scalars(select(Endpoint)))
    if endpoint_id:
        endpoints = [e for e in endpoints if e.id == endpoint_id]

    online = [e for e in endpoints if e.status == "online" and e.last_seen and e.last_seen > now -
              timedelta(seconds=60)]
    worst = max(endpoints, key=lambda e: e.current_risk_score, default=None)

    def count(model, *extra):
        stmt = select(func.count()).select_from(model)
        stmt = _endpoint_filter(stmt, model.endpoint_id, endpoint_id)
        for e in extra:
            stmt = stmt.where(e)
        return session.scalar(stmt) or 0

    monitored_files = count(FileInventory, FileInventory.deleted.is_(False))
    files_last_hour = count(FileEvent, FileEvent.timestamp > hour_ago,
                            FileEvent.event_type.in_(("created", "modified", "moved")))
    active_canaries = count(CanaryFile, CanaryFile.status == "active")
    triggered_canaries = count(CanaryFile, CanaryFile.trigger_count > 0)
    suspicious_processes = count(Process, Process.suspicious.is_(True), Process.is_running.is_(True))
    total_alerts = count(SecurityAlert)
    open_alerts = count(SecurityAlert, SecurityAlert.status.in_(("new", "investigating")))
    alerts_24h = count(SecurityAlert, SecurityAlert.timestamp > day_ago)
    open_incidents = count(Incident, Incident.response_status.in_(
        ("open", "acknowledged", "containing")))
    protected_dirs = count(MonitoredDirectory, MonitoredDirectory.protected.is_(True))
    monitored_dirs = count(MonitoredDirectory, MonitoredDirectory.monitoring_enabled.is_(True))

    status = "normal"
    risk_score = worst.current_risk_score if worst else 0.0
    risk_level = worst.current_risk_level if worst else "normal"
    if not online and endpoints:
        status = "agent_offline"
    elif risk_level in ("high", "critical"):
        status = "under_attack"
    elif risk_level in ("elevated", "low") or open_incidents:
        status = "elevated"

    return {
        "status": status,
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "risk_details": worst.risk_details if worst else None,
        "endpoints_total": len(endpoints),
        "endpoints_online": len(online),
        "monitored_files": monitored_files,
        "files_modified_last_hour": files_last_hour,
        "active_canaries": active_canaries,
        "triggered_canaries": triggered_canaries,
        "suspicious_processes": suspicious_processes,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "alerts_last_24h": alerts_24h,
        "open_incidents": open_incidents,
        "protected_directories": protected_dirs,
        "monitored_directories": monitored_dirs,
        "generated_at": now,
    }


def agent_health(session: Session, endpoint_id: int | None = None) -> list[dict[str, Any]]:
    now = utcnow()
    endpoints = list(session.scalars(select(Endpoint)))
    out = []
    for e in endpoints:
        if endpoint_id and e.id != endpoint_id:
            continue
        stale = not e.last_seen or (now - e.last_seen).total_seconds() > 60
        out.append({
            "id": e.id, "hostname": e.hostname, "operating_system": e.operating_system,
            "agent_version": e.agent_version, "status": "offline" if stale else e.status,
            "last_seen": e.last_seen, "risk_score": e.current_risk_score,
            "risk_level": e.current_risk_level, "health": e.health, "capabilities": e.capabilities,
            "policy_version": e.policy_version,
        })
    return out


def statistics(session: Session, endpoint_id: int | None = None, hours: int = 24) -> dict[str, Any]:
    now = utcnow()
    since = now - timedelta(hours=hours)

    # Event-type distribution.
    stmt = select(FileEvent.event_type, func.count()).where(FileEvent.timestamp > since)
    stmt = _endpoint_filter(stmt, FileEvent.endpoint_id, endpoint_id).group_by(FileEvent.event_type)
    event_types = {t: c for t, c in session.execute(stmt)}

    # Alert severity distribution.
    stmt = select(SecurityAlert.severity, func.count()).where(SecurityAlert.timestamp > since)
    stmt = _endpoint_filter(stmt, SecurityAlert.endpoint_id, endpoint_id).group_by(SecurityAlert.severity)
    alert_severity = {s: c for s, c in session.execute(stmt)}

    # Alert-type distribution.
    stmt = select(SecurityAlert.alert_type, func.count()).where(SecurityAlert.timestamp > since)
    stmt = _endpoint_filter(stmt, SecurityAlert.endpoint_id, endpoint_id).group_by(
        SecurityAlert.alert_type)
    alert_types = {t: c for t, c in session.execute(stmt)}

    # File-type (category) distribution of the inventory.
    stmt = select(FileInventory.category, func.count()).where(FileInventory.deleted.is_(False))
    stmt = _endpoint_filter(stmt, FileInventory.endpoint_id, endpoint_id).group_by(FileInventory.category)
    categories = {(c or "unknown"): n for c, n in session.execute(stmt)}

    return {
        "window_hours": hours,
        "event_type_distribution": event_types,
        "alert_severity_distribution": alert_severity,
        "alert_type_distribution": alert_types,
        "file_category_distribution": categories,
        "generated_at": now,
    }


def activity_timeline(session: Session, endpoint_id: int | None = None, hours: int = 24,
                      buckets: int = 48) -> list[dict[str, Any]]:
    """Bucketed counts of file events and alerts for the threat-activity timeline."""
    now = utcnow()
    since = now - timedelta(hours=hours)
    span = (now - since).total_seconds()
    bucket_seconds = max(1.0, span / buckets)

    events = session.execute(
        _endpoint_filter(select(FileEvent.timestamp).where(FileEvent.timestamp > since),
                         FileEvent.endpoint_id, endpoint_id)).all()
    alerts = session.execute(
        _endpoint_filter(select(SecurityAlert.timestamp, SecurityAlert.severity)
                         .where(SecurityAlert.timestamp > since),
                         SecurityAlert.endpoint_id, endpoint_id)).all()

    series = []
    for i in range(buckets):
        start = since + timedelta(seconds=i * bucket_seconds)
        end = start + timedelta(seconds=bucket_seconds)
        ev = sum(1 for (t,) in events if start <= t < end)
        al = sum(1 for (t, _s) in alerts if start <= t < end)
        crit = sum(1 for (t, s) in alerts if start <= t < end and s in ("high", "critical"))
        series.append({"bucket_start": start, "events": ev, "alerts": al, "critical_alerts": crit})
    return series
