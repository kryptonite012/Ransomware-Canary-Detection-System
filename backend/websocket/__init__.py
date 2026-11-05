"""WebSocket hub for live dashboard updates.

The API process does not share memory with the agent (the agent may be a
separate process, service, or even another host writing to a shared database),
so live updates are driven by a lightweight **database poller**: every second it
samples overview metrics, the newest alerts and the newest incidents, and
broadcasts deltas to connected dashboard clients.  This keeps the dashboard live
without coupling it to the agent's in-process event bus.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from typing import Any

from fastapi import WebSocket
from sqlalchemy import select

from backend.models import Incident, SecurityAlert
from backend.services import dashboard

log = logging.getLogger("sentinel.ws")


def _json_default(obj: Any):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


class WebSocketManager:
    def __init__(self, session_factory, poll_interval: float = 1.0):
        self.session_factory = session_factory
        self.poll_interval = poll_interval
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._task: asyncio.Task | None = None
        self._last_alert_id = 0
        self._last_incident_id = 0
        self._last_overview: dict[str, Any] | None = None

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        # Send a snapshot immediately on connect.
        try:
            await ws.send_text(json.dumps({"type": "snapshot", "data": self._snapshot()},
                                          default=_json_default))
        except Exception:
            await self.disconnect(ws)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    def _snapshot(self) -> dict[str, Any]:
        with self.session_factory() as s:
            return {"overview": dashboard.overview(s)}

    async def _broadcast(self, message: dict[str, Any]) -> None:
        data = json.dumps(message, default=_json_default)
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_text(data)
            except Exception:
                await self.disconnect(ws)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._poll_loop())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _poll_loop(self) -> None:
        # Initialise cursors so we do not replay history on first poll.
        try:
            with self.session_factory() as s:
                self._last_alert_id = s.scalar(select(SecurityAlert.id).order_by(
                    SecurityAlert.id.desc()).limit(1)) or 0
                self._last_incident_id = s.scalar(select(Incident.id).order_by(
                    Incident.id.desc()).limit(1)) or 0
        except Exception:
            log.exception("ws poller init failed")
        while True:
            try:
                await asyncio.sleep(self.poll_interval)
                if not self._clients:
                    continue
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("ws poll error")

    async def _poll_once(self) -> None:
        def _collect():
            with self.session_factory() as s:
                new_alerts = list(s.scalars(select(SecurityAlert).where(
                    SecurityAlert.id > self._last_alert_id).order_by(SecurityAlert.id).limit(50)))
                new_incidents = list(s.scalars(select(Incident).where(
                    Incident.id > self._last_incident_id).order_by(Incident.id).limit(50)))
                ov = dashboard.overview(s)
                return new_alerts, new_incidents, ov

        new_alerts, new_incidents, ov = await asyncio.to_thread(_collect)
        for a in new_alerts:
            self._last_alert_id = max(self._last_alert_id, a.id)
            await self._broadcast({"type": "alert", "data": {
                "id": a.id, "severity": a.severity, "alert_type": a.alert_type, "title": a.title,
                "risk_score": a.risk_score, "endpoint_id": a.endpoint_id, "timestamp": a.timestamp,
                "incident_id": a.incident_id}})
        for inc in new_incidents:
            self._last_incident_id = max(self._last_incident_id, inc.id)
            await self._broadcast({"type": "incident", "data": {
                "id": inc.id, "title": inc.title, "severity": inc.severity, "risk_score": inc.risk_score,
                "response_status": inc.response_status, "endpoint_id": inc.endpoint_id,
                "created_at": inc.created_at}})
        if ov != self._last_overview:
            self._last_overview = ov
            await self._broadcast({"type": "overview", "data": ov})
