"""ProtectionManager - alerts, incident correlation and the tiered response engine.

Flow for each :class:`DetectionContext` from the coordinator:

1. **Alert** - if the risk level is at/above ``risk.alert_min_level`` (or the
   signal is inherently high severity, e.g. a canary hit), create a
   :class:`SecurityAlert`, subject to a per-type cooldown.
2. **Incident** - if the risk level is at/above ``risk.incident_min_level``,
   open (or update, within a merge window) an :class:`Incident` and attach the
   alert and affected files/directories/processes to it.
3. **Response** - map the risk level to a response level via ``response.policy``
   and apply it:
   * OBSERVE  - record only
   * WARN     - desktop notification + dashboard event
   * PROTECT  - preserve evidence; write-protect affected directories
                (auto only if configured, else queue for approval)
   * CONTAIN  - preserve evidence; queue process-suspension / network-isolation
                actions for explicit approval (suspension auto only if
                ``auto_suspend_on_canary``)

High-impact actions (terminate, live network isolation) are **never** executed
automatically - they are created as ``pending_approval`` and executed only after
an authorised approval arrives.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta
from typing import Any

from sqlalchemy import select, update

from agent.core.config import RESPONSE_LEVEL_ORDER, RISK_LEVEL_ORDER
from agent.response.actions import ActionExecutor
from agent.response.evidence import EvidenceVault
from agent.response.notify import send_desktop_notification
from agent.response.recovery import RecoveryManager
from backend.database import utcnow
from backend.models import Incident, ResponseAction, SecurityAlert

log = logging.getLogger("sentinel.protection")

_LEVEL_TO_SEVERITY = {"normal": "info", "low": "low", "elevated": "medium", "high": "high",
                      "critical": "critical"}


class ProtectionManager:
    def __init__(self, agent, coordinator):
        self.agent = agent
        self.coordinator = coordinator
        self.config = agent.config
        self.store = agent.store
        self.endpoint_id = agent.endpoint_id
        akp = self.config.agent.resolved_agent_key_path()
        self.evidence = EvidenceVault(self.store, self.endpoint_id, self.config.agent.evidence_path(),
                                      self.config.response.evidence, akp)
        self.recovery = RecoveryManager(self.store, self.endpoint_id, self.config.agent.snapshots_path(),
                                        akp, exclusions=agent.exclusions)
        self.actions = ActionExecutor(self.config, agent.self_writes)
        self._lock = threading.Lock()
        self._alert_cooldown: dict[str, float] = {}
        self._active_incident_id: int | None = None
        self._incident_opened_at: float = 0.0
        self._protected_dirs: set[str] = set()
        self.alerts_created = 0
        self.incidents_created = 0
        self.actions_created = 0
        self.actions_executed = 0

    def start(self) -> None:
        self._register_commands()

    def stop(self) -> None:
        pass

    def on_config_changed(self, config) -> None:
        self.config = config
        self.actions = ActionExecutor(config, self.agent.self_writes)
        self.evidence.s = config.response.evidence

    # ================================================================= commands
    def _register_commands(self) -> None:
        h = self.agent.command_handlers
        h["approve_action"] = self._cmd_approve_action
        h["reject_action"] = self._cmd_reject_action
        h["rollback_action"] = self._cmd_rollback_action
        h["create_snapshot"] = self._cmd_create_snapshot
        h["restore_snapshot"] = self._cmd_restore_snapshot
        h["deploy_canaries"] = self._cmd_deploy_canaries
        h["verify_canaries"] = self._cmd_verify_canaries

    def _cmd_approve_action(self, params: dict[str, Any]) -> dict[str, Any]:
        action_id = int(params["action_id"])
        return self.execute_action(action_id, approved_by=params.get("user_id"))

    def _cmd_reject_action(self, params: dict[str, Any]) -> dict[str, Any]:
        action_id = int(params["action_id"])
        self.store.run(lambda s: s.execute(update(ResponseAction).where(ResponseAction.id == action_id)
                                           .values(status="rejected", decided_at=utcnow())))
        return {"action_id": action_id, "status": "rejected"}

    def _cmd_rollback_action(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.rollback_action(int(params["action_id"]))

    def _cmd_create_snapshot(self, params: dict[str, Any]) -> dict[str, Any]:
        sid = self.recovery.create_snapshot(params["directory"])
        return {"snapshot_id": sid, **self.recovery.verify_snapshot(sid)}

    def _cmd_restore_snapshot(self, params: dict[str, Any]) -> dict[str, Any]:
        report = self.recovery.restore_snapshot(int(params["snapshot_id"]),
                                                dry_run=bool(params.get("dry_run", True)))
        return report.to_dict()

    def _cmd_deploy_canaries(self, params: dict[str, Any]) -> dict[str, Any]:
        directory = params.get("directory")
        targets = [directory] if directory else self.agent.monitor.active_directories()
        created = []
        for d in targets:
            created += self.coordinator.canary.deploy_to_directory(d)
        self.coordinator._refresh_canary_watch_paths()
        return {"deployed": len(created)}

    def _cmd_verify_canaries(self, params: dict[str, Any]) -> dict[str, Any]:
        triggers = self.coordinator.canary.verify_all()
        return {"triggers": len(triggers)}

    # ================================================================= detection entry
    def handle_detection(self, ctx) -> None:
        update_ = ctx.risk
        level = update_.level
        severity = _LEVEL_TO_SEVERITY.get(ctx.behavior.severity_hint if ctx.behavior else level, level)
        try:
            with self._lock:
                alert_id, incident_id = self._record(ctx, level)
                self._respond(ctx, level, incident_id)
        except Exception:
            log.exception("error handling detection %s", ctx.kind)

    def _record(self, ctx, level: str) -> tuple[int | None, int | None]:
        cfg = self.config.risk
        want_alert = (RISK_LEVEL_ORDER[level] >= RISK_LEVEL_ORDER[cfg.alert_min_level]
                      or ctx.kind in ("canary", "tamper"))
        incident_id = None
        if RISK_LEVEL_ORDER[level] >= RISK_LEVEL_ORDER[cfg.incident_min_level] or ctx.kind == "canary":
            incident_id = self._get_or_open_incident(ctx, level)
        alert_id = None
        if want_alert and self._cooldown_ok(ctx):
            alert_id = self._create_alert(ctx, level, incident_id)
        return alert_id, incident_id

    def _cooldown_ok(self, ctx) -> bool:
        key = self._alert_key(ctx)
        now = time.monotonic()
        last = self._alert_cooldown.get(key, 0.0)
        if now - last < self.config.risk.alert_cooldown_seconds:
            return False
        self._alert_cooldown[key] = now
        return True

    def _alert_key(self, ctx) -> str:
        if ctx.canary:
            return f"canary:{ctx.canary.path}:{ctx.canary.interaction}"
        if ctx.behavior:
            return f"behavior:{ctx.behavior.signal_type}"
        if ctx.entropy:
            return f"entropy:{ctx.kind}"
        return f"{ctx.kind}:{ctx.risk.triggering_signal}"

    def _create_alert(self, ctx, level: str, incident_id: int | None) -> int:
        alert_type, title, description, file_paths, process_info, severity = self._describe(ctx, level)

        def _do(s):
            alert = SecurityAlert(
                endpoint_id=self.endpoint_id, incident_id=incident_id, alert_type=alert_type,
                severity=severity, risk_score=ctx.risk.score, risk_level=level, title=title[:255],
                description=description, file_paths=file_paths or None, process_info=process_info or None,
                signals=ctx.risk.contributions[:20], status="new")
            s.add(alert)
            s.flush()
            return alert.id

        alert_id = self.store.run(_do)
        self.alerts_created += 1
        log.warning("ALERT [%s] %s (risk %.0f)", severity.upper(), title, ctx.risk.score)
        return alert_id

    def _describe(self, ctx, level: str):
        severity = _LEVEL_TO_SEVERITY[level]
        files: list[str] = []
        process_info: dict[str, Any] | None = None
        if ctx.canary:
            c = ctx.canary
            alert_type = f"canary_{c.interaction}"
            title = f"Canary {c.interaction}: {c.path.split('/')[-1]}"
            description = (f"Decoy file '{c.path}' was {c.interaction} (detected by {c.detected_by})."
                          + (f" {c.detail}" if c.detail else ""))
            files = [c.path] + ([c.dest_path] if c.dest_path else [])
            severity = "critical" if c.interaction in ("modified", "deleted", "renamed") else "high"
            if ctx.pid:
                process_info = {"pid": ctx.pid, "name": ctx.process_name, "attribution": "event"}
        elif ctx.behavior:
            b = ctx.behavior
            alert_type = b.signal_type
            title = b.description[:120]
            description = b.description
            files = list(b.sample_paths)
            severity = {"low": "low", "medium": "medium", "high": "high"}.get(b.severity_hint, severity)
        elif ctx.entropy:
            r = ctx.entropy
            alert_type = "magic_mismatch" if r.magic_ok is False else "entropy_spike"
            title = f"Suspicious entropy change: {r.path.split('/')[-1]}"
            description = f"{r.reason} (entropy {r.entropy:.2f}, category {r.category})"
            files = [r.path]
        elif ctx.kind == "tamper":
            alert_type = "configuration_tamper"
            title = "Integrity / configuration tamper detected"
            description = ctx.detail or "integrity finding"
            severity = "high"
        else:
            alert_type = ctx.risk.triggering_signal
            title = ctx.detail or ctx.risk.triggering_signal
            description = ctx.detail or ""
            # suspicious_process carries process evidence
            for c in ctx.risk.contributions:
                if c["signal_type"] == "suspicious_process" and isinstance(c.get("evidence"), dict):
                    process_info = c["evidence"]
        return alert_type, title, description, files, process_info, severity

    # ================================================================= incidents
    def _get_or_open_incident(self, ctx, level: str) -> int:
        now = time.monotonic()
        window = self.config.risk.incident_merge_window_seconds
        if self._active_incident_id is not None and now - self._incident_opened_at <= window:
            self._update_incident(self._active_incident_id, ctx, level)
            return self._active_incident_id
        incident_id = self._open_incident(ctx, level)
        self._active_incident_id = incident_id
        self._incident_opened_at = now
        return incident_id

    def _open_incident(self, ctx, level: str) -> int:
        files, dirs, procs = self._affected(ctx)
        severity = _LEVEL_TO_SEVERITY[level]
        title = self._incident_title(ctx)

        def _do(s):
            inc = Incident(
                endpoint_id=self.endpoint_id, title=title[:255], severity=severity,
                risk_score=ctx.risk.score, summary=ctx.detail,
                affected_files=files[:200] or None, affected_directories=dirs[:50] or None,
                affected_processes=procs or None, signals=ctx.risk.contributions[:20],
                response_status="open", response_level=self._level_name(level))
            s.add(inc)
            s.flush()
            return inc.id

        incident_id = self.store.run(_do)
        self.incidents_created += 1
        log.error("INCIDENT #%d opened: %s (severity %s, risk %.0f)", incident_id, title, severity,
                  ctx.risk.score)
        return incident_id

    def _update_incident(self, incident_id: int, ctx, level: str) -> None:
        files, dirs, procs = self._affected(ctx)

        def _do(s):
            inc = s.get(Incident, incident_id)
            if inc is None:
                return
            if ctx.risk.score > inc.risk_score:
                inc.risk_score = ctx.risk.score
                inc.severity = _LEVEL_TO_SEVERITY[level]
                inc.response_level = self._level_name(level)
            inc.affected_files = _merge(inc.affected_files, files, 300)
            inc.affected_directories = _merge(inc.affected_directories, dirs, 80)
            inc.affected_processes = _merge_dicts(inc.affected_processes, procs, 50)
            inc.signals = ctx.risk.contributions[:20]
            inc.updated_at = utcnow()

        self.store.run(_do)

    def _incident_title(self, ctx) -> str:
        if ctx.canary:
            return f"Ransomware canary triggered ({ctx.canary.interaction})"
        contribs = {c["signal_type"] for c in ctx.risk.contributions}
        if "rapid_mass_modification" in contribs and (contribs & {"entropy_spike", "magic_mismatch",
                                                                   "suspicious_extension_change"}):
            return "Probable ransomware: mass encryption behaviour detected"
        if "ransom_note" in contribs:
            return "Probable ransomware: ransom note detected"
        return f"Elevated ransomware risk ({ctx.risk.level})"

    def _affected(self, ctx):
        import os as _os

        files: list[str] = []
        dirs: list[str] = []
        procs: list[dict[str, Any]] = []
        for c in ctx.risk.contributions:
            ev = c.get("evidence") or {}
            if isinstance(ev, dict):
                if ev.get("path"):
                    files.append(ev["path"])
                for p in ev.get("sample_paths", []) or []:
                    files.append(p)
                for d in ev.get("directories", []) or []:
                    dirs.append(d)
                if c["signal_type"] == "suspicious_process" and ev.get("pid"):
                    procs.append({"pid": ev.get("pid"), "name": ev.get("name"), "exe": ev.get("exe"),
                                  "reasons": ev.get("reasons")})
        if ctx.pid:
            procs.append({"pid": ctx.pid, "name": ctx.process_name, "attribution": "event"})
        files = list(dict.fromkeys(files))
        dirs = list(dict.fromkeys(dirs + [_os.path.dirname(f) for f in files]))
        # de-dup processes by pid
        seen = set()
        uniq_procs = []
        for p in procs:
            if p.get("pid") not in seen:
                seen.add(p.get("pid"))
                uniq_procs.append(p)
        return files, dirs, uniq_procs

    # ================================================================= response engine
    def _level_name(self, risk_level: str) -> str:
        return self.config.response.policy.get(risk_level, "observe")

    def _respond(self, ctx, risk_level: str, incident_id: int | None) -> None:
        level = self._level_name(risk_level)
        order = RESPONSE_LEVEL_ORDER[level]
        files, dirs, procs = self._affected(ctx)

        if order >= RESPONSE_LEVEL_ORDER["warn"]:
            self._warn(ctx, risk_level)
        if order >= RESPONSE_LEVEL_ORDER["protect"]:
            if files:
                self.evidence.preserve_files(files, incident_id, reason=f"{risk_level} risk response")
            for p in procs:
                if p.get("pid"):
                    self.evidence.preserve_process_metadata(incident_id, p)
            self._protect(dirs, incident_id, risk_level)
        if order >= RESPONSE_LEVEL_ORDER["contain"]:
            self._contain(ctx, procs, incident_id, risk_level)

    def _warn(self, ctx, risk_level: str) -> None:
        if not self.config.response.desktop_notifications:
            return
        title = ctx.detail or f"{risk_level.upper()} ransomware risk"
        send_desktop_notification(f"{risk_level.upper()} RISK",
                                  f"{title}\nRisk score {ctx.risk.score:.0f}", urgency="critical")

    def _protect(self, dirs: list[str], incident_id: int | None, risk_level: str) -> None:
        for directory in dirs:
            if directory in self._protected_dirs or not directory:
                continue
            auto = self.config.response.auto_protect_directories
            action_id = self._create_action(
                "protect_directory", {"path": directory}, incident_id, risk_level,
                requires_approval=not auto,
                reason=f"write-protect {directory} during {risk_level} risk")
            if auto and action_id:
                self.execute_action(action_id, approved_by=None, auto=True)
                self._protected_dirs.add(directory)

    def _contain(self, ctx, procs: list[dict[str, Any]], incident_id: int | None, risk_level: str) -> None:
        for p in procs:
            pid = p.get("pid")
            if not pid:
                continue
            auto = self.config.response.auto_suspend_on_canary and ctx.kind == "canary"
            action_id = self._create_action(
                "suspend_process", {"pid": pid}, incident_id, risk_level,
                requires_approval=not auto,
                reason=f"suspend {p.get('name')} (pid {pid}) during {risk_level} risk")
            if auto and action_id:
                self.execute_action(action_id, approved_by=None, auto=True)
            # Termination is always approval-gated (irreversible).
            self._create_action("terminate_process", {"pid": pid}, incident_id, risk_level,
                                requires_approval=True,
                                reason=f"terminate {p.get('name')} (pid {pid}) - requires authorization")
        iso = self.config.response.network_isolation
        if iso.enabled:
            self._create_action("isolate_network", {}, incident_id, risk_level,
                                requires_approval=not iso.dry_run,
                                reason="isolate endpoint from network")

    # ================================================================= actions
    def _create_action(self, action_type: str, target: dict[str, Any], incident_id: int | None,
                       risk_level: str, requires_approval: bool, reason: str) -> int | None:
        # Avoid duplicate pending actions for the same target.
        def _exists(s):
            return s.scalar(select(ResponseAction.id).where(
                ResponseAction.endpoint_id == self.endpoint_id,
                ResponseAction.action_type == action_type,
                ResponseAction.status.in_(("pending_approval", "approved", "executing", "completed")),
                ResponseAction.incident_id == incident_id))

        if incident_id is not None and self.store.run(_exists):
            # already have one for this incident+type
            same_target = self.store.run(lambda s: s.scalar(select(ResponseAction).where(
                ResponseAction.endpoint_id == self.endpoint_id,
                ResponseAction.action_type == action_type, ResponseAction.incident_id == incident_id)
                .order_by(ResponseAction.id.desc())))
            if same_target and (same_target.target or {}) == target:
                return None

        expires = utcnow() + timedelta(minutes=self.config.response.approval_timeout_minutes)

        def _do(s):
            act = ResponseAction(
                endpoint_id=self.endpoint_id, incident_id=incident_id,
                response_level=self._level_name(risk_level), action_type=action_type, target=target,
                status="pending_approval" if requires_approval else "approved",
                requires_approval=requires_approval, requested_by="agent", reason=reason,
                expires_at=expires if requires_approval else None)
            s.add(act)
            s.flush()
            return act.id

        action_id = self.store.run(_do)
        self.actions_created += 1
        log.warning("response action #%d queued: %s (%s)", action_id, action_type,
                    "needs approval" if requires_approval else "auto")
        return action_id

    def execute_action(self, action_id: int, approved_by: int | None = None, auto: bool = False) -> dict[str, Any]:
        row = self.store.run(lambda s: s.get(ResponseAction, action_id))
        if row is None:
            return {"error": "action not found"}
        if row.status not in ("approved", "pending_approval"):
            return {"action_id": action_id, "status": row.status, "note": "not in an executable state"}
        if row.expires_at and row.expires_at < utcnow() and row.status == "pending_approval":
            self.store.run(lambda s: s.execute(update(ResponseAction).where(ResponseAction.id == action_id)
                                               .values(status="expired")))
            return {"action_id": action_id, "status": "expired"}
        self.store.run(lambda s: s.execute(update(ResponseAction).where(ResponseAction.id == action_id)
                                           .values(status="executing", approved_by=approved_by,
                                                   decided_at=utcnow())))
        result = self.actions.dispatch(row.action_type, row.target or {})
        self.actions_executed += 1
        status = "completed" if result.ok else "failed"
        self.store.run(lambda s: s.execute(update(ResponseAction).where(ResponseAction.id == action_id)
                                           .values(status=status, executed_at=utcnow(),
                                                   result={"ok": result.ok, "detail": result.detail,
                                                           "data": result.data, "auto": auto},
                                                   rollback_data=result.rollback or None)))
        log.warning("response action #%d %s: %s", action_id, status, result.detail)
        return {"action_id": action_id, "status": status, "detail": result.detail, "data": result.data}

    def rollback_action(self, action_id: int) -> dict[str, Any]:
        row = self.store.run(lambda s: s.get(ResponseAction, action_id))
        if row is None or not row.rollback_data:
            return {"error": "no rollback data for this action"}
        rb = dict(row.rollback_data)
        action_type = rb.pop("action")
        result = self.actions.dispatch(action_type, rb)
        self.store.run(lambda s: s.execute(update(ResponseAction).where(ResponseAction.id == action_id)
                                           .values(status="rolled_back" if result.ok else row.status,
                                                   result={"rolled_back": result.ok, "detail": result.detail})))
        if row.action_type == "protect_directory" and result.ok:
            self._protected_dirs.discard((row.target or {}).get("path"))
        return {"action_id": action_id, "rolled_back": result.ok, "detail": result.detail}

    # ================================================================= periodic
    def periodic(self) -> None:
        # Execute actions that were approved out-of-band (via the API).
        try:
            approved = self.store.run(lambda s: [r.id for r in s.scalars(select(ResponseAction).where(
                ResponseAction.endpoint_id == self.endpoint_id, ResponseAction.status == "approved",
                ResponseAction.requires_approval.is_(True)).limit(20))])
        except Exception:
            log.exception("failed to poll approved actions")
            return
        for action_id in approved or []:
            self.execute_action(action_id)
        # Expire stale active incident pointer.
        if (self._active_incident_id is not None
                and time.monotonic() - self._incident_opened_at
                > self.config.risk.incident_merge_window_seconds):
            self._active_incident_id = None

    def health(self) -> dict[str, Any]:
        return {"protection": {"alerts": self.alerts_created, "incidents": self.incidents_created,
                               "actions_created": self.actions_created,
                               "actions_executed": self.actions_executed,
                               "active_incident": self._active_incident_id}}


def _merge(existing: list | None, new: list, limit: int) -> list | None:
    merged = list(dict.fromkeys((existing or []) + new))
    return merged[:limit] or None


def _merge_dicts(existing: list | None, new: list, limit: int) -> list | None:
    out = list(existing or [])
    seen = {d.get("pid") for d in out if isinstance(d, dict)}
    for d in new:
        if d.get("pid") not in seen:
            out.append(d)
            seen.add(d.get("pid"))
    return out[:limit] or None
