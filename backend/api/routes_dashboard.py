"""Dashboard, monitoring, canary, detection, incident and system endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.deps import (
    AppState, CurrentUser, get_db, get_state, require_admin, require_analyst, require_viewer,
)
from backend.database import utcnow
from backend.models import (
    CanaryFile, Endpoint, EntropyHistory, EvidenceItem, FileEvent, Incident, MonitoredDirectory,
    Process, ResponseAction, SecurityAlert, SystemConfiguration,
)
from backend.schemas import (
    AlertFeedbackRequest, AlertResponse, CanaryDeployRequest, CanaryResponse, ConfigUpdateRequest,
    ContainRequest, DirectoryCreate, DirectoryResponse, EndpointResponse, EntropyResponse,
    EvidenceResponse, FileEventResponse, IncidentActionRequest, IncidentResponse, MessageResponse,
    ProcessResponse, ResponseActionResponse, RestoreRequest, SnapshotRequest,
)
from backend.services import audit, dashboard
from backend.services.control_plane import ControlPlaneError

router = APIRouter(prefix="/api", tags=["dashboard"])


def _endpoint_or_404(db: Session, endpoint_id: int) -> Endpoint:
    ep = db.get(Endpoint, endpoint_id)
    if ep is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "endpoint not found")
    return ep


# =============================================================== dashboard
@router.get("/dashboard/overview")
def dashboard_overview(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                       endpoint_id: int | None = None):
    return dashboard.overview(db, endpoint_id)


@router.get("/dashboard/statistics")
def dashboard_statistics(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                         endpoint_id: int | None = None, hours: int = Query(24, ge=1, le=720)):
    return dashboard.statistics(db, endpoint_id, hours)


@router.get("/dashboard/activity")
def dashboard_activity(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                       endpoint_id: int | None = None, hours: int = Query(24, ge=1, le=720),
                       buckets: int = Query(48, ge=6, le=288)):
    return dashboard.activity_timeline(db, endpoint_id, hours, buckets)


# =============================================================== endpoints / monitoring
@router.get("/endpoints", response_model=list[EndpointResponse])
def list_endpoints(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer)):
    return [EndpointResponse.model_validate(e) for e in db.scalars(select(Endpoint).order_by(Endpoint.id))]


@router.get("/monitoring/status")
def monitoring_status(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                      endpoint_id: int | None = None):
    return dashboard.agent_health(db, endpoint_id)


@router.get("/monitoring/directories", response_model=list[DirectoryResponse])
def list_directories(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                     endpoint_id: int | None = None):
    stmt = select(MonitoredDirectory).order_by(MonitoredDirectory.id)
    if endpoint_id:
        stmt = stmt.where(MonitoredDirectory.endpoint_id == endpoint_id)
    return [DirectoryResponse.model_validate(d) for d in db.scalars(stmt)]


@router.post("/monitoring/directories", response_model=DirectoryResponse,
             status_code=status.HTTP_201_CREATED)
def add_directory(body: DirectoryCreate, request: Request, db: Session = Depends(get_db),
                  state: AppState = Depends(get_state), user: CurrentUser = Depends(require_analyst)):
    _endpoint_or_404(db, body.endpoint_id)
    try:
        row = state.control_plane.add_directory(db, body.endpoint_id, body.path, body.recursive,
                                                created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="monitoring.add_directory", resource=body.path, result="success",
                 user_id=user.id, details={"endpoint_id": body.endpoint_id, "recursive": body.recursive})
    return DirectoryResponse.model_validate(row)


@router.delete("/monitoring/directories/{dir_id}", response_model=DirectoryResponse)
def disable_directory(dir_id: int, db: Session = Depends(get_db), state: AppState = Depends(get_state),
                      user: CurrentUser = Depends(require_analyst)):
    row = db.get(MonitoredDirectory, dir_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "directory not found")
    try:
        state.control_plane.set_directory_enabled(db, row, False)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="monitoring.disable_directory", resource=row.directory_path,
                 result="success", user_id=user.id)
    return DirectoryResponse.model_validate(row)


# =============================================================== canaries
@router.get("/canaries", response_model=list[CanaryResponse])
def list_canaries(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                  endpoint_id: int | None = None):
    stmt = select(CanaryFile).order_by(CanaryFile.id)
    if endpoint_id:
        stmt = stmt.where(CanaryFile.endpoint_id == endpoint_id)
    return [CanaryResponse.model_validate(c) for c in db.scalars(stmt)]


@router.post("/canaries/deploy", response_model=MessageResponse)
def deploy_canaries(body: CanaryDeployRequest, db: Session = Depends(get_db),
                    state: AppState = Depends(get_state), user: CurrentUser = Depends(require_analyst)):
    _endpoint_or_404(db, body.endpoint_id)
    params = {"directory": body.directory} if body.directory else {}
    try:
        cmd = state.control_plane.issue_command(db, body.endpoint_id, "deploy_canaries", params,
                                                created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="canary.deploy", resource=f"endpoint:{body.endpoint_id}", result="success",
                 user_id=user.id, details=params)
    return MessageResponse(detail=f"deploy command #{cmd.id} issued")


@router.post("/canaries/verify", response_model=MessageResponse)
def verify_canaries(body: CanaryDeployRequest, db: Session = Depends(get_db),
                    state: AppState = Depends(get_state), user: CurrentUser = Depends(require_analyst)):
    _endpoint_or_404(db, body.endpoint_id)
    try:
        cmd = state.control_plane.issue_command(db, body.endpoint_id, "verify_canaries", {},
                                                created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return MessageResponse(detail=f"verify command #{cmd.id} issued")


@router.post("/canaries/regenerate", response_model=MessageResponse)
def regenerate_canaries(body: CanaryDeployRequest, db: Session = Depends(get_db),
                        state: AppState = Depends(get_state), user: CurrentUser = Depends(require_analyst)):
    _endpoint_or_404(db, body.endpoint_id)
    params = {"directory": body.directory} if body.directory else {}
    try:
        cmd = state.control_plane.issue_command(db, body.endpoint_id, "deploy_canaries", params,
                                                created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    return MessageResponse(detail=f"regenerate command #{cmd.id} issued")


# =============================================================== detection
@router.get("/detection/alerts", response_model=list[AlertResponse])
def list_alerts(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                endpoint_id: int | None = None, status_filter: str | None = Query(None, alias="status"),
                severity: str | None = None, limit: int = Query(100, ge=1, le=1000),
                offset: int = Query(0, ge=0)):
    stmt = select(SecurityAlert).order_by(SecurityAlert.timestamp.desc())
    if endpoint_id:
        stmt = stmt.where(SecurityAlert.endpoint_id == endpoint_id)
    if status_filter:
        stmt = stmt.where(SecurityAlert.status == status_filter)
    if severity:
        stmt = stmt.where(SecurityAlert.severity == severity)
    stmt = stmt.limit(limit).offset(offset)
    return [AlertResponse.model_validate(a) for a in db.scalars(stmt)]


@router.get("/detection/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer)):
    a = db.get(SecurityAlert, alert_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    return AlertResponse.model_validate(a)


@router.post("/detection/alerts/{alert_id}/feedback", response_model=AlertResponse)
def alert_feedback(alert_id: int, body: AlertFeedbackRequest, db: Session = Depends(get_db),
                   user: CurrentUser = Depends(require_analyst)):
    a = db.get(SecurityAlert, alert_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found")
    a.feedback = body.feedback
    a.feedback_note = body.note
    a.feedback_by = user.id
    if body.status:
        a.status = body.status
    elif body.feedback == "false_positive":
        a.status = "false_positive"
    audit.record(db, action="alert.feedback", resource=f"alert:{alert_id}", result="success",
                 user_id=user.id, details={"feedback": body.feedback})
    return AlertResponse.model_validate(a)


@router.get("/detection/events", response_model=list[FileEventResponse])
def list_events(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                endpoint_id: int | None = None, event_type: str | None = None,
                limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    stmt = select(FileEvent).order_by(FileEvent.id.desc())
    if endpoint_id:
        stmt = stmt.where(FileEvent.endpoint_id == endpoint_id)
    if event_type:
        stmt = stmt.where(FileEvent.event_type == event_type)
    return [FileEventResponse.model_validate(e) for e in db.scalars(stmt.limit(limit).offset(offset))]


@router.get("/detection/entropy-history", response_model=list[EntropyResponse])
def entropy_history(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                    endpoint_id: int | None = None, suspicious_only: bool = False,
                    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    stmt = select(EntropyHistory).order_by(EntropyHistory.id.desc())
    if endpoint_id:
        stmt = stmt.where(EntropyHistory.endpoint_id == endpoint_id)
    if suspicious_only:
        stmt = stmt.where(EntropyHistory.suspicious.is_(True))
    return [EntropyResponse.model_validate(e) for e in db.scalars(stmt.limit(limit).offset(offset))]


@router.get("/detection/risk-score")
def risk_score(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
               endpoint_id: int | None = None):
    stmt = select(Endpoint)
    if endpoint_id:
        stmt = stmt.where(Endpoint.id == endpoint_id)
    out = []
    for e in db.scalars(stmt):
        out.append({"endpoint_id": e.id, "hostname": e.hostname, "score": e.current_risk_score,
                    "level": e.current_risk_level, "details": e.risk_details, "updated": e.last_seen})
    return out


@router.get("/processes", response_model=list[ProcessResponse])
def list_processes(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                   endpoint_id: int | None = None, suspicious_only: bool = False,
                   running_only: bool = True, limit: int = Query(200, ge=1, le=2000)):
    stmt = select(Process).order_by(Process.suspicious.desc(), Process.last_seen.desc())
    if endpoint_id:
        stmt = stmt.where(Process.endpoint_id == endpoint_id)
    if suspicious_only:
        stmt = stmt.where(Process.suspicious.is_(True))
    if running_only:
        stmt = stmt.where(Process.is_running.is_(True))
    return [ProcessResponse.model_validate(p) for p in db.scalars(stmt.limit(limit))]


# =============================================================== incidents
@router.get("/incidents", response_model=list[IncidentResponse])
def list_incidents(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                   endpoint_id: int | None = None, status_filter: str | None = Query(None, alias="status"),
                   limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)):
    stmt = select(Incident).order_by(Incident.created_at.desc())
    if endpoint_id:
        stmt = stmt.where(Incident.endpoint_id == endpoint_id)
    if status_filter:
        stmt = stmt.where(Incident.response_status == status_filter)
    return [IncidentResponse.model_validate(i) for i in db.scalars(stmt.limit(limit).offset(offset))]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db),
                 _: CurrentUser = Depends(require_viewer)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    alerts = db.scalars(select(SecurityAlert).where(SecurityAlert.incident_id == incident_id)
                        .order_by(SecurityAlert.timestamp)).all()
    actions = db.scalars(select(ResponseAction).where(ResponseAction.incident_id == incident_id)
                         .order_by(ResponseAction.id)).all()
    evidence = db.scalars(select(EvidenceItem).where(EvidenceItem.incident_id == incident_id)).all()
    return {
        "incident": IncidentResponse.model_validate(inc),
        "alerts": [AlertResponse.model_validate(a) for a in alerts],
        "actions": [ResponseActionResponse.model_validate(a) for a in actions],
        "evidence": [EvidenceResponse.model_validate(e) for e in evidence],
    }


@router.post("/incidents/{incident_id}/acknowledge", response_model=IncidentResponse)
def acknowledge_incident(incident_id: int, body: IncidentActionRequest | None = None,
                         db: Session = Depends(get_db), user: CurrentUser = Depends(require_analyst)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    inc.response_status = "acknowledged"
    inc.acknowledged_by = user.id
    inc.acknowledged_at = utcnow()
    inc.updated_at = utcnow()
    audit.record(db, action="incident.acknowledge", resource=f"incident:{incident_id}",
                 result="success", user_id=user.id)
    return IncidentResponse.model_validate(inc)


@router.post("/incidents/{incident_id}/contain", response_model=ResponseActionResponse)
def contain_incident(incident_id: int, body: ContainRequest, db: Session = Depends(get_db),
                     state: AppState = Depends(get_state), user: CurrentUser = Depends(require_admin)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    row = ResponseAction(endpoint_id=inc.endpoint_id, incident_id=incident_id, response_level="contain",
                         action_type=body.action_type, target=body.target, status="approved",
                         requires_approval=True, requested_by=f"user:{user.username}",
                         approved_by=user.id, reason=f"manual containment by {user.username}",
                         decided_at=utcnow())
    db.add(row)
    inc.response_status = "containing"
    inc.updated_at = utcnow()
    db.flush()
    # Issue a signed command so the agent executes it.
    try:
        state.control_plane.issue_command(db, inc.endpoint_id, "approve_action",
                                          {"action_id": row.id, "user_id": user.id}, created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="incident.contain", resource=f"incident:{incident_id}", result="success",
                 user_id=user.id, details={"action_type": body.action_type, "target": body.target})
    return ResponseActionResponse.model_validate(row)


@router.post("/incidents/{incident_id}/resolve", response_model=IncidentResponse)
def resolve_incident(incident_id: int, body: IncidentActionRequest, db: Session = Depends(get_db),
                     user: CurrentUser = Depends(require_analyst)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    inc.response_status = "resolved"
    inc.resolved_by = user.id
    inc.resolved_at = utcnow()
    inc.resolution_note = body.note
    inc.updated_at = utcnow()
    audit.record(db, action="incident.resolve", resource=f"incident:{incident_id}", result="success",
                 user_id=user.id, details={"note": body.note})
    return IncidentResponse.model_validate(inc)


# =============================================================== response actions
@router.get("/actions", response_model=list[ResponseActionResponse])
def list_actions(db: Session = Depends(get_db), _: CurrentUser = Depends(require_viewer),
                 status_filter: str | None = Query(None, alias="status"),
                 endpoint_id: int | None = None, limit: int = Query(100, ge=1, le=1000)):
    stmt = select(ResponseAction).order_by(ResponseAction.id.desc())
    if endpoint_id:
        stmt = stmt.where(ResponseAction.endpoint_id == endpoint_id)
    if status_filter:
        stmt = stmt.where(ResponseAction.status == status_filter)
    return [ResponseActionResponse.model_validate(a) for a in db.scalars(stmt.limit(limit))]


@router.post("/actions/{action_id}/approve", response_model=ResponseActionResponse)
def approve_action(action_id: int, db: Session = Depends(get_db), state: AppState = Depends(get_state),
                   user: CurrentUser = Depends(require_admin)):
    row = db.get(ResponseAction, action_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "action not found")
    if row.status != "pending_approval":
        raise HTTPException(status.HTTP_409_CONFLICT, f"action is {row.status}, not pending approval")
    row.status = "approved"
    row.approved_by = user.id
    row.decided_at = utcnow()
    db.flush()
    try:
        state.control_plane.issue_command(db, row.endpoint_id, "approve_action",
                                          {"action_id": row.id, "user_id": user.id}, created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="action.approve", resource=f"action:{action_id}", result="success",
                 user_id=user.id, details={"action_type": row.action_type})
    return ResponseActionResponse.model_validate(row)


@router.post("/actions/{action_id}/reject", response_model=ResponseActionResponse)
def reject_action(action_id: int, db: Session = Depends(get_db), state: AppState = Depends(get_state),
                  user: CurrentUser = Depends(require_admin)):
    row = db.get(ResponseAction, action_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "action not found")
    row.status = "rejected"
    row.decided_at = utcnow()
    db.flush()
    try:
        state.control_plane.issue_command(db, row.endpoint_id, "reject_action", {"action_id": row.id},
                                          created_by=user.id)
    except ControlPlaneError:
        pass
    audit.record(db, action="action.reject", resource=f"action:{action_id}", result="success",
                 user_id=user.id)
    return ResponseActionResponse.model_validate(row)


@router.post("/actions/{action_id}/rollback", response_model=MessageResponse)
def rollback_action(action_id: int, db: Session = Depends(get_db), state: AppState = Depends(get_state),
                    user: CurrentUser = Depends(require_admin)):
    row = db.get(ResponseAction, action_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "action not found")
    try:
        cmd = state.control_plane.issue_command(db, row.endpoint_id, "rollback_action",
                                                {"action_id": row.id}, created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="action.rollback", resource=f"action:{action_id}", result="success",
                 user_id=user.id)
    return MessageResponse(detail=f"rollback command #{cmd.id} issued")


# =============================================================== forensics
@router.get("/forensics/evidence", response_model=list[EvidenceResponse])
def list_evidence(db: Session = Depends(get_db), _: CurrentUser = Depends(require_analyst),
                  incident_id: int | None = None, limit: int = Query(200, ge=1, le=2000)):
    stmt = select(EvidenceItem).order_by(EvidenceItem.id.desc())
    if incident_id:
        stmt = stmt.where(EvidenceItem.incident_id == incident_id)
    return [EvidenceResponse.model_validate(e) for e in db.scalars(stmt.limit(limit))]


@router.get("/forensics/audit")
def list_audit(db: Session = Depends(get_db), _: CurrentUser = Depends(require_admin),
               limit: int = Query(200, ge=1, le=2000)):
    from backend.models import AuditLog

    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all()
    return [{"id": r.id, "user": r.username, "action": r.action, "resource": r.resource,
             "result": r.result, "ip": r.ip_address, "timestamp": r.timestamp, "details": r.details}
            for r in rows]


@router.get("/forensics/audit/verify")
def verify_audit(db: Session = Depends(get_db), _: CurrentUser = Depends(require_admin)):
    return audit.verify_chain(db)


# =============================================================== system
@router.get("/system/health")
def system_health(request: Request, db: Session = Depends(get_db),
                  state: AppState = Depends(get_state)):
    import time

    endpoints = dashboard.agent_health(db)
    return {
        "status": "ok",
        "api_uptime_seconds": round(time.time() - state.started_at, 1),
        "control_plane_can_sign": state.control_plane.can_sign,
        "database": state.sentinel_config.agent.resolved_database_url().split("://")[0],
        "endpoints": endpoints,
    }


@router.get("/system/configuration")
def get_configuration(db: Session = Depends(get_db), _: CurrentUser = Depends(require_analyst)):
    row = db.scalar(select(SystemConfiguration).order_by(SystemConfiguration.version.desc()))
    from backend.api.deps import AppState as _S  # noqa

    return {
        "active_version": row.version if row else None,
        "policy": row.policy if row else None,
        "published_at": row.created_at if row else None,
        "history": [{"version": r.version, "comment": r.comment, "created_at": r.created_at}
                    for r in db.scalars(select(SystemConfiguration)
                                        .order_by(SystemConfiguration.version.desc()).limit(20))],
    }


@router.put("/system/configuration", response_model=MessageResponse)
def update_configuration(body: ConfigUpdateRequest, db: Session = Depends(get_db),
                         state: AppState = Depends(get_state), user: CurrentUser = Depends(require_admin)):
    try:
        row = state.control_plane.publish_policy(db, body.policy, created_by=user.id,
                                                 comment=body.comment)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"invalid policy: {exc}")
    audit.record(db, action="system.publish_policy", resource=f"policy:v{row.version}",
                 result="success", user_id=user.id, details={"comment": body.comment})
    return MessageResponse(detail=f"policy v{row.version} published and signed")


@router.post("/system/snapshot", response_model=MessageResponse)
def create_snapshot(body: SnapshotRequest, db: Session = Depends(get_db),
                    state: AppState = Depends(get_state), user: CurrentUser = Depends(require_analyst)):
    _endpoint_or_404(db, body.endpoint_id)
    try:
        cmd = state.control_plane.issue_command(db, body.endpoint_id, "create_snapshot",
                                                {"directory": body.directory}, created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="recovery.snapshot", resource=body.directory, result="success",
                 user_id=user.id)
    return MessageResponse(detail=f"snapshot command #{cmd.id} issued")


@router.post("/system/restore", response_model=MessageResponse)
def restore_snapshot(body: RestoreRequest, db: Session = Depends(get_db),
                     state: AppState = Depends(get_state), user: CurrentUser = Depends(require_admin)):
    _endpoint_or_404(db, body.endpoint_id)
    try:
        cmd = state.control_plane.issue_command(db, body.endpoint_id, "restore_snapshot",
                                                {"snapshot_id": body.snapshot_id, "dry_run": body.dry_run},
                                                created_by=user.id)
    except ControlPlaneError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    audit.record(db, action="recovery.restore", resource=f"snapshot:{body.snapshot_id}",
                 result="success", user_id=user.id, details={"dry_run": body.dry_run})
    return MessageResponse(detail=f"restore command #{cmd.id} issued (dry_run={body.dry_run})")
