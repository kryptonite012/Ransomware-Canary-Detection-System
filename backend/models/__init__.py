"""SQLAlchemy ORM models for PROJECT SENTINEL.

The schema is shared by the endpoint agent (writer of telemetry) and the API
(reader of telemetry, writer of signed control-plane instructions).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from backend.database import UTCDateTime, utcnow

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    pass


Base.metadata.naming_convention = NAMING_CONVENTION

SEVERITIES = ("info", "low", "medium", "high", "critical")
ROLES = ("admin", "analyst", "viewer")


# --------------------------------------------------------------------------- identity
class User(Base):
    __tablename__ = "users"
    __table_args__ = (CheckConstraint("role IN ('admin','analyst','viewer')", name="role_valid"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_login: Mapped[datetime | None] = mapped_column(UTCDateTime())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    family_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    replaced_by: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))


# --------------------------------------------------------------------------- endpoints
class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        CheckConstraint("status IN ('online','offline','degraded','starting','stopped')", name="status_valid"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    operating_system: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="starting")
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime(), index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    current_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    current_risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="normal")
    risk_details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    health: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    capabilities: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    policy_version: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)

    directories: Mapped[list["MonitoredDirectory"]] = relationship(back_populates="endpoint")


class MonitoredDirectory(Base):
    __tablename__ = "monitored_directories"
    __table_args__ = (UniqueConstraint("endpoint_id", "directory_path", name="uq_monitored_dir_endpoint_path"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    directory_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    recursive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    signature: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    status_detail: Mapped[str | None] = mapped_column(String(512))
    protected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)

    endpoint: Mapped[Endpoint] = relationship(back_populates="directories")


# --------------------------------------------------------------------------- telemetry
class FileEvent(Base):
    __tablename__ = "file_events"
    __table_args__ = (
        Index("ix_file_events_endpoint_ts", "endpoint_id", "timestamp"),
        Index("ix_file_events_type_ts", "event_type", "timestamp"),
        Index("ix_file_events_path", "file_path"),
    )

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    dest_path: Mapped[str | None] = mapped_column(String(2048))
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    is_directory: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    process_id: Mapped[int | None] = mapped_column(Integer, index=True)
    process_name: Mapped[str | None] = mapped_column(String(255))
    attribution: Mapped[str | None] = mapped_column(String(32))
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    event_metadata: Mapped[dict[str, Any] | None] = mapped_column("metadata", JSON)


class FileInventory(Base):
    __tablename__ = "file_inventory"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "file_path", name="uq_file_inventory_endpoint_path"),
        Index("ix_file_inventory_category", "category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    extension: Mapped[str | None] = mapped_column(String(32))
    category: Mapped[str | None] = mapped_column(String(32))
    size: Mapped[int | None] = mapped_column(BigInteger)
    mtime: Mapped[float | None] = mapped_column(Float)
    entropy: Mapped[float | None] = mapped_column(Float)
    magic_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_scanned: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_modified_event: Mapped[datetime | None] = mapped_column(UTCDateTime())
    deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class EntropyHistory(Base):
    __tablename__ = "entropy_history"
    __table_args__ = (Index("ix_entropy_history_path_ts", "file_path", "timestamp"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), index=True)
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    file_category: Mapped[str | None] = mapped_column(String(32))
    previous_entropy: Mapped[float | None] = mapped_column(Float)
    current_entropy: Mapped[float] = mapped_column(Float, nullable=False)
    entropy_delta: Mapped[float | None] = mapped_column(Float)
    max_chunk_entropy: Mapped[float | None] = mapped_column(Float)
    magic_ok: Mapped[bool | None] = mapped_column(Boolean)
    suspicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str | None] = mapped_column(String(255))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow, index=True)


class CanaryFile(Base):
    __tablename__ = "canary_files"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "file_path", name="uq_canary_endpoint_path"),
        CheckConstraint(
            "status IN ('active','triggered','missing','regenerating','retired','error')", name="status_valid"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    directory: Mapped[str] = mapped_column(String(2048), nullable=False)
    canary_type: Mapped[str] = mapped_column(String(16), nullable=False)
    original_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    last_verified: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_interaction: Mapped[datetime | None] = mapped_column(UTCDateTime())
    last_interaction_type: Mapped[str | None] = mapped_column(String(32))
    trigger_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Process(Base):
    __tablename__ = "processes"
    __table_args__ = (
        UniqueConstraint("endpoint_id", "process_id", "create_time", name="uq_process_identity"),
        Index("ix_processes_running", "endpoint_id", "is_running"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    process_id: Mapped[int] = mapped_column(Integer, nullable=False)
    process_name: Mapped[str] = mapped_column(String(255), nullable=False)
    executable_path: Mapped[str | None] = mapped_column(String(2048))
    command_line: Mapped[str | None] = mapped_column(Text)
    parent_process_id: Mapped[int | None] = mapped_column(Integer)
    username: Mapped[str | None] = mapped_column(String(255))
    create_time: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    is_running: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="running")
    cpu_percent: Mapped[float | None] = mapped_column(Float)
    memory_rss: Mapped[int | None] = mapped_column(BigInteger)
    write_bytes_rate: Mapped[float | None] = mapped_column(Float)
    total_write_bytes: Mapped[int | None] = mapped_column(BigInteger)
    files_modified: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    suspicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    suspicion_reasons: Mapped[list[str] | None] = mapped_column(JSON)


# --------------------------------------------------------------------------- detection
class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "response_status IN ('open','acknowledged','containing','contained','resolved','false_positive')",
            name="response_status_valid",
        ),
        Index("ix_incidents_endpoint_status", "endpoint_id", "response_status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    summary: Mapped[str | None] = mapped_column(Text)
    affected_files: Mapped[list[str] | None] = mapped_column(JSON)
    affected_directories: Mapped[list[str] | None] = mapped_column(JSON)
    affected_processes: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    signals: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    response_status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    response_level: Mapped[str | None] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    acknowledged_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    resolved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    resolution_note: Mapped[str | None] = mapped_column(Text)

    alerts: Mapped[list["SecurityAlert"]] = relationship(back_populates="incident")


class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    __table_args__ = (
        CheckConstraint("severity IN ('info','low','medium','high','critical')", name="severity_valid"),
        CheckConstraint(
            "status IN ('new','acknowledged','investigating','resolved','false_positive')", name="status_valid"
        ),
        Index("ix_security_alerts_status_ts", "status", "timestamp"),
        Index("ix_security_alerts_endpoint_ts", "endpoint_id", "timestamp"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    alert_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_level: Mapped[str | None] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False)
    signals: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    file_paths: Mapped[list[str] | None] = mapped_column(JSON)
    process_info: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    feedback: Mapped[str | None] = mapped_column(String(32))
    feedback_note: Mapped[str | None] = mapped_column(Text)
    feedback_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    incident: Mapped[Incident | None] = relationship(back_populates="alerts")


class ResponseAction(Base):
    __tablename__ = "response_actions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending_approval','approved','executing','completed','failed','rejected',"
            "'expired','rolled_back','skipped')",
            name="status_valid",
        ),
        Index("ix_response_actions_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    response_level: Mapped[str] = mapped_column(String(16), nullable=False)
    action_type: Mapped[str] = mapped_column(String(48), nullable=False)
    target: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending_approval")
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False, default="agent")
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reason: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    rollback_data: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="SET NULL"), index=True)
    item_type: Mapped[str] = mapped_column(String(32), nullable=False)
    original_path: Mapped[str | None] = mapped_column(String(2048))
    stored_path: Mapped[str | None] = mapped_column(String(2048))
    sha256: Mapped[str | None] = mapped_column(String(64))
    size: Mapped[int | None] = mapped_column(BigInteger)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class Snapshot(Base):
    __tablename__ = "snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    source_directory: Mapped[str] = mapped_column(String(2048), nullable=False)
    snapshot_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    manifest_hash: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="creating")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime())


# --------------------------------------------------------------------------- control plane
class AgentCommand(Base):
    __tablename__ = "agent_commands"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending','running','completed','failed','rejected','expired')", name="status_valid"
        ),
        Index("ix_agent_commands_pending", "endpoint_id", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    endpoint_id: Mapped[int] = mapped_column(ForeignKey("endpoints.id", ondelete="CASCADE"), nullable=False)
    command: Mapped[str] = mapped_column(String(64), nullable=False)
    params: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    signature: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime())
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class SystemConfiguration(Base):
    __tablename__ = "system_configuration"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    policy: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    comment: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    username: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utcnow, index=True)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)


__all__ = [
    "Base",
    "User",
    "RefreshToken",
    "Endpoint",
    "MonitoredDirectory",
    "FileEvent",
    "FileInventory",
    "EntropyHistory",
    "CanaryFile",
    "Process",
    "Incident",
    "SecurityAlert",
    "ResponseAction",
    "EvidenceItem",
    "Snapshot",
    "AgentCommand",
    "SystemConfiguration",
    "AuditLog",
    "SEVERITIES",
    "ROLES",
]
