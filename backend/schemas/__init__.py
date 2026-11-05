"""Pydantic request/response schemas for the API."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ auth
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: "UserResponse"


class UserResponse(ORMModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    last_login: datetime | None = None
    created_at: datetime


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)
    role: str = "viewer"

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in ("admin", "analyst", "viewer"):
            raise ValueError("role must be admin, analyst or viewer")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=256)


# ------------------------------------------------------------------ monitoring
class DirectoryCreate(BaseModel):
    endpoint_id: int
    path: str = Field(min_length=1, max_length=1024)
    recursive: bool = True

    @field_validator("path")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if "\x00" in v:
            raise ValueError("path contains NUL")
        return v


class DirectoryResponse(ORMModel):
    id: int
    endpoint_id: int
    directory_path: str
    recursive: bool
    monitoring_enabled: bool
    status: str
    status_detail: str | None = None
    protected: bool
    created_at: datetime


class EndpointResponse(ORMModel):
    id: int
    hostname: str
    operating_system: str
    agent_version: str
    status: str
    last_seen: datetime | None = None
    current_risk_score: float
    current_risk_level: str
    policy_version: int | None = None


# ------------------------------------------------------------------ canaries
class CanaryResponse(ORMModel):
    id: int
    endpoint_id: int
    file_path: str
    directory: str
    canary_type: str
    status: str
    last_verified: datetime | None = None
    last_interaction: datetime | None = None
    last_interaction_type: str | None = None
    trigger_count: int
    generation: int
    created_at: datetime


class CanaryDeployRequest(BaseModel):
    endpoint_id: int
    directory: str | None = None


# ------------------------------------------------------------------ detection
class AlertResponse(ORMModel):
    id: int
    endpoint_id: int
    incident_id: int | None = None
    alert_type: str
    severity: str
    risk_score: float
    risk_level: str | None = None
    title: str
    description: str
    signals: list[dict[str, Any]] | None = None
    file_paths: list[str] | None = None
    process_info: dict[str, Any] | None = None
    timestamp: datetime
    status: str
    feedback: str | None = None


class AlertFeedbackRequest(BaseModel):
    feedback: str = Field(pattern=r"^(true_positive|false_positive|benign)$")
    note: str | None = None
    status: str | None = Field(default=None, pattern=r"^(acknowledged|investigating|resolved|false_positive)$")


class FileEventResponse(ORMModel):
    id: int
    file_path: str
    dest_path: str | None = None
    event_type: str
    process_id: int | None = None
    process_name: str | None = None
    attribution: str | None = None
    file_size: int | None = None
    timestamp: datetime


class EntropyResponse(ORMModel):
    id: int
    file_path: str
    file_category: str | None = None
    previous_entropy: float | None = None
    current_entropy: float
    entropy_delta: float | None = None
    max_chunk_entropy: float | None = None
    magic_ok: bool | None = None
    suspicious: bool
    reason: str | None = None
    timestamp: datetime


class ProcessResponse(ORMModel):
    id: int
    process_id: int
    process_name: str
    executable_path: str | None = None
    parent_process_id: int | None = None
    username: str | None = None
    is_running: bool
    cpu_percent: float | None = None
    memory_rss: int | None = None
    write_bytes_rate: float | None = None
    files_modified: int
    suspicious: bool
    risk_score: float
    suspicion_reasons: list[str] | None = None
    first_seen: datetime
    last_seen: datetime


# ------------------------------------------------------------------ incidents
class IncidentResponse(ORMModel):
    id: int
    endpoint_id: int
    title: str
    severity: str
    risk_score: float
    summary: str | None = None
    affected_files: list[str] | None = None
    affected_directories: list[str] | None = None
    affected_processes: list[dict[str, Any]] | None = None
    signals: list[dict[str, Any]] | None = None
    response_status: str
    response_level: str | None = None
    created_at: datetime
    updated_at: datetime
    resolution_note: str | None = None


class ResponseActionResponse(ORMModel):
    id: int
    endpoint_id: int
    incident_id: int | None = None
    response_level: str
    action_type: str
    target: dict[str, Any] | None = None
    status: str
    requires_approval: bool
    requested_by: str
    reason: str | None = None
    result: dict[str, Any] | None = None
    created_at: datetime
    executed_at: datetime | None = None
    expires_at: datetime | None = None


class IncidentActionRequest(BaseModel):
    note: str | None = None


class ContainRequest(BaseModel):
    action_type: str = Field(pattern=r"^(suspend_process|terminate_process|protect_directory|isolate_network)$")
    target: dict[str, Any] = Field(default_factory=dict)


class EvidenceResponse(ORMModel):
    id: int
    incident_id: int | None = None
    item_type: str
    original_path: str | None = None
    sha256: str | None = None
    size: int | None = None
    details: dict[str, Any] | None = None
    created_at: datetime


# ------------------------------------------------------------------ system / config
class ConfigUpdateRequest(BaseModel):
    policy: dict[str, Any]
    comment: str | None = None


class SnapshotRequest(BaseModel):
    endpoint_id: int
    directory: str


class RestoreRequest(BaseModel):
    endpoint_id: int
    snapshot_id: int
    dry_run: bool = True


class MessageResponse(BaseModel):
    detail: str


TokenResponse.model_rebuild()
