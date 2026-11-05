"""Configuration schema for PROJECT SENTINEL.

The configuration is split in two parts:

* **Bootstrap settings** (``agent`` section) - where the database lives, where
  keys and evidence are stored, queue sizes.  These come only from the local
  YAML file / environment because the agent needs them before it can reach the
  database.
* **Policy settings** (everything else) - monitoring scope, thresholds, risk
  weights, response policy, retention.  The YAML file supplies defaults; the
  control plane (backend) may publish a newer *signed* policy document into the
  ``system_configuration`` table.  The agent only applies a policy whose
  Ed25519 signature verifies against the control-plane public key.
"""
from __future__ import annotations

import copy
import os
import socket
from pathlib import Path
from typing import Any, ClassVar, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "sentinel.yaml"

RiskLevel = Literal["normal", "low", "elevated", "high", "critical"]
ResponseLevel = Literal["observe", "warn", "protect", "contain"]

RISK_LEVEL_ORDER: dict[str, int] = {"normal": 0, "low": 1, "elevated": 2, "high": 3, "critical": 4}
RESPONSE_LEVEL_ORDER: dict[str, int] = {"observe": 1, "warn": 2, "protect": 3, "contain": 4}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class AgentSettings(_Strict):
    endpoint_name: str | None = None
    data_dir: str = "./data"
    database_url: str | None = None
    public_key_path: str | None = None
    agent_key_path: str | None = None
    require_signed_policy: bool = True
    heartbeat_interval_seconds: float = Field(10.0, ge=1, le=300)
    command_poll_interval_seconds: float = Field(2.0, ge=0.5, le=60)
    config_poll_interval_seconds: float = Field(15.0, ge=1, le=600)
    queue_size: int = Field(50_000, ge=1_000, le=5_000_000)
    queue_high_watermark: float = Field(0.8, gt=0.1, lt=1.0)
    db_flush_interval_seconds: float = Field(1.0, ge=0.1, le=30)
    db_batch_size: int = Field(500, ge=10, le=20_000)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_file: str | None = None

    def resolved_endpoint_name(self) -> str:
        return self.endpoint_name or socket.gethostname()

    def data_path(self) -> Path:
        return Path(os.path.expanduser(self.data_dir)).resolve()

    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        return f"sqlite:///{(self.data_path() / 'sentinel.db').as_posix()}"

    def secrets_path(self) -> Path:
        return self.data_path() / "secrets"

    def resolved_public_key_path(self) -> Path:
        if self.public_key_path:
            return Path(os.path.expanduser(self.public_key_path)).resolve()
        return self.secrets_path() / "control_plane_ed25519.pub"

    def resolved_agent_key_path(self) -> Path:
        if self.agent_key_path:
            return Path(os.path.expanduser(self.agent_key_path)).resolve()
        return self.secrets_path() / "agent_hmac.key"

    def evidence_path(self) -> Path:
        return self.data_path() / "evidence"

    def snapshots_path(self) -> Path:
        return self.data_path() / "snapshots"

    def state_path(self) -> Path:
        return self.data_path() / "state"


class DirectoryConfig(_Strict):
    path: str
    recursive: bool = True

    @field_validator("path")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("directory path must not be empty")
        if "\x00" in v:
            raise ValueError("directory path contains NUL byte")
        return v.strip()


class MonitoringSettings(_Strict):
    directories: list[DirectoryConfig] = Field(default_factory=list)
    exclude_patterns: list[str] = Field(
        default_factory=lambda: [
            "*.tmp", "*.temp", "~$*", "*.swp", "*.swx", "*.part", "*.crdownload",
            "*/.git/*", "*/node_modules/*", "*/__pycache__/*", "*/.cache/*",
            "*/.Trash*/*", "*/$RECYCLE.BIN/*", "*.db-journal", "*.db-wal", "*.db-shm",
        ]
    )
    exclude_directories: list[str] = Field(default_factory=list)
    dedup_window_ms: int = Field(400, ge=0, le=10_000)
    inventory_scan_on_start: bool = True
    inventory_max_files: int = Field(250_000, ge=100, le=10_000_000)
    inventory_rescan_hours: float = Field(24.0, ge=0.1, le=720)
    detect_reads: bool = False


class EntropySettings(_Strict):
    enabled: bool = True
    min_file_size: int = Field(512, ge=16, le=10_485_760)
    full_read_max_bytes: int = Field(1_048_576, ge=4_096, le=268_435_456)
    chunk_size: int = Field(65_536, ge=1_024, le=4_194_304)
    sample_chunks: int = Field(4, ge=1, le=64)
    high_entropy_threshold: float = Field(7.2, ge=1.0, le=8.0)
    min_entropy_delta: float = Field(1.0, ge=0.1, le=8.0)
    text_high_entropy_threshold: float = Field(6.0, ge=1.0, le=8.0)
    max_analyses_per_second: int = Field(250, ge=1, le=100_000)
    analysis_queue_size: int = Field(5_000, ge=100, le=1_000_000)
    cache_size: int = Field(200_000, ge=1_000, le=10_000_000)
    baseline_on_inventory: bool = True


DEFAULT_CANARY_NAMES = [
    "Financial_Records_Canary.xlsx",
    "Employee_Database_Canary.csv",
    "Confidential_Archive_Canary.docx",
    "Backup_Index_Canary.txt",
    "Project_Assets_Canary.pdf",
]


class CanarySettings(_Strict):
    enabled: bool = True
    auto_deploy: bool = True
    auto_regenerate: bool = True
    regenerate_delay_seconds: float = Field(5.0, ge=0, le=3600)
    verify_interval_seconds: float = Field(300.0, ge=5, le=86_400)
    names: list[str] = Field(default_factory=lambda: list(DEFAULT_CANARY_NAMES))
    name_prefix: str = ""
    deploy_to_subdirectories: bool = False
    max_canaries_per_directory: int = Field(5, ge=1, le=50)
    alert_on_read: bool = False

    @field_validator("names")
    @classmethod
    def _safe_names(cls, names: list[str]) -> list[str]:
        for n in names:
            if not n or "/" in n or "\\" in n or n in (".", "..") or "\x00" in n:
                raise ValueError(f"invalid canary file name: {n!r}")
        return names

    @field_validator("name_prefix")
    @classmethod
    def _safe_prefix(cls, v: str) -> str:
        if "/" in v or "\\" in v or "\x00" in v:
            raise ValueError("canary name prefix must not contain path separators")
        return v


class BehaviorSettings(_Strict):
    window_seconds: float = Field(10.0, ge=1, le=600)
    mass_modification_threshold: int = Field(60, ge=5, le=100_000)
    directory_spread_threshold: int = Field(6, ge=2, le=10_000)
    extension_change_threshold: int = Field(5, ge=1, le=10_000)
    mass_deletion_threshold: int = Field(30, ge=3, le=100_000)
    replacement_threshold: int = Field(10, ge=2, le=100_000)
    rewrite_files_threshold: int = Field(20, ge=2, le=100_000)
    rewrite_count_per_file: int = Field(3, ge=2, le=1_000)
    ransom_note_threshold: int = Field(2, ge=1, le=1_000)
    baseline_bucket_seconds: float = Field(60.0, ge=5, le=3_600)
    baseline_learning_buckets: int = Field(30, ge=3, le=10_000)
    baseline_sigma: float = Field(4.0, ge=1.0, le=50.0)
    baseline_min_events: int = Field(40, ge=1, le=1_000_000)
    process_file_threshold: int = Field(40, ge=2, le=1_000_000)
    process_tree_threshold: int = Field(3, ge=2, le=1_000)
    process_write_rate_bytes: int = Field(20 * 1024 * 1024, ge=1024)
    signal_cooldown_seconds: float = Field(30.0, ge=0, le=3_600)


DEFAULT_WEIGHTS: dict[str, int] = {
    "canary_modified": 50,
    "canary_deleted": 50,
    "canary_renamed": 50,
    "canary_accessed": 20,
    "multiple_canaries": 20,
    "entropy_spike": 15,
    "magic_mismatch": 15,
    "rapid_mass_modification": 20,
    "directory_spread": 10,
    "suspicious_extension_change": 15,
    "mass_deletion": 15,
    "file_replacement": 15,
    "repeated_rewrites": 5,
    "ransom_note": 30,
    "baseline_deviation": 10,
    "suspicious_process": 20,
    "recovery_inhibition": 35,
    "configuration_tamper": 25,
}


class RiskSettings(_Strict):
    weights: dict[str, int] = Field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    signal_ttl_seconds: float = Field(300.0, ge=10, le=86_400)
    repeat_increment_ratio: float = Field(0.25, ge=0, le=1)
    repeat_max_ratio: float = Field(1.5, ge=1, le=5)
    correlation_bonus: dict[int, int] = Field(default_factory=lambda: {2: 10, 3: 20, 4: 25})
    level_thresholds: dict[str, int] = Field(
        default_factory=lambda: {"low": 20, "elevated": 40, "high": 60, "critical": 80}
    )
    alert_min_level: RiskLevel = "elevated"
    incident_min_level: RiskLevel = "high"
    incident_merge_window_seconds: float = Field(900.0, ge=30, le=86_400)
    alert_cooldown_seconds: float = Field(60.0, ge=0, le=86_400)

    @model_validator(mode="after")
    def _check(self) -> "RiskSettings":
        t = self.level_thresholds
        for k in ("low", "elevated", "high", "critical"):
            if k not in t:
                raise ValueError(f"level_thresholds missing '{k}'")
        if not (0 < t["low"] < t["elevated"] < t["high"] < t["critical"] <= 100):
            raise ValueError("level thresholds must be strictly increasing within 1..100")
        for name, w in self.weights.items():
            if not 0 <= w <= 100:
                raise ValueError(f"weight for {name} must be within 0..100")
        return self


class EvidenceSettings(_Strict):
    max_files_per_incident: int = Field(50, ge=0, le=10_000)
    max_file_bytes: int = Field(50 * 1024 * 1024, ge=0)
    max_total_bytes: int = Field(1024 * 1024 * 1024, ge=0)


class NetworkIsolationSettings(_Strict):
    enabled: bool = False
    dry_run: bool = True
    allow_hosts: list[str] = Field(default_factory=list)
    allow_ports: list[int] = Field(default_factory=lambda: [8443])


class ResponseSettings(_Strict):
    policy: dict[str, ResponseLevel] = Field(
        default_factory=lambda: {
            "normal": "observe",
            "low": "observe",
            "elevated": "warn",
            "high": "protect",
            "critical": "contain",
        }
    )
    desktop_notifications: bool = True
    evidence: EvidenceSettings = Field(default_factory=EvidenceSettings)
    auto_suspend_on_canary: bool = False
    auto_protect_directories: bool = False
    approval_timeout_minutes: int = Field(120, ge=1, le=10_080)
    protected_process_names: list[str] = Field(
        default_factory=lambda: [
            "systemd", "init", "kthreadd", "sshd", "dbus-daemon", "Xorg", "gnome-shell",
            "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "winlogon.exe", "svchost.exe", "explorer.exe", "dwm.exe",
            "MsMpEng.exe", "launchd", "kernel_task", "WindowServer",
        ]
    )
    network_isolation: NetworkIsolationSettings = Field(default_factory=NetworkIsolationSettings)

    @field_validator("policy")
    @classmethod
    def _policy_keys(cls, v: dict[str, str]) -> dict[str, str]:
        missing = set(RISK_LEVEL_ORDER) - set(v)
        if missing:
            raise ValueError(f"response policy missing levels: {sorted(missing)}")
        return v


class RetentionSettings(_Strict):
    file_events_days: int = Field(30, ge=1, le=3_650)
    entropy_history_days: int = Field(90, ge=1, le=3_650)
    process_days: int = Field(30, ge=1, le=3_650)
    alerts_days: int = Field(365, ge=7, le=3_650)
    commands_days: int = Field(30, ge=1, le=3_650)
    run_interval_hours: float = Field(6.0, ge=0.1, le=168)


class SentinelConfig(_Strict):
    agent: AgentSettings = Field(default_factory=AgentSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    entropy: EntropySettings = Field(default_factory=EntropySettings)
    canary: CanarySettings = Field(default_factory=CanarySettings)
    behavior: BehaviorSettings = Field(default_factory=BehaviorSettings)
    risk: RiskSettings = Field(default_factory=RiskSettings)
    response: ResponseSettings = Field(default_factory=ResponseSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)

    # Sections that the control plane is allowed to override with a signed policy.
    POLICY_SECTIONS: ClassVar[tuple[str, ...]] = (
        "monitoring", "entropy", "canary", "behavior", "risk", "response", "retention",
    )

    def policy_dict(self) -> dict[str, Any]:
        data = self.model_dump(mode="json")
        return {k: data[k] for k in self.POLICY_SECTIONS}

    def with_policy(self, policy: dict[str, Any]) -> "SentinelConfig":
        """Return a copy with policy sections replaced (validated)."""
        data = self.model_dump(mode="json")
        for key in self.POLICY_SECTIONS:
            if key in policy:
                data[key] = _deep_merge(data[key], policy[key])
        unknown = set(policy) - set(self.POLICY_SECTIONS)
        if unknown:
            raise ValueError(f"policy contains non-policy sections: {sorted(unknown)}")
        return SentinelConfig.model_validate(data)


def _deep_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged = copy.deepcopy(base)
        for k, v in override.items():
            merged[k] = _deep_merge(merged.get(k), v) if k in merged else copy.deepcopy(v)
        return merged
    return copy.deepcopy(override)


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    agent = data.setdefault("agent", {})
    env_map = {
        "SENTINEL_DATA_DIR": "data_dir",
        "SENTINEL_DATABASE_URL": "database_url",
        "SENTINEL_ENDPOINT_NAME": "endpoint_name",
        "SENTINEL_LOG_LEVEL": "log_level",
        "SENTINEL_PUBLIC_KEY_PATH": "public_key_path",
    }
    for env, key in env_map.items():
        val = os.environ.get(env)
        if val:
            agent[key] = val
    return data


def load_config(path: str | Path | None = None) -> SentinelConfig:
    """Load the bootstrap/default configuration from YAML (+ env overrides)."""
    cfg_path = Path(path or os.environ.get("SENTINEL_CONFIG") or DEFAULT_CONFIG_PATH)
    data: dict[str, Any] = {}
    if cfg_path.exists():
        with cfg_path.open("r", encoding="utf-8") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"configuration file {cfg_path} must contain a mapping")
        data = loaded
    data = _apply_env_overrides(data)
    cfg = SentinelConfig.model_validate(data)
    # Resolve a relative data_dir against the config file's project root so the
    # agent behaves identically regardless of the current working directory.
    data_dir = Path(os.path.expanduser(cfg.agent.data_dir))
    if not data_dir.is_absolute():
        base = cfg_path.resolve().parent.parent if cfg_path.exists() else Path.cwd()
        cfg.agent.data_dir = str((base / data_dir).resolve())
    return cfg


def risk_level_for(score: float, thresholds: dict[str, int]) -> str:
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["elevated"]:
        return "elevated"
    if score >= thresholds["low"]:
        return "low"
    return "normal"
