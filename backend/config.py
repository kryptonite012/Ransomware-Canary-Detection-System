"""Backend (API / control-plane) configuration.

The backend shares the agent's data directory so that on a single-host
deployment the dashboard reads the same database the agent writes, and the
control-plane private key lives next to the agent's public key.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from agent.core.config import load_config


class BackendSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_API_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8443
    config_path: str | None = None

    # Auth / tokens
    jwt_secret: str | None = None  # auto-generated & persisted if unset
    access_token_ttl_minutes: int = Field(30, ge=1, le=1440)
    refresh_token_ttl_days: int = Field(14, ge=1, le=365)
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None

    # Login hardening
    max_failed_logins: int = Field(5, ge=1, le=100)
    lockout_minutes: int = Field(15, ge=1, le=1440)

    # Rate limiting (token bucket per client IP)
    rate_limit_per_minute: int = Field(300, ge=10, le=100_000)
    login_rate_limit_per_minute: int = Field(10, ge=1, le=1000)

    # CORS: the dashboard dev server origin(s)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173",
                                                             "http://127.0.0.1:5173"])
    serve_frontend: bool = True

    # TLS (optional; terminate TLS at the app when certs are provided)
    tls_certfile: str | None = None
    tls_keyfile: str | None = None

    def sentinel_config(self):
        return load_config(self.config_path)


@lru_cache
def get_settings() -> BackendSettings:
    return BackendSettings()


def resolve_jwt_secret(settings: BackendSettings, data_dir: Path) -> str:
    if settings.jwt_secret:
        return settings.jwt_secret
    secrets_dir = data_dir / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    path = secrets_dir / "api_jwt.secret"
    from agent.core.signing import ensure_secret_file

    return ensure_secret_file(path, 48).hex()
