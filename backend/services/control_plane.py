"""Control-plane service: issues signed instructions the agent will trust.

Only the backend holds the Ed25519 *private* key.  Every instruction the agent
acts on - a monitored-directory registration, a response-approval command, a
policy update - is signed here.  If the private key is absent the backend runs
in read-only control mode: it can display telemetry but cannot issue
instructions, and it says so clearly rather than writing unsigned rows the agent
would reject.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.core.config import SentinelConfig
from agent.core.signing import Signer, command_payload, directory_payload, generate_keypair, policy_payload
from backend.database import utcnow
from backend.models import AgentCommand, Endpoint, MonitoredDirectory, SystemConfiguration

log = logging.getLogger("sentinel.control")


class ControlPlane:
    def __init__(self, private_key_path: Path, public_key_path: Path):
        self.private_key_path = private_key_path
        self.public_key_path = public_key_path
        self._signer: Signer | None = None
        self._load()

    def _load(self) -> None:
        if self.private_key_path.exists():
            try:
                self._signer = Signer.from_file(self.private_key_path)
            except Exception as exc:
                log.error("cannot load control-plane private key: %s", exc)
                self._signer = None

    @property
    def can_sign(self) -> bool:
        return self._signer is not None

    def ensure_keys(self) -> bool:
        """Generate a keypair if none exists. Returns True if a key is available."""
        if self.private_key_path.exists():
            self._load()
            return self.can_sign
        generate_keypair(self.private_key_path, self.public_key_path)
        self._load()
        log.info("generated control-plane keypair at %s", self.private_key_path)
        return self.can_sign

    def _require_signer(self) -> Signer:
        if self._signer is None:
            raise ControlPlaneError(
                "control-plane signing key is not available; cannot issue signed instructions")
        return self._signer

    # ------------------------------------------------------------------ directories
    def add_directory(self, session: Session, endpoint_id: int, path: str, recursive: bool = True,
                      created_by: int | None = None) -> MonitoredDirectory:
        signer = self._require_signer()
        existing = session.scalar(select(MonitoredDirectory).where(
            MonitoredDirectory.endpoint_id == endpoint_id, MonitoredDirectory.directory_path == path))
        payload = directory_payload(endpoint_id, path, recursive, True)
        signature = signer.sign(payload)
        if existing is not None:
            existing.recursive = recursive
            existing.monitoring_enabled = True
            existing.signature = signature
            existing.status = "pending"
            return existing
        row = MonitoredDirectory(endpoint_id=endpoint_id, directory_path=path, recursive=recursive,
                                 monitoring_enabled=True, signature=signature, status="pending",
                                 created_by=created_by)
        session.add(row)
        session.flush()
        return row

    def set_directory_enabled(self, session: Session, directory: MonitoredDirectory, enabled: bool) -> None:
        signer = self._require_signer()
        directory.monitoring_enabled = enabled
        directory.signature = signer.sign(
            directory_payload(directory.endpoint_id, directory.directory_path, directory.recursive, enabled))
        directory.status = "pending"

    # ------------------------------------------------------------------ commands
    def issue_command(self, session: Session, endpoint_id: int, command: str, params: dict[str, Any],
                      created_by: int | None = None) -> AgentCommand:
        signer = self._require_signer()
        row = AgentCommand(endpoint_id=endpoint_id, command=command, params=params, status="pending",
                           created_by=created_by)
        session.add(row)
        session.flush()
        row.signature = signer.sign(command_payload(row.id, endpoint_id, command, params))
        return row

    # ------------------------------------------------------------------ policy
    def publish_policy(self, session: Session, config: SentinelConfig | dict[str, Any],
                       created_by: int | None = None, comment: str | None = None) -> SystemConfiguration:
        signer = self._require_signer()
        policy = config.policy_dict() if isinstance(config, SentinelConfig) else config
        # Validate against the schema before signing so agents never receive junk.
        SentinelConfig().with_policy(policy)
        last = session.scalar(select(SystemConfiguration).order_by(SystemConfiguration.version.desc()))
        version = (last.version + 1) if last else 1
        signature = signer.sign(policy_payload(version, policy))
        row = SystemConfiguration(version=version, policy=policy, signature=signature,
                                  created_by=created_by, comment=comment, created_at=utcnow())
        session.add(row)
        session.flush()
        return row


class ControlPlaneError(RuntimeError):
    pass
