"""Verification of control-plane instructions (policy + monitored directories)."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from agent.core.config import DirectoryConfig, SentinelConfig
from agent.core.signing import Verifier, directory_payload, policy_payload

log = logging.getLogger("sentinel.policy")


@dataclass
class PolicyState:
    config: SentinelConfig
    version: int | None = None  # None = local file defaults
    source: str = "file"
    tamper_findings: list[str] = field(default_factory=list)


class PolicyManager:
    def __init__(self, base_config: SentinelConfig, store):
        self.base = base_config
        self.store = store
        self.verifier: Verifier | None = None
        self._load_verifier()

    def _load_verifier(self) -> None:
        path: Path = self.base.agent.resolved_public_key_path()
        if path.exists():
            try:
                self.verifier = Verifier.from_file(path)
                log.info("control-plane public key loaded from %s", path)
            except Exception as exc:  # malformed key
                log.error("cannot load control-plane public key %s: %s", path, exc)
                self.verifier = None
        else:
            log.warning("control-plane public key not found at %s; signed instructions will be rejected", path)

    @property
    def can_verify(self) -> bool:
        return self.verifier is not None

    def resolve(self, current_version: int | None = None) -> PolicyState:
        findings: list[str] = []
        row = self.store.latest_policy()
        if row is None:
            return PolicyState(config=self.base, version=None, source="file")
        if row.version == current_version:
            return PolicyState(config=self.base, version=current_version, source="unchanged")
        if self.verifier is None:
            if self.base.agent.require_signed_policy:
                findings.append(f"policy v{row.version} ignored: no public key to verify signature")
                return PolicyState(config=self.base, version=None, source="file", tamper_findings=findings)
        elif not self.verifier.verify(policy_payload(row.version, row.policy), row.signature):
            findings.append(f"policy v{row.version} has an INVALID signature and was rejected")
            log.error(findings[-1])
            return PolicyState(config=self.base, version=None, source="file", tamper_findings=findings)
        try:
            cfg = self.base.with_policy(row.policy)
        except Exception as exc:
            findings.append(f"policy v{row.version} failed validation: {exc}")
            log.error(findings[-1])
            return PolicyState(config=self.base, version=None, source="file", tamper_findings=findings)
        return PolicyState(config=cfg, version=row.version, source="database")

    def resolve_directories(self, config: SentinelConfig) -> tuple[list[tuple[DirectoryConfig, int | None]], list[str]]:
        """Return (directories, tamper findings).

        If the control plane has registered directories for this endpoint, only
        rows with a valid signature are used.  Otherwise the YAML defaults apply.
        """
        findings: list[str] = []
        rows = self.store.monitored_directories()
        if not rows:
            return [(d, None) for d in config.monitoring.directories], findings
        result: list[tuple[DirectoryConfig, int | None]] = []
        for row in rows:
            payload = directory_payload(row.endpoint_id, row.directory_path, row.recursive, row.monitoring_enabled)
            valid = self.verifier is not None and self.verifier.verify(payload, row.signature)
            if not valid:
                msg = f"monitored directory #{row.id} ({row.directory_path}) has an invalid signature"
                findings.append(msg)
                self.store.set_directory_status(row.id, "rejected", "invalid signature")
                continue
            if not row.monitoring_enabled:
                self.store.set_directory_status(row.id, "disabled", None)
                continue
            result.append((DirectoryConfig(path=row.directory_path, recursive=row.recursive), row.id))
        return result, findings
