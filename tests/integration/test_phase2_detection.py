"""Phase 2 integration: full detection pipeline against a disposable sandbox."""
from __future__ import annotations

import os
import secrets
import time

import pytest
from sqlalchemy import func, select

from agent.core.agent import SentinelAgent
from backend.database import make_session_factory
from backend.models import CanaryFile, Endpoint, EntropyHistory, SecurityAlert
from tests.conftest import wait_for

pytestmark = pytest.mark.integration


def _risk(factory, hostname):
    with factory() as s:
        ep = s.scalar(select(Endpoint).where(Endpoint.hostname == hostname))
        return (ep.current_risk_score, ep.current_risk_level, ep.risk_details) if ep else (0, "normal", None)


def test_canaries_autodeploy_and_trigger_raises_risk(config_factory, watched_dir):
    cfg = config_factory(
        [watched_dir],
        canary={"auto_deploy": True, "auto_regenerate": True, "regenerate_delay_seconds": 0.2},
        entropy={"min_file_size": 128},
    )
    agent = SentinelAgent(cfg)
    agent.start()
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        # Canaries are deployed into the monitored directory on startup.
        assert wait_for(lambda: len(list(watched_dir.glob("*Canary*"))) >= 5, timeout=10)
        with factory() as s:
            assert s.scalar(select(func.count()).select_from(CanaryFile)) >= 5

        time.sleep(3.0)  # let self-write guard windows expire (SELF_WRITE_TTL)
        # Attacker modifies a canary (overwrite with high-entropy content).
        canary = watched_dir / "Backup_Index_Canary.txt"
        canary.write_bytes(secrets.token_bytes(4096))

        def canary_triggered():
            with factory() as s:
                return s.scalar(select(func.count()).select_from(CanaryFile)
                                .where(CanaryFile.trigger_count > 0))

        assert wait_for(lambda: canary_triggered() >= 1, timeout=10)
        score, level, details = wait_for(
            lambda: (_risk(factory, cfg.agent.endpoint_name)
                     if _risk(factory, cfg.agent.endpoint_name)[0] >= 50 else None),
            timeout=10) or _risk(factory, cfg.agent.endpoint_name)
        assert score >= 50
        assert level in ("elevated", "high", "critical")
        types = {c["signal_type"] for c in (details or {}).get("active_signals", [])}
        assert "canary_modified" in types

        # Auto-regeneration restores the canary.
        assert wait_for(lambda: canary.exists() and canary.read_bytes().startswith(b"SENTINEL CANARY"),
                        timeout=10)
    finally:
        agent.stop()


def test_mass_encryption_simulation_detected(config_factory, watched_dir):
    # Seed a tree of normal, structured documents.
    sub = watched_dir / "projects"
    sub.mkdir()
    for i in range(40):
        d = watched_dir if i % 2 else sub
        (d / f"doc{i}.txt").write_text(("quarterly report section %d\n" % i) * 60)
    cfg = config_factory(
        [watched_dir],
        canary={"auto_deploy": False},
        entropy={"min_file_size": 128},
        behavior={"window_seconds": 30, "mass_modification_threshold": 15,
                  "extension_change_threshold": 8, "signal_cooldown_seconds": 0},
    )
    agent = SentinelAgent(cfg)
    agent.start()
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        # Wait for the inventory baseline so entropy deltas are meaningful.
        time.sleep(2.0)
        # Simulate ransomware: encrypt (high-entropy overwrite) + rename extension.
        for i in range(40):
            d = watched_dir if i % 2 else sub
            p = d / f"doc{i}.txt"
            p.write_bytes(secrets.token_bytes(4096))
            p.rename(d / f"doc{i}.txt.locked")

        def enough_risk():
            score, level, details = _risk(factory, cfg.agent.endpoint_name)
            return details if score >= 60 else None

        details = wait_for(enough_risk, timeout=20)
        assert details, f"risk did not reach High: {_risk(factory, cfg.agent.endpoint_name)}"
        types = {c["signal_type"] for c in details["active_signals"]}
        # Independent signals must corroborate each other.
        assert "rapid_mass_modification" in types
        assert types & {"suspicious_extension_change", "entropy_spike", "magic_mismatch"}
        assert details["correlation_bonus"] > 0  # multiple distinct signals

        # Entropy history was recorded for the transformed files.
        with factory() as s:
            suspicious_entropy = s.scalar(select(func.count()).select_from(EntropyHistory)
                                          .where(EntropyHistory.suspicious.is_(True)))
            assert suspicious_entropy >= 1
    finally:
        agent.stop()


def test_normal_activity_stays_low_risk(config_factory, watched_dir):
    cfg = config_factory([watched_dir], canary={"auto_deploy": False}, entropy={"min_file_size": 128})
    agent = SentinelAgent(cfg)
    agent.start()
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        time.sleep(1.0)
        # Ordinary user activity: a handful of text/code files, normal compressed files.
        for i in range(8):
            (watched_dir / f"note{i}.txt").write_text("meeting notes and action items\n" * 20)
            (watched_dir / f"photo{i}.jpg").write_bytes(b"\xff\xd8\xff\xe0" + secrets.token_bytes(8000))
        time.sleep(3.0)
        score, level, _ = _risk(factory, cfg.agent.endpoint_name)
        assert score < 40, f"benign activity produced {level} risk ({score})"
    finally:
        agent.stop()
