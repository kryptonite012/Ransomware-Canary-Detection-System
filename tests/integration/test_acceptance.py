"""Acceptance checks: agent restart/resume and offline operation."""
from __future__ import annotations

import secrets
import time

import pytest
from sqlalchemy import func, select

from agent.core.agent import SentinelAgent
from backend.database import make_session_factory
from backend.models import CanaryFile, Endpoint, FileInventory
from tests.conftest import wait_for

pytestmark = pytest.mark.integration


def test_agent_restart_resumes_same_endpoint_and_seeds_baselines(config_factory, watched_dir):
    (watched_dir / "ledger.txt").write_text("structured accounting text\n" * 80)
    cfg = config_factory([watched_dir], canary={"auto_deploy": True}, entropy={"min_file_size": 128})

    # First run: establish inventory + entropy baseline, deploy canaries.
    agent1 = SentinelAgent(cfg)
    agent1.start()
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        assert wait_for(lambda: len(list(watched_dir.glob("*Canary*"))) >= 5, timeout=10)

        def baselined():
            with factory() as s:
                row = s.scalar(select(FileInventory).where(FileInventory.file_path.like("%ledger.txt")))
                return row is not None and row.entropy is not None
        assert wait_for(baselined, timeout=10)
        with factory() as s:
            endpoint_id = s.scalar(select(Endpoint.id).where(
                Endpoint.hostname == cfg.agent.endpoint_name))
            canary_count = s.scalar(select(func.count()).select_from(CanaryFile))
        assert canary_count >= 5
    finally:
        agent1.stop()

    # Simulated reboot: a brand-new agent instance on the same data directory.
    agent2 = SentinelAgent(cfg)
    agent2.start()
    try:
        # Same endpoint identity is reused (not duplicated).
        with factory() as s:
            assert s.scalar(select(func.count()).select_from(Endpoint)) == 1
            assert agent2.endpoint_id == endpoint_id
        # Existing canaries are reloaded (not re-created as duplicates).
        assert agent2.engines.coordinator.canary.canary_paths()
        with factory() as s:
            assert s.scalar(select(func.count()).select_from(CanaryFile)) == canary_count

        # Baseline was seeded from the stored inventory, so an encryption of a file
        # that existed before the "reboot" is still detected via the history delta.
        time.sleep(3.0)
        (watched_dir / "ledger.txt").write_bytes(secrets.token_bytes(8000))

        def risk_rose():
            with factory() as s:
                ep = s.get(Endpoint, endpoint_id)
                return ep.current_risk_score if ep and ep.current_risk_score >= 15 else None
        assert wait_for(risk_rose, timeout=12), "post-restart detection did not fire"
    finally:
        agent2.stop()


def test_agent_runs_without_api_or_network(config_factory, watched_dir):
    # The agent must work with no API process and no network (offline).
    cfg = config_factory([watched_dir], canary={"auto_deploy": False}, entropy={"min_file_size": 128})
    agent = SentinelAgent(cfg)
    agent.start()
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        for i in range(3):
            (watched_dir / f"f{i}.txt").write_text("data " * 50)
        from backend.models import FileEvent
        assert wait_for(lambda: _count(factory, FileEvent) >= 3, timeout=10)
        # Health is recorded locally; no network calls are required anywhere above.
        assert agent.health()["monitor_alive"] is True
    finally:
        agent.stop()


def _count(factory, model):
    from sqlalchemy import func, select
    with factory() as s:
        return s.scalar(select(func.count()).select_from(model))
