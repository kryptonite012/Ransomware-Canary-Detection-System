"""Phase 1 integration tests: real filesystem events, persistence, signed control plane."""
from __future__ import annotations

import os
import time

import pytest
from sqlalchemy import func, select

from agent.core.agent import SentinelAgent
from agent.core.events import EventType
from agent.core.queue import BoundedEventQueue
from agent.core.signing import Signer, command_payload, directory_payload
from agent.filesystem.exclusions import ExclusionRules, SelfWriteGuard
from agent.filesystem.monitor import FilesystemMonitor
from backend.database import make_session_factory
from backend.models import AgentCommand, Endpoint, FileEvent, FileInventory, MonitoredDirectory
from tests.conftest import wait_for

pytestmark = pytest.mark.integration


def _drain(q):
    out = []
    while True:
        e = q.get(timeout=0.3)
        if e is None:
            return out
        out.append(e)


def test_monitor_captures_create_modify_rename_delete(watched_dir):
    q = BoundedEventQueue(10000, dedup_window_seconds=0.1)
    mon = FilesystemMonitor(q, ExclusionRules(["*.tmp"], []), SelfWriteGuard())
    mon.start()
    try:
        status = mon.add_directory(str(watched_dir))
        assert status.state == "active"
        f = watched_dir / "report.txt"
        f.write_text("hello world")
        time.sleep(0.2)
        with f.open("a") as fh:
            fh.write(" more")
        time.sleep(0.2)
        f.rename(watched_dir / "report.locked")
        time.sleep(0.2)
        (watched_dir / "report.locked").unlink()
        (watched_dir / "ignored.tmp").write_text("x")
        time.sleep(0.5)
        events = _drain(q)
    finally:
        mon.stop()
    types = [(e.event_type, os.path.basename(e.src_path)) for e in events]
    assert (EventType.CREATED, "report.txt") in types
    assert (EventType.MODIFIED, "report.txt") in types
    moved = [e for e in events if e.event_type is EventType.MOVED]
    assert moved and moved[0].dest_path.endswith("report.locked")
    assert (EventType.DELETED, "report.locked") in types
    assert not any("ignored.tmp" in e.src_path for e in events)


def test_monitor_reports_missing_directory(tmp_path):
    mon = FilesystemMonitor(BoundedEventQueue(1000), ExclusionRules([], []), SelfWriteGuard())
    mon.start()
    try:
        st = mon.add_directory(str(tmp_path / "does-not-exist"))
        assert st.state == "missing"
    finally:
        mon.stop()


def test_temp_then_rename_is_treated_as_write(watched_dir):
    q = BoundedEventQueue(1000, dedup_window_seconds=0)
    mon = FilesystemMonitor(q, ExclusionRules(["*.tmp"], []), SelfWriteGuard())
    mon.start()
    try:
        mon.add_directory(str(watched_dir))
        tmp = watched_dir / "doc.docx.tmp"
        tmp.write_bytes(b"PK\x03\x04data")
        tmp.rename(watched_dir / "doc.docx")
        time.sleep(0.5)
        events = _drain(q)
    finally:
        mon.stop()
    assert any(e.event_type is EventType.MODIFIED and e.src_path.endswith("doc.docx") for e in events)
    assert not any(e.event_type is EventType.MOVED for e in events)


def test_agent_persists_events_and_heartbeats(config_factory, watched_dir):
    (watched_dir / "existing.txt").write_text("baseline content")
    cfg = config_factory([watched_dir])
    agent = SentinelAgent(cfg)
    agent.start()
    try:
        for i in range(5):
            (watched_dir / f"file{i}.txt").write_text("data " * 50)
        factory = make_session_factory(cfg.agent.resolved_database_url())

        def count_events():
            with factory() as s:
                return s.scalar(select(func.count()).select_from(FileEvent).where(FileEvent.event_type == "created"))

        assert wait_for(lambda: count_events() >= 5, timeout=10)

        def inventory_has_existing():
            with factory() as s:
                return s.scalar(select(FileInventory).where(FileInventory.file_path.like("%existing.txt")))

        assert wait_for(inventory_has_existing, timeout=10)
        with factory() as s:
            ep = s.scalar(select(Endpoint).where(Endpoint.hostname == cfg.agent.endpoint_name))
            assert ep is not None and ep.status in ("online", "degraded")
            assert ep.health["monitor_alive"] is True
        # the agent's data directory is never monitored
        assert str(cfg.agent.data_path()) in agent.exclusions.directories
    finally:
        agent.stop()
    with factory() as s:
        ep = s.scalar(select(Endpoint).where(Endpoint.hostname == cfg.agent.endpoint_name))
        assert ep.status == "stopped"


def test_signed_directories_and_commands(config_factory, watched_dir, tmp_path, keypair):
    other = tmp_path / "other"
    other.mkdir()
    rogue = tmp_path / "rogue"
    rogue.mkdir()
    cfg = config_factory([watched_dir])
    agent = SentinelAgent(cfg)
    agent.start()
    signer = Signer.from_file(keypair[0])
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        eid = agent.endpoint_id
        with factory() as s:
            good = MonitoredDirectory(endpoint_id=eid, directory_path=str(other), recursive=True,
                                      monitoring_enabled=True)
            good.signature = signer.sign(directory_payload(eid, str(other), True, True))
            bad = MonitoredDirectory(endpoint_id=eid, directory_path=str(rogue), recursive=True,
                                     monitoring_enabled=True, signature="AAAA")
            s.add_all([good, bad])
            s.commit()
            good_id, bad_id = good.id, bad.id
        agent.reload_policy()
        active = agent.monitor.active_directories()
        assert str(other) in active
        assert str(rogue) not in active
        assert str(watched_dir) not in active  # DB registration supersedes YAML defaults
        with factory() as s:
            assert s.get(MonitoredDirectory, bad_id).status == "rejected"
            assert s.get(MonitoredDirectory, good_id).status == "active"
            ok = AgentCommand(endpoint_id=eid, command="ping", params={})
            forged = AgentCommand(endpoint_id=eid, command="ping", params={}, signature="AAAA")
            s.add_all([ok, forged])
            s.flush()
            ok.signature = signer.sign(command_payload(ok.id, eid, "ping", {}))
            s.commit()
            ok_id, forged_id = ok.id, forged.id

        def done():
            with factory() as s:
                a, b = s.get(AgentCommand, ok_id), s.get(AgentCommand, forged_id)
                return a.status == "completed" and b.status == "rejected" and (a, b)

        result = wait_for(done, timeout=10)
        assert result, "commands were not processed"
        assert result[0].result["pong"] is True
        assert any("invalid" in f for f in agent.tamper_findings)
    finally:
        agent.stop()
