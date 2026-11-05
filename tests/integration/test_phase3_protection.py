"""Phase 3 integration: alerts, incidents, approval workflow, evidence, recovery."""
from __future__ import annotations

import secrets
import subprocess
import sys
import time

import pytest
from sqlalchemy import func, select

from agent.core.agent import SentinelAgent
from agent.core.signing import Signer, command_payload
from backend.database import make_session_factory
from backend.models import (
    AgentCommand, EvidenceItem, Incident, ResponseAction, SecurityAlert, Snapshot,
)
from tests.conftest import wait_for

pytestmark = pytest.mark.integration


def test_canary_trigger_creates_incident_alert_and_pending_actions(config_factory, watched_dir):
    cfg = config_factory(
        [watched_dir],
        canary={"auto_deploy": True, "regenerate_delay_seconds": 0.2},
        entropy={"min_file_size": 128},
        response={"desktop_notifications": False, "auto_protect_directories": False,
                  "auto_suspend_on_canary": False},
    )
    agent = SentinelAgent(cfg)
    agent.start()
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        assert wait_for(lambda: len(list(watched_dir.glob("*Canary*"))) >= 5, timeout=10)
        time.sleep(3.0)
        # Two DISTINCT canaries -> multiple_canaries + correlation -> CONTAIN level.
        (watched_dir / "Confidential_Archive_Canary.docx").write_bytes(secrets.token_bytes(4096))
        time.sleep(0.5)
        (watched_dir / "Financial_Records_Canary.xlsx").write_bytes(secrets.token_bytes(4096))

        def ready():
            with factory() as s:
                inc = s.scalar(select(func.count()).select_from(Incident))
                al = s.scalar(select(func.count()).select_from(SecurityAlert))
                ev = s.scalar(select(func.count()).select_from(EvidenceItem))
                has_terminate = s.scalar(select(func.count()).select_from(ResponseAction)
                                         .where(ResponseAction.action_type == "terminate_process"))
            return inc >= 1 and al >= 1 and ev >= 1 and has_terminate >= 1

        assert wait_for(ready, timeout=15)
        with factory() as s:
            inc = s.scalar(select(Incident))
            assert inc.severity in ("high", "critical")
            assert inc.affected_files
            alert = s.scalar(select(SecurityAlert))
            assert alert.severity == "critical" and alert.incident_id == inc.id
            # all high-impact actions require approval, none auto-executed
            actions = list(s.scalars(select(ResponseAction)))
            types = {a.action_type for a in actions}
            assert "terminate_process" in types
            for a in actions:
                assert a.status == "pending_approval"
                assert a.requires_approval
    finally:
        agent.stop()


def test_approval_workflow_executes_reversible_action(config_factory, watched_dir, keypair):
    # Spawn a victim process we can safely suspend/resume.
    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    cfg = config_factory([watched_dir], canary={"auto_deploy": False},
                         response={"desktop_notifications": False})
    agent = SentinelAgent(cfg)
    agent.start()
    signer = Signer.from_file(keypair[0])
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        eid = agent.endpoint_id
        with factory() as s:
            from backend.models import User
            admin = User(username="approver", email="a@example.com", password_hash="x", role="admin")
            s.add(admin)
            s.commit()
            admin_id = admin.id
        # Manually create a pending suspend action for the victim.
        with factory() as s:
            act = ResponseAction(endpoint_id=eid, response_level="contain", action_type="suspend_process",
                                 target={"pid": victim.pid}, status="pending_approval",
                                 requires_approval=True, requested_by="agent", reason="test")
            s.add(act)
            s.commit()
            action_id = act.id
        # Approve it through a signed command (as the API/control plane would).
        with factory() as s:
            cmd = AgentCommand(endpoint_id=eid, command="approve_action",
                               params={"action_id": action_id, "user_id": admin_id})
            s.add(cmd)
            s.flush()
            cmd.signature = signer.sign(command_payload(cmd.id, eid, "approve_action",
                                                        {"action_id": action_id, "user_id": admin_id}))
            s.commit()
            cmd_id = cmd.id

        def executed():
            with factory() as s:
                a = s.get(ResponseAction, action_id)
                c = s.get(AgentCommand, cmd_id)
                return a.status == "completed" and c.status == "completed"

        assert wait_for(executed, timeout=10)
        import psutil
        assert psutil.Process(victim.pid).status() in (psutil.STATUS_STOPPED, psutil.STATUS_SLEEPING)
        with factory() as s:
            a = s.get(ResponseAction, action_id)
            assert a.rollback_data and a.rollback_data["action"] == "resume_process"

        # Roll back (resume) via signed command.
        with factory() as s:
            cmd = AgentCommand(endpoint_id=eid, command="rollback_action", params={"action_id": action_id})
            s.add(cmd)
            s.flush()
            cmd.signature = signer.sign(command_payload(cmd.id, eid, "rollback_action",
                                                        {"action_id": action_id}))
            s.commit()
            rb_id = cmd.id
        assert wait_for(lambda: _status(factory, action_id) == "rolled_back", timeout=10)
    finally:
        agent.stop()
        victim.kill()
        victim.wait()


def test_snapshot_and_restore_via_command(config_factory, watched_dir, tmp_path, keypair):
    src = tmp_path / "valuable"
    src.mkdir()
    (src / "report.txt").write_text("the real report")
    cfg = config_factory([watched_dir], canary={"auto_deploy": False})
    agent = SentinelAgent(cfg)
    agent.start()
    signer = Signer.from_file(keypair[0])
    factory = make_session_factory(cfg.agent.resolved_database_url())
    try:
        eid = agent.endpoint_id
        sid = _run_command(agent, factory, signer, eid, "create_snapshot", {"directory": str(src)})
        assert sid["snapshot_id"] and sid["verified"]
        snapshot_id = sid["snapshot_id"]
        # Corrupt the original, then restore.
        (src / "report.txt").write_bytes(secrets.token_bytes(200))
        res = _run_command(agent, factory, signer, eid, "restore_snapshot",
                           {"snapshot_id": snapshot_id, "dry_run": False})
        assert res["verified"] and res["restored_count"] == 1
        assert (src / "report.txt").read_text() == "the real report"
        with factory() as s:
            assert s.get(Snapshot, snapshot_id).status == "ready"
    finally:
        agent.stop()


def _status(factory, action_id):
    with factory() as s:
        a = s.get(ResponseAction, action_id)
        return a.status if a else None


def _run_command(agent, factory, signer, eid, command, params):
    from agent.core.signing import command_payload
    with factory() as s:
        cmd = AgentCommand(endpoint_id=eid, command=command, params=params)
        s.add(cmd)
        s.flush()
        cmd.signature = signer.sign(command_payload(cmd.id, eid, command, params))
        s.commit()
        cmd_id = cmd.id

    def done():
        with factory() as s:
            c = s.get(AgentCommand, cmd_id)
            return c.result if c.status == "completed" else None

    result = wait_for(done, timeout=15)
    assert result is not None, f"command {command} did not complete"
    return result
