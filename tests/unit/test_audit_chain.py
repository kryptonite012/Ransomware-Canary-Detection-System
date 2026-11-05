from sqlalchemy import select

from agent.core.store import AgentStore  # noqa: F401 (ensures model import side-effects)
from backend.database import make_session_factory, run_migrations, session_scope
from backend.models import AuditLog
from backend.services import audit


def _factory(tmp_path):
    url = f"sqlite:///{tmp_path/'audit.db'}"
    run_migrations(url)
    return make_session_factory(url)


def test_audit_chain_links_and_verifies(tmp_path):
    f = _factory(tmp_path)
    with session_scope(f) as s:
        for i in range(5):
            audit.record(s, action="test.action", resource=f"res:{i}", result="success",
                         username="admin")
    with session_scope(f) as s:
        result = audit.verify_chain(s)
        assert result["entries"] == 5 and result["valid"]
        rows = list(s.scalars(select(AuditLog).order_by(AuditLog.id)))
        # each entry chains to the previous
        for prev, cur in zip(rows, rows[1:]):
            assert cur.prev_hash == prev.entry_hash


def test_audit_chain_detects_tampering(tmp_path):
    f = _factory(tmp_path)
    with session_scope(f) as s:
        for i in range(4):
            audit.record(s, action="a", resource=f"r{i}", result="success")
    # Tamper with a historical row's content.
    with session_scope(f) as s:
        row = s.scalars(select(AuditLog).order_by(AuditLog.id)).all()[1]
        row.result = "failure"  # change without recomputing the hash chain
    with session_scope(f) as s:
        result = audit.verify_chain(s)
        assert not result["valid"]
        assert len(result["broken_entry_ids"]) >= 1


def test_audit_chain_detects_deletion(tmp_path):
    f = _factory(tmp_path)
    with session_scope(f) as s:
        for i in range(5):
            audit.record(s, action="a", resource=f"r{i}", result="success")
    with session_scope(f) as s:
        row = s.scalars(select(AuditLog).order_by(AuditLog.id)).all()[2]
        s.delete(row)  # remove a middle entry
    with session_scope(f) as s:
        assert not audit.verify_chain(s)["valid"]
