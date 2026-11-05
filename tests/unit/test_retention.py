from datetime import timedelta

from sqlalchemy import func, select

from agent.core.config import RetentionSettings
from agent.core.retention import run_retention
from agent.core.store import AgentStore
from backend.database import run_migrations, utcnow
from backend.models import EntropyHistory, FileEvent


def test_retention_purges_old_rows(tmp_path):
    url = f"sqlite:///{tmp_path/'r.db'}"
    run_migrations(url)
    store = AgentStore(url)
    eid = store.register_endpoint("rhost", {})
    old = utcnow() - timedelta(days=100)
    recent = utcnow() - timedelta(hours=1)
    with store.session() as s:
        s.add_all([
            FileEvent(endpoint_id=eid, file_path="/old", event_type="modified", timestamp=old),
            FileEvent(endpoint_id=eid, file_path="/new", event_type="modified", timestamp=recent),
            EntropyHistory(endpoint_id=eid, file_path="/old", current_entropy=7.0, timestamp=old),
            EntropyHistory(endpoint_id=eid, file_path="/new", current_entropy=7.0, timestamp=recent),
        ])
    result = run_retention(store, RetentionSettings(file_events_days=30, entropy_history_days=30))
    assert result["file_events"] == 1
    assert result["entropy_history"] == 1
    with store.session() as s:
        assert s.scalar(select(func.count()).select_from(FileEvent)) == 1
        assert s.scalar(select(func.count()).select_from(EntropyHistory)) == 1
