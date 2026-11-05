import hashlib
import os
import zipfile

import pytest

from agent.canary.content import (
    assert_no_secrets, generate_csv, generate_docx, generate_for_name, generate_pdf, generate_txt,
    generate_xlsx,
)
from agent.canary.engine import CanaryEngine, hash_file
from agent.core.config import CanarySettings
from agent.core.events import EventType, FileEvent
from agent.filesystem.exclusions import SelfWriteGuard


def test_generators_produce_valid_structure_and_no_secrets():
    assert generate_txt("s").startswith(b"SENTINEL CANARY")
    assert b"record_id" in generate_csv("s")
    for gen in (generate_docx, generate_xlsx):
        data = gen("s")
        assert data[:4] == b"PK\x03\x04"
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            assert "[Content_Types].xml" in z.namelist()
    assert generate_pdf("s").startswith(b"%PDF")
    assert generate_pdf("s").rstrip().endswith(b"%%EOF")
    for name in ("a.txt", "a.csv", "a.docx", "a.xlsx", "a.pdf"):
        _, content = generate_for_name(name, "seed")
        assert_no_secrets(content)


def test_assert_no_secrets_rejects_keys():
    with pytest.raises(ValueError):
        assert_no_secrets(b"-----BEGIN PRIVATE KEY-----")


def test_generators_are_seeded_unique_but_reproducible():
    assert generate_csv("a") == generate_csv("a")
    assert generate_csv("a") != generate_csv("b")


class _FakeStore:
    """In-memory stand-in for AgentStore for canary unit tests."""

    def __init__(self):
        self.rows = {}
        self._id = 0

    def run(self, fn, retries=3):
        import types
        sess = _FakeSession(self)
        return fn(sess)


class _FakeSession:
    def __init__(self, store):
        self.store = store

    # Only the subset the canary engine uses.
    def scalar(self, *a, **k):
        return None

    def scalars(self, *a, **k):
        return iter([])

    def execute(self, *a, **k):
        class _R:
            rowcount = 0
        return _R()

    def add(self, obj):
        self.store._id += 1
        obj.id = self.store._id
        self.store.rows[obj.id] = obj

    def flush(self):
        pass

    def expunge(self, obj):
        pass

    def get(self, model, pk):
        return self.store.rows.get(pk)


def _engine(tmp_path, **overrides):
    settings = CanarySettings(auto_regenerate=False, regenerate_delay_seconds=0, **overrides)
    return CanaryEngine(_FakeStore(), settings, SelfWriteGuard(), endpoint_id=1)


def test_deploy_creates_valid_canaries(tmp_path):
    eng = _engine(tmp_path)
    ids = eng.deploy_to_directory(str(tmp_path))
    assert len(ids) == 5
    for name in CanarySettings().names:
        p = tmp_path / name
        assert p.exists()
        digest, size = hash_file(str(p))
        assert size > 0
    assert eng.is_canary(str(tmp_path / "Backup_Index_Canary.txt"))


def test_self_write_during_deploy_not_a_trigger(tmp_path):
    eng = _engine(tmp_path)
    eng.deploy_to_directory(str(tmp_path))
    path = str(tmp_path / "Backup_Index_Canary.txt")
    # Immediately after deploy the path is registered as a self-write.
    ev = FileEvent(EventType.MODIFIED, path)
    assert eng.handle_event(ev) is None


def test_modification_triggers(tmp_path):
    triggers = []
    eng = _engine(tmp_path)
    eng.on_trigger = lambda t, pid, name: triggers.append(t)
    eng.deploy_to_directory(str(tmp_path))
    path = str(tmp_path / "Backup_Index_Canary.txt")
    eng.self_writes._paths.clear()  # simulate time passing past the self-write window
    trig = eng.handle_event(FileEvent(EventType.MODIFIED, path))
    assert trig is not None and trig.interaction == "modified"
    assert triggers and triggers[0].path == path


def test_deletion_and_rename_trigger(tmp_path):
    eng = _engine(tmp_path)
    eng.deploy_to_directory(str(tmp_path))
    eng.self_writes._paths.clear()
    p = str(tmp_path / "Financial_Records_Canary.xlsx")
    assert eng.handle_event(FileEvent(EventType.DELETED, p)).interaction == "deleted"
    p2 = str(tmp_path / "Employee_Database_Canary.csv")
    trig = eng.handle_event(FileEvent(EventType.MOVED, p2, dest_path=str(tmp_path / "x.locked")))
    assert trig.interaction == "renamed"


def test_verification_detects_tampering_and_deletion(tmp_path):
    eng = _engine(tmp_path)
    eng.deploy_to_directory(str(tmp_path))
    eng.self_writes._paths.clear()
    txt = tmp_path / "Backup_Index_Canary.txt"
    txt.write_bytes(b"attacker encrypted this" * 10)
    xlsx = tmp_path / "Financial_Records_Canary.xlsx"
    xlsx.unlink()
    triggers = eng.verify_all()
    interactions = {t.interaction for t in triggers}
    assert "modified" in interactions
    assert "deleted" in interactions


def test_regeneration_restores_canary(tmp_path):
    settings = CanarySettings(auto_regenerate=True, regenerate_delay_seconds=0.01)
    eng = CanaryEngine(_FakeStore(), settings, SelfWriteGuard(), endpoint_id=1)
    eng.deploy_to_directory(str(tmp_path))
    eng.self_writes._paths.clear()
    txt = tmp_path / "Backup_Index_Canary.txt"
    txt.unlink()
    eng.handle_event(FileEvent(EventType.DELETED, str(txt)))
    import time
    time.sleep(0.2)
    assert txt.exists()  # auto-regenerated
    eng.shutdown()
