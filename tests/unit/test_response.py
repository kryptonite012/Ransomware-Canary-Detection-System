import os
import secrets
import stat

import psutil
import pytest

from agent.core.config import EvidenceSettings, SentinelConfig
from agent.response.actions import ActionExecutor
from agent.response.evidence import EvidenceVault
from agent.response.recovery import RecoveryManager


class _Store:
    def __init__(self):
        self.rows = {}
        self._id = 0

    def run(self, fn, retries=3):
        return fn(_Session(self))


class _Session:
    def __init__(self, store):
        self.store = store

    def add(self, obj):
        self.store._id += 1
        obj.id = self.store._id
        self.store.rows[obj.id] = obj

    def flush(self):
        pass

    def get(self, model, pk):
        return self.store.rows.get(pk)

    def execute(self, *a, **k):
        class _R:
            rowcount = 0
        return _R()


def test_evidence_preserve_and_verify(tmp_path):
    secret = tmp_path / "agent.key"
    vault_dir = tmp_path / "vault"
    f1 = tmp_path / "doc.txt"
    f1.write_text("important data " * 100)
    f2 = tmp_path / "gone.txt"  # will not exist
    vault = EvidenceVault(_Store(), 1, vault_dir, EvidenceSettings(), secret)
    ids = vault.preserve_files([str(f1), str(f2)], incident_id=7, reason="test")
    assert len(ids) == 2  # one copy + one missing-metadata record
    inc_dir = vault_dir / "incident_7"
    manifest = inc_dir / "manifest.json"
    assert manifest.exists()
    result = vault.verify_manifest(manifest)
    assert result["signature_ok"] and result["all_intact"]
    # tamper with a preserved copy -> verification fails
    copies = [p for p in inc_dir.iterdir() if p.name != "manifest.json"]
    copies[0].chmod(0o600)
    copies[0].write_text("tampered")
    assert not vault.verify_manifest(manifest)["all_intact"]


def test_evidence_respects_limits(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_text("x" * 1000)
    settings = EvidenceSettings(max_files_per_incident=3)
    vault = EvidenceVault(_Store(), 1, tmp_path / "v", settings, tmp_path / "k")
    ids = vault.preserve_files([str(tmp_path / f"f{i}.txt") for i in range(10)], incident_id=1)
    assert len(ids) == 3


def test_evidence_never_modifies_original(tmp_path):
    f = tmp_path / "orig.txt"
    f.write_text("original")
    before = f.read_text()
    vault = EvidenceVault(_Store(), 1, tmp_path / "v", EvidenceSettings(), tmp_path / "k")
    vault.preserve_files([str(f)], incident_id=1)
    assert f.read_text() == before


def test_snapshot_create_verify_restore(tmp_path):
    src = tmp_path / "docs"
    src.mkdir()
    (src / "a.txt").write_text("alpha content")
    (src / "sub").mkdir()
    (src / "sub" / "b.txt").write_text("beta content")
    mgr = RecoveryManager(_Store(), 1, tmp_path / "snaps", tmp_path / "key.bin")
    sid = mgr.create_snapshot(str(src))
    assert mgr.verify_snapshot(sid)["verified"]

    # Simulate ransomware encrypting the originals.
    (src / "a.txt").write_bytes(secrets.token_bytes(500))
    (src / "sub" / "b.txt").unlink()

    dry = mgr.restore_snapshot(sid, dry_run=True)
    assert set(dry.restored) == {"a.txt", os.path.join("sub", "b.txt")}

    report = mgr.restore_snapshot(sid, dry_run=False)
    assert len(report.restored) == 2 and not report.failed
    assert (src / "a.txt").read_text() == "alpha content"
    assert (src / "sub" / "b.txt").read_text() == "beta content"


def test_restore_refuses_corrupted_snapshot(tmp_path):
    src = tmp_path / "docs"
    src.mkdir()
    (src / "a.txt").write_text("data")
    mgr = RecoveryManager(_Store(), 1, tmp_path / "snaps", tmp_path / "key.bin")
    sid = mgr.create_snapshot(str(src))
    # Corrupt a file inside the snapshot store.
    snap_row = mgr.store.rows[sid]
    for p in __import__("pathlib").Path(snap_row.snapshot_path).rglob("a.txt"):
        p.write_text("corrupted in vault")
    report = mgr.restore_snapshot(sid, dry_run=False)
    assert not report.verified and report.skipped_reason and not report.restored


def test_action_executor_protects_critical_processes(tmp_path):
    cfg = SentinelConfig()
    ex = ActionExecutor(cfg)
    # Our own process is always protected (dispatch catches the guard).
    assert not ex.dispatch("suspend_process", {"pid": os.getpid()}).ok
    assert not ex.dispatch("terminate_process", {"pid": os.getpid()}).ok
    assert not ex.dispatch("suspend_process", {"pid": 1}).ok  # never touch PID 1


def test_action_protect_and_unprotect_directory(tmp_path):
    d = tmp_path / "protect_me"
    d.mkdir()
    f = d / "file.txt"
    f.write_text("data")
    ex = ActionExecutor(SentinelConfig())
    res = ex.protect_directory(str(d))
    assert res.ok
    if os.name != "nt":
        assert not (os.stat(f).st_mode & stat.S_IWUSR)
        back = ex.dispatch("unprotect_directory", res.rollback)
        assert back.ok
        assert os.stat(f).st_mode & stat.S_IWUSR


def test_action_dispatch_unknown():
    ex = ActionExecutor(SentinelConfig())
    assert not ex.dispatch("nonexistent", {}).ok


def test_suspend_resume_real_child_process():
    import subprocess
    import sys
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        ex = ActionExecutor(SentinelConfig())
        res = ex.suspend_process(proc.pid)
        assert res.ok and res.rollback["action"] == "resume_process"
        assert psutil.Process(proc.pid).status() in (psutil.STATUS_STOPPED, psutil.STATUS_SLEEPING)
        back = ex.dispatch("resume_process", {"pid": proc.pid})
        assert back.ok
    finally:
        proc.kill()
        proc.wait()
