"""Backup snapshots and verified recovery.

SENTINEL can take point-in-time snapshots of protected directories.  Each
snapshot stores a copy of every file plus an HMAC-signed manifest of SHA-256
hashes.  Recovery compares the live directory against a *verified* snapshot and
restores files that are missing or whose content has changed.

Safety rules:

* Snapshots only read user files and write into the agent's snapshot store.
* A snapshot is used for restore **only after its manifest signature and file
  hashes verify** - a corrupted or tampered snapshot is never trusted.
* Restore is an explicit, authorized action (CLI / approved ResponseAction),
  never automatic, and it reports exactly which files it changed so the
  operation is auditable and reversible.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.core.signing import HmacSigner, canonical_json, ensure_secret_file
from backend.database import utcnow
from backend.models import Snapshot

log = logging.getLogger("sentinel.recovery")


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(131072):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class RestoreReport:
    snapshot_id: int
    source_directory: str
    verified: bool
    restored: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    failed: list[dict[str, str]] = field(default_factory=list)
    skipped_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id, "source_directory": self.source_directory,
            "verified": self.verified, "restored": self.restored[:200], "restored_count": len(self.restored),
            "unchanged_count": len(self.unchanged), "failed": self.failed[:50],
            "skipped_reason": self.skipped_reason,
        }


class RecoveryManager:
    def __init__(self, store, endpoint_id: int, snapshots_dir: Path, agent_key_path: Path,
                 exclusions=None, max_files: int = 200_000):
        self.store = store
        self.endpoint_id = endpoint_id
        self.snapshots_dir = Path(snapshots_dir)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.signer = HmacSigner(ensure_secret_file(agent_key_path))
        self.exclusions = exclusions
        self.max_files = max_files

    # -------------------------------------------------------------------- create
    def create_snapshot(self, directory: str) -> int:
        directory = os.path.abspath(directory)
        if not os.path.isdir(directory):
            raise FileNotFoundError(directory)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        dest_root = self.snapshots_dir / f"{Path(directory).name}_{stamp}_{os.getpid()}"
        dest_root.mkdir(parents=True, exist_ok=True)

        def _create_row(s):
            row = Snapshot(endpoint_id=self.endpoint_id, source_directory=directory,
                           snapshot_path=str(dest_root), status="creating", created_at=utcnow())
            s.add(row)
            s.flush()
            return row.id

        snapshot_id = self.store.run(_create_row)
        manifest: list[dict[str, Any]] = []
        total_bytes = 0
        count = 0
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]
            for fname in files:
                src = os.path.join(root, fname)
                if os.path.islink(src):
                    continue
                if self.exclusions is not None and self.exclusions.is_excluded(src):
                    continue
                try:
                    st = os.stat(src)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                except OSError:
                    continue
                rel = os.path.relpath(src, directory)
                dest = dest_root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    digest = self._copy_hash(src, dest)
                except OSError as exc:
                    log.warning("snapshot skip %s: %s", src, exc)
                    continue
                manifest.append({"rel": rel, "sha256": digest, "size": st.st_size, "mtime": st.st_mtime})
                total_bytes += st.st_size
                count += 1
                if count >= self.max_files:
                    log.warning("snapshot file limit reached at %d files", count)
                    break
            if count >= self.max_files:
                break

        manifest_hash = self._write_manifest(dest_root, directory, snapshot_id, manifest)
        self.store.run(lambda s: s.execute(
            __import__("sqlalchemy").update(Snapshot).where(Snapshot.id == snapshot_id).values(
                file_count=count, total_bytes=total_bytes, manifest_hash=manifest_hash,
                status="ready", verified_at=utcnow())))
        log.info("snapshot %d created: %d files, %d bytes from %s", snapshot_id, count, total_bytes, directory)
        return snapshot_id

    def _copy_hash(self, src: str, dest: Path) -> str:
        h = hashlib.sha256()
        with open(src, "rb") as fin, open(dest, "wb") as fout:
            while chunk := fin.read(131072):
                h.update(chunk)
                fout.write(chunk)
        return h.hexdigest()

    def _write_manifest(self, dest_root: Path, directory: str, snapshot_id: int,
                        manifest: list[dict[str, Any]]) -> str:
        doc = {"snapshot_id": snapshot_id, "endpoint_id": self.endpoint_id, "source_directory": directory,
               "created_at": utcnow().isoformat(), "files": manifest}
        payload = canonical_json(doc)
        doc["signature"] = self.signer.sign(doc)
        (dest_root / "manifest.json").write_text(canonical_json(doc).decode("utf-8"), encoding="utf-8")
        return hashlib.sha256(payload).hexdigest()

    # -------------------------------------------------------------------- verify
    def verify_snapshot(self, snapshot_id: int) -> dict[str, Any]:
        row = self.store.run(lambda s: s.get(Snapshot, snapshot_id))
        if row is None:
            raise ValueError(f"snapshot {snapshot_id} not found")
        return self._verify_path(Path(row.snapshot_path))

    def _verify_path(self, dest_root: Path) -> dict[str, Any]:
        import json

        manifest_path = dest_root / "manifest.json"
        if not manifest_path.exists():
            return {"verified": False, "reason": "manifest missing"}
        doc = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = doc.pop("signature", None)
        if not self.signer.verify(doc, signature):
            return {"verified": False, "reason": "manifest signature invalid"}
        bad = []
        for entry in doc["files"]:
            fp = dest_root / entry["rel"]
            if not fp.exists() or _hash_file(fp) != entry["sha256"]:
                bad.append(entry["rel"])
        return {"verified": not bad, "reason": None if not bad else f"{len(bad)} file(s) corrupted in snapshot",
                "corrupted": bad[:50], "file_count": len(doc["files"]), "manifest": doc}

    # -------------------------------------------------------------------- restore
    def restore_snapshot(self, snapshot_id: int, dry_run: bool = True,
                         only_changed: bool = True) -> RestoreReport:
        import json

        row = self.store.run(lambda s: s.get(Snapshot, snapshot_id))
        if row is None:
            raise ValueError(f"snapshot {snapshot_id} not found")
        dest_root = Path(row.snapshot_path)
        verification = self._verify_path(dest_root)
        report = RestoreReport(snapshot_id=snapshot_id, source_directory=row.source_directory,
                               verified=verification["verified"])
        if not verification["verified"]:
            report.skipped_reason = f"snapshot failed verification: {verification['reason']}"
            log.error("refusing to restore from unverified snapshot %d: %s", snapshot_id,
                      verification["reason"])
            return report
        doc = verification["manifest"]
        for entry in doc["files"]:
            src = dest_root / entry["rel"]
            target = Path(row.source_directory) / entry["rel"]
            try:
                if only_changed and target.exists() and _hash_file(target) == entry["sha256"]:
                    report.unchanged.append(entry["rel"])
                    continue
                if dry_run:
                    report.restored.append(entry["rel"])
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                tmp = target.with_suffix(target.suffix + ".sentinel-restore")
                shutil.copy2(src, tmp)
                os.replace(tmp, target)
                report.restored.append(entry["rel"])
            except OSError as exc:
                report.failed.append({"file": entry["rel"], "error": str(exc)})
        log.info("restore snapshot %d (dry_run=%s): %d restored, %d unchanged, %d failed",
                 snapshot_id, dry_run, len(report.restored), len(report.unchanged), len(report.failed))
        return report


def create_snapshot_cli(config, directory: str) -> int:
    """`python -m agent snapshot <dir>` entry point."""
    from agent.core.store import AgentStore
    from agent.filesystem.exclusions import ExclusionRules
    from backend.database import run_migrations

    db_url = config.agent.resolved_database_url()
    run_migrations(db_url)
    store = AgentStore(db_url)
    endpoint_id = store.register_endpoint(config.agent.resolved_endpoint_name(), {})
    excl = ExclusionRules(config.monitoring.exclude_patterns, config.monitoring.exclude_directories)
    excl.add_directory(str(config.agent.data_path()))
    mgr = RecoveryManager(store, endpoint_id, config.agent.snapshots_path(),
                          config.agent.resolved_agent_key_path(), exclusions=excl)
    try:
        sid = mgr.create_snapshot(directory)
    except FileNotFoundError:
        print(f"directory not found: {directory}")
        return 1
    result = mgr.verify_snapshot(sid)
    print(f"snapshot {sid} created and {'VERIFIED' if result['verified'] else 'FAILED VERIFICATION'}")
    return 0 if result["verified"] else 2
