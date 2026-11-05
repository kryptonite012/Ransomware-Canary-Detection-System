"""Forensic evidence preservation.

When a high-severity detection fires, SENTINEL copies the affected files into a
tamper-evident vault *before* any protective action touches them.  Each copy is
hashed (SHA-256) and recorded in an HMAC-signed manifest so that later tampering
with the vault is detectable.

Safety: evidence collection only ever **reads** user files and **writes** into
the agent's own vault directory.  It never modifies, moves or deletes the
originals.  Collection is bounded by per-incident file-count and byte limits so
a storm of events cannot fill the disk.
"""
from __future__ import annotations

import logging
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent.core.signing import HmacSigner, canonical_json, ensure_secret_file, sha256_hex
from backend.database import utcnow
from backend.models import EvidenceItem

log = logging.getLogger("sentinel.evidence")


class EvidenceVault:
    def __init__(self, store, endpoint_id: int, base_dir: Path, settings, agent_key_path: Path):
        self.store = store
        self.endpoint_id = endpoint_id
        self.base_dir = Path(base_dir)
        self.s = settings
        self.base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.base_dir, 0o700)
        except OSError:
            pass
        self.signer = HmacSigner(ensure_secret_file(agent_key_path))

    def _incident_dir(self, incident_id: int | None) -> Path:
        name = f"incident_{incident_id}" if incident_id else f"adhoc_{datetime.now(timezone.utc):%Y%m%dT%H%M%S}"
        d = self.base_dir / name
        d.mkdir(parents=True, exist_ok=True)
        return d

    def preserve_files(self, paths: list[str], incident_id: int | None = None,
                       reason: str | None = None) -> list[int]:
        """Copy up to the configured number of files into the vault."""
        collected: list[int] = []
        total = 0
        dest_dir = self._incident_dir(incident_id)
        manifest: list[dict[str, Any]] = []
        seen: set[str] = set()
        for path in paths:
            if len(collected) >= self.s.max_files_per_incident:
                break
            norm = os.path.normpath(path)
            if norm in seen:
                continue
            seen.add(norm)
            item_id = self._preserve_one(path, dest_dir, incident_id, reason, manifest)
            if item_id is not None:
                collected.append(item_id)
                total += manifest[-1]["size"]
                if total >= self.s.max_total_bytes:
                    log.warning("evidence byte budget reached; stopping collection")
                    break
        if manifest:
            self._write_manifest(dest_dir, incident_id, reason, manifest)
        return collected

    def _preserve_one(self, path: str, dest_dir: Path, incident_id: int | None, reason: str | None,
                      manifest: list[dict[str, Any]]) -> int | None:
        try:
            st = os.stat(path)
        except OSError:
            # File already gone (e.g. deleted by the attack) - record metadata only.
            return self._record(incident_id, "missing_file", path, None, None, 0,
                                 {"reason": reason, "note": "file not present at collection time"})
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > self.s.max_file_bytes:
            return self._record(incident_id, "oversized_file", path, None, None, st.st_size,
                                {"reason": reason, "note": "exceeds max_file_bytes; metadata only",
                                 "mtime": st.st_mtime})
        safe_name = f"{len(manifest):04d}_{os.path.basename(path)}"[:200]
        dest = dest_dir / safe_name
        try:
            digest = self._copy_and_hash(path, dest)
        except OSError as exc:
            log.warning("cannot preserve %s: %s", path, exc)
            return None
        meta = {
            "original_path": path, "stored_name": safe_name, "sha256": digest, "size": st.st_size,
            "mtime": st.st_mtime, "collected_at": utcnow().isoformat(),
        }
        manifest.append(meta)
        return self._record(incident_id, "file_copy", path, str(dest), digest, st.st_size,
                            {"reason": reason, "mtime": st.st_mtime})

    def _copy_and_hash(self, src: str, dest: Path) -> str:
        import hashlib

        h = hashlib.sha256()
        with open(src, "rb") as fin, open(dest, "wb") as fout:
            while chunk := fin.read(131072):
                h.update(chunk)
                fout.write(chunk)
        try:
            os.chmod(dest, 0o400)
        except OSError:
            pass
        return h.hexdigest()

    def _record(self, incident_id: int | None, item_type: str, original: str | None, stored: str | None,
                digest: str | None, size: int, details: dict[str, Any]) -> int | None:
        def _do(s):
            item = EvidenceItem(endpoint_id=self.endpoint_id, incident_id=incident_id, item_type=item_type,
                                original_path=(original or "")[:2048] or None,
                                stored_path=(stored or "")[:2048] or None, sha256=digest, size=size,
                                details=details)
            s.add(item)
            s.flush()
            return item.id

        return self.store.run(_do)

    def preserve_process_metadata(self, incident_id: int | None, process_info: dict[str, Any]) -> int | None:
        return self._record(incident_id, "process_metadata", None, None, None, 0, process_info)

    def _write_manifest(self, dest_dir: Path, incident_id: int | None, reason: str | None,
                        manifest: list[dict[str, Any]]) -> None:
        doc = {
            "endpoint_id": self.endpoint_id, "incident_id": incident_id, "reason": reason,
            "created_at": utcnow().isoformat(), "files": manifest,
        }
        doc["signature"] = self.signer.sign(doc)
        path = dest_dir / "manifest.json"
        path.write_text(canonical_json(doc).decode("utf-8"), encoding="utf-8")
        try:
            os.chmod(path, 0o400)
        except OSError:
            pass

    def verify_manifest(self, manifest_path: str | Path) -> dict[str, Any]:
        import json

        doc = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        signature = doc.pop("signature", None)
        signature_ok = self.signer.verify(doc, signature)
        file_results = []
        for entry in doc.get("files", []):
            stored = Path(manifest_path).parent / entry["stored_name"]
            ok = stored.exists() and sha256_hex(stored.read_bytes()) == entry["sha256"]
            file_results.append({"stored_name": entry["stored_name"], "intact": ok})
        return {"signature_ok": signature_ok, "files": file_results,
                "all_intact": signature_ok and all(f["intact"] for f in file_results)}
