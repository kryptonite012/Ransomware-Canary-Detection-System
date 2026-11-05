"""Canary intelligence engine: deploy, verify, detect tampering, regenerate.

A canary (decoy) file is the lowest-false-positive ransomware signal available:
no legitimate user or application has any reason to open, modify, rename or
delete a file they did not create and cannot see in normal workflows.  Any such
interaction is therefore treated as high severity.

The engine keeps the authoritative hash of every canary.  Detection happens two
ways that back each other up:

* **Event-driven** - the filesystem monitor reports a modify/rename/delete on a
  canary path; the engine reacts immediately (sub-second).
* **Periodic verification** - every ``verify_interval_seconds`` the engine
  re-hashes each canary.  This catches tampering that the notification API
  missed (e.g. events dropped under load, or a watch that errored).
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select, update

from agent.canary.content import assert_no_secrets, generate_for_name, kind_for_name
from agent.core.events import EventType, FileEvent
from backend.database import utcnow
from backend.models import CanaryFile

log = logging.getLogger("sentinel.canary")

# Window (seconds) during which the agent ignores events for a file it just
# wrote itself (canary deploy/regeneration). Long enough to absorb the
# create/replace events, short enough that a genuine attack on a freshly
# deployed canary is still detected.
SELF_WRITE_TTL = 2.5


def hash_file(path: str) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(131072):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


@dataclass(slots=True)
class CanaryTrigger:
    canary_id: int
    path: str
    directory: str
    canary_type: str
    interaction: str  # modified | renamed | deleted | accessed
    detected_by: str  # event | verification
    dest_path: str | None = None
    detail: str | None = None
    timestamp: float = 0.0


class CanaryEngine:
    def __init__(self, store, settings, self_writes, endpoint_id: int,
                 on_trigger=None):
        self.store = store
        self.s = settings
        self.self_writes = self_writes
        self.endpoint_id = endpoint_id
        self.on_trigger = on_trigger
        self._paths: dict[str, int] = {}          # normalized path -> canary id
        self._meta: dict[int, dict] = {}          # id -> {path, hash, type, dir, size}
        self._lock = threading.Lock()
        self._regen_timers: list[threading.Timer] = []
        self.deployed = 0
        self.triggers = 0

    # ------------------------------------------------------------------ loading
    def load_existing(self) -> None:
        def _do(s):
            rows = list(s.scalars(select(CanaryFile).where(
                CanaryFile.endpoint_id == self.endpoint_id,
                CanaryFile.status.in_(("active", "triggered", "missing", "regenerating")))))
            for r in rows:
                s.expunge(r)
            return rows

        for row in self.store.run(_do) or []:
            self._index(row)

    def _index(self, row: CanaryFile) -> None:
        with self._lock:
            self._paths[os.path.normpath(row.file_path)] = row.id
            self._meta[row.id] = {
                "path": row.file_path, "hash": row.original_hash, "type": row.canary_type,
                "dir": row.directory, "size": row.file_size, "generation": row.generation,
            }

    def canary_paths(self) -> list[str]:
        with self._lock:
            return list(self._paths.keys())

    def is_canary(self, path: str) -> bool:
        with self._lock:
            return os.path.normpath(path) in self._paths

    # ------------------------------------------------------------------ deploy
    def deploy_to_directory(self, directory: str, limit: int | None = None) -> list[int]:
        if not self.s.enabled:
            return []
        directory = os.path.abspath(directory)
        if not os.path.isdir(directory) or not os.access(directory, os.W_OK):
            log.warning("cannot deploy canaries to %s (missing or not writable)", directory)
            return []
        names = self.s.names[: (limit or self.s.max_canaries_per_directory)]
        created: list[int] = []
        for name in names:
            cid = self._deploy_one(directory, name)
            if cid is not None:
                created.append(cid)
        return created

    def _deploy_one(self, directory: str, name: str) -> int | None:
        filename = f"{self.s.name_prefix}{name}" if self.s.name_prefix else name
        path = os.path.join(directory, filename)
        norm = os.path.normpath(path)
        with self._lock:
            if norm in self._paths:
                return self._paths[norm]
        existing = self.store.run(lambda s: s.scalar(select(CanaryFile).where(
            CanaryFile.endpoint_id == self.endpoint_id, CanaryFile.file_path == path)))
        if existing is not None and os.path.exists(path):
            self.store.run(lambda s: s.execute(update(CanaryFile).where(CanaryFile.id == existing.id)
                                               .values(status="active")))
            self._index(existing)
            return existing.id
        try:
            digest, size = self._write_canary(path, name)
        except OSError as exc:
            log.error("failed to deploy canary %s: %s", path, exc)
            return None

        def _save(s):
            row = s.scalar(select(CanaryFile).where(CanaryFile.endpoint_id == self.endpoint_id,
                                                    CanaryFile.file_path == path))
            now = utcnow()
            if row is None:
                row = CanaryFile(endpoint_id=self.endpoint_id, file_path=path, directory=directory,
                                 canary_type=kind_for_name(name), original_hash=digest, file_size=size,
                                 status="active", last_verified=now, created_at=now, generation=1)
                s.add(row)
            else:
                row.original_hash, row.file_size, row.status = digest, size, "active"
                row.last_verified, row.generation = now, row.generation + 1
            s.flush()
            s.expunge(row)
            return row

        row = self.store.run(_save)
        self._index(row)
        self.deployed += 1
        log.info("deployed canary %s", path)
        return row.id

    def _write_canary(self, path: str, name: str, seed: str | None = None) -> tuple[str, int]:
        seed = seed or f"{path}:{time.time_ns()}"
        _, content = generate_for_name(name, seed)
        assert_no_secrets(content)
        # Register BOTH create and the modify that follows, so our own write is
        # not mistaken for tampering.
        self.self_writes.register(path, ttl=SELF_WRITE_TTL)
        tmp = f"{path}.sentinel-tmp-{os.getpid()}"
        self.self_writes.register(tmp, ttl=SELF_WRITE_TTL)
        with open(tmp, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        try:
            # Make it read-only-ish; still detectable if an attacker flips it back.
            os.chmod(path, 0o644)
        except OSError:
            pass
        digest = hashlib.sha256(content).hexdigest()
        return digest, len(content)

    # ------------------------------------------------------------------ event path
    def handle_event(self, ev: FileEvent) -> CanaryTrigger | None:
        if not self.s.enabled:
            return None
        norm_src = os.path.normpath(ev.src_path)
        with self._lock:
            cid = self._paths.get(norm_src)
            dest_is_canary = ev.dest_path and os.path.normpath(ev.dest_path) in self._paths
        if cid is None and not dest_is_canary:
            return None
        if self.self_writes.is_self_write(ev.src_path):
            return None

        if ev.event_type is EventType.MOVED:
            interaction = "renamed"
        elif ev.event_type is EventType.DELETED:
            interaction = "deleted"
        elif ev.event_type is EventType.OPENED:
            if not self.s.alert_on_read:
                return None
            interaction = "accessed"
        else:
            interaction = "modified"
        if cid is None:
            return None
        return self._fire(cid, interaction, "event", ev.dest_path,
                          pid=ev.pid, process_name=ev.process_name)

    # ------------------------------------------------------------------ verification
    def verify_all(self) -> list[CanaryTrigger]:
        triggers: list[CanaryTrigger] = []
        with self._lock:
            items = list(self._meta.items())
        for cid, meta in items:
            trig = self._verify_one(cid, meta)
            if trig is not None:
                triggers.append(trig)
        return triggers

    def _verify_one(self, cid: int, meta: dict) -> CanaryTrigger | None:
        path = meta["path"]
        if self.self_writes.is_self_write(path):
            return None
        if not os.path.exists(path):
            return self._fire(cid, "deleted", "verification", None)
        try:
            digest, size = hash_file(path)
        except OSError as exc:
            log.warning("cannot verify canary %s: %s", path, exc)
            return None
        if digest != meta["hash"]:
            return self._fire(cid, "modified", "verification", None,
                              detail=f"hash changed (size {meta['size']} -> {size})")
        self.store.run(lambda s: s.execute(update(CanaryFile).where(CanaryFile.id == cid)
                                           .values(last_verified=utcnow())))
        return None

    # ------------------------------------------------------------------ firing + regen
    def _fire(self, cid: int, interaction: str, detected_by: str, dest_path: str | None,
              detail: str | None = None, pid: int | None = None, process_name: str | None = None) -> CanaryTrigger:
        with self._lock:
            meta = self._meta.get(cid)
            if meta is None:
                meta = {"path": "", "type": "txt", "dir": ""}
        now = utcnow()

        def _update(s):
            s.execute(update(CanaryFile).where(CanaryFile.id == cid).values(
                status="triggered", last_interaction=now, last_interaction_type=interaction,
                trigger_count=CanaryFile.trigger_count + 1))

        self.store.run(_update)
        self.triggers += 1
        trig = CanaryTrigger(canary_id=cid, path=meta["path"], directory=meta.get("dir", ""),
                             canary_type=meta.get("type", "txt"), interaction=interaction,
                             detected_by=detected_by, dest_path=dest_path, detail=detail,
                             timestamp=time.time())
        trig_detail = detail or ""
        proc = f" by pid={pid} ({process_name})" if pid else ""
        log.warning("CANARY %s: %s (%s)%s %s", interaction.upper(), meta["path"], detected_by, proc, trig_detail)
        if self.on_trigger is not None:
            try:
                self.on_trigger(trig, pid, process_name)
            except Exception:
                log.exception("canary trigger callback failed")
        if self.s.auto_regenerate and interaction in ("deleted", "modified", "renamed"):
            self._schedule_regen(cid)
        return trig

    def _schedule_regen(self, cid: int) -> None:
        with self._lock:
            meta = self._meta.get(cid)
        if not meta:
            return
        self.store.run(lambda s: s.execute(update(CanaryFile).where(CanaryFile.id == cid)
                                           .values(status="regenerating")))
        timer = threading.Timer(self.s.regenerate_delay_seconds, self._regenerate, args=(cid,))
        timer.daemon = True
        timer.start()
        with self._lock:
            self._regen_timers = [t for t in self._regen_timers if t.is_alive()]
            self._regen_timers.append(timer)

    def _regenerate(self, cid: int) -> None:
        with self._lock:
            meta = self._meta.get(cid)
        if not meta:
            return
        name = os.path.basename(meta["path"])
        if self.s.name_prefix and name.startswith(self.s.name_prefix):
            name = name[len(self.s.name_prefix):]
        try:
            # Remove any attacker-left artifact at the path first.
            if os.path.exists(meta["path"]):
                self.self_writes.register(meta["path"], ttl=5.0)
            digest, size = self._write_canary(meta["path"], name)
        except OSError as exc:
            log.error("failed to regenerate canary %s: %s", meta["path"], exc)
            self.store.run(lambda s: s.execute(update(CanaryFile).where(CanaryFile.id == cid)
                                               .values(status="error")))
            return
        with self._lock:
            self._meta[cid].update({"hash": digest, "size": size})
        self.store.run(lambda s: s.execute(update(CanaryFile).where(CanaryFile.id == cid).values(
            original_hash=digest, file_size=size, status="active", last_verified=utcnow(),
            generation=CanaryFile.generation + 1)))
        log.info("regenerated canary %s", meta["path"])

    def retire_directory(self, directory: str) -> None:
        directory = os.path.abspath(directory)
        with self._lock:
            ids = [cid for cid, m in self._meta.items() if m.get("dir") == directory]
            for cid in ids:
                path = self._meta[cid]["path"]
                self._paths.pop(os.path.normpath(path), None)
                self._meta.pop(cid, None)
        if ids:
            self.store.run(lambda s: s.execute(update(CanaryFile).where(CanaryFile.id.in_(ids))
                                               .values(status="retired")))

    def shutdown(self) -> None:
        with self._lock:
            timers = list(self._regen_timers)
        for t in timers:
            t.cancel()

    def stats(self) -> dict:
        with self._lock:
            active = sum(1 for m in self._meta.values() if m)
        return {"canaries": active, "deployed": self.deployed, "triggers": self.triggers}
