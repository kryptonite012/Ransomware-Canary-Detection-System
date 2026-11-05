"""Tamper-evident audit log.

Each audit entry stores the SHA-256 hash of the previous entry plus its own
content; the per-entry hash chains back to a genesis value.  Any insertion,
deletion or modification of a historical row breaks the chain, which
:func:`verify_chain` detects.  This gives a cheap, append-only, verifiable
audit trail without external infrastructure.
"""
from __future__ import annotations

import threading
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.core.signing import canonical_json, sha256_hex
from backend.database import utcnow
from backend.models import AuditLog

GENESIS = "0" * 64
_lock = threading.Lock()


def _entry_hash(prev_hash: str, fields: dict[str, Any]) -> str:
    return sha256_hex(prev_hash.encode() + canonical_json(fields))


def record(session: Session, *, action: str, resource: str, result: str,
           user_id: int | None = None, username: str | None = None, ip_address: str | None = None,
           details: dict[str, Any] | None = None) -> AuditLog:
    """Append an audit entry within the caller's transaction."""
    with _lock:
        last = session.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
        prev_hash = last.entry_hash if last else GENESIS
        ts = utcnow()
        fields = {
            "user_id": user_id, "username": username, "action": action, "resource": resource,
            "result": result, "ip_address": ip_address, "details": details or {},
            "timestamp": ts.isoformat(),
        }
        entry = AuditLog(
            user_id=user_id, username=username, action=action, resource=resource, result=result,
            ip_address=ip_address, details=details, timestamp=ts, prev_hash=prev_hash,
            entry_hash=_entry_hash(prev_hash, fields))
        session.add(entry)
        session.flush()
        return entry


def verify_chain(session: Session, limit: int | None = None) -> dict[str, Any]:
    stmt = select(AuditLog).order_by(AuditLog.id.asc())
    rows = list(session.scalars(stmt))
    if limit:
        rows = rows[-limit:]
    prev_hash = GENESIS if not limit else (rows[0].prev_hash if rows else GENESIS)
    broken: list[int] = []
    for row in rows:
        fields = {
            "user_id": row.user_id, "username": row.username, "action": row.action,
            "resource": row.resource, "result": row.result, "ip_address": row.ip_address,
            "details": row.details or {}, "timestamp": row.timestamp.isoformat(),
        }
        expected = _entry_hash(prev_hash, fields)
        if expected != row.entry_hash or row.prev_hash != prev_hash:
            broken.append(row.id)
        prev_hash = row.entry_hash
    return {"entries": len(rows), "valid": not broken, "broken_entry_ids": broken}
