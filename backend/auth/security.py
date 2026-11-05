"""Password hashing (Argon2id) and JWT access/refresh tokens.

Refresh tokens are **rotated**: each use issues a new refresh token in the same
family and revokes the old one.  If a revoked token is ever presented again
(token theft / replay), the entire family is revoked - a standard refresh-token
reuse-detection scheme.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from argon2.low_level import Type

# Argon2id with sensible interactive parameters.
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16,
                         type=Type.ID)

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    if not password or len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError, ValueError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except (InvalidHashError, ValueError):
        return True


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(secret: str, *, user_id: int, username: str, role: str,
                        ttl_minutes: int) -> tuple[str, datetime]:
    expires = _now() + timedelta(minutes=ttl_minutes)
    payload = {
        "sub": str(user_id), "username": username, "role": role, "type": "access",
        "iat": int(_now().timestamp()), "exp": int(expires.timestamp()), "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM), expires


def decode_token(secret: str, token: str) -> dict[str, Any]:
    return jwt.decode(token, secret, algorithms=[ALGORITHM])


def generate_refresh_token() -> tuple[str, str]:
    """Return (raw_token, sha256_hex). Only the hash is stored."""
    raw = secrets.token_urlsafe(48)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def hash_refresh_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def new_family_id() -> str:
    return uuid.uuid4().hex
