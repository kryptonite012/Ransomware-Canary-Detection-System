"""FastAPI dependencies: app state, DB sessions, authentication and RBAC."""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Iterator

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, sessionmaker

from backend.auth import security
from backend.auth.service import AuthService
from backend.models import User
from backend.services.control_plane import ControlPlane

bearer = HTTPBearer(auto_error=False)

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


@dataclass
class AppState:
    settings: object
    sentinel_config: object
    jwt_secret: str
    session_factory: sessionmaker
    auth: AuthService
    control_plane: ControlPlane
    ws_manager: object = None
    started_at: float = field(default_factory=time.time)


def get_state(request: Request) -> AppState:
    return request.app.state.sentinel


def get_db(request: Request) -> Iterator[Session]:
    state: AppState = request.app.state.sentinel
    session = state.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@dataclass
class CurrentUser:
    id: int
    username: str
    role: str


def get_current_user(request: Request,
                     credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    state: AppState = request.app.state.sentinel
    try:
        payload = security.decode_token(state.jwt_secret, credentials.credentials)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "token expired",
                            headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidTokenError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token",
                            headers={"WWW-Authenticate": "Bearer"})
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "wrong token type")
    return CurrentUser(id=int(payload["sub"]), username=payload["username"], role=payload["role"])


def require_role(minimum: str):
    min_rank = ROLE_RANK[minimum]

    def checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if ROLE_RANK.get(user.role, 0) < min_rank:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"requires {minimum} role or higher")
        return user

    return checker


require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("admin")


def load_user(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "account unavailable")
    return user


class RateLimiter:
    """In-process token-bucket rate limiter keyed by client IP + scope."""

    def __init__(self):
        self._buckets: dict[tuple[str, str], tuple[float, float]] = defaultdict(lambda: (0.0, 0.0))
        self._lock = Lock()

    def check(self, key: str, scope: str, per_minute: int) -> bool:
        rate = per_minute / 60.0
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets[(key, scope)]
            if last == 0.0:
                tokens = per_minute
            tokens = min(per_minute, tokens + (now - last) * rate)
            if tokens < 1:
                self._buckets[(key, scope)] = (tokens, now)
                return False
            self._buckets[(key, scope)] = (tokens - 1, now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


rate_limiter = RateLimiter()


def client_ip(request: Request) -> str:
    # Trust the socket peer; do not trust X-Forwarded-* unless a known proxy terminates TLS.
    return request.client.host if request.client else "unknown"
