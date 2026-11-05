"""Authentication service: login, token issue/rotation, user management."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.auth import security
from backend.database import utcnow
from backend.models import RefreshToken, User
from backend.services import audit


class AuthError(Exception):
    def __init__(self, message: str, code: str = "auth_error"):
        super().__init__(message)
        self.code = code


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    expires_at: Any
    user: User


class AuthService:
    def __init__(self, settings, jwt_secret: str):
        self.settings = settings
        self.jwt_secret = jwt_secret

    # ------------------------------------------------------------------ users
    def create_user(self, session: Session, username: str, email: str, password: str, role: str,
                    actor_id: int | None = None) -> User:
        if role not in ("admin", "analyst", "viewer"):
            raise AuthError("invalid role", "invalid_role")
        if session.scalar(select(User).where(User.username == username)):
            raise AuthError("username already exists", "duplicate")
        if session.scalar(select(User).where(User.email == email)):
            raise AuthError("email already exists", "duplicate")
        user = User(username=username, email=email, password_hash=security.hash_password(password),
                    role=role)
        session.add(user)
        session.flush()
        audit.record(session, action="user.create", resource=f"user:{username}", result="success",
                     user_id=actor_id, details={"role": role})
        return user

    def set_password(self, session: Session, user: User, password: str, actor_id: int | None = None) -> None:
        user.password_hash = security.hash_password(password)
        # Revoke all refresh tokens on password change.
        for tok in session.scalars(select(RefreshToken).where(RefreshToken.user_id == user.id,
                                                              RefreshToken.revoked_at.is_(None))):
            tok.revoked_at = utcnow()
        audit.record(session, action="user.set_password", resource=f"user:{user.username}",
                     result="success", user_id=actor_id)

    # ------------------------------------------------------------------ login
    def authenticate(self, session: Session, username: str, password: str, ip: str | None,
                     user_agent: str | None) -> TokenPair:
        user = session.scalar(select(User).where(User.username == username))
        now = utcnow()
        if user is None:
            # Perform a dummy hash to equalize timing against user enumeration.
            security.verify_password(password, security.hash_password("x" * 12))
            audit.record(session, action="auth.login", resource=f"user:{username}", result="failure",
                         ip_address=ip, details={"reason": "unknown_user"})
            session.commit()
            raise AuthError("invalid credentials", "invalid_credentials")
        if user.locked_until and user.locked_until > now:
            audit.record(session, action="auth.login", resource=f"user:{username}", result="failure",
                         ip_address=ip, user_id=user.id, details={"reason": "locked"})
            session.commit()
            raise AuthError("account temporarily locked", "locked")
        if not user.is_active:
            raise AuthError("account disabled", "disabled")
        if not security.verify_password(password, user.password_hash):
            user.failed_login_count += 1
            if user.failed_login_count >= self.settings.max_failed_logins:
                user.locked_until = now + timedelta(minutes=self.settings.lockout_minutes)
                user.failed_login_count = 0
            audit.record(session, action="auth.login", resource=f"user:{username}", result="failure",
                         ip_address=ip, user_id=user.id, details={"reason": "bad_password"})
            session.commit()  # persist lockout counter even though we signal failure
            raise AuthError("invalid credentials", "invalid_credentials")
        # Success.
        if security.needs_rehash(user.password_hash):
            user.password_hash = security.hash_password(password)
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login = now
        audit.record(session, action="auth.login", resource=f"user:{username}", result="success",
                     ip_address=ip, user_id=user.id)
        return self._issue_pair(session, user, ip, user_agent, security.new_family_id())

    def _issue_pair(self, session: Session, user: User, ip: str | None, user_agent: str | None,
                    family_id: str) -> TokenPair:
        access, expires = security.create_access_token(
            self.jwt_secret, user_id=user.id, username=user.username, role=user.role,
            ttl_minutes=self.settings.access_token_ttl_minutes)
        raw, token_hash = security.generate_refresh_token()
        rt = RefreshToken(
            user_id=user.id, token_hash=token_hash, family_id=family_id,
            expires_at=utcnow() + timedelta(days=self.settings.refresh_token_ttl_days),
            ip_address=ip, user_agent=(user_agent or "")[:255] or None)
        session.add(rt)
        session.flush()
        return TokenPair(access_token=access, refresh_token=raw, expires_at=expires, user=user)

    def refresh(self, session: Session, raw_token: str, ip: str | None, user_agent: str | None) -> TokenPair:
        token_hash = security.hash_refresh_token(raw_token)
        rt = session.scalar(select(RefreshToken).where(RefreshToken.token_hash == token_hash))
        now = utcnow()
        if rt is None:
            raise AuthError("invalid refresh token", "invalid_token")
        if rt.revoked_at is not None:
            # Reuse of a revoked token -> revoke the whole family (theft response).
            for sibling in session.scalars(select(RefreshToken).where(RefreshToken.family_id == rt.family_id,
                                                                     RefreshToken.revoked_at.is_(None))):
                sibling.revoked_at = now
            audit.record(session, action="auth.refresh_reuse", resource=f"family:{rt.family_id}",
                         result="failure", user_id=rt.user_id, ip_address=ip)
            session.commit()  # persist family revocation (theft response)
            raise AuthError("refresh token reuse detected; session revoked", "token_reuse")
        if rt.expires_at < now:
            raise AuthError("refresh token expired", "expired")
        user = session.get(User, rt.user_id)
        if user is None or not user.is_active:
            raise AuthError("account unavailable", "disabled")
        # Rotate.
        rt.revoked_at = now
        pair = self._issue_pair(session, user, ip, user_agent, rt.family_id)
        rt.replaced_by = session.scalar(select(RefreshToken.id).where(
            RefreshToken.token_hash == security.hash_refresh_token(pair.refresh_token)))
        return pair

    def logout(self, session: Session, raw_token: str | None, user_id: int | None) -> None:
        now = utcnow()
        if raw_token:
            rt = session.scalar(select(RefreshToken).where(
                RefreshToken.token_hash == security.hash_refresh_token(raw_token)))
            if rt and rt.revoked_at is None:
                for sibling in session.scalars(select(RefreshToken).where(
                        RefreshToken.family_id == rt.family_id, RefreshToken.revoked_at.is_(None))):
                    sibling.revoked_at = now
        if user_id is not None:
            audit.record(session, action="auth.logout", resource=f"user:{user_id}", result="success",
                         user_id=user_id)
