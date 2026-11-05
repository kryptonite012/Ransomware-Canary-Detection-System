"""Authentication endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.api.deps import (
    AppState, CurrentUser, client_ip, get_current_user, get_db, get_state, load_user, rate_limiter,
    require_admin,
)
from backend.auth.service import AuthError
from backend.schemas import (
    ChangePasswordRequest, CreateUserRequest, LoginRequest, MessageResponse, RefreshRequest,
    TokenResponse, UserResponse,
)
from backend.auth import security

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _rl(request: Request, state: AppState):
    if not rate_limiter.check(client_ip(request), "login", state.settings.login_rate_limit_per_minute):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many login attempts; slow down")


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db),
          state: AppState = Depends(get_state)):
    _rl(request, state)
    try:
        pair = state.auth.authenticate(db, body.username, body.password, client_ip(request),
                                       request.headers.get("user-agent"))
    except AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc))
    return TokenResponse(access_token=pair.access_token, refresh_token=pair.refresh_token,
                         expires_at=pair.expires_at, user=UserResponse.model_validate(pair.user))


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest, request: Request, db: Session = Depends(get_db),
            state: AppState = Depends(get_state)):
    _rl(request, state)
    try:
        pair = state.auth.refresh(db, body.refresh_token, client_ip(request),
                                  request.headers.get("user-agent"))
    except AuthError as exc:
        code = status.HTTP_401_UNAUTHORIZED
        raise HTTPException(code, str(exc))
    return TokenResponse(access_token=pair.access_token, refresh_token=pair.refresh_token,
                         expires_at=pair.expires_at, user=UserResponse.model_validate(pair.user))


@router.post("/logout", response_model=MessageResponse)
def logout(body: RefreshRequest | None = None, db: Session = Depends(get_db),
           state: AppState = Depends(get_state), user: CurrentUser = Depends(get_current_user)):
    state.auth.logout(db, body.refresh_token if body else None, user.id)
    return MessageResponse(detail="logged out")


@router.get("/profile", response_model=UserResponse)
def profile(db: Session = Depends(get_db), user: CurrentUser = Depends(get_current_user)):
    return UserResponse.model_validate(load_user(db, user.id))


@router.post("/change-password", response_model=MessageResponse)
def change_password(body: ChangePasswordRequest, db: Session = Depends(get_db),
                    state: AppState = Depends(get_state), user: CurrentUser = Depends(get_current_user)):
    row = load_user(db, user.id)
    if not security.verify_password(body.current_password, row.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password is incorrect")
    state.auth.set_password(db, row, body.new_password, actor_id=user.id)
    return MessageResponse(detail="password changed; please log in again")


# ------------------------------------------------------------------ user admin
@router.get("/users", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), _: CurrentUser = Depends(require_admin)):
    from sqlalchemy import select

    from backend.models import User

    return [UserResponse.model_validate(u) for u in db.scalars(select(User).order_by(User.id))]


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(body: CreateUserRequest, db: Session = Depends(get_db),
                state: AppState = Depends(get_state), admin: CurrentUser = Depends(require_admin)):
    try:
        user = state.auth.create_user(db, body.username, body.email, body.password, body.role,
                                      actor_id=admin.id)
    except AuthError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT if exc.code == "duplicate"
                            else status.HTTP_400_BAD_REQUEST, str(exc))
    return UserResponse.model_validate(user)
