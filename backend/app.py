"""FastAPI application factory."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agent.core.logging_setup import configure_logging
from agent.version import __version__
from backend.api import routes_auth, routes_dashboard
from backend.api.deps import AppState, client_ip, rate_limiter
from backend.auth.service import AuthService
from backend.config import BackendSettings, get_settings, resolve_jwt_secret
from backend.database import make_session_factory, run_migrations
from backend.services.control_plane import ControlPlane
from backend.websocket import WebSocketManager

log = logging.getLogger("sentinel.api")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}
# A strict CSP suitable for the self-contained dashboard bundle.
CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
       "script-src 'self'; connect-src 'self' ws: wss:; font-src 'self' data:; "
       "object-src 'none'; base-uri 'self'; frame-ancestors 'none'")


def create_app(settings: BackendSettings | None = None) -> FastAPI:
    settings = settings or get_settings()
    sentinel_config = settings.sentinel_config()
    configure_logging(sentinel_config.agent.log_level, sentinel_config.agent.log_file)

    data_dir = sentinel_config.agent.data_path()
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "secrets").mkdir(parents=True, exist_ok=True)
    db_url = sentinel_config.agent.resolved_database_url()
    run_migrations(db_url)
    jwt_secret = resolve_jwt_secret(settings, data_dir)
    session_factory = make_session_factory(db_url)
    control_plane = ControlPlane(
        sentinel_config.agent.secrets_path() / "control_plane_ed25519.key",
        sentinel_config.agent.resolved_public_key_path())
    # The API is the control plane: it owns the signing identity.  Generate the
    # keypair on first start so monitored-directory rows, commands and policies
    # can be signed (the agent only needs the public key, written alongside).
    if not control_plane.ensure_keys():
        log.warning("control-plane signing key unavailable; running in read-only control mode")
    auth = AuthService(settings, jwt_secret)
    ws_manager = WebSocketManager(session_factory)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ws_manager.start()
        log.info("PROJECT SENTINEL API v%s started (control-plane signing: %s)",
                 __version__, control_plane.can_sign)
        try:
            yield
        finally:
            await ws_manager.stop()

    app = FastAPI(title="PROJECT SENTINEL", version=__version__,
                  description="Ransomware canary & early-detection platform API",
                  lifespan=lifespan, docs_url="/api/docs", openapi_url="/api/openapi.json",
                  redoc_url=None)
    app.state.sentinel = AppState(
        settings=settings, sentinel_config=sentinel_config, jwt_secret=jwt_secret,
        session_factory=session_factory, auth=auth, control_plane=control_plane, ws_manager=ws_manager)

    if settings.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins,
                           allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

    @app.middleware("http")
    async def security_and_rate_limit(request: Request, call_next):
        # Global per-IP rate limit (login has its own stricter bucket).
        if request.url.path.startswith("/api") and not request.url.path.startswith("/api/docs"):
            if not rate_limiter.check(client_ip(request), "global", settings.rate_limit_per_minute):
                return JSONResponse(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                    content={"detail": "rate limit exceeded"})
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        response.headers.setdefault("Content-Security-Policy", CSP)
        return response

    app.include_router(routes_auth.router)
    app.include_router(routes_dashboard.router)

    @app.get("/api/health", tags=["system"])
    def health():
        return {"status": "ok", "version": __version__, "control_plane_can_sign": control_plane.can_sign}

    @app.websocket("/api/ws")
    async def ws_endpoint(websocket: WebSocket):
        # Authenticate via ?token= (browsers cannot set WS headers).
        token = websocket.query_params.get("token")
        from backend.auth import security as sec
        try:
            payload = sec.decode_token(jwt_secret, token or "")
            if payload.get("type") != "access":
                raise ValueError("wrong token type")
        except Exception:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        await ws_manager.connect(websocket)
        try:
            while True:
                await websocket.receive_text()  # keepalive / ignore client messages
        except WebSocketDisconnect:
            await ws_manager.disconnect(websocket)
        except Exception:
            await ws_manager.disconnect(websocket)

    _mount_frontend(app, settings)
    return app


def _mount_frontend(app: FastAPI, settings: BackendSettings) -> None:
    if not settings.serve_frontend:
        return
    dist = Path(__file__).resolve().parents[1] / "frontend" / "dist"
    if not dist.exists():
        return
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    assets = dist / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/", include_in_schema=False)
    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str = ""):
        # Serve static files directly; fall back to index.html for client-side routing.
        candidate = dist / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(dist / "index.html")
