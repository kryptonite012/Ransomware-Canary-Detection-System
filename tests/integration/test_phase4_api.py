"""Phase 4 integration: API auth, RBAC, control plane, dashboard, websocket."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.app import create_app
from backend.config import BackendSettings
from backend.database import make_session_factory
from backend.models import Endpoint, MonitoredDirectory, SystemConfiguration

pytestmark = pytest.mark.integration


@pytest.fixture
def api(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setenv("SENTINEL_DATA_DIR", str(data))
    monkeypatch.setenv("SENTINEL_CONFIG", "/nonexistent-so-defaults-apply")
    settings = BackendSettings(serve_frontend=False, cors_origins=[],
                               rate_limit_per_minute=100000, login_rate_limit_per_minute=1000)
    from backend.api.deps import rate_limiter
    rate_limiter.reset()
    app = create_app(settings)
    client = TestClient(app)
    # Create an endpoint row to target.
    factory = make_session_factory(settings.sentinel_config().agent.resolved_database_url())
    with factory() as s:
        ep = Endpoint(hostname="host-a", operating_system="Linux", agent_version="1.0.0", status="online")
        s.add(ep)
        s.commit()
        ep_id = ep.id
    # Bootstrap an admin + analyst + viewer via the auth service directly.
    from backend.auth.service import AuthService
    from backend.config import resolve_jwt_secret
    auth = AuthService(settings, resolve_jwt_secret(settings, data))
    with factory() as s:
        auth.create_user(s, "admin", "admin@x.io", "adminpass123", "admin")
        auth.create_user(s, "analyst", "analyst@x.io", "analystpass123", "analyst")
        auth.create_user(s, "viewer", "viewer@x.io", "viewerpass123", "viewer")
        s.commit()
    return client, ep_id, factory


def _login(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_login_refresh_rotation_and_reuse_detection(api):
    client, _, _ = api
    tokens = _login(client, "admin", "adminpass123")
    assert tokens["user"]["role"] == "admin"
    # profile works with access token
    r = client.get("/api/auth/profile", headers=_auth(tokens["access_token"]))
    assert r.status_code == 200 and r.json()["username"] == "admin"
    # refresh rotates
    r = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    new_tokens = r.json()
    assert new_tokens["refresh_token"] != tokens["refresh_token"]
    # reusing the OLD refresh token triggers reuse detection -> family revoked
    r = client.post("/api/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401
    # the rotated token is now also revoked
    r = client.post("/api/auth/refresh", json={"refresh_token": new_tokens["refresh_token"]})
    assert r.status_code == 401


def test_bad_login_and_lockout(api):
    client, _, _ = api
    for _ in range(5):
        r = client.post("/api/auth/login", json={"username": "viewer", "password": "wrong"})
        assert r.status_code == 401
    # account now locked even with correct password
    r = client.post("/api/auth/login", json={"username": "viewer", "password": "viewerpass123"})
    assert r.status_code == 401 and "lock" in r.json()["detail"].lower()


def test_unauthenticated_and_rbac(api):
    client, ep_id, _ = api
    assert client.get("/api/dashboard/overview").status_code == 401
    viewer = _login(client, "viewer", "viewerpass123")["access_token"]
    analyst = _login(client, "analyst", "analystpass123")["access_token"]
    admin = _login(client, "admin", "adminpass123")["access_token"]
    # viewer can read overview
    assert client.get("/api/dashboard/overview", headers=_auth(viewer)).status_code == 200
    # viewer CANNOT add a directory (needs analyst)
    body = {"endpoint_id": ep_id, "path": "/home/u/Documents", "recursive": True}
    assert client.post("/api/monitoring/directories", json=body, headers=_auth(viewer)).status_code == 403
    # analyst CAN
    r = client.post("/api/monitoring/directories", json=body, headers=_auth(analyst))
    assert r.status_code == 201, r.text
    # viewer cannot publish policy (admin only)
    assert client.put("/api/system/configuration", json={"policy": {}}, headers=_auth(analyst)).status_code == 403
    assert client.put("/api/system/configuration", json={"policy": {}}, headers=_auth(admin)).status_code == 200


def test_control_plane_signs_directories_and_policy(api):
    client, ep_id, factory = api
    admin = _login(client, "admin", "adminpass123")["access_token"]
    body = {"endpoint_id": ep_id, "path": "/data/share", "recursive": True}
    r = client.post("/api/monitoring/directories", json=body, headers=_auth(admin))
    assert r.status_code == 201
    dir_id = r.json()["id"]
    # The row must carry a signature the agent can verify.
    with factory() as s:
        row = s.get(MonitoredDirectory, dir_id)
        assert row.signature
        from agent.core.signing import Verifier, directory_payload
        settings = BackendSettings(serve_frontend=False)
        pub = settings.sentinel_config().agent.resolved_public_key_path()
        v = Verifier.from_file(pub)
        assert v.verify(directory_payload(ep_id, "/data/share", True, True), row.signature)
    # Publish a policy with an override and verify version increments + signature.
    r = client.put("/api/system/configuration",
                   json={"policy": {"entropy": {"high_entropy_threshold": 7.6}}, "comment": "tune"},
                   headers=_auth(admin))
    assert r.status_code == 200
    with factory() as s:
        cfg = s.scalar(select(SystemConfiguration).order_by(SystemConfiguration.version.desc()))
        assert cfg.policy["entropy"]["high_entropy_threshold"] == 7.6


def test_invalid_policy_rejected(api):
    client, _, _ = api
    admin = _login(client, "admin", "adminpass123")["access_token"]
    # thresholds not increasing -> 422
    bad = {"policy": {"risk": {"level_thresholds": {"low": 80, "elevated": 40, "high": 60, "critical": 90}}}}
    assert client.put("/api/system/configuration", json=bad, headers=_auth(admin)).status_code == 422


def test_dashboard_statistics_and_security_headers(api):
    client, _, _ = api
    viewer = _login(client, "viewer", "viewerpass123")["access_token"]
    r = client.get("/api/dashboard/statistics", headers=_auth(viewer))
    assert r.status_code == 200
    assert "event_type_distribution" in r.json()
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert "default-src 'self'" in r.headers.get("Content-Security-Policy", "")
    r = client.get("/api/dashboard/activity", headers=_auth(viewer))
    assert r.status_code == 200 and isinstance(r.json(), list)


def test_openapi_available(api):
    client, _, _ = api
    assert client.get("/api/openapi.json").status_code == 200
    assert client.get("/api/health").json()["status"] == "ok"


def test_websocket_requires_token(api):
    client, _, _ = api
    tokens = _login(client, "viewer", "viewerpass123")
    # no token -> rejected
    with pytest.raises(Exception):
        with client.websocket_connect("/api/ws"):
            pass
    # valid token -> snapshot delivered
    with client.websocket_connect(f"/api/ws?token={tokens['access_token']}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "snapshot"
        assert "overview" in msg["data"]
