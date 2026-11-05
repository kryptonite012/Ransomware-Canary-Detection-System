"""Backend CLI: run the API, bootstrap admin, generate keys, publish defaults."""
from __future__ import annotations

import argparse
import getpass
import sys

from agent.core.logging_setup import configure_logging


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-api", description="PROJECT SENTINEL control plane / API")
    parser.add_argument("--config", help="path to sentinel.yaml")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the API server")
    run.add_argument("--host")
    run.add_argument("--port", type=int)
    cu = sub.add_parser("create-user", help="create a dashboard user")
    cu.add_argument("username")
    cu.add_argument("email")
    cu.add_argument("--role", choices=["admin", "analyst", "viewer"], default="admin")
    cu.add_argument("--password", help="(insecure) password; omit to be prompted")
    sub.add_parser("init-keys", help="generate the control-plane Ed25519 keypair")
    sub.add_parser("publish-defaults", help="sign and publish the default policy from sentinel.yaml")
    sub.add_parser("verify-audit", help="verify the tamper-evident audit log chain")
    args = parser.parse_args(argv)

    from backend.config import BackendSettings, resolve_jwt_secret
    settings = BackendSettings(config_path=args.config) if args.config else BackendSettings()
    sentinel_config = settings.sentinel_config()
    configure_logging(sentinel_config.agent.log_level, sentinel_config.agent.log_file, json_console=False)

    from backend.database import make_session_factory, run_migrations, session_scope
    db_url = sentinel_config.agent.resolved_database_url()
    data_dir = sentinel_config.agent.data_path()
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "secrets").mkdir(parents=True, exist_ok=True)
    run_migrations(db_url)
    factory = make_session_factory(db_url)

    from backend.services.control_plane import ControlPlane
    cp = ControlPlane(sentinel_config.agent.secrets_path() / "control_plane_ed25519.key",
                      sentinel_config.agent.resolved_public_key_path())

    if args.command == "init-keys":
        if cp.ensure_keys():
            print(f"control-plane keypair ready:\n  private: {cp.private_key_path}\n  public:  {cp.public_key_path}")
            return 0
        print("failed to create control-plane keypair")
        return 1

    if args.command == "create-user":
        from backend.auth.service import AuthError, AuthService
        password = args.password or getpass.getpass("password: ")
        auth = AuthService(settings, resolve_jwt_secret(settings, data_dir))
        try:
            with session_scope(factory) as s:
                user = auth.create_user(s, args.username, args.email, password, args.role)
                print(f"created {args.role} user '{user.username}' (id {user.id})")
            return 0
        except (AuthError, ValueError) as exc:
            print(f"error: {exc}")
            return 1

    if args.command == "publish-defaults":
        if not cp.ensure_keys():
            print("no signing key available")
            return 1
        with session_scope(factory) as s:
            row = cp.publish_policy(s, sentinel_config, comment="default policy from sentinel.yaml")
            print(f"published policy v{row.version}")
        return 0

    if args.command == "verify-audit":
        from backend.services import audit
        with session_scope(factory) as s:
            result = audit.verify_chain(s)
        print(result)
        return 0 if result["valid"] else 2

    if args.command == "run":
        import uvicorn

        from backend.app import create_app
        if args.host:
            settings.host = args.host
        if args.port:
            settings.port = args.port
        cp.ensure_keys()
        _bootstrap_admin(settings, factory, data_dir)
        app = create_app(settings)
        uvicorn.run(app, host=settings.host, port=settings.port,
                    ssl_certfile=settings.tls_certfile, ssl_keyfile=settings.tls_keyfile,
                    log_level=sentinel_config.agent.log_level.lower())
        return 0
    return 2


def _bootstrap_admin(settings, factory, data_dir) -> None:
    """Create the initial admin from env vars if no users exist yet."""
    if not (settings.bootstrap_admin_username and settings.bootstrap_admin_password):
        return
    from sqlalchemy import func, select

    from backend.auth.service import AuthError, AuthService
    from backend.config import resolve_jwt_secret
    from backend.database import session_scope
    from backend.models import User

    with session_scope(factory) as s:
        if s.scalar(select(func.count()).select_from(User)):
            return
        auth = AuthService(settings, resolve_jwt_secret(settings, data_dir))
        try:
            auth.create_user(s, settings.bootstrap_admin_username,
                             f"{settings.bootstrap_admin_username}@sentinel.local",
                             settings.bootstrap_admin_password, "admin")
            print(f"bootstrapped admin user '{settings.bootstrap_admin_username}'")
        except (AuthError, ValueError) as exc:
            print(f"admin bootstrap skipped: {exc}")


if __name__ == "__main__":
    sys.exit(main())
