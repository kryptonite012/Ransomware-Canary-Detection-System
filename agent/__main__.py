"""Command line entry point: ``python -m agent <command>``."""
from __future__ import annotations

import argparse
import json
import sys

from agent.core.config import load_config
from agent.core.logging_setup import configure_logging
from agent.version import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-agent", description="PROJECT SENTINEL endpoint agent")
    parser.add_argument("--config", help="path to sentinel.yaml (default: config/sentinel.yaml or $SENTINEL_CONFIG)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run the agent in the foreground (used by service managers)")
    sub.add_parser("init", help="create data directories and apply database migrations")
    sub.add_parser("status", help="print the endpoint status recorded in the database")
    sub.add_parser("show-config", help="print the effective bootstrap configuration")
    sub.add_parser("version")
    snap = sub.add_parser("snapshot", help="create a verified backup snapshot of a directory")
    snap.add_argument("directory")
    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0

    config = load_config(args.config)
    configure_logging(config.agent.log_level, config.agent.log_file)

    if args.command == "show-config":
        print(json.dumps(config.model_dump(mode="json"), indent=2))
        return 0
    if args.command == "init":
        from backend.database import run_migrations

        data = config.agent.data_path()
        for sub_dir in ("", "secrets", "evidence", "snapshots", "state", "logs"):
            (data / sub_dir).mkdir(parents=True, exist_ok=True)
        run_migrations(config.agent.resolved_database_url())
        print(f"initialized data directory {data}")
        return 0
    if args.command == "status":
        from sqlalchemy import select

        from backend.database import make_session_factory
        from backend.models import Endpoint

        factory = make_session_factory(config.agent.resolved_database_url())
        with factory() as s:
            ep = s.scalar(select(Endpoint).where(Endpoint.hostname == config.agent.resolved_endpoint_name()))
            if ep is None:
                print("endpoint not registered (agent has never run)")
                return 1
            print(json.dumps({
                "hostname": ep.hostname, "status": ep.status, "last_seen": ep.last_seen,
                "risk_score": ep.current_risk_score, "risk_level": ep.current_risk_level,
                "agent_version": ep.agent_version,
            }, indent=2, default=str))
        return 0
    if args.command == "snapshot":
        from agent.response.recovery import create_snapshot_cli

        return create_snapshot_cli(config, args.directory)
    if args.command == "run":
        from agent.service.runner import run_service

        return run_service(config)
    parser.error(f"unknown command {args.command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
