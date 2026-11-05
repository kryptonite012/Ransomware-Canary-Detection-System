"""Alembic environment for PROJECT SENTINEL."""
from __future__ import annotations

import logging

from alembic import context
from sqlalchemy import pool

from backend.database import get_engine
from backend.models import Base

config = context.config
target_metadata = Base.metadata
log = logging.getLogger("alembic.env")


def _url() -> str:
    url = config.get_main_option("sqlalchemy.url")
    if not url:
        import os

        url = os.environ.get("SENTINEL_DATABASE_URL", "sqlite:///./data/sentinel.db")
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = get_engine(_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=connection.dialect.name == "sqlite",
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
        connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
