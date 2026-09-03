"""Async database engine, session factory and schema bootstrap."""

from __future__ import annotations

import asyncio
import logging
import os

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

#: asyncpg takes its TLS setting through connect_args rather than the URL —
#: a ``?sslmode=`` query parameter is a libpq spelling and asyncpg rejects it.
_connect_args: dict = {}
if settings.database_ssl_required:
    _connect_args["ssl"] = "require"
    logger.info("Database connections require TLS")

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_recycle=1800,
    connect_args=_connect_args,
)
async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

#: backend/ directory (two levels up from app/core/database.py)
BACKEND_DIR = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)


class Base(DeclarativeBase):
    pass


async def get_db():
    """Yield a request-scoped session.

    Routes commit explicitly when they write. Committing here unconditionally
    (the previous behaviour) opened a write transaction for every read and
    could silently persist half-finished work from a handler that raised after
    its last mutation.
    """
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def init_db():
    """Bring the schema up to date via Alembic."""
    from alembic import command
    from alembic.config import Config

    alembic_ini = os.path.join(BACKEND_DIR, "alembic.ini")
    alembic_dir = os.path.join(BACKEND_DIR, "alembic")

    if not os.path.exists(alembic_ini):
        raise RuntimeError(f"alembic.ini not found at {alembic_ini}")

    alembic_cfg = Config(alembic_ini)
    alembic_cfg.set_main_option("script_location", alembic_dir)
    alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL_SYNC)

    def _upgrade():
        command.upgrade(alembic_cfg, "head")

    # Alembic is synchronous; run it off the event loop.
    await asyncio.to_thread(_upgrade)
    logger.info("Database migrations applied")
