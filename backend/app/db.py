"""Async SQLAlchemy 2.0 engine and session factories (D2, D4).

Factories take :class:`~app.core.config.Settings` explicitly so tests and
short-lived probes can build isolated engines; the module-level accessors lazily
cache one engine/sessionmaker per process for the api/worker runtime.

:func:`get_session` is the FastAPI session-per-request dependency (M1).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def create_engine(settings: Settings) -> AsyncEngine:
    """Build a new async engine from *settings* (does not connect)."""
    return create_async_engine(settings.database_url, pool_pre_ping=True)


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Build an :class:`async_sessionmaker` bound to *engine*."""
    return async_sessionmaker(engine, expire_on_commit=False)


def get_engine() -> AsyncEngine:
    """Return the process-wide lazily created engine."""
    global _engine
    if _engine is None:
        _engine = create_engine(get_settings())
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """Return the process-wide sessionmaker bound to :func:`get_engine`."""
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = create_sessionmaker(get_engine())
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: one :class:`AsyncSession` per request.

    The session is closed (and any in-flight transaction released) when the
    request scope exits; commit/rollback is the caller's responsibility.
    """
    async with get_sessionmaker()() as session:
        yield session


async def dispose_engine() -> None:
    """Dispose the cached engine (lifespan shutdown hook); safe when unused."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
