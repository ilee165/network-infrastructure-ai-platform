"""Async SQLAlchemy 2.0 engine and session factories (D2, D4).

Factories take :class:`~app.core.config.Settings` explicitly so tests and
short-lived probes can build isolated engines; the module-level accessors lazily
cache one engine/sessionmaker per process for the api/worker runtime.

:func:`get_session` is the FastAPI session-per-request dependency (M1).
"""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def build_ssl_connect_args(settings: Settings) -> dict[str, Any]:
    """Build the asyncpg ``ssl`` connect-arg for the api/worker -> Postgres link.

    Implements ADR-0039 §4 (mutual TLS, ``verify-full`` class) on the client
    side: when :attr:`Settings.db_ssl_mode` is set the returned mapping carries an
    :class:`ssl.SSLContext` that (a) verifies the Postgres SERVER cert against the
    mounted CA and (b) PRESENTS the mounted client cert/key so the server can
    authenticate it (``clientcert=verify-full`` on the server). With no SSL mode
    the mapping is empty and the connection stays plaintext — unchanged behaviour
    so the default deployment is unaffected; mTLS is opt-in via the chart.

    The cert material is read from the mounted FILES referenced in *settings*;
    the key bytes never pass through config, logs, or this function's return value
    (ADR-0039 §5 — cert keys are mounted files, never inlined).

    Raises
    ------
    ValueError
        When an SSL mode is requested without a root CA (a verify mode with no
        trust anchor must fail closed, never silently downgrade to no-verify), or
        when the client cert/key pair is missing/half-set while a mode is set
        (mutual TLS must present a client cert — fail closed at the client layer,
        never silently downgrade to one-way server-auth-only TLS).
    """
    mode = settings.db_ssl_mode
    if mode is None:
        return {}
    if settings.db_ssl_root_cert is None:
        raise ValueError(
            "NETOPS_DB_SSL_MODE is set but no root cert (NETOPS_DB_SSL_ROOT_CERT) "
            "was provided — a verify mode with no trust anchor must fail closed"
        )
    # Mutual TLS (ADR-0039 §4): the client MUST present a cert/key. Fail closed if
    # the pair is half-set or absent — silently building a server-auth-only context
    # would downgrade mTLS to one-way TLS at the client's own layer (relying on the
    # server's clientcert=verify-full to refuse a certless client is fail-open here).
    if (settings.db_ssl_cert is None) != (settings.db_ssl_key is None):
        raise ValueError(
            "NETOPS_DB_SSL_CERT and NETOPS_DB_SSL_KEY must be set together "
            "(mutual TLS requires both the client cert and its key)"
        )
    if settings.db_ssl_cert is None:
        raise ValueError(
            "NETOPS_DB_SSL_MODE is set but no client cert/key "
            "(NETOPS_DB_SSL_CERT / NETOPS_DB_SSL_KEY) was provided — mutual TLS "
            "requires a client cert/key; verify-full must present a client certificate"
        )
    context = ssl.create_default_context(cafile=str(settings.db_ssl_root_cert))
    # verify-full == verify the chain AND match the server hostname; verify-ca
    # verifies the chain only (the libpq distinction). Both REQUIRE the peer cert.
    context.check_hostname = mode == "verify-full"
    context.verify_mode = ssl.CERT_REQUIRED
    # Present the client certificate (mutual TLS): the server authenticates it.
    context.load_cert_chain(
        certfile=str(settings.db_ssl_cert),
        keyfile=str(settings.db_ssl_key),
    )
    return {"ssl": context}


def create_engine(settings: Settings) -> AsyncEngine:
    """Build a new async engine from *settings* (does not connect).

    Threads the api/worker -> Postgres mTLS connect-args (ADR-0039 §4) into the
    asyncpg driver when SSL is configured; a plaintext deployment is unchanged.
    """
    connect_args = build_ssl_connect_args(settings)
    return create_async_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)


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
