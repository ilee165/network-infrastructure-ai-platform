"""Async Neo4j client wrapper (ADR-0005 access path).

Thin lifecycle/retry layer over the official ``neo4j`` AsyncDriver:

- lazy connect (the driver is created on first use, never at import/construct)
- session/transaction helpers (:meth:`Neo4jClient.session`,
  :meth:`Neo4jClient.execute_read`, :meth:`Neo4jClient.execute_write`)
- bounded retry with exponential backoff on transient driver errors
  (``ServiceUnavailable`` / ``SessionExpired``), one fresh session per attempt
- :meth:`Neo4jClient.health_check` — a single non-retried ``RETURN 1`` probe

Module-level accessors (:func:`get_client` / :func:`dispose_client`) mirror how
``app.db`` exposes the process-wide Postgres engine. Credentials come from
:class:`app.core.config.Settings` and are never logged or included in reprs.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any, TypeVar

import structlog
from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncManagedTransaction, AsyncSession
from neo4j.exceptions import DriverError, Neo4jError, ServiceUnavailable, SessionExpired

from app.core.config import Settings, get_settings

logger = structlog.get_logger(__name__)

T = TypeVar("T")

#: Driver errors worth retrying: the server/route may come back momentarily.
TRANSIENT_ERRORS: tuple[type[Exception], ...] = (ServiceUnavailable, SessionExpired)

#: Builds an :class:`AsyncDriver` from settings; injectable for unit tests.
DriverFactory = Callable[[Settings], AsyncDriver]


def _default_driver_factory(settings: Settings) -> AsyncDriver:
    """Official async driver against the configured bolt endpoint (no I/O yet)."""
    return AsyncGraphDatabase.driver(
        settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
    )


class Neo4jClient:
    """Lazy, retrying wrapper around one :class:`neo4j.AsyncDriver`."""

    def __init__(
        self,
        settings: Settings,
        *,
        max_attempts: int = 3,
        backoff_base_seconds: float = 0.25,
        driver_factory: DriverFactory | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._settings = settings
        self._max_attempts = max_attempts
        self._backoff_base_seconds = backoff_base_seconds
        self._driver_factory = driver_factory or _default_driver_factory
        self._driver: AsyncDriver | None = None

    def __repr__(self) -> str:  # never includes credentials
        return f"Neo4jClient(uri={self._settings.neo4j_uri!r})"

    # -- lifecycle ----------------------------------------------------------

    def _get_driver(self) -> AsyncDriver:
        """Create the driver on first use; creation itself opens no connection."""
        if self._driver is None:
            self._driver = self._driver_factory(self._settings)
        return self._driver

    async def close(self) -> None:
        """Close the underlying driver if one was opened; safe to call repeatedly."""
        if self._driver is not None:
            await self._driver.close()
        self._driver = None

    # -- session / transaction helpers --------------------------------------

    @asynccontextmanager
    async def session(self, **kwargs: Any) -> AsyncIterator[AsyncSession]:
        """One driver session, always closed on scope exit."""
        session = self._get_driver().session(**kwargs)
        try:
            yield session
        finally:
            await session.close()

    async def execute_read(self, work: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any) -> T:
        """Run *work(tx, ...)* in a managed read transaction with bounded retry."""

        async def attempt() -> T:
            async with self.session() as session:
                return await session.execute_read(work, *args, **kwargs)

        return await self._run_with_retry("execute_read", attempt)

    async def execute_write(
        self, work: Callable[..., Awaitable[T]], *args: Any, **kwargs: Any
    ) -> T:
        """Run *work(tx, ...)* in a managed write transaction with bounded retry."""

        async def attempt() -> T:
            async with self.session() as session:
                return await session.execute_write(work, *args, **kwargs)

        return await self._run_with_retry("execute_write", attempt)

    # -- retry ---------------------------------------------------------------

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff: base * 2^(attempt-1) seconds."""
        return self._backoff_base_seconds * 2 ** (attempt - 1)

    async def _run_with_retry(self, operation: str, runner: Callable[[], Awaitable[T]]) -> T:
        """Retry *runner* on transient driver errors, at most ``max_attempts`` tries."""
        for attempt in range(1, self._max_attempts + 1):
            try:
                return await runner()
            except TRANSIENT_ERRORS as exc:
                if attempt == self._max_attempts:
                    logger.warning(
                        "neo4j_retries_exhausted",
                        operation=operation,
                        attempts=attempt,
                        error=type(exc).__name__,
                    )
                    raise
                delay = self._backoff_delay(attempt)
                logger.warning(
                    "neo4j_transient_error",
                    operation=operation,
                    attempt=attempt,
                    retry_in_seconds=delay,
                    error=type(exc).__name__,
                )
                await asyncio.sleep(delay)
        raise AssertionError("unreachable: retry loop always returns or raises")

    # -- health --------------------------------------------------------------

    async def health_check(self) -> bool:
        """``RETURN 1`` round-trip; True when the graph answers, False otherwise.

        Single attempt (no retry/backoff) so readiness probes stay within their
        timeout budget. Never raises for connectivity-class failures.
        """

        async def _ping(tx: AsyncManagedTransaction) -> bool:
            result = await tx.run("RETURN 1 AS ok")
            record = await result.single()
            return record is not None and record["ok"] == 1

        try:
            async with self.session() as session:
                return bool(await session.execute_read(_ping))
        except (Neo4jError, DriverError, OSError) as exc:
            logger.warning("neo4j_health_check_failed", error=type(exc).__name__)
            return False


# ---------------------------------------------------------------------------
# Module-level singleton (mirrors app.db engine accessors)
# ---------------------------------------------------------------------------

_client: Neo4jClient | None = None


def create_client(settings: Settings) -> Neo4jClient:
    """Build a new client from *settings* (does not connect)."""
    return Neo4jClient(settings)


def get_client() -> Neo4jClient:
    """Return the process-wide lazily created client."""
    global _client
    if _client is None:
        _client = create_client(get_settings())
    return _client


async def dispose_client() -> None:
    """Close the cached client (lifespan shutdown hook); safe when unused."""
    global _client
    if _client is not None:
        await _client.close()
    _client = None
