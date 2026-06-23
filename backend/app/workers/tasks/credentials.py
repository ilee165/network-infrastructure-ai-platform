"""Celery KEK-rotation task (P1 W6-T3, ADR-0032 §3): the DEK re-wrap pass.

``credentials.re_wrap_keys`` is an **app task triggered by the operator or a KMS
auto-rotation hook** (not Celery-beat-coupled to the DR jobs): once the active
KEK version has advanced, it streams ``device_credentials WHERE kek_version !=
active`` in batches and re-wraps each DEK under the new KEK — leaving the payload
``ciphertext``/``nonce`` untouched (the ADR-0011 §1 cheap re-wrap). The heavy
lifting (compare-and-set, audit bracketing) lives in
:func:`app.services.credentials.re_wrap_keys`; this task is the worker shell.

Idempotent + resumable (ADR-0008 §5 acks-late): the worklist predicate is
``kek_version != active``, so a redelivery (or a crash mid-pass) simply re-runs
on whatever rows still match — already-migrated rows are skipped, and a
fully-migrated corpus migrates zero rows. The task commits per batch via the
autonomous sessionmaker so progress is durable across a redelivery.

Async DB from sync Celery: like the topology task, each invocation opens a fresh
engine + event loop via ``asyncio.run``; module-level seams (``_make_engine``,
``_key_provider``) let unit tests drive everything eagerly with fakes.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app import db
from app.core.config import get_settings
from app.core.crypto import KeyProvider, get_key_provider
from app.services import credentials as credentials_service
from app.services.credentials.rotation import DEFAULT_BATCH_SIZE
from app.workers.celery_app import celery_app

__all__ = ["re_wrap_keys"]

logger = structlog.get_logger(__name__)

#: Actor recorded on the ``kek.rotate.*`` audit rows for a worker-driven pass.
_ACTOR = "system:kek_rotation"


# ---------------------------------------------------------------------------
# Seams (monkeypatched by unit tests)
# ---------------------------------------------------------------------------


def _make_engine() -> AsyncEngine:
    """New async engine for one pass (loop-scoped, disposed after use)."""
    return db.create_engine(get_settings())


def _key_provider() -> KeyProvider:
    """Build the configured KEK provider (its active version is the rotate target)."""
    return get_key_provider(get_settings())


@asynccontextmanager
async def _sessionmaker() -> AsyncIterator[async_sessionmaker[AsyncSession]]:
    """An autonomous sessionmaker on a fresh engine, disposed when the pass ends.

    The re-wrap pass commits per batch (and brackets durable ``kek.rotate.*``
    audit rows) through this sessionmaker, so progress survives a redelivery.
    """
    engine = _make_engine()
    try:
        yield db.create_sessionmaker(engine)
    finally:
        await engine.dispose()


async def _run_pass(batch_size: int) -> dict[str, Any]:
    """Stream the worklist and re-wrap every un-migrated DEK under the active KEK."""
    provider = _key_provider()
    async with _sessionmaker() as maker, maker() as session:
        result = await credentials_service.re_wrap_keys(
            session,
            provider,
            actor=_ACTOR,
            batch_size=batch_size,
            sessionmaker=maker,
        )
    return {
        "from_version": result.from_version,
        "to_version": result.to_version,
        "row_count": result.row_count,
        "rows_migrated": result.rows_migrated,
    }


@celery_app.task(name="credentials.re_wrap_keys")
def re_wrap_keys(batch_size: int = DEFAULT_BATCH_SIZE) -> dict[str, Any]:
    """Re-wrap every credential's DEK under the active KEK (operator/KMS trigger).

    Returns a JSON-safe versions/counts summary (no key material). The pass is
    idempotent and resumable, so a redelivery is safe (ADR-0008 §5).
    """
    summary = asyncio.run(_run_pass(batch_size))
    logger.info(
        "credentials.re_wrap_complete",
        to_version=summary["to_version"],
        row_count=summary["row_count"],
        rows_migrated=summary["rows_migrated"],
    )
    return summary
