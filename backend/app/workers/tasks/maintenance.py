"""DB maintenance tasks on the ``system`` queue.

``system.ensure_partitions`` (H4, 2026-07-10 repo review): the four
range-partitioned tables (ADR-0011, D11) shipped with explicit monthly
partitions only through ``2026_07`` plus a DEFAULT partition, and no
partition-creation code existed anywhere. From 2026-08-01 every new row would
have landed in the unbounded DEFAULT partition — permanently defeating
partition pruning and partition-drop retention for that data.

This beat task pre-creates the current and next month's partitions for all
four tables, daily and idempotently (``CREATE TABLE IF NOT EXISTS``), mirroring
the migrations' explicit ``+00`` bounds so the windows never shift with the
session timezone. PostgreSQL-only: on any other backend the tables are
unpartitioned (the 0001/0004 migrations' own dialect guard) and the task
no-ops.

Failure mode is loud by design: if a bound conflicts (e.g. rows already leaked
into the DEFAULT partition for that window — PostgreSQL refuses to attach an
overlapping partition), the task raises and the beat run is marked failed, so
the gap surfaces in worker logs/monitoring instead of silently continuing to
fill DEFAULT.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import text

from app import db
from app.core.config import get_settings
from app.workers.celery_app import celery_app

__all__ = ["ensure_partitions"]

logger = structlog.get_logger(__name__)

#: The range-partitioned parents (0001 baseline + 0004 traces). Fixed
#: identifiers — never user input — so f-string DDL below is injection-safe.
PARTITIONED_TABLES: tuple[str, ...] = (
    "audit_log",
    "raw_artifacts",
    "reasoning_traces",
    "reasoning_trace_steps",
)

#: How many monthly windows to guarantee ahead, counting the current month.
#: 2 = current + next; with a daily beat the next month's partition exists at
#: least ~28 days before it is first written to.
MONTHS_AHEAD = 2


def _month_start(year: int, month: int) -> str:
    return f"{year:04d}-{month:02d}-01 00:00:00+00"


def month_windows(now: datetime, count: int = MONTHS_AHEAD) -> list[tuple[str, str, str]]:
    """The ``(suffix, lower, upper)`` monthly windows starting at *now*'s month.

    Same shape and explicit ``+00`` bounds as the ``_PARTITION_WINDOWS`` tuples
    in migrations 0001/0004.
    """
    windows: list[tuple[str, str, str]] = []
    year, month = now.year, now.month
    for _ in range(count):
        next_year, next_month = (year + 1, 1) if month == 12 else (year, month + 1)
        suffix = f"{year:04d}_{month:02d}"
        windows.append((suffix, _month_start(year, month), _month_start(next_year, next_month)))
        year, month = next_year, next_month
    return windows


async def _ensure_partitions(windows: list[tuple[str, str, str]]) -> list[str]:
    """Create any missing monthly partitions; return the statements' targets."""
    engine = db.create_engine(get_settings())
    created: list[str] = []
    try:
        if engine.dialect.name != "postgresql":
            return created
        async with engine.begin() as conn:
            for parent in PARTITIONED_TABLES:
                for suffix, lower, upper in windows:
                    await conn.execute(
                        text(
                            f"CREATE TABLE IF NOT EXISTS {parent}_{suffix} "
                            f"PARTITION OF {parent} "
                            f"FOR VALUES FROM ('{lower}') TO ('{upper}')"
                        )
                    )
                    created.append(f"{parent}_{suffix}")
    finally:
        await engine.dispose()
    return created


@celery_app.task(name="system.ensure_partitions")
def ensure_partitions() -> dict[str, Any]:
    """Beat task: guarantee current+next monthly partitions exist (PG only)."""
    windows = month_windows(datetime.now(UTC))
    ensured = asyncio.run(_ensure_partitions(windows))
    if not ensured:
        logger.info("maintenance.partitions_skipped", reason="non_postgresql_backend")
        return {"ensured": [], "skipped": True}
    logger.info(
        "maintenance.partitions_ensured",
        windows=[w[0] for w in windows],
        tables=len(PARTITIONED_TABLES),
    )
    return {"ensured": ensured, "skipped": False}
