"""Durable export cursor I/O — the at-least-once / no-gap watermark (ADR-0045 §2).

The cursor is the source of truth for "what has the SIEM confirmed". The pipeline:

  1. loads the cursor (``exported_seq``, ``0`` if never set),
  2. reads committed ``audit_log`` rows with ``seq > exported_seq`` ORDERED BY
     ``seq`` (the ADR-0038 append order), filtering ``seq IS NOT NULL`` so NULL-``seq``
     pre-chain rows are NEVER streamed into the SIEM (mirroring the verifier's
     ``_entries_after``, ADR-0045 §2),
  3. delivers them to the sink,
  4. advances the cursor to the last delivered ``seq`` **only after the sink ACKs**.

Because the cursor is advanced only on ACK and in a SEPARATE transaction from the
audit write (strictly downstream, ADR-0045 §3), a crash between "sink received" and
"cursor persisted" re-exports the un-advanced rows on restart — at-least-once, never
at-most-once, no gap, bounded duplication (the SIEM dedups on ``seq``).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditExportCursor, AuditLog
from app.models.mixins import utcnow
from app.services.audit.export.record import ExportRecord


async def load_cursor(session: AsyncSession) -> AuditExportCursor | None:
    """Return the singleton export-cursor row, or ``None`` if never set."""
    return (
        await session.execute(
            select(AuditExportCursor).where(AuditExportCursor.id == AuditExportCursor.SINGLETON_ID)
        )
    ).scalar_one_or_none()


async def current_exported_seq(session: AsyncSession) -> int:
    """Return the highest exported ``seq`` (``0`` before the first export)."""
    cursor = await load_cursor(session)
    return cursor.exported_seq if cursor is not None else 0


async def read_unexported(
    session: AsyncSession, *, after_seq: int, limit: int
) -> list[ExportRecord]:
    """Read up to *limit* committed rows with ``seq > after_seq`` ordered by ``seq``.

    Mirrors the ADR-0038 verifier's ``_entries_after`` (ADR-0045 §2): ``seq IS NOT
    NULL`` excludes pre-chain rows from the export stream, ``ORDER BY seq`` is the
    append order, and the keyset filter ``seq > after_seq`` resumes exactly at the
    cursor with no gap. The ``created_at, id`` tiebreak is retained defensively
    (``seq`` is unique by the writer's under-lock assignment).
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.seq.is_not(None), AuditLog.seq > after_seq)
        .order_by(AuditLog.seq.asc(), AuditLog.created_at.asc(), AuditLog.id.asc())
        .limit(limit)
    )
    rows = (await session.execute(stmt)).scalars().all()
    return [ExportRecord.from_row(row) for row in rows]


async def advance_cursor(session: AsyncSession, *, last: ExportRecord) -> None:
    """Advance the durable watermark to *last* (called ONLY after a sink ACK).

    Upserts the singleton row to ``exported_seq = last.seq`` and records the
    exported row's commit timestamp (the ``export_lag_seconds`` basis, ADR-0045 §3).
    The caller commits; on a crash before that commit, the un-advanced rows are
    re-read and re-delivered (at-least-once, ADR-0045 §2).

    MONOTONIC + ATOMIC (never a regress). On PostgreSQL the write is a single
    ``INSERT ... ON CONFLICT (id) DO UPDATE ... WHERE cursor.exported_seq <
    EXCLUDED.exported_seq`` statement, so two concurrent exporters (a rolling-update
    overlap, an accidental second runner) can neither PK-collide on the first insert
    NOR let a stale batch overwrite a newer watermark with an older ``seq`` — the
    cursor only ever moves FORWARD, decided at the DB level. On the unit-test SQLite
    backend the same guard is enforced with a portable load-then-write (a single
    exporter there, so the read-modify-write is race-free); the real concurrency
    assertion rides ``tests/pg`` on PostgreSQL.
    """
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        await _advance_cursor_pg(session, last=last)
        return
    await _advance_cursor_portable(session, last=last)


async def _advance_cursor_pg(session: AsyncSession, *, last: ExportRecord) -> None:
    """Atomic monotonic upsert on PostgreSQL (forward-only, concurrency-safe)."""
    now = utcnow()
    stmt = pg_insert(AuditExportCursor).values(
        id=AuditExportCursor.SINGLETON_ID,
        exported_seq=last.seq,
        last_exported_commit_at=last.created_at,
        updated_at=now,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[AuditExportCursor.id],
        set_={
            "exported_seq": stmt.excluded.exported_seq,
            "last_exported_commit_at": stmt.excluded.last_exported_commit_at,
            "updated_at": stmt.excluded.updated_at,
        },
        # Forward-only: a stale exporter re-ACKing an OLD batch is a no-op, never a
        # regress of a newer watermark written by a concurrent runner.
        where=AuditExportCursor.exported_seq < stmt.excluded.exported_seq,
    )
    await session.execute(stmt)


async def _advance_cursor_portable(session: AsyncSession, *, last: ExportRecord) -> None:
    """Load-then-write monotonic guard for the unit-test SQLite backend.

    ``exported_seq`` only ever moves forward — ``last.seq`` is the max ``seq`` of a
    contiguous delivered batch read in ``seq`` order, and a lower value is refused so
    the SQLite path mirrors the PG forward-only invariant.
    """
    cursor = await load_cursor(session)
    if cursor is None:
        session.add(
            AuditExportCursor(
                id=AuditExportCursor.SINGLETON_ID,
                exported_seq=last.seq,
                last_exported_commit_at=last.created_at,
                updated_at=utcnow(),
            )
        )
    elif cursor.exported_seq < last.seq:
        cursor.exported_seq = last.seq
        cursor.last_exported_commit_at = last.created_at
        cursor.updated_at = utcnow()
    await session.flush()
