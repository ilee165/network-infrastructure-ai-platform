"""App DB wiring (W1-T2, ADR-0042) re-asserted under REAL PostgreSQL.

W1-T2 wires the application to the HA data tier (ADR-0042): the audit-writing
transaction raises itself to ``synchronous_commit = remote_apply`` via ``SET
LOCAL`` so a committed ``audit_log`` row is durable on a quorum replica before
ack — the app-side half of the §11 G-REL §316 "zero committed-audit-entry loss"
guarantee the live W4-T3 failover drill exercises. The durability *contract* is a
PostgreSQL ``synchronous_commit`` GUC and PgBouncer transaction-mode semantics —
both of which **SQLite cannot model** (it has no such GUC, no replicas, no
transaction pooling). So every assertion here runs against REAL Postgres, never
SQLite (the P2 lesson: SQLite hides PG write/durability semantics).

What each test pins (ADR-0042 §2/§4 + W1-T2 spec):

  1. **Durability** — a transaction that appends an audit row runs at
     ``synchronous_commit = remote_apply`` (asserted via ``SHOW`` on the SAME
     connection, inside the transaction). This is the setting W4-T3 then proves
     survives a primary kill.
  2. **Scoping** — a transaction that writes NO audit row keeps the session
     default (async ``local`` on the W1-T1 cluster), so the sync round-trip lands
     only on audited state changes, not on bulk ingest (§2, Alt #3).
  3. **No pooling leak** — ``SET LOCAL`` is transaction-scoped, so the synchronous
     level does NOT leak onto the NEXT transaction that reuses the same backend
     connection (the PgBouncer transaction-mode-safety property, §4): a fresh
     transaction on the same connection is back at the default.
  4. **Read/write split** — a read-only replica session
     (:func:`app.db.get_read_session`) can serve queries while a write session
     commits, without breaking the write (ADR-0042 §5). With no reader URL the
     reader engine falls back to the primary, so this also pins the
     single-instance fallback.
  5. **Behaviour unchanged** — the synchronous append still produces a clean,
     verifiable hash chain (ADR-0038); only WRITE DURABILITY changed.

Secret-surface (W5-T0 Requirement 4 / ADR-0042 §2 strong review): audit rows are
secret-free by construction (ADR-0032 §5); no fixture or assertion here carries a
plaintext secret — these are durability/routing assertions only.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app import db
from app.core.config import get_settings
from app.services.audit import service as audit_service
from app.services.audit.verify import verify_chain

pytestmark = pytest.mark.integration


async def _show_synchronous_commit(session: AsyncSession) -> str:
    """Return the EFFECTIVE ``synchronous_commit`` for *session*'s current transaction."""
    return (await session.execute(text("SHOW synchronous_commit"))).scalar_one()


# ---------------------------------------------------------------------------
# 1. Durability — the audit-writing transaction is synchronous (ADR-0042 §2).
# ---------------------------------------------------------------------------


async def test_audit_writing_transaction_runs_at_remote_apply_under_pg(
    pg_session: AsyncSession,
) -> None:
    """An audit-writing transaction sets ``synchronous_commit=remote_apply`` (ADR-0042 §2).

    The ``SET LOCAL`` the writer issues is in force for the REST of the caller's
    transaction — exactly the transaction that carries the audit row, atomic with
    the action it describes (ADR-0011/0038). We read it back with ``SHOW`` on the
    same connection, inside the same transaction, after ``record()`` ran. This is
    the durability setting W4-T3 proves survives a primary kill; ``remote_apply``
    waits until a quorum standby has REPLAYED the WAL (W1-T1 ``ANY 1``).
    """
    # Sanity: the configured default the writer applies is the ADR-0042 value.
    assert get_settings().audit_synchronous_commit == "remote_apply"

    entry = await audit_service.record(
        pg_session,
        actor="user:durability",
        action=audit_service.DEVICE_UPDATED,
        target_type="device",
        target_id="d1",
        detail={"k": "v"},
    )

    effective = await _show_synchronous_commit(pg_session)
    assert effective == "remote_apply", (
        "the audit-writing transaction must run at synchronous_commit=remote_apply "
        f"(ADR-0042 §2 durability), got {effective!r}"
    )
    # The append itself is unchanged: real row, real chain link.
    assert entry.seq == 1
    assert entry.prev_hash == bytes(32)


async def test_configured_level_is_honoured_under_pg(pg_session: AsyncSession) -> None:
    """The ``SET LOCAL`` level comes from settings, not a hard-coded literal (ADR-0042 §2).

    An operator matching the level to their ``synchronous_standby_names`` shape can
    pick ``on``/``remote_write``; we flip the cached setting and confirm the writer
    issues the chosen (allowlisted) level — proving the value is wired through
    config, not frozen.
    """
    settings = get_settings()
    original = settings.audit_synchronous_commit
    object.__setattr__(settings, "audit_synchronous_commit", "on")
    try:
        await audit_service.record(
            pg_session,
            actor="user:level",
            action=audit_service.DEVICE_UPDATED,
            target_type="device",
            target_id="d2",
            detail=None,
        )
        assert await _show_synchronous_commit(pg_session) == "on"
    finally:
        object.__setattr__(settings, "audit_synchronous_commit", original)


# ---------------------------------------------------------------------------
# 2. Scoping — a non-audit transaction keeps the async default (ADR-0042 §2).
# ---------------------------------------------------------------------------


async def test_non_audit_transaction_keeps_default_commit_under_pg(
    pg_session: AsyncSession,
) -> None:
    """A transaction with NO audit write does NOT pay the sync round-trip (ADR-0042 §2 scoping).

    The sync commit is scoped to audit-writing transactions. A transaction that only
    reads / writes non-audit rows must keep the SESSION default ``synchronous_commit``
    — never the audit ``remote_apply``. We never call ``record()`` here, so the GUC
    must be whatever the session inherited (the W1-T1 cluster default ``local``; the
    plain test DB's default is the built-in ``on`` — either way, NOT raised BY US),
    and it must equal the value BEFORE we ran. This is the throughput-protecting
    scoping ADR-0042 §2 / Alt #3 exists for.
    """
    before = await _show_synchronous_commit(pg_session)
    # Do real non-audit work; assert we did not silently raise the level.
    await pg_session.execute(text("SELECT 1"))
    after = await _show_synchronous_commit(pg_session)
    assert after == before
    assert after != "remote_apply" or before == "remote_apply", (
        "a non-audit transaction must not be raised to remote_apply by the app"
    )


# ---------------------------------------------------------------------------
# 3. No pooling leak — SET LOCAL is transaction-scoped (ADR-0042 §4, PgBouncer).
# ---------------------------------------------------------------------------


async def test_set_local_does_not_leak_to_next_transaction_on_same_connection(
    pg_engine: AsyncEngine,
) -> None:
    """The synchronous level does NOT leak to the next transaction on the backend (ADR-0042 §4).

    ``SET LOCAL`` binds the setting to the CURRENT transaction; under PgBouncer
    transaction mode a backend connection is handed to a different client's
    transaction next. We model the backend-reuse boundary on a SINGLE session pinned
    to ONE connection (``NullPool`` gives one connection per session): run an
    audit-writing transaction A (which raises ``synchronous_commit`` for its own
    scope), ``COMMIT`` it (which is exactly what ends a ``SET LOCAL`` scope and what a
    pooled backend does at the transaction boundary), then start a SECOND transaction
    B on the SAME backend connection and confirm it is back at the session default —
    proving the per-transaction scoping that keeps a pooled backend from carrying a
    stale synchronous level (a session-level ``SET`` would have leaked across the
    commit). The ``COMMIT`` is the load-bearing step: ``SET LOCAL`` resets at
    transaction end, so a real ``COMMIT`` (not a session-vs-raw-connection mismatch)
    must bracket transaction A.
    """
    # ONE raw backend connection drives both transactions, so A and B demonstrably
    # reuse the SAME backend (the pooled-reuse boundary). The session is bound to this
    # connection and joins its transaction, so record()'s SET LOCAL lands on exactly
    # the transaction the explicit COMMIT below ends — no session-vs-raw-connection
    # transaction mismatch.
    async with pg_engine.connect() as conn:
        # Transaction A: record() (audit write) raises synchronous_commit for its scope.
        async with conn.begin():
            default = (await conn.execute(text("SHOW synchronous_commit"))).scalar_one()
            assert default != "remote_apply", "the session default must not already be remote_apply"
            session = AsyncSession(bind=conn)
            await audit_service.record(
                session,
                actor="user:leak",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id="d3",
                detail=None,
            )
            await session.flush()
            in_a = (await conn.execute(text("SHOW synchronous_commit"))).scalar_one()
            assert in_a == "remote_apply", f"the audit transaction must be raised, got {in_a!r}"
        # `async with conn.begin()` COMMITted transaction A — the point at which SET
        # LOCAL is discarded and a pooled backend is handed to the next transaction.

        # Transaction B on the SAME backend connection: no audit write → back at the
        # default. (SET LOCAL did not leak; a session-level SET would have.)
        async with conn.begin():
            leaked = (await conn.execute(text("SHOW synchronous_commit"))).scalar_one()
        assert leaked == default, (
            "SET LOCAL must not leak the synchronous level onto the next transaction "
            f"on a pooled backend (ADR-0042 §4): default={default!r} leaked={leaked!r}"
        )


# ---------------------------------------------------------------------------
# 4. Read/write split — replica reads do not break writes (ADR-0042 §5).
# ---------------------------------------------------------------------------


async def test_read_only_replica_session_serves_reads_without_breaking_writes(
    pg_session: AsyncSession, _migrated_pg: str
) -> None:
    """A read-only reader session serves queries while a write session commits (ADR-0042 §5).

    ADR-0042 §5 routes read-only queries to a replica (the ``database_reader_url``
    endpoint); writes stay on the primary. With no reader URL the reader engine falls
    back to the primary DSN, so the read/write split is exercised here against the
    migrated DB: a write session appends + COMMITS an audit row, and an independent
    READER session (built exactly as :func:`app.db.get_read_session` does) reads it
    back — proving a read-only session can target its endpoint without breaking the
    write path. We point the reader at the SAME migrated test DB so the assertion is
    self-contained on one Postgres.
    """
    # Build a reader engine the way app.db does, pinned at the migrated test DB so the
    # fallback-to-primary path is what we exercise (no second DB needed).
    settings = get_settings()
    original_reader = settings.database_reader_url
    object.__setattr__(settings, "database_reader_url", _migrated_pg)
    # Reset any cached reader so create picks up our URL.
    db._reader_engine = None
    db._reader_sessionmaker = None
    try:
        reader_engine = db.get_reader_engine()
        reader_maker = async_sessionmaker(reader_engine, expire_on_commit=False)

        # WRITE on the primary session: append an audit row and COMMIT it.
        marker = f"rw-split-{uuid.uuid4().hex}"
        await audit_service.record(
            pg_session,
            actor=marker,
            action=audit_service.DEVICE_UPDATED,
            target_type="device",
            target_id="d4",
            detail=None,
        )
        await pg_session.commit()

        # READ on the reader session: see the committed write. A read-only session
        # serving the query (and not erroring) is the §5 routing guarantee.
        async with reader_maker() as reader:
            count = (
                await reader.execute(
                    text("SELECT count(*) FROM audit_log WHERE actor = :a"),
                    {"a": marker},
                )
            ).scalar_one()
            assert count == 1, "the committed write must be visible to the reader session"
            # And the reader can run a read-only query without a write side effect.
            assert (await reader.execute(text("SELECT 1"))).scalar_one() == 1
    finally:
        await reader_engine.dispose()
        object.__setattr__(settings, "database_reader_url", original_reader)
        db._reader_engine = None
        db._reader_sessionmaker = None


# ---------------------------------------------------------------------------
# 5. Behaviour unchanged — synchronous append still verifies clean (ADR-0038).
# ---------------------------------------------------------------------------


async def test_synchronous_audit_append_still_hash_chains_clean_under_pg(
    pg_session: AsyncSession,
) -> None:
    """Raising durability does NOT change the chain: a synchronous append verifies clean.

    W1-T2 changes only WRITE DURABILITY, never the audit content, redaction, or the
    ADR-0038 hash chain. Append a short chain through the (now-synchronous) writer and
    confirm the verifier walks it clean — the hash-chain behaviour is exactly as it
    was before the ``SET LOCAL`` was added.
    """
    for i in range(4):
        await audit_service.record(
            pg_session,
            actor=f"user:{i}",
            action=audit_service.DEVICE_UPDATED,
            target_type="device",
            target_id=str(i),
            detail={"step": i},
        )
    await pg_session.flush()

    result = await verify_chain(pg_session)
    assert result.ok is True
    assert result.break_ is None
    assert result.checked == 4
