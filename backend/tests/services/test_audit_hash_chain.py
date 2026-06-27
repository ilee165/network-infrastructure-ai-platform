"""Audit hash chain (ADR-0038): writer chains, verifier bites, no secret hashed.

These are the W4-T1 exit-criteria "bites":

  * **Tamper-detection** — UPDATE/DELETE a mid-chain row → the verifier flags the
    break at the right index; an untouched chain verifies clean.
  * **Deterministic recompute** — the same rows hash to the same ``entry_hash``
    across runs; the genesis seeds entry 1.
  * **No-secret-in-hash** — the canonical field set excludes every secret column.
  * **Append-only intact** — the chain write does not introduce an UPDATE/DELETE
    path; the writer remains the single append path.

The suite runs on the in-memory aiosqlite ``session`` fixture (NullPool-equivalent:
a fresh in-memory engine per test, no shared pool — the W6 flaky-concurrency
lesson). No Postgres/Docker/network.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import event, func, select, update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.models import AuditChainCheckpoint, AuditLog, Base
from app.services.audit import chain
from app.services.audit import service as audit_service
from app.services.audit.verify import verify_chain


async def _seed_chain(session: AsyncSession, n: int) -> list[AuditLog]:
    """Append *n* audit entries through the real writer and return them in order."""
    entries: list[AuditLog] = []
    for i in range(n):
        entry = await audit_service.record(
            session,
            actor=f"user:{i}",
            action=audit_service.DEVICE_UPDATED,
            target_type="device",
            target_id=str(i),
            detail={"step": i},
        )
        entries.append(entry)
    await session.flush()
    return entries


# ---------------------------------------------------------------------------
# Chain construction (writer)
# ---------------------------------------------------------------------------


async def test_first_entry_chains_from_genesis(session: AsyncSession) -> None:
    """The first appended entry's prev_hash is the fixed genesis seed (ADR-0038 §1)."""
    [first] = await _seed_chain(session, 1)
    assert first.prev_hash == chain.GENESIS_HASH
    assert first.entry_hash == chain.compute_entry_hash(first, chain.GENESIS_HASH)
    assert len(first.entry_hash) == chain.HASH_LEN


async def test_each_entry_links_to_predecessor(session: AsyncSession) -> None:
    """Every entry's prev_hash equals the previous entry's entry_hash (the chain)."""
    entries = await _seed_chain(session, 5)
    prev = chain.GENESIS_HASH
    for entry in entries:
        assert entry.prev_hash == prev
        assert entry.entry_hash == chain.compute_entry_hash(entry, prev)
        prev = entry.entry_hash


async def test_hashes_are_raw_32_bytes_not_hex(session: AsyncSession) -> None:
    """Both chain columns store the RAW 32-byte digest — no hex variant (ADR-0038 §1)."""
    [entry] = await _seed_chain(session, 1)
    assert isinstance(entry.prev_hash, bytes | bytearray | memoryview)
    assert isinstance(entry.entry_hash, bytes | bytearray | memoryview)
    assert len(bytes(entry.entry_hash)) == 32
    # A 32-byte digest is NOT a 64-char hex string masquerading as bytes.
    assert len(bytes(entry.entry_hash)) != 64


# ---------------------------------------------------------------------------
# Deterministic recompute (ADR-0038 §2)
# ---------------------------------------------------------------------------


async def test_canonical_bytes_are_deterministic(session: AsyncSession) -> None:
    """The canonical hashed form is byte-identical across repeated serializations."""
    [entry] = await _seed_chain(session, 1)
    assert chain.canonical_bytes(entry) == chain.canonical_bytes(entry)


async def test_recompute_reproduces_stored_entry_hash(session: AsyncSession) -> None:
    """An independent recompute of the chain reproduces every stored entry_hash."""
    entries = await _seed_chain(session, 4)
    prev = chain.GENESIS_HASH
    for entry in entries:
        assert chain.compute_entry_hash(entry, prev) == entry.entry_hash
        prev = entry.entry_hash


async def test_canonical_created_at_fixed_microsecond_precision() -> None:
    """A whole-second timestamp renders with 6-digit microseconds (no drift)."""
    from datetime import UTC, datetime

    whole = datetime(2026, 6, 26, 12, 0, 0, tzinfo=UTC)
    rendered = chain._rfc3339_utc(whole)
    assert rendered == "2026-06-26T12:00:00.000000Z"


# ---------------------------------------------------------------------------
# No secret hashed in the clear (ADR-0038 §5 / ADR-0032 §5)
# ---------------------------------------------------------------------------


def test_canonical_field_set_excludes_secret_and_chain_columns() -> None:
    """The canonical field set is exactly the immutable, secret-free audit columns."""
    assert set(chain.CANONICAL_FIELDS) == {
        "id",
        "created_at",
        "actor",
        "action",
        "target_type",
        "target_id",
        "request_id",
        "reasoning_trace_id",
        "detail",
    }
    # The chain OUTPUTS must never feed back into the hashed form (would be circular)
    # and no secret-bearing/mutable column may participate.
    forbidden = {"prev_hash", "entry_hash", "ciphertext", "nonce", "wrapped_dek", "password"}
    assert not (set(chain.CANONICAL_FIELDS) & forbidden)


async def test_secret_like_column_not_in_canonical_bytes(session: AsyncSession) -> None:
    """A would-be secret column name never appears in the canonical serialization."""
    [entry] = await _seed_chain(session, 1)
    blob = chain.canonical_bytes(entry)
    for needle in (b"prev_hash", b"entry_hash", b"wrapped_dek", b"ciphertext"):
        assert needle not in blob


def test_genesis_matches_migration_inlined_constant() -> None:
    """The app genesis equals the value migration 0011 inlines (D4 — pinned by test)."""
    from app.models import audit as audit_model

    assert chain.GENESIS_HASH == b"\x00" * 32
    # The model inlines the same seed (no service import, REPO §3.2) — pin them equal
    # so the model default and the writer/verifier can never silently diverge.
    assert audit_model._GENESIS_HASH == chain.GENESIS_HASH


# ---------------------------------------------------------------------------
# Verifier: clean chain (ADR-0038 §4)
# ---------------------------------------------------------------------------


async def test_untouched_chain_verifies_clean(session: AsyncSession) -> None:
    """An untampered chain verifies clean and reports the head it walked."""
    entries = await _seed_chain(session, 6)
    result = await verify_chain(session)
    assert result.ok is True
    assert result.break_ is None
    assert result.checked == 6
    assert result.head_entry_id == str(entries[-1].id)


async def test_empty_log_verifies_clean(session: AsyncSession) -> None:
    """An empty audit log is a clean (zero-length) chain."""
    result = await verify_chain(session)
    assert result.ok is True
    assert result.checked == 0
    assert result.head_entry_id is None


# ---------------------------------------------------------------------------
# Tamper detection: the exit bite (ADR-0038 §4)
# ---------------------------------------------------------------------------


async def test_mid_chain_update_is_flagged_at_right_index(session: AsyncSession) -> None:
    """Mutating a mid-chain row's hashed field is caught at that row's position."""
    entries = await _seed_chain(session, 5)
    # Tamper with the 3rd entry's `action` (a hashed field) WITHOUT recomputing its
    # entry_hash — emulating a privileged DB UPDATE that bypasses the writer. (On
    # PostgreSQL the migration 0001 `REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC`
    # blocks a non-owner, but it does NOT bind the owner/superuser — the exact
    # privileged-actor case this chain catches; here on SQLite we force the row edit
    # to exercise the verifier exactly as it would behave against a tampered PG row.)
    target = entries[2]
    await session.execute(
        update(AuditLog)
        .where(AuditLog.id == target.id, AuditLog.created_at == target.created_at)
        .values(action="device.deleted")
    )
    await session.flush()

    result = await verify_chain(session)
    assert result.ok is False
    assert result.break_ is not None
    assert result.break_.position == 3
    assert result.break_.entry_id == str(target.id)
    assert result.break_.reason == "entry_hash_mismatch"


async def test_mid_chain_delete_is_flagged(session: AsyncSession) -> None:
    """Deleting a mid-chain row breaks the prev_hash link of its successor."""
    entries = await _seed_chain(session, 5)
    victim = entries[2]
    await session.execute(
        AuditLog.__table__.delete().where(
            AuditLog.id == victim.id, AuditLog.created_at == victim.created_at
        )
    )
    await session.flush()

    result = await verify_chain(session)
    assert result.ok is False
    assert result.break_ is not None
    # The successor (now at position 3 after the delete) no longer matches the
    # running chain head's entry_hash → prev_hash_mismatch at that index.
    assert result.break_.position == 3
    assert result.break_.entry_id == str(entries[3].id)
    assert result.break_.reason == "prev_hash_mismatch"


async def test_clean_segment_after_checkpoint_verifies(session: AsyncSession) -> None:
    """Advancing the checkpoint over a clean run lets the next pass resume from it."""
    await _seed_chain(session, 3)
    first = await verify_chain(session, advance_checkpoint=True)
    assert first.ok is True
    checkpoint = (await session.execute(select(AuditChainCheckpoint))).scalar_one()
    assert checkpoint.entry_hash == bytes(checkpoint.entry_hash)

    # Append more and re-verify: only the NEW entries are walked (resume from cp).
    await _seed_chain(session, 2)
    second = await verify_chain(session, advance_checkpoint=True)
    assert second.ok is True
    assert second.checked == 2


async def test_deleted_checkpoint_anchor_is_flagged(session: AsyncSession) -> None:
    """Deleting the verified-clean anchor row is caught as a missing checkpoint."""
    entries = await _seed_chain(session, 3)
    clean = await verify_chain(session, advance_checkpoint=True)
    assert clean.ok is True

    anchor = entries[-1]
    await session.execute(
        AuditLog.__table__.delete().where(
            AuditLog.id == anchor.id, AuditLog.created_at == anchor.created_at
        )
    )
    await session.flush()

    result = await verify_chain(session)
    assert result.ok is False
    assert result.break_ is not None
    assert result.break_.reason == "missing_checkpoint_entry"


async def test_first_clean_pass_inserts_checkpoint(session: AsyncSession) -> None:
    """The first advancing pass INSERTs the singleton checkpoint (none existed)."""
    entries = await _seed_chain(session, 2)
    # No checkpoint row exists yet.
    assert (await session.execute(select(AuditChainCheckpoint))).scalar_one_or_none() is None

    result = await verify_chain(session, advance_checkpoint=True)
    assert result.ok is True

    checkpoint = (await session.execute(select(AuditChainCheckpoint))).scalar_one()
    assert checkpoint.entry_id == entries[-1].id
    assert bytes(checkpoint.entry_hash) == bytes(entries[-1].entry_hash)


async def test_reverify_with_no_new_entries_is_clean_noop(session: AsyncSession) -> None:
    """A re-verify after the checkpoint with NO new appends is a clean no-op pass."""
    entries = await _seed_chain(session, 3)
    first = await verify_chain(session, advance_checkpoint=True)
    assert first.ok is True

    # No new appends — the second pass walks zero entries but still reports clean,
    # echoing the existing checkpoint as the verified head.
    second = await verify_chain(session, advance_checkpoint=True)
    assert second.ok is True
    assert second.checked == 0
    assert second.head_entry_id == str(entries[-1].id)


async def test_tamper_below_checkpoint_anchor_is_flagged(session: AsyncSession) -> None:
    """Mutating the checkpoint anchor row is caught — the verifier never trusts it."""
    entries = await _seed_chain(session, 4)
    clean = await verify_chain(session, advance_checkpoint=True)
    assert clean.ok is True

    # Tamper with the checkpoint anchor (the last verified-clean entry) directly.
    anchor = entries[-1]
    await session.execute(
        update(AuditLog)
        .where(AuditLog.id == anchor.id, AuditLog.created_at == anchor.created_at)
        .values(actor="user:evil")
    )
    await session.flush()

    result = await verify_chain(session)
    assert result.ok is False
    assert result.break_ is not None
    assert result.break_.reason == "checkpoint_mismatch"


# ---------------------------------------------------------------------------
# Append-only intact: the writer is still the single append path
# ---------------------------------------------------------------------------


async def test_writer_remains_single_append_path_no_update(session: AsyncSession) -> None:
    """record() only ever INSERTs — repeated calls grow the log, never mutate rows."""
    before = (await session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    await _seed_chain(session, 3)
    after = (await session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    assert after - before == 3


async def test_existing_writer_callers_need_no_chain_args(session: AsyncSession) -> None:
    """A caller that omits chain args still gets a fully-chained row (back-compat)."""
    entry = await audit_service.record(
        session,
        actor="user:compat",
        action=audit_service.AUTH_LOGIN,
        target_type="user",
        target_id=None,
        detail=None,
    )
    assert entry.prev_hash == chain.GENESIS_HASH
    assert entry.entry_hash == chain.compute_entry_hash(entry, chain.GENESIS_HASH)


async def test_chain_survives_unicode_detail(session: AsyncSession) -> None:
    """Non-ASCII detail hashes deterministically (UTF-8, ensure_ascii=False)."""
    entry = await audit_service.record(
        session,
        actor="user:üser",
        action=audit_service.SETTINGS_UPDATED,
        target_type="settings",
        target_id=None,
        detail={"note": "naïve café — "},
    )
    await session.flush()
    assert entry.entry_hash == chain.compute_entry_hash(entry, chain.GENESIS_HASH)
    result = await verify_chain(session)
    assert result.ok is True


async def test_genesis_is_not_a_valid_real_entry_hash(session: AsyncSession) -> None:
    """A real entry_hash never equals the all-zero genesis sentinel (collision-free)."""
    [entry] = await _seed_chain(session, 1)
    assert entry.entry_hash != chain.GENESIS_HASH


def _unused_uuid() -> uuid.UUID:
    """A fresh UUID (kept for parity with id-shaped fixtures)."""
    return uuid.uuid4()


async def test_stored_bytes_round_trip_byte_identical(session: AsyncSession) -> None:
    """The stored bytea/BLOB round-trips byte-identically (no hex/encoding drift)."""
    [entry] = await _seed_chain(session, 1)
    expected = bytes(entry.entry_hash)
    # Reload from the DB (populate_existing forces a fresh fetch, not the identity
    # map) and confirm the raw 32 bytes survived the persist/load cycle unchanged.
    reloaded = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.id == entry.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert bytes(reloaded.entry_hash) == expected
    assert len(expected) == 32
    # And the digest column is queryable as raw bytes via a direct SELECT.
    row = (await session.execute(select(AuditLog.entry_hash))).one()
    assert bytes(row[0]) == expected


# ---------------------------------------------------------------------------
# Concurrent appends do not fork the chain (W4-T1 #1/#2)
# ---------------------------------------------------------------------------
#
# Under PostgreSQL READ COMMITTED two concurrent record() transactions reading
# the head with a plain SELECT would both see head H and both insert prev_hash=H
# — a chain FORK the linear verifier then false-alarms on (ADR-0038 §2). The
# writer serialises the head read+insert with a transaction-scoped advisory lock
# so concurrent appends QUEUE into a single linear chain instead. The two tests
# below assert that property on both backends: a deterministic SQLite-NullPool
# proof (CI) and an integration-marked real-Postgres proof (true concurrency).


async def _verify_linear(session: AsyncSession, expected_len: int) -> None:
    """Assert the persisted chain is a single linear, verifier-clean run of *n* rows."""
    rows = (
        (
            await session.execute(
                select(AuditLog).order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == expected_len
    # No two rows share a prev_hash (a fork would re-use the same head twice), and
    # each prev_hash equals the predecessor's entry_hash (a single linear chain).
    prev_hashes = [bytes(r.prev_hash) for r in rows]
    assert len(set(prev_hashes)) == len(prev_hashes)
    running = chain.GENESIS_HASH
    for row in rows:
        assert bytes(row.prev_hash) == running
        running = bytes(row.entry_hash)
    result = await verify_chain(session)
    assert result.ok is True
    assert result.break_ is None
    assert result.checked == expected_len


@pytest.fixture()
async def file_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """File-backed async SQLite engine with ``NullPool`` (one real conn per session).

    The default in-memory ``StaticPool`` shares a single connection, so two sessions
    would interleave inside one transaction and could never exercise the cross-
    connection race the advisory lock guards. A file URL with ``NullPool`` gives each
    session its own connection + SQLite file write-locking — the same fixture shape
    the reasoning-trace recorder concurrency test uses (W6 flaky-concurrency lesson).
    """
    db_path = tmp_path / "audit_chain_concurrency_test.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path.as_posix()}",
        poolclass=NullPool,
        connect_args={"check_same_thread": False, "timeout": 30},
    )

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


async def test_interleaved_appends_under_one_engine_are_linear(file_engine: AsyncEngine) -> None:
    """Two record() calls on distinct sessions/connections form ONE linear chain.

    Each append commits in its own transaction on its own connection (NullPool), so
    the second reads the now-current head the first committed — the read+insert is
    serialised, never forked. (SQLite has no advisory lock; its per-connection write
    lock provides the same serialisation the PostgreSQL advisory lock provides — the
    integration test below proves the lock itself on real concurrency.)
    """
    maker = async_sessionmaker(file_engine, expire_on_commit=False)

    async def append(i: int) -> None:
        async with maker() as s:
            await audit_service.record(
                s,
                actor=f"user:{i}",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id=str(i),
                detail={"step": i},
            )
            await s.commit()

    await append(0)
    await append(1)

    async with maker() as verify_session:
        await _verify_linear(verify_session, expected_len=2)


@pytest.mark.integration
async def test_concurrent_appends_on_postgres_do_not_fork() -> None:
    """Two PARALLEL record() transactions on real Postgres yield one linear chain.

    This is the bite that the SQLite suite cannot surface (single connection): with
    a plain head SELECT the two transactions would both read head H and fork the
    chain (false prev_hash_mismatch). The advisory lock serialises them, so the
    persisted chain is linear and verifies clean. Skipped unless a Postgres URL is
    reachable (compose-backed integration run).
    """
    url = os.environ.get(
        "NETOPS_TEST_DATABASE_URL",
        "postgresql+asyncpg://netops:netops@127.0.0.1:5432/netops_test",
    )
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as exc:  # pragma: no cover - skip when no Postgres is reachable
        await engine.dispose()
        pytest.skip(f"no reachable Postgres for the integration concurrency test: {exc}")

    maker = async_sessionmaker(engine, expire_on_commit=False)
    tag = uuid.uuid4().hex  # isolate this run's rows from any other test data

    async def append(i: int) -> None:
        async with maker() as s:
            await audit_service.record(
                s,
                actor=f"user:{tag}:{i}",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id=f"{tag}:{i}",
                detail={"step": i, "tag": tag},
            )
            await s.commit()

    try:
        # Fire both appends in parallel; the advisory lock must queue them.
        await asyncio.gather(append(0), append(1))

        async with maker() as verify_session:
            rows = (
                (
                    await verify_session.execute(
                        select(AuditLog)
                        .where(AuditLog.target_id.like(f"{tag}:%"))
                        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
                    )
                )
                .scalars()
                .all()
            )
            assert len(rows) == 2
            # No fork: the two rows carry DISTINCT prev_hash values and the second
            # chains off the first's entry_hash (a single linear segment).
            prev_a, prev_b = bytes(rows[0].prev_hash), bytes(rows[1].prev_hash)
            assert prev_a != prev_b
            assert bytes(rows[1].prev_hash) == bytes(rows[0].entry_hash)
            assert bytes(rows[0].entry_hash) == chain.compute_entry_hash(rows[0], prev_a)
            assert bytes(rows[1].entry_hash) == chain.compute_entry_hash(rows[1], prev_b)
    finally:
        async with maker() as cleanup:
            await cleanup.execute(
                AuditLog.__table__.delete().where(AuditLog.target_id.like(f"{tag}:%"))
            )
            await cleanup.commit()
        await engine.dispose()
