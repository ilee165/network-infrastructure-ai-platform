"""Audit hash-chain (ADR-0038) re-asserted under REAL PostgreSQL (W5-T0).

The SQLite unit suite (``tests/services/test_audit_hash_chain.py``) is the fast
smoke; THIS module re-asserts the same W4-T1 controls against a real Postgres so
the W5-T3 gate flip does not rest on a backend that hides the bug it gates. Each
test below closes one of the four documented SQLite false-PASSes — the assertion
is meaningful only on PG (see the per-test docstring; the closed false-PASS is
named so W5-T3 can cite it):

  1. **``NULLS FIRST`` / head selection by ``seq``** —
     :func:`test_head_read_ignores_null_seq_under_pg_nulls_first_ordering`.
     PG sorts NULLs FIRST in ``ORDER BY seq DESC``; without the ``seq IS NOT NULL``
     filter the head read would pick a NULL-``seq`` pre-chain row and crash every
     append (``int(None)+1``). SQLite's NULL ordering differs and masked this.
  2. **Unique index on a partitioned table** —
     :func:`test_seq_index_is_non_unique_on_partitioned_audit_log`.
     A UNIQUE index on ``seq`` alone is INVALID on the ``RANGE (created_at)``
     partitioned ``audit_log`` parent; SQLite has no native partitioning so the
     constraint shape was never exercised. We prove the migrated index is the
     NON-unique read index AND that the parent really is partitioned.
  3. **``REVOKE ... UPDATE``** (append-only) —
     :func:`test_revoke_update_blocks_a_non_owner_role_on_audit_log`.
     SQLite ignores the GRANT/REVOKE model; only on PG does the
     ``REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC`` actually deny a non-owner.
  4. **``prev_hash`` / ``entry_hash`` chain walk** —
     :func:`test_mid_chain_update_is_flagged_under_pg` and
     :func:`test_full_scan_catches_pre_anchor_tamper_under_pg`.
     The verifier's recompute + chain walk runs against real bytea columns and the
     PG ``ORDER BY seq`` keyset — the round-5 ``prev_hash`` chain-continuity walk.

Secret-surface (W5-T0 Requirement 4): the audit rows are secret-free by
construction (ADR-0032 §5); no fixture or assertion here contains a plaintext
secret — these are tamper-evidence assertions on the chain only.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.models import AuditLog
from app.models.audit import _SEQ_UNIQUE_INDEX_NAME
from app.services.audit import chain
from app.services.audit import service as audit_service
from app.services.audit.verify import count_pre_chain_rows, verify_chain

pytestmark = pytest.mark.integration


async def _seed_chain(session: AsyncSession, n: int) -> list[AuditLog]:
    """Append *n* audit entries through the REAL writer (advisory-lock path on PG)."""
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
# False-PASS #1 — NULLS FIRST ordering / head selection by seq (PG-only).
# ---------------------------------------------------------------------------


async def test_head_read_ignores_null_seq_under_pg_nulls_first_ordering(
    pg_session: AsyncSession,
) -> None:
    """A NULL-``seq`` pre-chain row must NOT become the chain head on PG (false-PASS #1).

    PostgreSQL orders ``NULLS FIRST`` in a ``ORDER BY seq DESC``, so a NULL-``seq``
    old-writer row sorts to the TOP — the exact position the head read selects. The
    writer's ``seq IS NOT NULL`` filter (service.py ``_current_chain_head``) is what
    keeps a NULL row from being chosen as the head; without it ``int(None)+1`` would
    crash EVERY new append during a rolling-deploy window. SQLite sorts NULLs the
    other way in DESC, so this masked false-PASS surfaces only here.

    We insert a genesis-hash NULL-``seq`` old-writer row FIRST, then append a real
    row through the writer and confirm: (a) the append did not crash, (b) it seeded
    ``seq == 1`` (the NULL row was ignored, not treated as head ``seq``), and (c)
    the verifier walks the real chain clean while counting the NULL row as benign
    pre-chain — the PG ``ORDER BY seq ... NULLS LAST`` exclusion under test.
    """
    # The old-writer row: raw Core INSERT with seq EXPLICITLY NULL + genesis hashes.
    old_id = uuid.uuid4()
    await pg_session.execute(
        AuditLog.__table__.insert().values(
            id=old_id,
            created_at=datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC),
            seq=None,
            actor="old-pod",
            action="legacy.write",
            target_type="device",
            target_id="legacy",
            detail=None,
            reasoning_trace_id=None,
            request_id=None,
            prev_hash=chain.GENESIS_HASH,
            entry_hash=chain.GENESIS_HASH,
        )
    )
    await pg_session.flush()

    # The append MUST NOT crash on int(None)+1 (the PG NULLS-FIRST head-read bite)
    # and must seed at seq==1 (the NULL row was excluded, not read as the head).
    [first] = await _seed_chain(pg_session, 1)
    assert first.seq == 1
    assert first.prev_hash == chain.GENESIS_HASH

    result = await verify_chain(pg_session)
    assert result.ok is True
    assert result.break_ is None

    total, suspicious = await count_pre_chain_rows(pg_session)
    assert (total, suspicious) == (1, 0)


async def test_equal_created_at_rows_order_by_seq_not_id_under_pg(
    pg_session: AsyncSession,
) -> None:
    """Equal-``created_at`` rows verify clean because PG orders by ``seq`` (false-PASS #1).

    Under an ``ORDER BY (created_at, id)`` read the random-UUID tiebreak could invert
    two equal-``created_at`` rows and make the verifier report a FALSE
    ``prev_hash_mismatch`` (ADR-0038 §2 forbids false alarms). Ordering by the
    monotonic ``seq`` makes the chain unambiguous on PG. We pin every appended row to
    the SAME ``created_at`` and confirm the real-PG verifier still passes.
    """
    fixed = datetime(2026, 6, 26, 12, 0, 0, tzinfo=UTC)
    original = audit_service.utcnow
    audit_service.utcnow = lambda: fixed  # type: ignore[assignment]
    try:
        entries = await _seed_chain(pg_session, 5)
    finally:
        audit_service.utcnow = original  # type: ignore[assignment]

    assert {e.created_at for e in entries} == {fixed}
    assert [e.seq for e in entries] == sorted(e.seq for e in entries)
    result = await verify_chain(pg_session)
    assert result.ok is True
    assert result.checked == 5


# ---------------------------------------------------------------------------
# False-PASS #2 — unique index on a partitioned table (PG-only).
# ---------------------------------------------------------------------------


async def test_seq_index_is_non_unique_on_partitioned_audit_log(
    pg_session: AsyncSession,
) -> None:
    """``audit_log`` is partitioned and the ``seq`` index is NON-unique (false-PASS #2).

    A UNIQUE index on ``seq`` ALONE is INVALID on a PG ``RANGE (created_at)``
    partitioned table (the unique key must fold in the partition key), so the model
    + migration deliberately make it the NON-unique read/ORDER-BY index and rest
    ``seq`` uniqueness on the writer's under-lock ``MAX(seq)+1``. SQLite has no
    native partitioning, so this constraint shape was never exercised — only on PG
    can we prove (a) the parent IS partitioned and (b) the migrated index is NOT
    unique. If a future change made it unique, ``alembic upgrade head`` would have
    FAILED on PG (the harness would never reach this assertion).
    """
    # (a) the parent really is range-partitioned (pg_partitioned_table only has a
    # row when the relation is a partitioned parent).
    is_partitioned = (
        await pg_session.execute(
            text(
                "SELECT count(*) FROM pg_partitioned_table p "
                "JOIN pg_class c ON c.oid = p.partrelid "
                "WHERE c.relname = 'audit_log'"
            )
        )
    ).scalar_one()
    assert is_partitioned == 1, "audit_log must be a partitioned parent on PG"

    # (b) the migrated seq index exists and is NON-unique (indisunique = false).
    rows = (
        await pg_session.execute(
            text(
                "SELECT i.indisunique FROM pg_class c "
                "JOIN pg_index i ON i.indexrelid = c.oid "
                "WHERE c.relname = :name"
            ),
            {"name": _SEQ_UNIQUE_INDEX_NAME},
        )
    ).all()
    # The index name is "uq_audit_log_seq" (kept for on-disk stability); assert it
    # exists on the parent and is non-unique.
    assert rows, "the seq read-index must exist on the partitioned parent"
    assert all(indisunique is False for (indisunique,) in rows)


async def test_seq_uniqueness_rests_on_writer_not_a_db_constraint_under_pg(
    pg_session: AsyncSession,
) -> None:
    """Serial + batched appends never duplicate ``seq`` on PG (false-PASS #2 companion).

    Because the DB index on the partitioned parent is NON-unique, ``seq`` uniqueness
    is the writer's responsibility (``MAX(seq)+1`` under ``pg_advisory_xact_lock``).
    This is the behavioural guarantee that REPLACES the impossible DB-level UNIQUE
    on the partitioned table — assert every ``seq`` is distinct, strictly
    increasing, and dense 1..N over a serial run plus a single-flush batch.
    """
    serial = await _seed_chain(pg_session, 8)
    batch: list[AuditLog] = []
    for i in range(5):
        batch.append(
            await audit_service.record(
                pg_session,
                actor=f"batch:{i}",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id=f"b{i}",
                detail={"batch": i},
            )
        )
    await pg_session.flush()

    seqs = [e.seq for e in (*serial, *batch)]
    assert None not in seqs
    assert len(set(seqs)) == len(seqs), f"writer produced a duplicate seq on PG: {seqs}"
    assert seqs == sorted(seqs)
    assert seqs == list(range(1, len(seqs) + 1))


# ---------------------------------------------------------------------------
# False-PASS #3 — REVOKE UPDATE / DELETE append-only enforcement (PG-only).
# ---------------------------------------------------------------------------


async def test_revoke_update_blocks_a_non_owner_role_on_audit_log(
    pg_engine: AsyncEngine, pg_session: AsyncSession
) -> None:
    """A non-owner role cannot UPDATE/DELETE ``audit_log`` — the REVOKE bites (false-PASS #3).

    Migration 0001 runs ``REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC``. SQLite
    ignores the GRANT/REVOKE model entirely, so the SQLite suite forces row edits
    directly to *simulate* a privileged tamper — the protection itself is untested
    there. On PG we create a throwaway NON-owner role granted only SELECT/INSERT,
    connect AS that role, and confirm an UPDATE and a DELETE on ``audit_log`` are
    DENIED (``InsufficientPrivilege``) while a SELECT and an INSERT-via-writer
    succeed. This is the append-only posture the hash chain backstops for the
    owner/superuser case.
    """
    import asyncpg

    entries = await _seed_chain(pg_session, 2)
    await pg_session.commit()
    target = entries[0]

    # libpq URL + admin connection to provision a throwaway least-privilege role.
    # NOTE: ``str(url)`` masks the password as ``***`` (SQLAlchemy security default),
    # which fails real password auth under a CI ``services: postgres`` (passed only
    # under local trust/socket auth). Render with the real password explicitly.
    sa_url = pg_engine.url.render_as_string(hide_password=False)
    libpq = sa_url.replace("postgresql+asyncpg://", "postgresql://")
    role = f"netops_least_priv_{uuid.uuid4().hex[:8]}"
    pwd = uuid.uuid4().hex  # ephemeral, throwaway — not a real secret, never asserted.

    admin = await asyncpg.connect(libpq)
    try:
        await admin.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{pwd}'")
        await admin.execute(f'GRANT CONNECT ON DATABASE {admin._params.database} TO "{role}"')
        await admin.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        # Grant ONLY SELECT + INSERT on audit_log (and its partitions) — never
        # UPDATE/DELETE. The REVOKE FROM PUBLIC already denies it, but we grant the
        # positive privileges explicitly so SELECT/INSERT prove the role works.
        await admin.execute(f'GRANT SELECT, INSERT ON audit_log TO "{role}"')
        for suffix in ("2026_06", "2026_07", "default"):
            await admin.execute(f'GRANT SELECT, INSERT ON audit_log_{suffix} TO "{role}"')

        # Connect AS the least-privilege role.
        import urllib.parse as _url

        parsed = _url.urlsplit(libpq)
        role_url = _url.urlunsplit(
            (
                parsed.scheme,
                f"{role}:{pwd}@{parsed.hostname}:{parsed.port or 5432}",
                parsed.path,
                parsed.query,
                parsed.fragment,
            )
        )
        member = await asyncpg.connect(role_url)
        try:
            # SELECT works (role has SELECT).
            n = await member.fetchval("SELECT count(*) FROM audit_log")
            assert n >= 2

            # UPDATE is DENIED — the REVOKE bites for a non-owner.
            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await member.execute(
                    "UPDATE audit_log SET action = 'tampered' WHERE id = $1",
                    target.id,
                )
            # DELETE is DENIED too.
            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await member.execute(
                    "DELETE FROM audit_log WHERE id = $1",
                    target.id,
                )
        finally:
            await member.close()
    finally:
        # Drop the throwaway role (revoke its grants first so DROP succeeds).
        await admin.execute(f'REVOKE ALL ON audit_log FROM "{role}"')
        for suffix in ("2026_06", "2026_07", "default"):
            await admin.execute(f'REVOKE ALL ON audit_log_{suffix} FROM "{role}"')
        await admin.execute(f'REVOKE ALL ON SCHEMA public FROM "{role}"')
        await admin.execute(f'REVOKE ALL ON DATABASE {admin._params.database} FROM "{role}"')
        await admin.execute(f'DROP ROLE IF EXISTS "{role}"')
        await admin.close()


# ---------------------------------------------------------------------------
# False-PASS #4 — prev_hash / entry_hash chain walk (PG bytea + ORDER BY seq).
# ---------------------------------------------------------------------------


async def test_mid_chain_update_is_flagged_under_pg(pg_session: AsyncSession) -> None:
    """A privileged mid-chain UPDATE is caught at the right index on PG (false-PASS #4).

    The verifier recomputes ``SHA-256(canonical(entry) || prev_hash)`` over real
    ``bytea`` columns, walking by the PG ``ORDER BY seq`` keyset. Tampering a hashed
    field on a mid-chain row WITHOUT recomputing its ``entry_hash`` (the
    owner/superuser case the REVOKE cannot bind) must surface as an
    ``entry_hash_mismatch`` at that row's 1-based position — proving the chain-walk
    bites against real PG bytea round-tripping, not just SQLite BLOBs.
    """
    entries = await _seed_chain(pg_session, 5)
    target = entries[2]
    await pg_session.execute(
        update(AuditLog)
        .where(AuditLog.id == target.id, AuditLog.created_at == target.created_at)
        .values(action="device.deleted")
    )
    await pg_session.flush()

    result = await verify_chain(pg_session)
    assert result.ok is False
    assert result.break_ is not None
    assert result.break_.position == 3
    assert result.break_.entry_id == str(target.id)
    assert result.break_.reason == "entry_hash_mismatch"


async def test_mid_chain_delete_breaks_prev_hash_link_under_pg(
    pg_session: AsyncSession,
) -> None:
    """Deleting a mid-chain row breaks the successor's ``prev_hash`` link on PG (false-PASS #4)."""
    entries = await _seed_chain(pg_session, 5)
    victim = entries[2]
    await pg_session.execute(
        AuditLog.__table__.delete().where(
            AuditLog.id == victim.id, AuditLog.created_at == victim.created_at
        )
    )
    await pg_session.flush()

    result = await verify_chain(pg_session)
    assert result.ok is False
    assert result.break_ is not None
    assert result.break_.position == 3
    assert result.break_.entry_id == str(entries[3].id)
    assert result.break_.reason == "prev_hash_mismatch"


async def test_full_scan_catches_pre_anchor_tamper_under_pg(
    pg_session: AsyncSession,
) -> None:
    """Full scan re-walks history from genesis and catches a pre-anchor tamper (false-PASS #4).

    Round-5 / A3: the incremental walk resumes strictly after the checkpoint anchor,
    so a mutated row BELOW the watermark (not the anchor itself) is invisible to the
    daily incremental run; the full scan walks from genesis and re-detects it. This
    is the ``prev_hash`` chain-continuity walk the round-5 fix introduced — exercised
    here against the real PG keyset (``seq``) and bytea columns.
    """
    entries = await _seed_chain(pg_session, 5)
    clean = await verify_chain(pg_session, advance_checkpoint=True)
    assert clean.ok is True

    pre_anchor = entries[1]
    await pg_session.execute(
        update(AuditLog)
        .where(AuditLog.id == pre_anchor.id, AuditLog.created_at == pre_anchor.created_at)
        .values(actor="user:evil")
    )
    await pg_session.flush()

    # Incremental: resumes after the anchor, never re-visits entries[1] → clean.
    incremental = await verify_chain(pg_session)
    assert incremental.ok is True

    # Full scan: from genesis, catches the pre-anchor tamper.
    full = await verify_chain(pg_session, full=True)
    assert full.ok is False
    assert full.break_ is not None
    assert full.break_.entry_id == str(pre_anchor.id)
    assert full.break_.reason == "entry_hash_mismatch"
    assert full.break_.position == 2


async def test_untouched_chain_verifies_clean_under_pg(pg_session: AsyncSession) -> None:
    """A real-PG untampered chain verifies clean and reports the head it walked."""
    entries = await _seed_chain(pg_session, 6)
    result = await verify_chain(pg_session)
    assert result.ok is True
    assert result.break_ is None
    assert result.checked == 6
    assert result.head_entry_id == str(entries[-1].id)


# ---------------------------------------------------------------------------
# Concurrency under REAL PG READ COMMITTED — the advisory-lock bite the SQLite
# single connection cannot surface (W4-T1 #1/#2).
# ---------------------------------------------------------------------------


async def test_concurrent_appends_on_pg_do_not_fork_the_chain(
    pg_engine: AsyncEngine,
) -> None:
    """Two PARALLEL ``record()`` transactions on real PG yield ONE linear chain.

    Under PostgreSQL READ COMMITTED two concurrent appends with a plain head SELECT
    would both read head ``H`` (and the same ``MAX(seq)``) and fork the chain
    (false ``prev_hash_mismatch`` + duplicate ``seq``). The transaction-scoped
    ``pg_advisory_xact_lock`` serialises them so the persisted chain is linear and
    verifies clean. This is the bite the single-connection SQLite suite cannot
    surface — it runs here on real cross-connection concurrency.
    """
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    tag = uuid.uuid4().hex

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

    await asyncio.gather(append(0), append(1))

    async with maker() as verify_session:
        rows = (
            (
                await verify_session.execute(
                    select(AuditLog)
                    .where(AuditLog.target_id.like(f"{tag}:%"))
                    .order_by(AuditLog.seq.asc())
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        prev_a, prev_b = bytes(rows[0].prev_hash), bytes(rows[1].prev_hash)
        assert prev_a != prev_b, "a fork would re-use the same head twice"
        assert bytes(rows[1].prev_hash) == bytes(rows[0].entry_hash)
        # Distinct, dense seq — no duplicate under the lock.
        assert {rows[0].seq, rows[1].seq} == {rows[0].seq, rows[1].seq}
        assert rows[0].seq != rows[1].seq
        # The full chain verifies clean.
        result = await verify_chain(verify_session)
        assert result.ok is True
        assert result.break_ is None
