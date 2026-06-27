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
    """The canonical field set is exactly the immutable, secret-free audit columns.

    ``seq`` (the append-order key) is INCLUDED (PR #76 round-2 #5): it is the chain's
    order key and the verifier's incremental keyset boundary, so a tampered ``seq``
    on a checkpointed row could otherwise silently shift the boundary and SKIP
    entries. Hashing ``seq`` means a tampered value breaks ``entry_hash`` instead.
    """
    assert set(chain.CANONICAL_FIELDS) == {
        "id",
        "seq",
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


async def test_tampered_seq_breaks_entry_hash(session: AsyncSession) -> None:
    """Mutating a row's ``seq`` (the keyset boundary) is detected (PR #76 round-2 #5).

    ``seq`` is the verifier's incremental keyset boundary (verify.py resumes strictly
    after the anchor's ``seq``). If ``seq`` did not participate in ``entry_hash`` a
    privileged actor could mutate it without breaking the hash and silently shift the
    boundary so the incremental walk skips entries. With ``seq`` hashed, a tampered
    ``seq`` makes the recompute mismatch the stored ``entry_hash`` — a chain break.
    """
    entries = await _seed_chain(session, 4)
    # Tamper the LAST entry's seq to a larger value: the walk order (ORDER BY seq) is
    # unchanged so its predecessor link still matches (no prev_hash_mismatch), which
    # ISOLATES the seq-in-hash check — the recompute now sees the new seq and must
    # diverge from the stored entry_hash. Use a free value so it stays distinct from
    # the other rows' seq (the chain order key must stay unambiguous).
    target = entries[-1]
    await session.execute(
        update(AuditLog)
        .where(AuditLog.id == target.id, AuditLog.created_at == target.created_at)
        .values(seq=10_000)
    )
    await session.flush()

    result = await verify_chain(session)
    assert result.ok is False
    assert result.break_ is not None
    assert result.break_.entry_id == str(target.id)
    assert result.break_.reason == "entry_hash_mismatch"


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


async def test_pre_anchor_tamper_caught_by_full_scan_not_incremental(
    session: AsyncSession,
) -> None:
    """A mutated PRE-anchor historical row is caught ONLY by the full scan (A3/A11).

    The incremental walk resumes strictly AFTER the checkpoint anchor (entries[-1]
    here), and the anchor itself is re-proven each pass — so tampering of a row
    BELOW the watermark that is NOT the anchor (entries[1]) is invisible to the
    daily incremental run. The full scan walks from genesis and re-detects it. This
    is the bite that proves the new full mode is the guard for the A3 gap (the old
    "tamper below checkpoint" test mutated entries[-1], i.e. the anchor, which is
    already caught by the anchor recompute — it did NOT cover this gap).
    """
    entries = await _seed_chain(session, 5)
    clean = await verify_chain(session, advance_checkpoint=True)
    assert clean.ok is True
    # The watermark now sits on the last entry; entries[1] is well below it.

    pre_anchor = entries[1]
    await session.execute(
        update(AuditLog)
        .where(AuditLog.id == pre_anchor.id, AuditLog.created_at == pre_anchor.created_at)
        .values(actor="user:evil")  # a hashed field, not recomputed → tampering
    )
    await session.flush()

    # Incremental run: resumes after the anchor and never re-visits entries[1] —
    # so it passes clean, demonstrating the A3 gap the full scan closes.
    incremental = await verify_chain(session)
    assert incremental.ok is True, "incremental run does not re-detect a pre-anchor tamper"

    # Full scan: walks from genesis, ignoring the checkpoint, and catches it.
    full = await verify_chain(session, full=True)
    assert full.ok is False
    assert full.break_ is not None
    assert full.break_.entry_id == str(pre_anchor.id)
    assert full.break_.reason == "entry_hash_mismatch"
    # entries[1] is the 2nd row from genesis → 1-based position 2.
    assert full.break_.position == 2


async def test_full_scan_on_untampered_chain_verifies_clean(session: AsyncSession) -> None:
    """A full (genesis) scan over a clean chain verifies every row and reports head."""
    entries = await _seed_chain(session, 4)
    await verify_chain(session, advance_checkpoint=True)

    result = await verify_chain(session, full=True)
    assert result.ok is True
    assert result.break_ is None
    assert result.checked == 4  # every row, not just the post-checkpoint tail
    assert result.head_entry_id == str(entries[-1].id)


async def test_recompute_or_break_turns_malformed_length_into_a_break(
    session: AsyncSession,
) -> None:
    """The in-loop recompute guard converts a wrong-length hash to a break (A1).

    ``compute_entry_hash`` raises ``ValueError`` on a prev_hash that is not exactly
    HASH_LEN raw bytes (chain.py:133). The verifier's ``_recompute_or_break`` helper
    (verify.py:210 path) must NOT let that crash the walk before the metric/alert
    path — it returns an ``entry_hash_mismatch`` :class:`VerifyResult` break instead.
    We drive the helper directly with a malformed stored prev_hash (the in-loop
    Direction-1 guard otherwise pre-empts this row, so the helper's ValueError
    branch is pinned here).
    """
    from app.services.audit.verify import VerifyResult, _recompute_or_break

    [entry] = await _seed_chain(session, 1)
    entry.prev_hash = b"\x00\x01\x02"  # 3 bytes, not 32 → compute_entry_hash raises

    outcome = _recompute_or_break(entry, entry.prev_hash, position=1, head_entry=None, checked=0)
    assert isinstance(outcome, VerifyResult)
    assert outcome.ok is False
    assert outcome.break_ is not None
    assert outcome.break_.reason == "entry_hash_mismatch"
    assert outcome.break_.entry_id == str(entry.id)
    assert outcome.break_.found == "malformed_length"


async def test_malformed_length_anchor_hash_is_checkpoint_break_not_a_crash(
    session: AsyncSession,
) -> None:
    """A wrong-length stored prev_hash on the checkpoint ANCHOR is a break (A1).

    The anchor recompute (verify.py:163) runs without a Direction-1 guard, so a
    length-tampered anchor would raise ``ValueError`` and crash the job before the
    metric/alert path. The verifier must instead report a ``checkpoint_mismatch``
    break so the job fails cleanly with the alert + non-zero exit.
    """
    entries = await _seed_chain(session, 3)
    clean = await verify_chain(session, advance_checkpoint=True)
    assert clean.ok is True

    anchor = entries[-1]
    await session.execute(
        update(AuditLog)
        .where(AuditLog.id == anchor.id, AuditLog.created_at == anchor.created_at)
        .values(prev_hash=b"\x00\x01\x02")  # 3 bytes, not 32
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


async def test_record_emits_no_update_on_audit_log(session: AsyncSession) -> None:
    """record() issues exactly ONE INSERT and NO UPDATE on audit_log (W4-T1 A2).

    The previous write shape inserted a placeholder entry_hash then UPDATEd it in a
    second flush — which contradicts the append-only ``REVOKE UPDATE ... FROM
    PUBLIC`` posture and fails under a least-privilege (non-owner) DB role. This
    test captures the real emitted SQL via a ``before_cursor_execute`` listener and
    asserts the writer never UPDATEs ``audit_log`` (and that it does INSERT it),
    closing the gap that let A2 through (the prior test only counted rows).
    """
    statements: list[str] = []

    bind = session.bind
    assert bind is not None
    sync_engine = bind.sync_engine

    @event.listens_for(sync_engine, "before_cursor_execute")
    def _capture(
        _conn: Any,
        _cursor: Any,
        statement: str,
        _parameters: Any,
        _context: Any,
        _executemany: bool,
    ) -> None:
        statements.append(statement)

    try:
        await _seed_chain(session, 2)
    finally:
        event.remove(sync_engine, "before_cursor_execute", _capture)

    lowered = [s.lower() for s in statements]
    inserts = [s for s in lowered if "insert into audit_log" in s]
    updates = [s for s in lowered if "update audit_log" in s]
    # Two appends → exactly two INSERTs, zero UPDATEs (single-insert write shape).
    assert len(inserts) == 2, f"expected one INSERT per append, saw: {inserts}"
    assert updates == [], f"record() must not UPDATE audit_log, saw: {updates}"


async def test_seq_is_monotonic_in_append_order(session: AsyncSession) -> None:
    """Each append gets a strictly-increasing ``seq`` — the chain's true order (A4)."""
    entries = await _seed_chain(session, 4)
    seqs = [e.seq for e in entries]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs)
    # Strictly increasing (no plateau): the head read + assignment never repeats.
    assert all(b > a for a, b in zip(seqs, seqs[1:], strict=False))


async def test_seq_is_app_assigned_starting_at_one(session: AsyncSession) -> None:
    """The writer app-assigns ``seq`` (MAX(seq)+1), starting at 1 (PR #76 round-2 #1).

    ``seq`` must be known BEFORE the insert (it participates in the canonical hash),
    so the writer assigns it rather than relying on a DB default. The first entry
    seeds the chain at ``seq == 1`` and each subsequent entry is the previous + 1.
    """
    [first] = await _seed_chain(session, 1)
    assert first.seq == 1
    [second] = [
        e
        for e in await _seed_chain(session, 1)
        # the just-appended row is the only new one
    ]
    assert second.seq == 2


async def test_serial_and_batched_appends_never_duplicate_seq(session: AsyncSession) -> None:
    """Serial + batched appends never produce a duplicate ``seq`` (round-3 #03/#04).

    Round-3 #03/#04 DROPPED the model/migration UNIQUE index on ``seq``: a UNIQUE
    index on ``seq`` ALONE is INVALID on the ``RANGE (created_at)`` partitioned
    PostgreSQL ``audit_log`` parent (the unique key must fold in the partition key), so
    keeping it would break ``create_all`` / autogenerate on PostgreSQL. This is the
    BEHAVIOURAL test that REPLACES the lost DB-level guarantee: the writer's
    ``MAX(seq)+1`` assignment (under the append advisory lock on PG / the single
    connection on SQLite) must itself never emit a duplicate. Append a long serial run
    AND a batch flushed together, then assert every ``seq`` is distinct, strictly
    increasing, and dense (1..N) — the chain's order key stays unambiguous.
    """
    serial = await _seed_chain(session, 8)
    # A "batch": several appends recorded back-to-back before a single flush — the
    # writer still assigns each its own MAX(seq)+1, so no two collide.
    batch: list[AuditLog] = []
    for i in range(5):
        batch.append(
            await audit_service.record(
                session,
                actor=f"batch:{i}",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id=f"b{i}",
                detail={"batch": i},
            )
        )
    await session.flush()

    seqs = [e.seq for e in (*serial, *batch)]
    assert None not in seqs, "the writer always app-assigns seq (never NULL)"
    assert len(set(seqs)) == len(seqs), f"writer produced a duplicate seq: {seqs}"
    assert seqs == sorted(seqs), "seq must be strictly increasing in append order"
    assert seqs == list(range(1, len(seqs) + 1)), "seq must be dense 1..N (no gaps/dupes)"


async def test_old_writer_null_seq_insert_succeeds_and_verifier_is_deterministic(
    session: AsyncSession,
) -> None:
    """An old-writer insert WITHOUT ``seq`` succeeds, and the verifier handles NULL ``seq``.

    Round-3 #01/#02: ``seq`` is NULLABLE through the W4 expand phase so an OLD (pre-W4)
    pod still inserting audit rows during an N→N+1 rolling deploy — which does NOT
    assign the app-side ``seq`` — does not hit a NOT NULL violation. Simulate that old
    writer with a raw INSERT that omits ``seq`` (the column default is bypassed via an
    explicit ``seq=None``), carrying the genesis ``entry_hash`` it would have (pre-W4
    rows are pre-chain). The insert must SUCCEED against the 0011 schema, and
    :func:`verify_chain` must walk DETERMINISTICALLY (``ORDER BY seq NULLS LAST,
    created_at, id``) without crashing — the NULL-``seq`` genesis row is flagged like
    any pre-chain/genesis-hash row, never an uncaught error.
    """
    from datetime import UTC, datetime

    # A real, fully-chained appended row first (so there IS a live chain head).
    [real] = await _seed_chain(session, 1)
    assert real.seq == 1

    # The "old writer": a Core INSERT with seq EXPLICITLY NULL — what a pre-W4 pod
    # (which knows nothing of seq) effectively emits. Passing ``seq=None`` in
    # ``.values()`` makes Core insert a literal NULL (an explicit value overrides the
    # ORM ``_next_seq`` column default, which only fires when the column is omitted).
    # Using the table's own insert keeps id/created_at type rendering correct. The row
    # carries the genesis entry_hash an unchained pre-W4 row would have. It MUST NOT
    # raise a NOT NULL violation against the round-3 #01/#02 nullable-seq schema.
    old_id = uuid.uuid4()
    old_created_at = datetime(2026, 6, 27, 12, 0, 0, tzinfo=UTC)
    await session.execute(
        AuditLog.__table__.insert().values(
            id=old_id,
            created_at=old_created_at,
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
    await session.flush()  # MUST NOT raise a NOT NULL violation (round-3 #01/#02)

    reloaded = (await session.execute(select(AuditLog).where(AuditLog.id == old_id))).scalar_one()
    assert reloaded.seq is None, "old-writer row stays NULL-seq (pre-chain history)"

    # The verifier orders NULLS LAST and must not crash; the genesis-hash NULL-seq row
    # is untrusted pre-chain history → a break (entry_hash != recompute), deterministic
    # across runs. The point is: no exception, and the same loud result every pass.
    first = await verify_chain(session)
    second = await verify_chain(session)
    assert first == second, "verifier must be deterministic with a NULL-seq row present"
    assert first.ok is False, "the genesis-hash NULL-seq old-writer row is flagged"
    assert first.break_ is not None
    assert first.break_.entry_id == str(old_id)


async def test_equal_created_at_rows_verify_clean_by_seq(session: AsyncSession) -> None:
    """Rows that share created_at still verify clean — ordering is by seq, not id (A4).

    Two appends are forced to the SAME ``created_at`` (clock granularity / same
    instant). Under the old ``ORDER BY (created_at, id)`` read the random-UUID
    tiebreak could invert their order and make the verifier report a FALSE
    ``prev_hash_mismatch`` (ADR-0038 §2 forbids false alarms). Ordering by the
    monotonic ``seq`` makes the chain unambiguous, so the verifier passes.
    """
    from datetime import UTC, datetime

    fixed = datetime(2026, 6, 26, 12, 0, 0, tzinfo=UTC)

    # Pin every appended row to the SAME created_at so (created_at, id) cannot order
    # them — only seq can. Patch the writer's clock for the duration of the appends.
    import app.services.audit.service as svc

    original = svc.utcnow
    svc.utcnow = lambda: fixed  # type: ignore[assignment]
    try:
        entries = await _seed_chain(session, 5)
    finally:
        svc.utcnow = original  # type: ignore[assignment]

    assert {e.created_at for e in entries} == {fixed}, "all rows must share created_at"
    # seq remains strictly increasing despite the identical timestamps.
    assert [e.seq for e in entries] == sorted(e.seq for e in entries)
    # The verifier walks by seq and finds a clean linear chain (no false alarm).
    result = await verify_chain(session)
    assert result.ok is True
    assert result.break_ is None
    assert result.checked == 5


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
