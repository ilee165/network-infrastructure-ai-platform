"""Audit hash-chain verifier (ADR-0038 §4) — shared by the daily job and the test.

Recomputes the ``audit_log`` hash chain FROM the last verified-clean checkpoint
(the :class:`~app.models.audit.AuditChainCheckpoint` watermark) to the current
head, walking entries in append order ``seq`` (the monotonic append-order column,
W4-T1 A4 — never ``(created_at, id)``, whose random-UUID tiebreak could invert
two equal-``created_at`` rows and false-alarm the chain). ``seq`` is NULLABLE
through the W4 expand phase (round-3 #01/#02): a NULL-``seq`` row is an old-writer
/ pre-chain row (genesis ``entry_hash`` too), sorted NULLS LAST and flagged as
untrusted pre-chain history like any genesis-hash row. Each entry's stored
``entry_hash`` must equal ``SHA-256(canonical(entry) || prev_hash)`` and each
entry's stored ``prev_hash`` must equal the predecessor's ``entry_hash`` — a
mismatch on EITHER is a chain break (a mutated, deleted, reordered, or inserted
row). The verifier reports the FIRST break (its position + entry id) so the daily
job can alert and exit non-zero (ADR-0038 §4); on a clean segment it advances the
checkpoint over the verified-clean range so the next run does not re-walk it.

This module is the single recompute path used by both the CronJob entrypoint
(:mod:`app.services.audit.verify_job`) and the tamper-detection test, so what the
test asserts is exactly what the job runs (no drift, ADR-0038 §2).

Secure by default: a break report carries the entry id, the 1-based chain
position, and hex PREFIXES of the expected/found digests (correlation handles
only, ADR-0038 §1) — never secret material (the audit rows are secret-free by
construction, ADR-0032 §5).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditChainCheckpoint, AuditLog
from app.models.mixins import utcnow
from app.services.audit.chain import GENESIS_HASH, compute_entry_hash, hex_short


@dataclass(frozen=True, slots=True)
class ChainBreak:
    """A detected break in the audit hash chain (ADR-0038 §4).

    ``position`` is the 1-based index of the offending entry within the verified
    segment (so the test can assert the break is flagged at the RIGHT index).
    ``reason`` is a coarse machine class (``entry_hash_mismatch`` |
    ``prev_hash_mismatch`` | ``checkpoint_mismatch`` | ``missing_checkpoint_entry``).
    Digests are rendered as hex PREFIXES only — never raw secret-adjacent bytes.
    """

    position: int
    entry_id: str
    reason: str
    expected: str
    found: str


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of one chain-verification pass (ADR-0038 §4).

    ``ok`` is ``True`` iff no break was found over the walked segment. ``checked``
    is the number of entries recomputed this pass. ``head_entry_id`` /
    ``head_entry_hash_hex`` describe the new verified head (the watermark the job
    advances to on success). ``break_`` is the FIRST detected break, or ``None``
    on a clean pass. ``ok`` is the loud signal the daily job turns into a non-zero
    exit + alert (it never silently passes on a break).
    """

    ok: bool
    checked: int
    head_position: int
    head_entry_id: str | None
    head_entry_hash_hex: str | None
    break_: ChainBreak | None


async def _load_checkpoint(session: AsyncSession) -> AuditChainCheckpoint | None:
    """Return the singleton verified-clean watermark, or ``None`` if never set."""
    return (
        await session.execute(
            select(AuditChainCheckpoint).where(
                AuditChainCheckpoint.id == AuditChainCheckpoint.SINGLETON_ID
            )
        )
    ).scalar_one_or_none()


async def _entries_after(session: AsyncSession, after_seq: int | None) -> list[AuditLog]:
    """Load audit entries in append order, starting strictly AFTER *after_seq*.

    *after_seq* is the ``seq`` of the checkpoint entry (``None`` to start from the
    genesis). Ordering and the keyset filter ``seq > after_seq`` both use the
    monotonic append-order column (W4-T1 A4) so the recompute walks the chain in the
    SAME total order the writer appended it — never the ambiguous ``(created_at, id)``
    order — and resumes exactly where the last verified-clean pass stopped
    (ADR-0038 §4) without re-walking history.

    ``seq`` is NULLABLE through the W4 expand phase (migration 0011, round-3 #01/#02):
    a NULL-``seq`` row is an OLD-writer / pre-chain row (an old pod that inserted
    during an N→N+1 rolling deploy without assigning ``seq``). Such rows are NOT part
    of the verifiable chain (they have no chain position and carry the genesis
    ``entry_hash`` default), so the walk EXCLUDES them with an explicit
    ``seq IS NOT NULL`` filter (round-4 #01). This is load-bearing on the FULL-scan
    path: without it, a legitimate NULL-``seq`` old-writer row would be walked (it
    sorts after the real chain) and its genesis ``prev_hash`` would FALSE-break the
    chain as a ``prev_hash_mismatch``. NULL-``seq`` rows are not silently dropped —
    they are counted and surfaced separately by :func:`count_pre_chain_rows` (the job
    logs the count and FAILS LOUD on any *suspicious* NULL-``seq`` row, i.e. one whose
    ``entry_hash`` is not the genesis default), so real legacy corruption can never
    hide behind the pre-chain classification. Ordering by ``seq`` ASC is now over
    non-NULL values only; the ``created_at, id`` tiebreak is retained defensively
    (``seq`` is unique, so it is not relied upon).
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.seq.is_not(None))
        .order_by(AuditLog.seq.asc(), AuditLog.created_at.asc(), AuditLog.id.asc())
    )
    if after_seq is not None:
        stmt = stmt.where(AuditLog.seq > after_seq)
    return list((await session.execute(stmt)).scalars().all())


async def count_pre_chain_rows(session: AsyncSession) -> tuple[int, int]:
    """Count NULL-``seq`` (pre-chain) audit rows, and how many are SUSPICIOUS.

    Returns ``(total, suspicious)``:

    * ``total`` — rows with ``seq IS NULL``. Through the W4 expand phase these are
      EXPECTED only transiently: old (pre-W4) pods that inserted audit rows during an
      N→N+1 rolling deploy before ``seq`` became NOT NULL (a later contract
      migration). They are pre-chain history (genesis ``entry_hash``), excluded from
      the chain walk (:func:`_entries_after`).
    * ``suspicious`` — pre-chain rows whose ``entry_hash`` OR ``prev_hash`` is NOT the
      genesis default. A genuine old-writer row carries the genesis seed in BOTH
      columns; a NULL-``seq`` row with a real-looking hash in EITHER means ``seq`` was
      likely NULLED by tampering (legacy corruption) — checking only ``entry_hash``
      would misclassify a row whose ``prev_hash`` was mutated to a real predecessor
      digest as benign (round-5 #01, a false PASS). This must NEVER be hidden by the
      pre-chain classification — the job treats ``suspicious > 0`` as a loud failure
      (ADR-0038 §4, fail toward false-positive).

    Outside a known rolling-deploy window ANY ``total > 0`` warrants investigation;
    the verify job logs the count explicitly so it is visible, never silent.
    """
    total = (
        await session.execute(
            select(func.count()).select_from(AuditLog).where(AuditLog.seq.is_(None))
        )
    ).scalar_one()
    suspicious = (
        await session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(
                AuditLog.seq.is_(None),
                or_(
                    AuditLog.entry_hash != GENESIS_HASH,
                    AuditLog.prev_hash != GENESIS_HASH,
                ),
            )
        )
    ).scalar_one()
    return int(total), int(suspicious)


def _recompute_or_break(
    entry: AuditLog, prev_hash: bytes, *, position: int, head_entry: AuditLog | None, checked: int
) -> bytes | VerifyResult:
    """Recompute *entry*'s hash, turning a malformed-length stored hash into a break.

    :func:`compute_entry_hash` raises ``ValueError`` when the stored ``prev_hash``
    is not exactly :data:`~app.services.audit.chain.HASH_LEN` raw bytes (A1) — a
    length-tampered row. The verifier must NOT crash before the metric/alert path
    on such a row, so a malformed length is treated as an ``entry_hash_mismatch``
    :class:`ChainBreak` (the loud signal) rather than a propagating exception.
    Returns the recomputed digest on success, or a :class:`VerifyResult` break.
    """
    try:
        return compute_entry_hash(entry, entry.prev_hash)
    except ValueError:
        # A wrong-length stored prev_hash/entry_hash is a tampered row, not a crash.
        return VerifyResult(
            ok=False,
            checked=checked,
            head_position=checked,
            head_entry_id=str(head_entry.id) if head_entry is not None else None,
            head_entry_hash_hex=hex_short(head_entry.entry_hash) if head_entry else None,
            break_=ChainBreak(
                position=position,
                entry_id=str(entry.id),
                reason="entry_hash_mismatch",
                expected="",
                found="malformed_length",
            ),
        )


async def verify_chain(
    session: AsyncSession, *, advance_checkpoint: bool = False, full: bool = False
) -> VerifyResult:
    """Recompute the audit hash chain from the checkpoint to head (ADR-0038 §4).

    Walks every entry after the verified-clean watermark in append order and checks
    both directions of each link: the stored ``entry_hash`` must equal the recompute
    ``SHA-256(canonical(entry) || prev_hash)`` AND the stored ``prev_hash`` must
    equal the predecessor's ``entry_hash``. Returns the FIRST break (position +
    entry id) or a clean result. When *advance_checkpoint* is true and the pass is
    clean, the watermark is moved to the new head over the verified-clean segment
    (the job advances; the read-only test does not).

    The checkpoint itself is validated first: if the watermarked entry no longer
    carries the recorded ``entry_hash`` (it was mutated/deleted), that is reported
    as a break at the checkpoint — the verifier never trusts a tampered anchor.

    When *full* is true the checkpoint is IGNORED and the walk starts from the
    genesis over EVERY entry (A3). The incremental walk resumes strictly after the
    checkpoint, so tampering of an already-checkpointed *historical* row (below the
    watermark, but NOT the anchor itself — the anchor is re-proven each pass) is
    never re-detected by the daily incremental run. The full scan is the guard for
    that gap: it re-walks history from genesis so a mutated pre-anchor row surfaces
    as a break. The job runs the cheap incremental daily and a full scan on a slower
    cadence (see ``AUDIT_CHAIN_VERIFY_FULL`` / the runbook). A clean full pass may
    still advance the checkpoint over the verified-clean head.
    """
    checkpoint = await _load_checkpoint(session)

    if checkpoint is not None and not full:
        anchor = (
            await session.execute(
                select(AuditLog).where(
                    AuditLog.id == checkpoint.entry_id,
                    AuditLog.created_at == checkpoint.entry_created_at,
                )
            )
        ).scalar_one_or_none()
        if anchor is None:
            # The verified-clean anchor row is gone (deleted) — the chain cannot be
            # resumed from a missing watermark; surface it loudly (never pass).
            return VerifyResult(
                ok=False,
                checked=0,
                head_position=0,
                head_entry_id=None,
                head_entry_hash_hex=None,
                break_=ChainBreak(
                    position=0,
                    entry_id=str(checkpoint.entry_id),
                    reason="missing_checkpoint_entry",
                    expected=hex_short(checkpoint.entry_hash),
                    found="",
                ),
            )
        # The anchor must still (a) carry the entry_hash we checkpointed AND (b)
        # have an entry_hash consistent with its own canonical fields. Recomputing
        # (b) catches content tampering of an already-checkpointed row whose stored
        # entry_hash column was left untouched — the incremental walk below would
        # otherwise never re-visit it (ADR-0038 §4: the verified anchor is trusted
        # as a boundary, so it is re-proven here before we resume past it).
        try:
            anchor_recomputed = compute_entry_hash(anchor, anchor.prev_hash)
        except ValueError:
            # A wrong-length stored prev_hash on the anchor is tampering, not a crash
            # (A1) — surface it as a checkpoint break rather than propagating.
            anchor_recomputed = b""
        if anchor.entry_hash != checkpoint.entry_hash or anchor_recomputed != anchor.entry_hash:
            return VerifyResult(
                ok=False,
                checked=0,
                head_position=0,
                head_entry_id=None,
                head_entry_hash_hex=None,
                break_=ChainBreak(
                    position=0,
                    entry_id=str(checkpoint.entry_id),
                    reason="checkpoint_mismatch",
                    expected=hex_short(checkpoint.entry_hash),
                    found=hex_short(anchor.entry_hash),
                ),
            )
        prev_hash = checkpoint.entry_hash
        # Resume strictly after the anchor's monotonic ``seq`` (W4-T1 A4). The
        # anchor row was just re-fetched and re-proven above, so reading its ``seq``
        # gives the exact keyset boundary for the incremental walk.
        after_seq: int | None = anchor.seq
    else:
        prev_hash = GENESIS_HASH
        after_seq = None

    entries = await _entries_after(session, after_seq)

    head_entry: AuditLog | None = None
    for offset, entry in enumerate(entries):
        position = offset + 1
        # Direction 1: the stored predecessor link must match the running chain.
        if entry.prev_hash != prev_hash:
            return VerifyResult(
                ok=False,
                checked=offset,
                head_position=offset,
                head_entry_id=str(head_entry.id) if head_entry is not None else None,
                head_entry_hash_hex=hex_short(head_entry.entry_hash) if head_entry else None,
                break_=ChainBreak(
                    position=position,
                    entry_id=str(entry.id),
                    reason="prev_hash_mismatch",
                    expected=hex_short(prev_hash),
                    found=hex_short(entry.prev_hash),
                ),
            )
        # Direction 2: the stored entry_hash must equal the canonical recompute.
        # A wrong-length stored prev_hash makes the recompute a break, not a crash (A1).
        recomputed = _recompute_or_break(
            entry, entry.prev_hash, position=position, head_entry=head_entry, checked=offset
        )
        if isinstance(recomputed, VerifyResult):
            return recomputed
        if recomputed != entry.entry_hash:
            return VerifyResult(
                ok=False,
                checked=offset,
                head_position=offset,
                head_entry_id=str(head_entry.id) if head_entry is not None else None,
                head_entry_hash_hex=hex_short(head_entry.entry_hash) if head_entry else None,
                break_=ChainBreak(
                    position=position,
                    entry_id=str(entry.id),
                    reason="entry_hash_mismatch",
                    expected=hex_short(recomputed),
                    found=hex_short(entry.entry_hash),
                ),
            )
        prev_hash = entry.entry_hash
        head_entry = entry

    checked = len(entries)
    if head_entry is not None and advance_checkpoint:
        await _upsert_checkpoint(session, head_entry)

    # The new verified head: the last clean entry this pass, or the prior
    # checkpoint when no new entries existed (a clean no-op pass).
    if head_entry is not None:
        head_id: str | None = str(head_entry.id)
        head_hex: str | None = hex_short(head_entry.entry_hash)
        head_position = checked
    elif checkpoint is not None and not full:
        # Incremental no-op pass (no new appends): echo the existing checkpoint as
        # the verified head. A FULL pass walks from genesis, so a zero-entry full
        # scan means an empty log — report a genesis-empty head, never a stale cp.
        head_id = str(checkpoint.entry_id)
        head_hex = hex_short(checkpoint.entry_hash)
        head_position = 0
    else:
        head_id = None
        head_hex = None
        head_position = 0

    return VerifyResult(
        ok=True,
        checked=checked,
        head_position=head_position,
        head_entry_id=head_id,
        head_entry_hash_hex=head_hex,
        break_=None,
    )


async def _upsert_checkpoint(session: AsyncSession, head: AuditLog) -> None:
    """Advance the singleton watermark to *head* over a verified-clean segment.

    Updates the one checkpoint row in place (or inserts it on the first clean
    pass). Only ever called after a clean walk, so the watermark advances strictly
    over verified-clean data (ADR-0038 §4 — never past a break).
    """
    checkpoint = await _load_checkpoint(session)
    if checkpoint is None:
        session.add(
            AuditChainCheckpoint(
                id=AuditChainCheckpoint.SINGLETON_ID,
                entry_id=head.id,
                entry_created_at=head.created_at,
                entry_hash=head.entry_hash,
                verified_at=utcnow(),
            )
        )
    else:
        checkpoint.entry_id = head.id
        checkpoint.entry_created_at = head.created_at
        checkpoint.entry_hash = head.entry_hash
        checkpoint.verified_at = utcnow()
    await session.flush()
