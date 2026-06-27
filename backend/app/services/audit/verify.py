"""Audit hash-chain verifier (ADR-0038 §4) — shared by the daily job and the test.

Recomputes the ``audit_log`` hash chain FROM the last verified-clean checkpoint
(the :class:`~app.models.audit.AuditChainCheckpoint` watermark) to the current
head, walking entries in append order ``(created_at, id)``. Each entry's stored
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
from datetime import datetime

from sqlalchemy import select
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


async def _entries_after(
    session: AsyncSession, after: tuple[datetime, str] | None
) -> list[AuditLog]:
    """Load audit entries in append order, starting strictly AFTER *after*.

    *after* is the ``(created_at, id)`` of the checkpoint entry (``None`` to start
    from the genesis). The keyset filter ``(created_at, id) > (cp_ts, cp_id)`` is
    expressed as the standard row-comparison so the recompute resumes exactly where
    the last verified-clean pass stopped (ADR-0038 §4) without re-walking history.
    """
    stmt = select(AuditLog).order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
    if after is not None:
        cp_ts, cp_id = after
        # (created_at, id) strictly greater than the checkpoint key — a portable
        # keyset predicate (no tuple-comparison reliance) valid on SQLite + PG.
        stmt = stmt.where(
            (AuditLog.created_at > cp_ts)
            | ((AuditLog.created_at == cp_ts) & (AuditLog.id > _as_uuid(cp_id)))
        )
    return list((await session.execute(stmt)).scalars().all())


def _as_uuid(value: str) -> object:
    """Parse a string id back to UUID for the keyset comparison (PG/SQLite safe)."""
    import uuid

    return uuid.UUID(value)


async def verify_chain(session: AsyncSession, *, advance_checkpoint: bool = False) -> VerifyResult:
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
    """
    checkpoint = await _load_checkpoint(session)

    if checkpoint is not None:
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
        anchor_recomputed = compute_entry_hash(anchor, anchor.prev_hash)
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
        after: tuple[datetime, str] | None = (
            checkpoint.entry_created_at,
            str(checkpoint.entry_id),
        )
    else:
        prev_hash = GENESIS_HASH
        after = None

    entries = await _entries_after(session, after)

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
        recomputed = compute_entry_hash(entry, entry.prev_hash)
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
    elif checkpoint is not None:
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
