"""Master-key (KEK) rotation as a DEK re-wrap pass (ADR-0032 §3/§5, ADR-0011 §1).

Rotation rotates the *wrapper*, never the secrets: the platform bumps the active
KEK version (a manual bump or a KMS auto-rotation hook), then this pass re-wraps
each credential's DEK under the new KEK while leaving the AES-256-GCM payload
``ciphertext``/``nonce`` byte-for-byte untouched (the ADR-0011 §1 "cheap re-wrap"
promise). Because no payload is re-encrypted, a full-corpus re-wrap is cheap and
online — the rehearsed procedure for a suspected KEK compromise (ADR-0032 §3).

The pass is **idempotent, resumable, and online** (ADR-0032 §3):

- The worklist predicate is ``kek_version != active``. A crash mid-pass simply
  leaves the un-migrated rows for the next run; re-running on a fully-migrated
  corpus updates **zero** rows.
- Each row migrates with a **compare-and-set** ``UPDATE … WHERE id=:id AND
  kek_version=:old`` so a per-credential ``rotate_secret`` racing the pass is
  never clobbered (the row already moved off ``:old``, the CAS matches nothing).
- Mixed ``kek_version`` rows decrypt correctly throughout: :func:`decrypt` reads
  ``row.kek_version`` and unwraps under that specific version, so credentials keep
  serving during the migration — no maintenance window, no big-bang re-encrypt.

Audit (ADR-0032 §5): the pass brackets its work with ``kek.rotate.start``
(before=``{from_version, row_count}``) and ``kek.rotate.complete``
(after=``{to_version, rows_migrated}``) into the append-only ``audit_log`` —
identifiers/versions/counts only, never DEK/KEK/wrapped bytes (ADR-0032 §6).

Secure by default: this module never reads or writes the payload columns, never
places key material in an audit row, log line, or exception, and re-uses the
typed-error / fail-closed posture of :mod:`app.core.crypto`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import CursorResult, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.crypto import EncryptedSecret, KeyProvider, KeyProviderUnavailable, rewrap
from app.models.inventory import DeviceCredential
from app.services import audit

_TARGET_TYPE = "credential"

#: Audit ``target_type`` for the provider-level (non-row) KEK rotation events.
_PROVIDER_TARGET_TYPE = "key_provider"

#: Default streaming batch size for the re-wrap worklist (ADR-0032 §3 batches).
DEFAULT_BATCH_SIZE = 100


@dataclass(frozen=True, slots=True)
class RotationStatus:
    """Versions/counts-only view of the credential corpus's KEK migration state.

    Carries **no** wrapped/blob bytes (ADR-0032 §6): ``from_version`` is the
    oldest KEK version still referenced by an un-migrated row (``None`` when the
    corpus is fully migrated), ``to_version`` is the provider's active KEK, and
    ``rows_pending`` is the count of rows still wrapped under a non-active KEK.
    """

    from_version: str | None
    to_version: str
    rows_pending: int


@dataclass(frozen=True, slots=True)
class ReWrapResult:
    """Outcome of one :func:`re_wrap_keys` pass — versions/counts only.

    ``rows_migrated`` counts rows whose compare-and-set actually fired; a row that
    a concurrent ``rotate_secret`` moved off the old version first is **not**
    counted (its CAS matched nothing — the freshly-rotated secret is preserved).
    """

    from_version: str | None
    to_version: str
    row_count: int
    rows_migrated: int


def _aad(credential_id: uuid.UUID) -> bytes:
    """Row-binding associated data: the credential id as UTF-8 (ADR-0011)."""
    return str(credential_id).encode()


async def get_rotation_status(session: AsyncSession, provider: KeyProvider) -> RotationStatus:
    """Report the corpus's KEK migration state — versions/counts only (ADR-0032 §6).

    Reads aggregate counts/versions over ``device_credentials`` only; it never
    selects, returns, or logs a wrapped-DEK / payload blob.
    """
    active = provider.kek_version
    rows_pending = (
        await session.execute(
            select(func.count())
            .select_from(DeviceCredential)
            .where(DeviceCredential.kek_version != active)
        )
    ).scalar_one()
    from_version = (
        await session.execute(
            select(func.min(DeviceCredential.kek_version)).where(
                DeviceCredential.kek_version != active
            )
        )
    ).scalar_one()
    return RotationStatus(from_version=from_version, to_version=active, rows_pending=rows_pending)


async def _audit_rotation_event(
    sessionmaker: async_sessionmaker[AsyncSession] | None,
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    detail: dict[str, object],
) -> None:
    """Write a ``kek.rotate.*`` audit row, durably when a *sessionmaker* is given.

    The bracketing rotation events must survive a crash mid-pass (the row-by-row
    work commits per batch), so production callers pass an autonomous
    *sessionmaker*: the event is written and committed on its own short-lived
    session. Unit tests asserting on the same session omit it and flush on the
    caller's session. ``detail`` carries ids/versions/counts only (ADR-0032 §6).
    """
    if sessionmaker is not None:
        async with sessionmaker() as audit_session:
            await audit.record(
                audit_session,
                actor=actor,
                action=action,
                target_type=_PROVIDER_TARGET_TYPE,
                target_id=None,
                detail=detail,
            )
            await audit_session.commit()
        return
    await audit.record(
        session,
        actor=actor,
        action=action,
        target_type=_PROVIDER_TARGET_TYPE,
        target_id=None,
        detail=detail,
    )


async def _load_batch(
    session: AsyncSession, active: str, batch_size: int
) -> list[DeviceCredential]:
    """Load up to *batch_size* un-migrated credentials (``kek_version != active``).

    Ordered by id for a stable, resumable worklist. Returns full ORM rows so the
    re-wrap can read the wrap-layer columns; the payload columns are read only to
    reconstruct the :class:`EncryptedSecret` and are never mutated.
    """
    rows = (
        (
            await session.execute(
                select(DeviceCredential)
                .where(DeviceCredential.kek_version != active)
                .order_by(DeviceCredential.id)
                .limit(batch_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def _rewrap_row(
    session: AsyncSession,
    provider: KeyProvider,
    credential: DeviceCredential,
) -> bool:
    """Compare-and-set re-wrap one credential's DEK under the active KEK.

    Unwraps under the row's recorded (old) version, re-wraps under the active KEK,
    then issues ``UPDATE … SET wrapped_dek, dek_nonce, kek_version WHERE id=:id AND
    kek_version=:old``. The payload ``ciphertext``/``nonce`` are never read for the
    update nor written. Returns ``True`` iff the CAS affected the row (it had not
    already been moved off ``:old`` by a concurrent rotation).
    """
    old_version = credential.kek_version
    envelope = EncryptedSecret(
        ciphertext=credential.ciphertext,
        nonce=credential.nonce,
        wrapped_dek=credential.wrapped_dek,
        dek_nonce=credential.dek_nonce,
        kek_version=old_version,
    )
    # ``rewrap`` unwraps the DEK under ``old_version``, re-wraps under the active
    # KEK, and zeroizes the transient DEK; the payload is returned untouched.
    rewrapped = rewrap(envelope, _aad(credential.id), provider)
    # ``execute`` is typed as returning ``Result``; an UPDATE yields a
    # ``CursorResult`` whose ``rowcount`` reports how many rows the compare-and-set
    # matched (0 if a concurrent rotation already moved the row off ``old_version``).
    result = await session.execute(
        update(DeviceCredential)
        .where(
            DeviceCredential.id == credential.id,
            DeviceCredential.kek_version == old_version,
        )
        .values(
            wrapped_dek=rewrapped.wrapped_dek,
            dek_nonce=rewrapped.dek_nonce,
            kek_version=rewrapped.kek_version,
        )
    )
    rowcount: int = cast("CursorResult[Any]", result).rowcount
    return rowcount == 1


async def re_wrap_keys(
    session: AsyncSession,
    provider: KeyProvider,
    *,
    actor: str,
    batch_size: int = DEFAULT_BATCH_SIZE,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> ReWrapResult:
    """Re-wrap every un-migrated DEK under the active KEK (ADR-0032 §3 re-wrap pass).

    Streams ``device_credentials WHERE kek_version != active`` in batches and
    re-wraps each row with a compare-and-set (see :func:`_rewrap_row`); the payload
    ``ciphertext``/``nonce`` are never touched. Brackets the work with
    ``kek.rotate.start`` / ``kek.rotate.complete`` audit events (versions/counts
    only). Idempotent + resumable: a re-run picks up whatever the predicate still
    matches, and a fully-migrated corpus migrates zero rows.

    The caller owns the transaction boundary for the row-by-row work; production
    callers pass an autonomous *sessionmaker* so the bracketing audit events and
    each migrated batch commit durably (the work survives a crash mid-pass).

    Raises:
        KeyProviderUnavailable: If the provider becomes unreachable mid-pass —
            re-raised; already-migrated rows stay migrated (the predicate makes
            the next run resume). The exception carries a coarse reason class only.
    """
    active = provider.kek_version
    status = await get_rotation_status(session, provider)
    from_version = status.from_version
    row_count = status.rows_pending

    await _audit_rotation_event(
        sessionmaker,
        session,
        actor=actor,
        action=audit.KEK_ROTATE_START,
        detail={"from_version": from_version, "row_count": row_count},
    )

    rows_migrated = 0
    while True:
        batch = await _load_batch(session, active, batch_size)
        if not batch:
            break
        for credential in batch:
            try:
                migrated = await _rewrap_row(session, provider, credential)
            except KeyProviderUnavailable:
                # Fail closed: persist whatever migrated so far so the next run
                # resumes (the predicate excludes the already-migrated rows).
                if sessionmaker is not None:
                    await session.commit()
                raise
            if migrated:
                rows_migrated += 1
        if sessionmaker is not None:
            # Commit each batch so progress is durable and resumable mid-pass.
            await session.commit()

    await _audit_rotation_event(
        sessionmaker,
        session,
        actor=actor,
        action=audit.KEK_ROTATE_COMPLETE,
        detail={"to_version": active, "rows_migrated": rows_migrated},
    )

    return ReWrapResult(
        from_version=from_version,
        to_version=active,
        row_count=row_count,
        rows_migrated=rows_migrated,
    )
