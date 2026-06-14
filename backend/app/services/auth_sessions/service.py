"""Server-side refresh-session service (Auth & Account UI, B2).

A :class:`~app.models.identity.RefreshSession` row is the durable, revocable
record behind every refresh JWT: the token carries the row's ``id`` as its
``sid`` claim, and ``refresh`` only rotates while that row is live
(``revoked_at IS NULL``) and the user is active. Logout / admin revoke flips
``revoked_at`` instead of deleting, so the login/logout trail survives.

Every function operates on the *caller's* :class:`AsyncSession` and is
flush-only: it assigns ids and makes rows queryable within the transaction but
never commits — the route that owns the request transaction commits (or rolls
back) the session change atomically with its audit row.

No credential material is read or written here: the rows carry only the user
FK plus best-effort request metadata (``user_agent`` / ``ip``).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.identity import RefreshSession, User
from app.models.mixins import utcnow


async def create_session(
    session: AsyncSession,
    *,
    user: User,
    user_agent: str | None,
    ip: str | None,
) -> RefreshSession:
    """Open and flush a new live refresh session for *user*.

    Returns the persisted row (``id`` assigned by the flush) so the caller can
    embed ``row.id`` as the refresh JWT's ``sid`` claim.
    """
    row = RefreshSession(user_id=user.id, user_agent=user_agent, ip=ip)
    session.add(row)
    await session.flush()
    return row


async def get_live_session(
    session: AsyncSession,
    *,
    sid: uuid.UUID,
    user_id: uuid.UUID,
) -> RefreshSession | None:
    """Return the live session for *sid* belonging to *user_id*, else ``None``.

    ``None`` is returned uniformly when the session is missing, already revoked,
    or owned by a different user — callers must not distinguish these cases
    (no oracle), they are all simply "not a session this token may rotate".
    """
    row = (
        await session.execute(
            select(RefreshSession).where(
                RefreshSession.id == sid,
                RefreshSession.user_id == user_id,
                RefreshSession.revoked_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    return row


async def touch(session: AsyncSession, refresh_session: RefreshSession) -> None:
    """Mark *refresh_session* as just used (``last_used_at = now``); flush only."""
    refresh_session.last_used_at = utcnow()
    await session.flush()


async def revoke(session: AsyncSession, *, sid: uuid.UUID) -> bool:
    """Revoke the session *sid* if it exists and is live.

    Returns ``True`` when this call performed the revocation, ``False`` if the
    session is unknown or was already revoked (idempotent — the original
    ``revoked_at`` is preserved). Flush only.
    """
    row = (
        await session.execute(select(RefreshSession).where(RefreshSession.id == sid))
    ).scalar_one_or_none()
    if row is None or row.revoked_at is not None:
        return False
    row.revoked_at = utcnow()
    await session.flush()
    return True


async def revoke_all_for_user(session: AsyncSession, *, user_id: uuid.UUID) -> int:
    """Revoke every live session owned by *user_id*; return the count revoked.

    Already-revoked sessions keep their original ``revoked_at`` and are not
    counted. Flush only — the caller commits.
    """
    rows = (
        (
            await session.execute(
                select(RefreshSession).where(
                    RefreshSession.user_id == user_id,
                    RefreshSession.revoked_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    now = utcnow()
    for row in rows:
        row.revoked_at = now
    if rows:
        await session.flush()
    return len(rows)
