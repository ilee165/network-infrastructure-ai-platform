"""Account / profile (Auth & Account UI, B3): self-service ``/me`` + sessions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Final

from fastapi import Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TOKEN_TYPE_REFRESH,
    get_app_settings,
    get_current_user,
    get_db,
)
from app.api.v1.auth._shared import _EMAIL_TAKEN, REFRESH_COOKIE_NAME, router
from app.core.config import Settings
from app.core.errors import AuthError, BadRequestError, ConflictError, NotFoundError
from app.core.security import decode_access_token, hash_password_async, verify_password_async
from app.models import User
from app.services.audit import service as audit_service
from app.services.auth_sessions import service as session_service

#: Generic 400 for a wrong current password — no oracle for what was wrong.
_BAD_CURRENT_PASSWORD: Final = "Current password is incorrect"


class UserMe(BaseModel):
    """The current user's own profile — never carries ``password_hash``.

    ``role`` is flattened to the role *name* (the wire value) so the client
    never sees internal role ids; no credential material is included.
    """

    id: uuid.UUID
    username: str
    email: str | None
    display_name: str | None
    role: str
    is_active: bool
    must_change_password: bool

    @classmethod
    def from_user(cls, user: User) -> UserMe:
        """Project a :class:`User` ORM row, dropping every secret field."""
        return cls(
            id=user.id,
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            role=user.role.name,
            is_active=user.is_active,
            must_change_password=user.must_change_password,
        )


class UpdateMeRequest(BaseModel):
    """Editable profile fields for ``PATCH /me`` (both optional)."""

    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)


class ChangePasswordRequest(BaseModel):
    """Body for ``POST /me/password`` — current proof + new secret (min 8)."""

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=8, max_length=255)


class SessionInfo(BaseModel):
    """One row of the caller's "your sessions" view (no credential material)."""

    sid: uuid.UUID
    created_at: datetime
    last_used_at: datetime
    user_agent: str | None
    ip: str | None
    revoked_at: datetime | None
    is_current: bool


def _current_sid(request: Request, settings: Settings) -> uuid.UUID | None:
    """Best-effort ``sid`` of the caller's refresh cookie, or ``None``.

    The access token (Bearer) carries no ``sid``; the refresh cookie does, but
    it is only sent to ``/api/v1/auth/*`` — which is exactly this router — so
    "which session am I on" is resolvable here. Any decode/shape failure yields
    ``None`` (the session simply is not flagged current); never raises.
    """
    cookie = request.cookies.get(REFRESH_COOKIE_NAME)
    if cookie is None:
        return None
    try:
        claims = decode_access_token(cookie, settings)
    except AuthError:
        return None
    if claims.get("type") != TOKEN_TYPE_REFRESH:
        return None
    try:
        return uuid.UUID(str(claims["sid"]))
    except (KeyError, ValueError):
        return None


@router.get("/me", response_model=UserMe)
async def read_me(user: Annotated[User, Depends(get_current_user)]) -> UserMe:
    """Return the authenticated user's own profile.

    Uses :func:`get_current_user` (not the forced-change guard) so a user owing
    a password change can still read their profile to orient themselves.
    """
    return UserMe.from_user(user)


@router.patch("/me", response_model=UserMe)
async def update_me(
    body: UpdateMeRequest,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> UserMe:
    """Update the caller's own ``email`` / ``display_name``; audit ``user.updated``.

    A request that sets ``email`` to a value already owned by *another* user is
    rejected with 409 (the unique constraint, surfaced before the flush).
    """
    if body.email is not None and body.email != user.email:
        clash = (
            await session.execute(
                select(User.id).where(User.email == body.email, User.id != user.id)
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise ConflictError(_EMAIL_TAKEN)
        user.email = body.email
    if body.display_name is not None:
        user.display_name = body.display_name

    await audit_service.record(
        session,
        actor=f"user:{user.username}",
        action=audit_service.USER_UPDATED,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    await session.refresh(user)
    return UserMe.from_user(user)


@router.post("/me/password", status_code=200)
async def change_my_password(
    body: ChangePasswordRequest,
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> dict[str, bool]:
    """Change the caller's own password.

    Verifies ``current_password`` (generic 400 on mismatch — no detail about
    what was wrong), stores a fresh bcrypt hash, clears
    ``must_change_password``, and revokes every *other* live session for the
    user while keeping the caller's current session live. Audits
    ``auth.password_changed``. Available to a flagged user (no forced-change
    guard) so the forced first-login change can actually be performed.
    """
    if not await verify_password_async(body.current_password, user.password_hash):
        raise BadRequestError(_BAD_CURRENT_PASSWORD)

    user.password_hash = await hash_password_async(body.new_password)
    user.must_change_password = False

    keep_sid = _current_sid(request, settings)
    await session_service.revoke_other_sessions_for_user(
        session, user_id=user.id, keep_sid=keep_sid
    )
    await audit_service.record(
        session,
        actor=f"user:{user.username}",
        action=audit_service.AUTH_PASSWORD_CHANGED,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return {"changed": True}


@router.get("/sessions", response_model=list[SessionInfo])
async def list_my_sessions(
    request: Request,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> list[SessionInfo]:
    """List the caller's own sessions; flag the one matching the refresh cookie."""
    current = _current_sid(request, settings)
    rows = await session_service.list_for_user(session, user_id=user.id)
    return [
        SessionInfo(
            sid=row.id,
            created_at=row.created_at,
            last_used_at=row.last_used_at,
            user_agent=row.user_agent,
            ip=row.ip,
            revoked_at=row.revoked_at,
            is_current=current is not None and row.id == current,
        )
        for row in rows
    ]


@router.delete("/sessions/{sid}", status_code=200)
async def revoke_my_session(
    sid: uuid.UUID,
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, bool]:
    """Revoke one of the caller's own sessions; 404 if the sid is not theirs.

    Ownership is enforced before revocation — a sid that exists but belongs to
    another user is indistinguishable from one that does not exist (both 404),
    so this endpoint never confirms the existence of another user's session.
    """
    owned = await session_service.get_owned_session(session, sid=sid, user_id=user.id)
    if owned is None:
        raise NotFoundError("Session not found")
    await session_service.revoke(session, sid=sid)
    await audit_service.record(
        session,
        actor=f"user:{user.username}",
        action=audit_service.AUTH_SESSION_REVOKED,
        target_type="refresh_session",
        target_id=str(sid),
        detail=None,
    )
    await session.commit()
    return {"revoked": True}


@router.post("/sessions/revoke-all", status_code=200)
async def revoke_all_my_sessions(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, int]:
    """Revoke every live session owned by the caller; audit ``auth.session_revoked``."""
    count = await session_service.revoke_all_for_user(session, user_id=user.id)
    await audit_service.record(
        session,
        actor=f"user:{user.username}",
        action=audit_service.AUTH_SESSION_REVOKED,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return {"revoked": count}
