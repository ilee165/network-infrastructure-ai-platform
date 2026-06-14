"""Authentication routes (D10, ADR-0010): session-aware login / refresh / logout.

- ``POST /auth/login``   — username/password in, ``{access_token, token_type}``
  out (access JWT carries a ``roles`` claim), plus an ``HttpOnly; Secure;
  SameSite=strict`` refresh cookie (separate JWT, ``type=refresh``, 8 h). A
  server-side :class:`~app.models.identity.RefreshSession` row is created and
  its id is embedded in the refresh JWT as the ``sid`` claim.
- ``POST /auth/refresh`` — validates the refresh cookie AND that its ``sid``
  names a live session for an active user, then rotates in place: a new access
  token in the body and a new refresh cookie that keeps the same ``sid`` with a
  fresh ``jti``. 401 on a missing/invalid cookie, a revoked/unknown session, or
  an inactive/deleted user.
- ``POST /auth/logout`` — revokes the cookie's session and clears the refresh
  cookie. Idempotent: a missing/garbage cookie still returns 200.

Endpoints write audit rows via the audit service (``auth.login`` on success,
``auth.login_failed`` on every failed attempt, ``auth.refresh``, and
``auth.logout`` only when a session was actually revoked). Failures never set a
refresh cookie.

Server-side session model (Auth & Account UI): refresh JWTs are **stateful**.
Each carries a ``sid`` claim naming a ``refresh_sessions`` row; ``refresh`` only
rotates while that row is live (``revoked_at IS NULL``) and the user is active.
Logout / admin revoke flips ``revoked_at`` — the row is never deleted — so a
logged-out, admin-revoked, or deactivated session's refresh token is rejected
on its next use rather than staying verifiable until its natural 8 h expiry.

Revocation is per-session (``sid``), not per-token (``jti``): rotation reuses
the same ``sid`` with a fresh ``jti`` and the ``jti`` is never persisted or
compared. A rotated-out (superseded) refresh token therefore still names the
same live ``sid`` and remains valid — replayable — until that session is logged
out / revoked or the token reaches its 8 h expiry. Rotation does not, by itself,
invalidate the previous refresh token.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Final, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    get_app_settings,
    get_current_user,
    get_db,
)
from app.core.config import Settings
from app.core.errors import AuthError, BadRequestError, ConflictError, NotFoundError
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.models import User
from app.services.audit import service as audit_service
from app.services.auth_sessions import service as session_service

router = APIRouter(prefix="/auth", tags=["auth"])

#: Refresh-token lifetime (ADR-0010: 8 hours, rotated on use).
REFRESH_TOKEN_LIFETIME: Final = timedelta(hours=8)

REFRESH_COOKIE_NAME: Final = "netops_refresh"

#: Cookie scope: the auth router under the canonical ``/api/v1`` mount
#: (``app.main.API_V1_PREFIX`` — not imported here to avoid a cycle), so the
#: refresh JWT is only ever transmitted to ``/auth/*`` endpoints.
REFRESH_COOKIE_PATH: Final = "/api/v1/auth"

#: One generic detail for every login failure — usernames are not enumerable.
_BAD_CREDENTIALS: Final = "Invalid username or password"

#: bcrypt hash of an unguessable random value (matches no real credential).
#: Verified against when the username is unknown so the response time matches
#: the wrong-password path (no timing oracle for username enumeration).
_DUMMY_PASSWORD_HASH: Final = "$2b$12$8fN.6WnGqPWQFSZUhWJ4F.9L11oer6MlHBukev2yj9anUc5laj06y"


class LoginRequest(BaseModel):
    """Credentials for ``POST /auth/login``."""

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)


class TokenResponse(BaseModel):
    """A freshly minted Bearer access token."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"


def _issue_tokens(user: User, sid: uuid.UUID, settings: Settings, response: Response) -> str:
    """Mint the access token, set a refresh cookie for session *sid*, return the access JWT.

    The refresh JWT carries the server-side session id as its ``sid`` claim plus
    a fresh ``jti`` per issuance; rotation reuses the same ``sid`` so the live
    session survives a refresh, while the changing ``jti`` keeps every emitted
    token distinct. The access token is unchanged (``type=access`` + ``roles``).
    """
    access_token = create_access_token(
        str(user.id),
        settings,
        extra_claims={"type": TOKEN_TYPE_ACCESS, "roles": [user.role.name]},
    )
    refresh_token = create_access_token(
        str(user.id),
        settings,
        expires_delta=REFRESH_TOKEN_LIFETIME,
        # sid binds the token to a revocable server-side session; jti makes every
        # issuance unique within that session.
        extra_claims={
            "type": TOKEN_TYPE_REFRESH,
            "sid": str(sid),
            "jti": str(uuid.uuid4()),
        },
    )
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=int(REFRESH_TOKEN_LIFETIME.total_seconds()),
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    return access_token


async def _audit_login_failed(session: AsyncSession, username: str) -> None:
    """Audit a failed login without revealing whether *username* exists.

    ``actor`` is the attempted username (so an operator can correlate the
    attempt), but neither the target nor ``detail`` discloses whether the user
    is real, inactive, or simply had a wrong password — one generic record for
    every failure mode. Committed by the caller after raising is avoided; this
    helper flushes and the caller commits the failure audit before raising.
    """
    await audit_service.record(
        session,
        actor=f"user:{username}",
        action=audit_service.AUTH_LOGIN_FAILED,
        target_type="user",
        target_id=None,
        detail=None,
    )
    await session.commit()


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> TokenResponse:
    """Authenticate with username/password; issue access token + refresh cookie.

    On success a server-side :class:`RefreshSession` is created and its id is
    embedded in the refresh JWT. Every failure mode (unknown user, bad password,
    inactive account) raises one generic :class:`AuthError`, keeps the
    constant-time verification path, and writes an ``auth.login_failed`` audit
    row that does not reveal which mode occurred.
    """
    user = (
        await session.execute(select(User).where(User.username == body.username))
    ).scalar_one_or_none()
    if user is None:
        verify_password(body.password, _DUMMY_PASSWORD_HASH)  # timing equalizer
        await _audit_login_failed(session, body.username)
        raise AuthError(_BAD_CREDENTIALS)
    if not verify_password(body.password, user.password_hash) or not user.is_active:
        await _audit_login_failed(session, body.username)
        raise AuthError(_BAD_CREDENTIALS)

    refresh_session = await session_service.create_session(
        session,
        user=user,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    access_token = _issue_tokens(user, refresh_session.id, settings, response)
    await audit_service.record(
        session,
        actor=f"user:{user.username}",
        action=audit_service.AUTH_LOGIN,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return TokenResponse(access_token=access_token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> TokenResponse:
    """Rotate: validate the cookie + live session, issue a new access token + cookie.

    The refresh cookie's ``sid`` must name a live session (``revoked_at IS
    NULL``) owned by an active user; otherwise a generic 401 is returned (no
    oracle for whether the session was revoked vs. the user deactivated).
    Rotation reuses the same ``sid`` with a fresh ``jti`` and advances the
    session's ``last_used_at``.
    """
    cookie = request.cookies.get(REFRESH_COOKIE_NAME)
    if cookie is None:
        raise AuthError("Missing refresh token")
    claims = decode_access_token(cookie, settings)
    if claims.get("type") != TOKEN_TYPE_REFRESH:
        raise AuthError("Invalid refresh token")
    try:
        user_id = uuid.UUID(str(claims["sub"]))
        sid = uuid.UUID(str(claims["sid"]))
    except (KeyError, ValueError) as exc:
        raise AuthError("Invalid refresh token") from exc
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthError("Invalid refresh token")
    refresh_session = await session_service.get_live_session(session, sid=sid, user_id=user_id)
    if refresh_session is None:
        raise AuthError("Invalid refresh token")

    await session_service.touch(session, refresh_session)
    access_token = _issue_tokens(user, refresh_session.id, settings, response)
    await audit_service.record(
        session,
        actor=f"user:{user.username}",
        action=audit_service.AUTH_REFRESH,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return TokenResponse(access_token=access_token)


def _clear_refresh_cookie(response: Response) -> None:
    """Delete the refresh cookie using the exact same name + path it was set with."""
    response.delete_cookie(REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)


@router.post("/logout", status_code=200)
async def logout(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> dict[str, bool]:
    """Revoke the cookie's session and clear the refresh cookie.

    Idempotent: a missing, malformed, or already-revoked cookie still returns
    200 with the cookie cleared. ``auth.logout`` is audited only when this call
    actually revoked a live session.
    """
    _clear_refresh_cookie(response)
    cookie = request.cookies.get(REFRESH_COOKIE_NAME)
    if cookie is None:
        return {"revoked": False}
    try:
        claims = decode_access_token(cookie, settings)
    except AuthError:
        return {"revoked": False}
    if claims.get("type") != TOKEN_TYPE_REFRESH or "sid" not in claims:
        return {"revoked": False}
    try:
        sid = uuid.UUID(str(claims["sid"]))
    except ValueError:
        return {"revoked": False}

    revoked = await session_service.revoke(session, sid=sid)
    if not revoked:
        return {"revoked": False}

    # Resolve the actor for the audit trail from the now-revoked session's user.
    user_id: uuid.UUID | None
    try:
        user_id = uuid.UUID(str(claims["sub"]))
    except (KeyError, ValueError):
        user_id = None
    actor = "user:unknown"
    if user_id is not None:
        user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
        if user is not None:
            actor = f"user:{user.username}"
    await audit_service.record(
        session,
        actor=actor,
        action=audit_service.AUTH_LOGOUT,
        target_type="refresh_session",
        target_id=str(sid),
        detail=None,
    )
    await session.commit()
    return {"revoked": True}


# ---------------------------------------------------------------------------
# Account / profile (Auth & Account UI, B3): self-service ``/me`` + sessions.
# ---------------------------------------------------------------------------

#: Generic 400 for a wrong current password — no oracle for what was wrong.
_BAD_CURRENT_PASSWORD: Final = "Current password is incorrect"

#: An email already used by a different account.
_EMAIL_TAKEN: Final = "That email is already in use"


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
    if not verify_password(body.current_password, user.password_hash):
        raise BadRequestError(_BAD_CURRENT_PASSWORD)

    user.password_hash = hash_password(body.new_password)
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
