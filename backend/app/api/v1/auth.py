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
rotated-out, logged-out, or admin-revoked refresh token is rejected immediately
on its next use rather than staying verifiable until its natural 8 h expiry.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated, Final, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH, get_app_settings, get_db
from app.core.config import Settings
from app.core.errors import AuthError
from app.core.security import create_access_token, decode_access_token, verify_password
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
