"""Authentication routes (D10, ADR-0010): login and refresh-token rotation.

- ``POST /auth/login``   — username/password in, ``{access_token, token_type}``
  out (access JWT carries a ``roles`` claim), plus an ``HttpOnly; Secure;
  SameSite=strict`` refresh cookie (separate JWT, ``type=refresh``, 8 h).
- ``POST /auth/refresh`` — validates the refresh cookie and rotates: a new
  access token in the body and a new refresh cookie. 401 on a missing/invalid
  cookie or an inactive/deleted user.

Both endpoints write an audit row (``auth.login`` / ``auth.refresh``) via the
audit service; failures never set a cookie.

MVP decision (fixed): refresh JWTs are **stateless** — there is no
server-side revocation table, so a rotated-out or stolen refresh token stays
verifiable until its natural 8 h expiry. Production roadmap (ADR-0010
"revocable server-side"): persist the refresh ``jti`` per session and reject
any token whose ``jti`` is not the latest for that session.
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


def _issue_tokens(user: User, settings: Settings, response: Response) -> str:
    """Mint the access token, set a rotated refresh cookie, return the access JWT."""
    access_token = create_access_token(
        str(user.id),
        settings,
        extra_claims={"type": TOKEN_TYPE_ACCESS, "roles": [user.role.name]},
    )
    refresh_token = create_access_token(
        str(user.id),
        settings,
        expires_delta=REFRESH_TOKEN_LIFETIME,
        # jti makes every rotation unique and enables the future revocation table.
        extra_claims={"type": TOKEN_TYPE_REFRESH, "jti": str(uuid.uuid4())},
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


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> TokenResponse:
    """Authenticate with username/password; issue access token + refresh cookie."""
    user = (
        await session.execute(select(User).where(User.username == body.username))
    ).scalar_one_or_none()
    if user is None:
        verify_password(body.password, _DUMMY_PASSWORD_HASH)  # timing equalizer
        raise AuthError(_BAD_CREDENTIALS)
    if not verify_password(body.password, user.password_hash) or not user.is_active:
        raise AuthError(_BAD_CREDENTIALS)

    access_token = _issue_tokens(user, settings, response)
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
    """Rotate: validate the refresh cookie, issue a new access token + cookie."""
    cookie = request.cookies.get(REFRESH_COOKIE_NAME)
    if cookie is None:
        raise AuthError("Missing refresh token")
    claims = decode_access_token(cookie, settings)
    if claims.get("type") != TOKEN_TYPE_REFRESH:
        raise AuthError("Invalid refresh token")
    try:
        user_id = uuid.UUID(str(claims["sub"]))
    except ValueError as exc:
        raise AuthError("Invalid refresh token") from exc
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthError("Invalid refresh token")

    access_token = _issue_tokens(user, settings, response)
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
