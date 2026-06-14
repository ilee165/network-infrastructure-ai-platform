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

import secrets
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Final, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    get_app_settings,
    get_current_user,
    get_db,
    require_role,
)
from app.core.config import Settings
from app.core.errors import (
    AuthError,
    BadRequestError,
    ConflictError,
    NotFoundError,
)
from app.core.security import (
    Role as RoleEnum,
)
from app.core.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from app.models import Role, User
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


# ---------------------------------------------------------------------------
# Admin user management (Auth & Account UI, B4): admin-only CRUD over accounts.
# Every route here is gated by ``require_role("admin")``. No endpoint ever puts
# a password hash in a response body or an audit detail, and the temp password
# generated/accepted for create + reset is returned EXACTLY once (in the create
# and reset responses) — never logged and never written to an audit ``detail``.
# ---------------------------------------------------------------------------

#: Length (chars) of a generated temp password. ``secrets.token_urlsafe(16)``
#: yields ~22 URL-safe characters, comfortably above the >=16 requirement and
#: well under bcrypt's 72-byte input limit.
_TEMP_PASSWORD_BYTES: Final = 16

#: A username already taken by another account.
_USERNAME_TAKEN: Final = "That username is already in use"

#: Refusing to remove the platform's last reachable admin (lockout prevention).
_LAST_ADMIN: Final = "Cannot remove the last active admin"


def _generate_temp_password() -> str:
    """Return a fresh, unguessable temp password (URL-safe, >=16 chars).

    Uses :mod:`secrets` so the value is cryptographically random. The plaintext
    is returned to the admin once via the response and is never logged, audited,
    or persisted — only its bcrypt hash is stored.
    """
    return secrets.token_urlsafe(_TEMP_PASSWORD_BYTES)


class CreateUserRequest(BaseModel):
    """Body for ``POST /users`` — admin creates an account with a temp password."""

    username: str = Field(min_length=1, max_length=255)
    role: str = Field(min_length=1, max_length=64)
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    temp_password: str | None = Field(default=None, min_length=1, max_length=255)


class UpdateUserRequest(BaseModel):
    """Body for ``PATCH /users/{id}`` — every field optional (partial update)."""

    role: str | None = Field(default=None, min_length=1, max_length=64)
    is_active: bool | None = None
    email: str | None = Field(default=None, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)


class ResetPasswordRequest(BaseModel):
    """Body for ``POST /users/{id}/reset-password`` — optional explicit secret."""

    temp_password: str | None = Field(default=None, min_length=1, max_length=255)


class UserSummary(BaseModel):
    """An admin-visible account projection — never carries ``password_hash``."""

    id: uuid.UUID
    username: str
    email: str | None
    display_name: str | None
    role: str
    is_active: bool
    must_change_password: bool

    @classmethod
    def from_user(cls, user: User) -> UserSummary:
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


class CreatedUserResponse(BaseModel):
    """``POST /users`` result: the created account plus the one-time temp password.

    This is the ONLY endpoint (alongside reset-password) that ever returns a
    plaintext password, and it does so exactly once — the value is not persisted
    or audited in plaintext.
    """

    user: UserSummary
    temp_password: str


class TempPasswordResponse(BaseModel):
    """``POST /users/{id}/reset-password`` result: the one-time temp password."""

    temp_password: str


async def _resolve_role(session: AsyncSession, name: str) -> Role:
    """Resolve a wire role *name* to its :class:`Role` row or raise 400.

    Validates the name against the canonical :class:`RoleEnum` first (so an
    unknown role is a clean :class:`BadRequestError`, not a 500), then loads the
    seeded row. A known-but-unseeded role is also a 400 rather than a crash.
    """
    if RoleEnum.from_name(name) is None:
        raise BadRequestError(f"Unknown role {name!r}")
    row = (await session.execute(select(Role).where(Role.name == name))).scalar_one_or_none()
    if row is None:
        raise BadRequestError(f"Unknown role {name!r}")
    return row


async def _count_other_active_admins(session: AsyncSession, *, exclude_id: uuid.UUID) -> int:
    """Count active users with the ``admin`` role other than *exclude_id*.

    Used by the last-admin guard: a demotion/deactivation of the target is only
    safe when at least one *other* active admin remains.
    """
    count = (
        await session.execute(
            select(func.count())
            .select_from(User)
            .join(Role, User.role_id == Role.id)
            .where(
                Role.name == RoleEnum.ADMIN.value,
                User.is_active.is_(True),
                User.id != exclude_id,
            )
        )
    ).scalar_one()
    return int(count)


async def _load_user(session: AsyncSession, user_id: uuid.UUID) -> User:
    """Load a :class:`User` by id or raise 404 (no oracle beyond existence)."""
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None:
        raise NotFoundError("User not found")
    return user


@router.get("/users", response_model=list[UserSummary])
async def list_users(
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> list[UserSummary]:
    """List every account (admin only); never includes password hashes."""
    rows = (await session.execute(select(User).order_by(User.username))).scalars().all()
    return [UserSummary.from_user(row) for row in rows]


@router.post("/users", response_model=CreatedUserResponse, status_code=201)
async def create_user(
    body: CreateUserRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> CreatedUserResponse:
    """Create an account with a temp password (admin only).

    The role name must be one of the four RBAC roles (else 400). A duplicate
    username or email is 409. When ``temp_password`` is omitted a strong random
    one is generated. The new account is forced to change its password on first
    login (``must_change_password=True``); only the bcrypt hash is stored. The
    plaintext temp password is returned exactly once and never audited.
    """
    role = await _resolve_role(session, body.role)

    clash_username = (
        await session.execute(select(User.id).where(User.username == body.username))
    ).scalar_one_or_none()
    if clash_username is not None:
        raise ConflictError(_USERNAME_TAKEN)
    if body.email is not None:
        clash_email = (
            await session.execute(select(User.id).where(User.email == body.email))
        ).scalar_one_or_none()
        if clash_email is not None:
            raise ConflictError(_EMAIL_TAKEN)

    temp_password = body.temp_password or _generate_temp_password()
    user = User(
        username=body.username,
        password_hash=hash_password(temp_password),
        role=role,
        email=body.email,
        display_name=body.display_name,
        must_change_password=True,
    )
    session.add(user)
    await session.flush()

    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.USER_CREATED,
        target_type="user",
        target_id=str(user.id),
        detail={"username": user.username, "role": role.name},
    )
    await session.commit()
    await session.refresh(user)
    return CreatedUserResponse(user=UserSummary.from_user(user), temp_password=temp_password)


@router.get("/users/{user_id}", response_model=UserSummary)
async def get_user(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> UserSummary:
    """Return one account by id (admin only); 404 if unknown."""
    user = await _load_user(session, user_id)
    return UserSummary.from_user(user)


@router.patch("/users/{user_id}", response_model=UserSummary)
async def update_user(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> UserSummary:
    """Update an account's role / active flag / email / display name (admin only).

    Audits ``user.role_changed`` when the role changes, else ``user.updated``.
    Deactivating a user (``is_active`` to ``False``) revokes all that user's live
    sessions. The last-admin guard returns 409 if demoting-from-admin or
    deactivating the target would leave zero other active admins.
    """
    user = await _load_user(session, user_id)

    role_changed = False
    if body.role is not None and body.role != user.role.name:
        new_role = await _resolve_role(session, body.role)
        # Last-admin guard: demoting the final active admin would lock everyone out.
        if (
            user.role.name == RoleEnum.ADMIN.value
            and new_role.name != RoleEnum.ADMIN.value
            and user.is_active
            and await _count_other_active_admins(session, exclude_id=user.id) == 0
        ):
            raise ConflictError(_LAST_ADMIN)
        user.role = new_role
        role_changed = True

    deactivating = body.is_active is False and user.is_active
    if body.is_active is not None and body.is_active != user.is_active:
        # Last-admin guard: deactivating the final active admin locks everyone out.
        if (
            deactivating
            and user.role.name == RoleEnum.ADMIN.value
            and await _count_other_active_admins(session, exclude_id=user.id) == 0
        ):
            raise ConflictError(_LAST_ADMIN)
        user.is_active = body.is_active

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

    if deactivating:
        await session_service.revoke_all_for_user(session, user_id=user.id)

    action = audit_service.USER_ROLE_CHANGED if role_changed else audit_service.USER_UPDATED
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=action,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    await session.refresh(user)
    return UserSummary.from_user(user)


@router.post("/users/{user_id}/reset-password", response_model=TempPasswordResponse)
async def reset_user_password(
    user_id: uuid.UUID,
    body: ResetPasswordRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> TempPasswordResponse:
    """Set a forced-change temp password for an account (admin only).

    Generates a strong random temp password when one is not supplied, stores its
    bcrypt hash, sets ``must_change_password``, and revokes every live session of
    the target. Audits ``user.password_reset`` (never with the plaintext). The
    plaintext is returned exactly once.
    """
    user = await _load_user(session, user_id)
    temp_password = body.temp_password or _generate_temp_password()
    user.password_hash = hash_password(temp_password)
    user.must_change_password = True

    await session_service.revoke_all_for_user(session, user_id=user.id)
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.USER_PASSWORD_RESET,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return TempPasswordResponse(temp_password=temp_password)


@router.post("/users/{user_id}/revoke-sessions", status_code=200)
async def revoke_user_sessions(
    user_id: uuid.UUID,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, int]:
    """Revoke every live session of an account (admin only); audit the revoke."""
    user = await _load_user(session, user_id)
    count = await session_service.revoke_all_for_user(session, user_id=user.id)
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.AUTH_SESSION_REVOKED,
        target_type="user",
        target_id=str(user.id),
        detail=None,
    )
    await session.commit()
    return {"revoked": count}
