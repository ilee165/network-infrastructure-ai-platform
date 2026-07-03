"""Local username/password login, refresh-token rotation, and logout (D10, ADR-0010).

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

Reuse detection (audit PRODUCTION_READINESS #5, migration 0015): every issuance
persists the SHA-256 of the new refresh token's ``jti`` on the session row
(``current_jti_hash`` — hash only, never token material). ``refresh`` compares
the presented ``jti`` hash against it: a mismatch means a rotated-out
(superseded) token was replayed — a theft signal — so the session is revoked,
``auth.refresh_reuse_detected`` is audited, and a generic 401 is returned.
"""

from __future__ import annotations

import secrets
import uuid
from typing import Annotated, Final

from fastapi import Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TOKEN_TYPE_REFRESH,
    get_app_settings,
    get_db,
    get_rate_limiter,
)
from app.api.v1.auth._shared import (
    REFRESH_COOKIE_NAME,
    REFRESH_COOKIE_PATH,
    TokenResponse,
    _hash_jti,
    _issue_tokens,
    _request_id,
    router,
)
from app.core.config import Settings
from app.core.errors import AuthError, RateLimitedError
from app.core.security import Role as RoleEnum
from app.core.security import decode_access_token, verify_password
from app.models import User
from app.services import rate_limit
from app.services.audit import service as audit_service
from app.services.auth_sessions import service as session_service
from app.services.rate_limit import RateLimiter

#: One generic detail for every login failure — usernames are not enumerable.
_BAD_CREDENTIALS: Final = "Invalid username or password"

#: Mirror of the deps-layer generic token detail (kept local to avoid a cycle).
_INVALID_TOKEN_DETAIL: Final = "Invalid authentication credentials"

#: bcrypt hash of an unguessable random value (matches no real credential).
#: Verified against when the username is unknown so the response time matches
#: the wrong-password path (no timing oracle for username enumeration).
_DUMMY_PASSWORD_HASH: Final = "$2b$12$8fN.6WnGqPWQFSZUhWJ4F.9L11oer6MlHBukev2yj9anUc5laj06y"


class LoginRequest(BaseModel):
    """Credentials for ``POST /auth/login``."""

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)


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


# One generic detail for a throttled/locked login — coarse, and revealing
# nothing about whether the account exists or how many attempts remain (no
# oracle), mirroring ``_BAD_CREDENTIALS``.
_LOGIN_THROTTLED: Final = "Too many login attempts; try again later"


async def _audit_login_locked(
    session: AsyncSession,
    *,
    username: str,
    source: str | None,
    request_id: uuid.UUID | None,
) -> None:
    """Audit ``auth.login_locked`` — attempted username + source only, never secrets.

    The lockout is temporary and alerting-friendly (break-glass already alerts,
    ADR-0028 §84); the audit row carries the attempted ``actor`` and source so an
    operator can correlate a brute-force attempt without learning a password or
    whether the account is real.
    """
    await audit_service.record(
        session,
        actor=f"user:{username}",
        action=audit_service.AUTH_LOGIN_LOCKED,
        target_type="user",
        target_id=None,
        detail={"source": source, "outcome": "locked"},
        request_id=request_id,
    )
    await session.commit()


async def _enforce_login_not_locked(
    limiter: RateLimiter,
    settings: Settings,
    *,
    username: str,
    source: str | None,
    session: AsyncSession,
    request_id: uuid.UUID | None,
) -> None:
    """Reject the attempt up-front if this account+source is currently locked.

    Reads (does not increment) the dedicated lock-STATE keys for the
    account+source pair and the source-wide flood; once the failure counter has
    crossed threshold :func:`_record_login_failure` arms these lock keys with a
    TTL of ``login_lockout_duration_secs``, so the lock holds for the FULL
    configured duration (not merely the shorter failure window) and the advertised
    ``Retry-After`` is truthful. If either lock is set the attempt is refused with
    a generic 429 + coarse ``Retry-After`` and an ``auth.login_locked`` audit row
    — before the password is even checked, so a locked account+source costs an
    attacker nothing further (and leaks no existence oracle).

    **Fail-closed** (security — W6-T6 §4): if the lockout backend (Redis) is
    unavailable we deny the attempt rather than wave it through, so a Redis blip
    cannot hand out unlimited login attempts.
    """
    src = source if source is not None else "unknown"
    lock_keys = (
        rate_limit.login_lockout_state_key(username, src),
        rate_limit.login_source_lock_key(src),
    )
    locked = False
    try:
        for key in lock_keys:
            if await limiter.peek(key) >= 1:
                locked = True
                break
    except rate_limit.RateLimitBackendError as exc:
        # FAIL CLOSED (security): no unlimited attempts during a Redis outage.
        raise RateLimitedError(
            _LOGIN_THROTTLED,
            retry_after=settings.login_lockout_duration_secs,
        ) from exc
    if locked:
        await _audit_login_locked(
            session,
            username=username,
            source=source,
            request_id=request_id,
        )
        raise RateLimitedError(
            _LOGIN_THROTTLED,
            retry_after=settings.login_lockout_duration_secs,
        )


async def _record_login_failure(
    limiter: RateLimiter,
    settings: Settings,
    *,
    username: str,
    source: str | None,
) -> None:
    """Increment the failed-login counters for this account+source and source.

    Each failure increments a short failure-WINDOW counter
    (``login_lockout_window_secs``); the ``threshold``-th failure inside that
    window arms a dedicated lock-STATE key with a TTL of
    ``login_lockout_duration_secs``. The lock-state key — not the failure counter
    — is what :func:`_enforce_login_not_locked` consults, so the lock holds for
    the full configured *duration* and the advertised ``Retry-After`` is truthful
    (the failure window merely controls how quickly failures accumulate).

    Best-effort: a backend outage on the *increment* path must not turn a normal
    bad-password 401 into a 500 (the up-front :func:`_enforce_login_not_locked`
    is the fail-closed guard for the *next* attempt).
    """
    src = source if source is not None else "unknown"
    window = settings.login_lockout_window_secs
    duration = settings.login_lockout_duration_secs
    threshold = settings.login_lockout_threshold
    try:
        account = await limiter.hit(
            rate_limit.login_lockout_key(username, src), limit=threshold, window_secs=window
        )
        srcwide = await limiter.hit(
            rate_limit.login_source_key(src), limit=threshold, window_secs=window
        )
        # Threshold crossed ⇒ arm the duration-TTL lock so it outlives the window.
        if account.count >= threshold:
            await limiter.hit(
                rate_limit.login_lockout_state_key(username, src), limit=1, window_secs=duration
            )
        if srcwide.count >= threshold:
            await limiter.hit(rate_limit.login_source_lock_key(src), limit=1, window_secs=duration)
    except rate_limit.RateLimitBackendError:
        # Swallow: the credentials were already wrong (401 stands); the lockout
        # guard fails closed independently on the next attempt's read path.
        return


async def _clear_login_failures(limiter: RateLimiter, *, username: str, source: str | None) -> None:
    """Clear the account+source failure counter (and lock state) after success.

    Source-wide counter and lock are left intact: a single legitimate success
    must not wipe the brute-force signal another account on the same source is
    generating.
    """
    src = source if source is not None else "unknown"
    try:
        await limiter.reset(rate_limit.login_lockout_key(username, src))
        await limiter.reset(rate_limit.login_lockout_state_key(username, src))
    except rate_limit.RateLimitBackendError:
        return


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> TokenResponse:
    """Authenticate with username/password; issue access token + refresh cookie.

    On success a server-side :class:`RefreshSession` is created and its id is
    embedded in the refresh JWT. Every failure mode (unknown user, bad password,
    inactive account) raises one generic :class:`AuthError`, keeps the
    constant-time verification path, and writes an ``auth.login_failed`` audit
    row that does not reveal which mode occurred.

    W6-T6: the break-glass local path is brute-force protected. Before the
    password is checked, a temporary lockout for this account+source (or a
    source-wide flood) is enforced fail-closed (Redis outage ⇒ deny, never
    unlimited attempts); each genuine failure increments the counters; a success
    clears the account+source counter. A locked attempt returns a generic 429 —
    no account-existence oracle — and audits ``auth.login_locked`` (alerting).
    """
    source = request.client.host if request.client else None
    request_id = _request_id(request)
    await _enforce_login_not_locked(
        limiter,
        settings,
        username=body.username,
        source=source,
        session=session,
        request_id=request_id,
    )

    user = (
        await session.execute(select(User).where(User.username == body.username))
    ).scalar_one_or_none()
    if user is None:
        verify_password(body.password, _DUMMY_PASSWORD_HASH)  # timing equalizer
        await _audit_login_failed(session, body.username)
        await _record_login_failure(limiter, settings, username=body.username, source=source)
        raise AuthError(_BAD_CREDENTIALS)
    if not verify_password(body.password, user.password_hash) or not user.is_active:
        await _audit_login_failed(session, body.username)
        await _record_login_failure(limiter, settings, username=body.username, source=source)
        raise AuthError(_BAD_CREDENTIALS)
    # ADR-0028 §5 break-glass: when OIDC is enabled the local-login path is
    # fenced to the ``admin`` role only — it is the audited, alerted recovery
    # path for an unreachable/misconfigured IdP. A non-admin local login is
    # denied with the same generic 401 (no oracle for the fence).
    if settings.oidc_enabled and user.role.name != RoleEnum.ADMIN.value:
        await _audit_login_failed(session, body.username)
        await _record_login_failure(limiter, settings, username=body.username, source=source)
        raise AuthError(_BAD_CREDENTIALS)

    await _clear_login_failures(limiter, username=body.username, source=source)
    refresh_session = await session_service.create_session(
        session,
        user=user,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    access_token = _issue_tokens(user, refresh_session, settings, response)
    # Normal local login when OIDC is off; a fenced admin login while OIDC is on
    # is the alerted break-glass event (a distinct, reviewable audit action).
    login_action = (
        audit_service.AUTH_LOCAL_BREAKGLASS_LOGIN
        if settings.oidc_enabled
        else audit_service.AUTH_LOGIN
    )
    await audit_service.record(
        session,
        actor=f"user:{user.username}",
        action=login_action,
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

    Reuse detection (PRODUCTION_READINESS #5): the presented ``jti`` hash must
    match the session's persisted ``current_jti_hash``. A mismatch means a
    rotated-out token was replayed (theft signal): the session is revoked,
    ``auth.refresh_reuse_detected`` is audited (hash only — never token
    material), and the same generic 401 is returned. A NULL stored hash
    (session predates migration 0015) is accepted once and backfilled by this
    rotation. Server-side race window: two truly concurrent refreshes with the
    same cookie can both pass the check before either commits — the loser's
    NEXT refresh then falsely trips the detector (fail-closed re-login, never
    an access grant); the frontend single-flight guard (Wave 2 item 2) keeps
    that window unreachable in normal operation.
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

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise AuthError("Invalid refresh token")
    presented_hash = _hash_jti(jti)
    if refresh_session.current_jti_hash is not None and not secrets.compare_digest(
        refresh_session.current_jti_hash, presented_hash
    ):
        # A validly signed refresh token whose jti is not the session's current
        # one is a rotated-out token being replayed — a theft signal. Kill the
        # whole session (both the thief's and the victim's copies die) and
        # audit; the response stays the generic 401 (no oracle).
        await session_service.revoke(session, sid=refresh_session.id)
        await audit_service.record(
            session,
            actor=f"user:{user.username}",
            action=audit_service.AUTH_REFRESH_REUSE_DETECTED,
            target_type="refresh_session",
            target_id=str(refresh_session.id),
            detail={"presented_jti_hash": presented_hash, "outcome": "session_revoked"},
        )
        await session.commit()
        raise AuthError("Invalid refresh token")

    await session_service.touch(session, refresh_session)
    access_token = _issue_tokens(user, refresh_session, settings, response)
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
