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

Reuse detection (audit PRODUCTION_READINESS #5, migration 0015): every issuance
persists the SHA-256 of the new refresh token's ``jti`` on the session row
(``current_jti_hash`` — hash only, never token material). ``refresh`` compares
the presented ``jti`` hash against it: a mismatch means a rotated-out
(superseded) token was replayed — a theft signal — so the session is revoked,
``auth.refresh_reuse_detected`` is audited, and a generic 401 is returned.
Rotation therefore invalidates the previous refresh token on the very next use.
Sessions created before migration 0015 carry a NULL hash and are backfilled on
their next legitimate rotation.

Known server-side race window: two truly concurrent refreshes with the same
cookie can both read the stored hash before either commits; the loser's cookie
then presents a stale ``jti`` on ITS next refresh and falsely trips the
detector (fail-closed: the user re-authenticates, no access is granted). The
frontend single-flight refresh guard (Wave 2 item 2) serializes refreshes per
browser, making this window unreachable in normal operation.
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta
from typing import Annotated, Final, Literal

import httpx
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_REFRESH,
    get_app_settings,
    get_current_user,
    get_db,
    get_jwks_cache,
    get_pending_auth_store,
    get_rate_limiter,
    require_role,
    resolve_oidc_client_secret,
)
from app.api.v1.credentials import get_key_provider
from app.core import crypto, oidc
from app.core.config import Settings
from app.core.errors import (
    AuthError,
    BadRequestError,
    ConflictError,
    NotFoundError,
    RateLimitedError,
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
from app.llm.providers import KNOWN_PROFILES
from app.models import RefreshSession, Role, SystemSetting, User
from app.services import oidc as oidc_service
from app.services import rate_limit
from app.services.audit import service as audit_service
from app.services.auth_sessions import service as session_service
from app.services.oidc import PendingAuthStore
from app.services.rate_limit import RateLimiter

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

#: One generic detail for every OIDC callback failure — the browser learns only
#: "denied", never which validation/mapping branch failed (ADR-0028 §3).
_INVALID_OIDC: Final = "OIDC authentication failed"

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


class TokenResponse(BaseModel):
    """A freshly minted Bearer access token."""

    access_token: str
    token_type: Literal["bearer"] = "bearer"


def _hash_jti(jti: str) -> str:
    """SHA-256 hex of a refresh-token ``jti`` — the only form ever persisted or audited."""
    return hashlib.sha256(jti.encode("utf-8")).hexdigest()


def _issue_tokens(
    user: User, refresh_session: RefreshSession, settings: Settings, response: Response
) -> str:
    """Mint the access token, set a refresh cookie for *refresh_session*, return the access JWT.

    The refresh JWT carries the server-side session id as its ``sid`` claim plus
    a fresh ``jti`` per issuance; rotation reuses the same ``sid`` so the live
    session survives a refresh, while the changing ``jti`` keeps every emitted
    token distinct. The SHA-256 of the new ``jti`` is persisted on the session
    row (``current_jti_hash``) so a later replay of a rotated-out token is
    detectable (reuse detection, PRODUCTION_READINESS #5) — the caller's commit
    makes it durable atomically with the rest of the request. The access token
    is unchanged (``type=access`` + ``roles``).
    """
    # ``jti`` makes every access token individually identifiable so the W6-T6
    # API rate-limiter can key a per-token budget (``token:<jti>``) without ever
    # handling the token bytes themselves.
    access_claims: dict[str, object] = {
        "type": TOKEN_TYPE_ACCESS,
        "roles": [user.role.name],
        "jti": str(uuid.uuid4()),
    }
    # ADR-0028 §2: a federated session carries the IdP-anchored principal as
    # first-class claims so downstream four-eyes/audit read it from the token
    # without a DB round-trip. Local accounts have neither, and omit them.
    if user.idp_subject is not None and user.idp_iss is not None:
        access_claims["idp_iss"] = user.idp_iss
        access_claims["idp_subject"] = user.idp_subject
    access_token = create_access_token(
        str(user.id),
        settings,
        extra_claims=access_claims,
    )
    refresh_jti = str(uuid.uuid4())
    refresh_token = create_access_token(
        str(user.id),
        settings,
        expires_delta=REFRESH_TOKEN_LIFETIME,
        # sid binds the token to a revocable server-side session; jti makes every
        # issuance unique within that session.
        extra_claims={
            "type": TOKEN_TYPE_REFRESH,
            "sid": str(refresh_session.id),
            "jti": refresh_jti,
        },
    )
    # Persist ONLY the hash of the current jti: a later refresh presenting any
    # other (rotated-out) jti for this session is a theft signal.
    refresh_session.current_jti_hash = _hash_jti(refresh_jti)
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


# ---------------------------------------------------------------------------
# OIDC / SSO identity federation (ADR-0028): Authorization-Code + PKCE relying
# party that mints the SAME platform JWT after full ID-token validation. The
# client secret is a vault credential_ref, materialized in-process only at the
# token-exchange. Every failure mode is fail-closed (no token / bad claim / no
# mapped role ⇒ no session) and audited without any token material.
# ---------------------------------------------------------------------------

_OIDC_DISABLED: Final = "OIDC is not enabled"


def _oidc_actor(claims_iss: str, subject: str) -> str:
    """Audit actor for an OIDC outcome — the anchor pair only, never a token."""
    return f"oidc:{claims_iss}#{subject}"


async def _audit_oidc_failed(
    session: AsyncSession,
    *,
    reason: str,
    request_id: uuid.UUID | None,
    iss: str | None = None,
) -> None:
    """Audit ``auth.oidc.login_failed`` with a coarse reason — never token material."""
    await audit_service.record(
        session,
        actor=f"oidc:{iss}" if iss else "oidc:unknown",
        action=audit_service.AUTH_OIDC_LOGIN_FAILED,
        target_type="oidc",
        target_id=None,
        detail={"reason": reason},
        request_id=request_id,
    )
    await session.commit()


def _request_id(request: Request) -> uuid.UUID | None:
    """Best-effort inbound request id (for the audit trail), or ``None``."""
    raw = request.headers.get("X-Request-ID")
    if raw is None:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


async def _enforce_oidc_callback_rate_limit(
    limiter: RateLimiter,
    settings: Settings,
    *,
    source: str | None,
    session: AsyncSession,
    request_id: uuid.UUID | None,
) -> None:
    """Per-source OIDC-callback budget (ADR-0028 §2): blunt code/``state`` flooding.

    Distinct from the JWKS forced-refresh rate-limit (ADR-0028 §63, handled in
    :class:`app.core.oidc.JwksCache`): this caps callback *hits* per source so a
    flood of forged ``code``/``state`` cannot drive token exchanges, while a
    single legitimate callback stays well under the budget. Over-budget ⇒ generic
    429 + coarse ``Retry-After``, audited ``auth.rate_limited`` (source only).

    **Fail-open** (availability): a backend outage must not break legitimate SSO
    logins — the §3 fail-closed claim-validation still gates access on every
    callback, so an un-throttled callback cannot itself mint a bad session.
    """
    src = source if source is not None else "unknown"
    try:
        result = await limiter.hit(
            rate_limit.oidc_callback_key(src),
            limit=settings.oidc_callback_rate_limit,
            window_secs=settings.oidc_callback_window_secs,
        )
    except rate_limit.RateLimitBackendError:
        return  # fail open: do not block SSO on a limiter outage
    if not result.allowed:
        await audit_service.record(
            session,
            actor=f"oidc:source:{src}",
            action=audit_service.AUTH_RATE_LIMITED,
            target_type="oidc",
            target_id=None,
            detail={"source": source, "outcome": "rate_limited"},
            request_id=request_id,
        )
        await session.commit()
        raise RateLimitedError(_INVALID_OIDC, retry_after=result.retry_after_secs)


@router.get("/oidc/login")
async def oidc_login(
    request: Request,
    settings: Annotated[Settings, Depends(get_app_settings)],
    pending_store: Annotated[PendingAuthStore, Depends(get_pending_auth_store)],
) -> RedirectResponse:
    """Begin Authorization-Code + PKCE: stash pending-auth, redirect to the IdP.

    Generates a CSPRNG ``code_verifier`` / ``state`` / ``nonce`` (ADR-0028 §1),
    persists the verifier+nonce server-side keyed by ``state`` (single-use,
    short-TTL — never sent to the browser), and 307-redirects to the IdP
    authorize URL. 404 when OIDC is not configured.
    """
    if not settings.oidc_enabled:
        raise NotFoundError(_OIDC_DISABLED)
    metadata = await oidc.fetch_discovery(str(settings.oidc_issuer))
    pkce = oidc.generate_pkce()
    state = oidc.generate_state()
    nonce = oidc.generate_nonce()
    await pending_store.put(
        state,
        oidc_service.PendingAuth(
            verifier=pkce.verifier,
            nonce=nonce,
            redirect_uri=settings.oidc_redirect_uri,
            created_at=time.monotonic(),
        ),
    )
    url = oidc.build_authorize_url(
        metadata,
        client_id=str(settings.oidc_client_id),
        redirect_uri=settings.oidc_redirect_uri,
        scopes=settings.oidc_scopes,
        state=state,
        nonce=nonce,
        challenge=pkce,
    )
    # 307 keeps the GET; the browser carries no verifier/nonce (server-held only).
    return RedirectResponse(url, status_code=307)


@router.get("/oidc/callback", response_model=TokenResponse)
async def oidc_callback(
    request: Request,
    response: Response,
    state: str,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    pending_store: Annotated[PendingAuthStore, Depends(get_pending_auth_store)],
    jwks_cache: Annotated[oidc.JwksCache, Depends(get_jwks_cache)],
    provider: Annotated[crypto.KeyProvider, Depends(get_key_provider)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    code: str | None = None,
) -> TokenResponse:
    """Complete the OIDC login: validate, JIT-provision, mint the platform JWT.

    Fail-closed at every step (ADR-0028 §1/§3/§4): a missing/replayed ``state``,
    any ID-token validation failure (bad signature/iss/aud/exp/nonce/alg:none),
    or a groups claim that maps to no platform role all raise a generic 401 and
    audit ``auth.oidc.login_failed`` with a coarse reason — never token material.
    On success it mints the SAME platform JWT + refresh cookie as local login,
    so ``require_role`` / four-eyes are unchanged.

    W6-T6: a per-source callback budget (ADR-0028 §2) blunts ``code``/``state``
    flooding before any token exchange; it fails open so a limiter outage cannot
    break legitimate SSO (claim validation below still fails closed).
    """
    if not settings.oidc_enabled:
        raise NotFoundError(_OIDC_DISABLED)
    request_id = _request_id(request)
    issuer = str(settings.oidc_issuer)
    client_id = str(settings.oidc_client_id)

    await _enforce_oidc_callback_rate_limit(
        limiter,
        settings,
        source=request.client.host if request.client else None,
        session=session,
        request_id=request_id,
    )

    pending = await pending_store.consume(state)
    if pending is None or code is None:
        # Absent/replayed state or no code ⇒ forged/expired callback (§3).
        await _audit_oidc_failed(session, reason="state_invalid", request_id=request_id, iss=issuer)
        raise AuthError(_INVALID_OIDC)

    try:
        metadata = await oidc.fetch_discovery(issuer)
        client_secret = await resolve_oidc_client_secret(
            session,
            provider,
            credential_ref=str(settings.oidc_client_secret_ref),
            actor=f"oidc:{issuer}",
        )
        tokens = await oidc.exchange_code(
            metadata,
            code=code,
            redirect_uri=pending.redirect_uri,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=pending.verifier,
        )
        claims = await oidc.validate_id_token(
            tokens.id_token,
            jwks_cache=jwks_cache,
            issuer=issuer,
            jwks_uri=metadata.jwks_uri,
            client_id=client_id,
            nonce=pending.nonce,
            clock_skew_secs=settings.oidc_clock_skew_secs,
        )
    except oidc.OidcError as exc:
        await _audit_oidc_failed(session, reason=exc.reason, request_id=request_id, iss=issuer)
        raise AuthError(_INVALID_OIDC) from exc

    subject = str(claims["sub"])
    groups = claims.get(settings.oidc_groups_claim)
    role = oidc_service.map_groups_to_role(
        groups if isinstance(groups, list) else None,
        settings.oidc_group_role_map,
        allow_admin=settings.oidc_allow_admin,
    )
    if role is None:
        # Deny-default: authenticated but no mapped group ⇒ NO session (§4).
        await _audit_oidc_failed(
            session, reason="no_mapped_role", request_id=request_id, iss=issuer
        )
        raise AuthError(_INVALID_OIDC)

    email, display_name = oidc_service.resolve_display_claims(claims)
    user = await oidc_service.provision_or_link_user(
        session,
        idp_iss=issuer,
        idp_subject=subject,
        role=role,
        email=email,
        display_name=display_name,
        request_id=request_id,
    )
    refresh_session = await session_service.create_session(
        session,
        user=user,
        user_agent=request.headers.get("user-agent"),
        ip=request.client.host if request.client else None,
    )
    access_token = _issue_tokens(user, refresh_session, settings, response)
    await audit_service.record(
        session,
        actor=_oidc_actor(issuer, subject),
        action=audit_service.AUTH_OIDC_LOGIN_SUCCEEDED,
        target_type="user",
        target_id=str(user.id),
        detail=None,
        request_id=request_id,
    )
    await session.commit()
    return TokenResponse(access_token=access_token)


@router.post("/oidc/logout")
async def oidc_logout(
    request: Request,
    response: Response,
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> dict[str, object]:
    """Revoke the platform session and offer RP-initiated IdP logout (ADR-0028 §5).

    Always revokes the cookie's server-side session and clears the cookie (the
    bounded-revocation window is the ≤15-min access-token life), exactly like
    :func:`logout`. Additionally, when the IdP advertises an
    ``end_session_endpoint``, returns its ``logout_url`` (with ``id_token_hint``
    omitted — P1 ships the redirect target; the hint is added when the IdP id
    token is retained) so the caller can terminate the IdP session too. 404 when
    OIDC is not enabled.
    """
    if not settings.oidc_enabled:
        raise NotFoundError(_OIDC_DISABLED)
    # Reuse the platform-side revoke + cookie-clear (idempotent, audited).
    revoke_result = await logout(request, response, session, settings)
    logout_url: str | None = None
    try:
        metadata = await oidc.fetch_discovery(str(settings.oidc_issuer))
        if metadata.end_session_endpoint is not None:
            params = httpx.QueryParams({"client_id": str(settings.oidc_client_id)})
            logout_url = f"{metadata.end_session_endpoint}?{params}"
    except oidc.OidcError:
        # A discovery failure must not block the (already-done) platform revoke;
        # the local session is gone regardless of IdP reachability (fail-closed
        # for *access*, best-effort for the convenience IdP redirect).
        logout_url = None
    return {"revoked": revoke_result["revoked"], "logout_url": logout_url}


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


# ---------------------------------------------------------------------------
# System settings — DB-persisted LLM profile + role map (admin only)
# ---------------------------------------------------------------------------
#
# Only the LLM *profile choice* (``llm_profile`` + the ``reasoning``/``fast``
# role map) is DB-persisted; the LLM registry reads the single
# ``system_settings`` row at runtime (env is the fallback). Provider API keys
# and the Ollama endpoint stay in env/``Settings`` and are NEVER accepted in a
# request body nor returned in a response — these schemas have no field for
# them, and unknown body fields are ignored by pydantic.


def _validate_profile(value: str | None) -> str | None:
    """Reject any profile name not in :data:`KNOWN_PROFILES` (``None`` passes)."""
    if value is not None and value not in KNOWN_PROFILES:
        raise BadRequestError(
            f"unknown LLM profile {value!r}; known profiles: {', '.join(KNOWN_PROFILES)}"
        )
    return value


class SystemSettingsResponse(BaseModel):
    """The effective LLM profile selection (DB row, or env fallback)."""

    llm_profile: str
    llm_role_reasoning: str | None
    llm_role_fast: str | None


class UpdateSettingsRequest(BaseModel):
    """Body for ``PATCH /settings`` — every field optional (partial update).

    A field that is *omitted* is left unchanged; a field set to ``null``
    explicitly clears that override. ``llm_profile`` cannot be cleared (the row
    always carries a base profile). Profile names are validated against
    :data:`KNOWN_PROFILES`; an unknown name is a 400. No key/endpoint field
    exists, so secrets cannot be supplied here.
    """

    model_config = {"extra": "ignore"}

    llm_profile: str | None = Field(default=None, max_length=64)
    llm_role_reasoning: str | None = Field(default=None, max_length=128)
    llm_role_fast: str | None = Field(default=None, max_length=128)

    @field_validator("llm_profile", "llm_role_reasoning", "llm_role_fast")
    @classmethod
    def _known_profile(cls, value: str | None) -> str | None:
        return _validate_profile(value)


async def _load_settings_row(session: AsyncSession) -> SystemSetting | None:
    """Return the single ``system_settings`` row, or ``None`` when unset."""
    result = await session.execute(select(SystemSetting).order_by(SystemSetting.id).limit(1))
    return result.scalar_one_or_none()


@router.get("/settings", response_model=SystemSettingsResponse)
async def get_app_system_settings(
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SystemSettingsResponse:
    """Return the effective LLM profile selection (admin only).

    Reads the single ``system_settings`` row; when no row exists yet, falls
    back to the env :class:`Settings` values so a fresh deployment reports its
    real (env) configuration. Never returns API keys or endpoints.
    """
    row = await _load_settings_row(session)
    if row is None:
        return SystemSettingsResponse(
            llm_profile=settings.llm_profile,
            llm_role_reasoning=settings.llm_role_reasoning,
            llm_role_fast=settings.llm_role_fast,
        )
    return SystemSettingsResponse(
        llm_profile=row.llm_profile,
        llm_role_reasoning=row.llm_role_reasoning,
        llm_role_fast=row.llm_role_fast,
    )


@router.patch("/settings", response_model=SystemSettingsResponse)
async def update_app_system_settings(
    body: UpdateSettingsRequest,
    admin: Annotated[User, Depends(require_role("admin"))],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> SystemSettingsResponse:
    """Upsert the single LLM settings row (admin only).

    Validates ``llm_profile`` and each role override against
    :data:`KNOWN_PROFILES` (an unknown name is a 400). Omitted fields are left
    unchanged; a field set explicitly to ``null`` clears that role override.
    Audits ``settings.updated`` with only the resulting profile selection — no
    secret material. API keys and endpoints are never accepted (no body field
    exists for them) nor stored.
    """
    provided = body.model_fields_set
    row = await _load_settings_row(session)
    if row is None:
        # Seed from env so an omitted field keeps the deployment's current
        # (env) value rather than silently resetting to the column default.
        row = SystemSetting(
            llm_profile=settings.llm_profile,
            llm_role_reasoning=settings.llm_role_reasoning,
            llm_role_fast=settings.llm_role_fast,
        )
        session.add(row)

    if "llm_profile" in provided and body.llm_profile is not None:
        row.llm_profile = body.llm_profile
    if "llm_role_reasoning" in provided:
        row.llm_role_reasoning = body.llm_role_reasoning
    if "llm_role_fast" in provided:
        row.llm_role_fast = body.llm_role_fast

    await session.flush()
    await audit_service.record(
        session,
        actor=f"user:{admin.username}",
        action=audit_service.SETTINGS_UPDATED,
        target_type="system_settings",
        target_id=str(row.id),
        detail={
            "llm_profile": row.llm_profile,
            "llm_role_reasoning": row.llm_role_reasoning,
            "llm_role_fast": row.llm_role_fast,
        },
    )
    await session.commit()
    await session.refresh(row)
    return SystemSettingsResponse(
        llm_profile=row.llm_profile,
        llm_role_reasoning=row.llm_role_reasoning,
        llm_role_fast=row.llm_role_fast,
    )
