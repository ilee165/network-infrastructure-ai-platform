"""Shared FastAPI dependencies: DB session, current user, RBAC enforcement (D10).

:func:`require_role` implements the ADR-0010 rank order
``viewer < operator < engineer < admin`` — a role passes every check at or
below its own rank, so ``admin`` passes everything. Authentication failures
are always 401 (:class:`~app.core.errors.AuthError`); an authenticated user
below the required rank is 403 (:class:`~app.core.errors.ForbiddenError`).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Annotated, Any, Final

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import db
from app.core import crypto, oidc
from app.core.config import Settings
from app.core.errors import AuthError, ForbiddenError, RateLimitedError
from app.core.security import Role, decode_access_token
from app.knowledge import Neo4jClient, get_client
from app.models import DeviceCredential, User
from app.services import credentials as credentials_service
from app.services import rate_limit
from app.services.audit import service as audit_service
from app.services.oidc import InMemoryPendingAuthStore, PendingAuthStore
from app.services.rate_limit import RateLimiter

#: ADR-0010 RBAC rank order, derived from the canonical :class:`Role` enum so
#: the API layer and the agent tool wrappers share one source of truth. Unknown
#: role names rank below everything (deny).
ROLE_RANKS: Final[dict[str, int]] = {role.value: role.rank for role in Role}

#: ``type`` claim values separating short-lived API tokens from refresh tokens.
TOKEN_TYPE_ACCESS: Final = "access"
TOKEN_TYPE_REFRESH: Final = "refresh"

#: ``auto_error=False`` so a missing/malformed header raises our 401 problem
#: (with ``WWW-Authenticate``) instead of FastAPI's default 403.
_bearer_scheme = HTTPBearer(auto_error=False)

#: One generic 401 detail for every token failure — no oracle for attackers.
_INVALID_TOKEN_DETAIL: Final = "Invalid authentication credentials"


async def get_db() -> AsyncIterator[AsyncSession]:
    """One :class:`AsyncSession` per request; yields from :func:`app.db.get_session`.

    Routes depend on this (not on ``app.db`` directly) so tests can override a
    single dependency to swap the database.
    """
    async for session in db.get_session():
        yield session


def get_app_settings(request: Request) -> Settings:
    """The :class:`Settings` bound to the app at ``create_app`` time."""
    settings: Settings = request.app.state.settings
    return settings


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    """The process-wide :class:`async_sessionmaker` (lifecycle-owning callers).

    Most routes take a request-scoped :func:`get_db` session, but services that
    own their own commit boundary across several short transactions — the agent
    session lifecycle + trace recorder (M3) — need the factory, not one session.
    Routes depend on this (not on ``app.db`` directly) so tests can override a
    single dependency to bind an isolated engine.
    """
    return db.get_sessionmaker()


def get_knowledge_client() -> Neo4jClient:
    """The process-wide Neo4j access wrapper (ADR-0005 read path).

    Routes depend on this (not on ``app.knowledge`` directly) so tests can
    override a single dependency to swap in a fake graph client.
    """
    return get_client()


def get_jwks_cache(request: Request) -> oidc.JwksCache:
    """The process-wide per-issuer JWKS cache (ADR-0028 §3).

    Lazily created once and stashed on ``app.state`` so the bounded-TTL +
    one-forced-refresh rotation handling is shared across requests. Tests
    override this dependency to inject a cache primed with a known key.
    """
    cache: oidc.JwksCache | None = getattr(request.app.state, "oidc_jwks_cache", None)
    if cache is None:
        settings: Settings = request.app.state.settings
        cache = oidc.JwksCache(ttl_secs=float(settings.oidc_jwks_cache_ttl_secs))
        request.app.state.oidc_jwks_cache = cache
    return cache


def get_pending_auth_store(request: Request) -> PendingAuthStore:
    """The process-wide single-use pending-auth store (ADR-0028 §2).

    Defaults to an in-process store (local-first); a Redis-backed store can be
    bound on ``app.state`` at startup for multi-instance deployments. Tests
    override this to share one store across the login + callback calls.
    """
    store: PendingAuthStore | None = getattr(request.app.state, "oidc_pending_store", None)
    if store is None:
        store = InMemoryPendingAuthStore()
        request.app.state.oidc_pending_store = store
    return store


def get_rate_limiter(request: Request) -> RateLimiter:
    """The process-wide shared-counter rate limiter (W6-T6; ADR-0008 Redis).

    Defaults to an in-process limiter (local-first / single-process / tests); a
    :class:`~app.services.rate_limit.RedisRateLimiter` over the shared Redis is
    bound on ``app.state`` at startup for multi-replica deployments so a limit
    holds across ``api`` pods (D13) rather than resetting per pod. Tests override
    this dependency to inject an in-memory limiter with a controllable clock.
    """
    limiter: RateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        limiter = rate_limit.InMemoryRateLimiter()
        request.app.state.rate_limiter = limiter
    return limiter


async def _audit_rate_limited(
    session: AsyncSession,
    *,
    actor: str,
    source: str | None,
    request_id: uuid.UUID | None,
) -> None:
    """Audit one ``auth.rate_limited`` outcome — ids/source only, no token bytes."""
    await audit_service.record(
        session,
        actor=actor,
        action=audit_service.AUTH_RATE_LIMITED,
        target_type="api",
        target_id=None,
        detail={"source": source, "outcome": "rate_limited"},
        request_id=request_id,
    )
    await session.commit()


def _client_source(request: Request) -> str | None:
    """Best-effort source identifier for a request (client IP), or ``None``."""
    return request.client.host if request.client else None


def _inbound_request_id(request: Request) -> uuid.UUID | None:
    """Inbound ``X-Request-ID`` parsed as a UUID for the audit trail, or ``None``."""
    raw = request.headers.get("X-Request-ID")
    if raw is None:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None


async def enforce_api_rate_limit(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> None:
    """Enforce the per-principal AND per-token API request budget (W6-T6).

    Keyed by ``user:<id>`` **and** the token id (``jti``) so neither a shared
    account nor a single leaked token can exceed the budget; the shared Redis
    backing (ADR-0008) makes the limit hold across replicas. The ``N+1``-th
    request in a window raises :class:`RateLimitedError` (429 + coarse
    ``Retry-After``) and audits ``auth.rate_limited``.

    **Fail-open** on a backend (Redis) outage: a degraded limiter must not take
    the API down (availability — W6-T6 §4). A backend error is swallowed and the
    request is served; only the *enforced* path can reject.
    """
    # No / malformed token: leave authn to the route's own dependency. There is
    # no principal to key on, and a global key would be a G-SCA hot key.
    if credentials is None:
        return
    try:
        claims = decode_access_token(credentials.credentials, settings)
    except AuthError:
        return
    subject = str(claims.get("sub", "")) or None
    jti = claims.get("jti")
    keys: list[str] = []
    if subject is not None:
        keys.append(rate_limit.api_principal_key(subject))
    if isinstance(jti, str) and jti:
        keys.append(rate_limit.api_token_key(jti))
    if not keys:
        return

    limit = settings.rate_limit_requests
    window = settings.rate_limit_window_secs
    worst: rate_limit.RateLimitResult | None = None
    try:
        for key in keys:
            result = await limiter.hit(key, limit=limit, window_secs=window)
            if result.allowed:
                continue
            if worst is None or result.retry_after_secs > worst.retry_after_secs:
                worst = result
    except rate_limit.RateLimitBackendError:
        # FAIL OPEN (availability): serve the request when the limiter is down.
        return

    if worst is not None:
        actor = f"user:{subject}" if subject is not None else "user:unknown"
        await _audit_rate_limited(
            session,
            actor=actor,
            source=_client_source(request),
            request_id=_inbound_request_id(request),
        )
        raise RateLimitedError("Rate limit exceeded", retry_after=worst.retry_after_secs)


async def resolve_oidc_client_secret(
    session: AsyncSession,
    provider: crypto.KeyProvider,
    *,
    credential_ref: str,
    actor: str,
) -> str:
    """Materialize the OIDC client secret in-process from the vault (ADR-0028 §6).

    The secret is referenced by ``credential_ref`` (a vault handle, never the
    value); it is decrypted only here, at the moment of a token-endpoint call,
    and returned to the caller to pin onto the back-channel POST body. It is
    never inlined in config, logged, or placed in a response/audit detail.

    Raises:
        AuthError: If the referenced credential does not exist (fail-closed —
            an OIDC deployment with a dangling secret-ref cannot mint sessions).
    """
    credential = (
        await session.execute(
            select(DeviceCredential).where(DeviceCredential.name == credential_ref)
        )
    ).scalar_one_or_none()
    if credential is None:
        raise AuthError(_INVALID_TOKEN_DETAIL)
    decrypted = await credentials_service.decrypt(
        session, provider, credential, actor=actor, reason="oidc_token_exchange"
    )
    return decrypted.plaintext.decode("utf-8")


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
    session: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> User:
    """Resolve the Bearer access token to an active :class:`User`.

    Raises:
        AuthError: (401) on any failure — missing/malformed header, bad
            signature, expired token, wrong token ``type`` (refresh tokens are
            never valid here), unknown subject, or inactive user.
    """
    if credentials is None:
        raise AuthError(_INVALID_TOKEN_DETAIL)
    claims = decode_access_token(credentials.credentials, settings)
    if claims.get("type") != TOKEN_TYPE_ACCESS:
        raise AuthError(_INVALID_TOKEN_DETAIL)
    try:
        user_id = uuid.UUID(str(claims["sub"]))
    except ValueError as exc:
        raise AuthError(_INVALID_TOKEN_DETAIL) from exc
    user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        raise AuthError(_INVALID_TOKEN_DETAIL)
    return user


#: Distinct 403 detail used as a sentinel code: an authenticated, active user
#: whose ``must_change_password`` flag is still set. The frontend keys off this
#: exact string to force the change-password flow before anything else.
PASSWORD_CHANGE_REQUIRED: Final = "password_change_required"


def _require_password_current(user: User) -> User:
    """Raise :class:`ForbiddenError` if *user* still owes a password change.

    Pure (no I/O) so the rule is unit-testable in isolation; the
    :func:`get_active_user` dependency wraps :func:`get_current_user` around it.
    """
    if user.must_change_password:
        raise ForbiddenError(PASSWORD_CHANGE_REQUIRED)
    return user


async def get_active_user(
    user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Like :func:`get_current_user`, but also blocks a forced password change.

    Gate the rest of the app with this (not bare :func:`get_current_user`): a
    user with ``must_change_password`` set is authenticated but may not act
    until they clear the flag. The self-service escape hatches — ``GET /me``,
    ``POST /me/password`` and ``POST /logout`` — deliberately keep
    :func:`get_current_user` so the user can still read their profile, change
    the password, and log out while flagged.

    Raises:
        ForbiddenError: (403, detail :data:`PASSWORD_CHANGE_REQUIRED`) when the
            caller must change their password before proceeding.
    """
    return _require_password_current(user)


def require_role(minimum: str) -> Callable[..., Coroutine[Any, Any, User]]:
    """Build a dependency enforcing that the caller holds *minimum* rank or above.

    Usage: ``Depends(require_role("engineer"))`` — 401 if unauthenticated,
    403 if authenticated below rank; returns the :class:`User` otherwise.

    Raises:
        ValueError: Immediately (at route definition time) if *minimum* is not
            one of the four ADR-0010 roles.
    """
    if minimum not in ROLE_RANKS:
        msg = f"unknown role {minimum!r}; expected one of {sorted(ROLE_RANKS)}"
        raise ValueError(msg)
    required_rank = ROLE_RANKS[minimum]

    async def _enforce(user: Annotated[User, Depends(get_active_user)]) -> User:
        if ROLE_RANKS.get(user.role.name, -1) < required_rank:
            raise ForbiddenError(f"This action requires the {minimum!r} role or higher")
        return user

    return _enforce
