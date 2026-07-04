"""OIDC / SSO identity federation (ADR-0028).

Authorization-Code + PKCE relying party that mints the SAME platform JWT after
full ID-token validation. The client secret is a vault ``credential_ref``,
materialized in-process only at the token-exchange. Every failure mode is
fail-closed (no token / bad claim / no mapped role ⇒ no session) and audited
without any token material.
"""

from __future__ import annotations

import time
import uuid
from typing import Annotated, Final

import httpx
from fastapi import Depends, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_app_settings,
    get_db,
    get_jwks_cache,
    get_pending_auth_store,
    get_rate_limiter,
    resolve_oidc_client_secret,
)
from app.api.v1.auth._shared import (
    TokenResponse,
    _issue_tokens,
    _request_id,
    router,
)
from app.api.v1.auth.login import logout
from app.api.v1.credentials import get_key_provider
from app.core import crypto, oidc
from app.core.config import Settings
from app.core.errors import AuthError, NotFoundError, RateLimitedError
from app.services import oidc as oidc_service
from app.services import rate_limit
from app.services.audit import service as audit_service
from app.services.auth_sessions import service as session_service
from app.services.oidc import PendingAuthStore
from app.services.rate_limit import RateLimiter

#: One generic detail for every OIDC callback failure — the browser learns only
#: "denied", never which validation/mapping branch failed (ADR-0028 §3).
_INVALID_OIDC: Final = "OIDC authentication failed"

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
