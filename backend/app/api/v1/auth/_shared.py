"""Shared router, cookie contract, and token-issuance helpers for the auth package.

This module owns the single ``/auth`` :class:`~fastapi.APIRouter` that every auth
submodule (:mod:`~app.api.v1.auth.login`, :mod:`~app.api.v1.auth.oidc`,
:mod:`~app.api.v1.auth.account`, :mod:`~app.api.v1.auth.users`,
:mod:`~app.api.v1.auth.settings`) attaches its routes to, plus the primitives
more than one of them needs: the refresh-cookie contract, the token-issuance
routine, and request-id extraction.

Splitting the former single ``auth.py`` module (audit ARCH_DEBT #4) is **pure
motion** — routes attach to this same router, in their original order, via the
package ``__init__`` import sequence, so the route inventory and OpenAPI schema
are byte-identical to the pre-split module.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from typing import Final, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from app.api.deps import TOKEN_TYPE_ACCESS, TOKEN_TYPE_REFRESH
from app.core.config import Settings
from app.core.security import create_access_token
from app.models import RefreshSession, User

router = APIRouter(prefix="/auth", tags=["auth"])

#: Refresh-token lifetime (ADR-0010: 8 hours, rotated on use).
REFRESH_TOKEN_LIFETIME: Final = timedelta(hours=8)

REFRESH_COOKIE_NAME: Final = "netops_refresh"

#: Cookie scope: the auth router under the canonical ``/api/v1`` mount
#: (``app.main.API_V1_PREFIX`` — not imported here to avoid a cycle), so the
#: refresh JWT is only ever transmitted to ``/auth/*`` endpoints.
REFRESH_COOKIE_PATH: Final = "/api/v1/auth"

#: An email already used by a different account (shared by self-service profile
#: edits and admin user management).
_EMAIL_TAKEN: Final = "That email is already in use"


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


def _request_id(request: Request) -> uuid.UUID | None:
    """Best-effort inbound request id (for the audit trail), or ``None``."""
    raw = request.headers.get("X-Request-ID")
    if raw is None:
        return None
    try:
        return uuid.UUID(raw)
    except ValueError:
        return None
