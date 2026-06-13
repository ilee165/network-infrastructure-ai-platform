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
from sqlalchemy.ext.asyncio import AsyncSession

from app import db
from app.core.config import Settings
from app.core.errors import AuthError, ForbiddenError
from app.core.security import Role, decode_access_token
from app.knowledge import Neo4jClient, get_client
from app.models import User

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


def get_knowledge_client() -> Neo4jClient:
    """The process-wide Neo4j access wrapper (ADR-0005 read path).

    Routes depend on this (not on ``app.knowledge`` directly) so tests can
    override a single dependency to swap in a fake graph client.
    """
    return get_client()


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

    async def _enforce(user: Annotated[User, Depends(get_current_user)]) -> User:
        if ROLE_RANKS.get(user.role.name, -1) < required_rank:
            raise ForbiddenError(f"This action requires the {minimum!r} role or higher")
        return user

    return _enforce
