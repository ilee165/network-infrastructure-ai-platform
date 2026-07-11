"""Security primitives: JWT access tokens (HS256), password hashing (bcrypt),
and the canonical RBAC :class:`Role` enum (D10).

The auth ROUTES (login/refresh/logout) and the FastAPI RBAC dependencies live
in ``api/`` (M1); :class:`Role` is the single source of truth for the
``viewer < operator < engineer < admin`` rank order so the API auth deps and
the agent tool wrappers enforce the same ordering. Credential-vault envelope
encryption (D11) lands in ``core/crypto.py`` (M1).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import bcrypt
import jwt

from app.core.config import Settings
from app.core.errors import AuthError


class Role(StrEnum):
    """The four RBAC roles (D10, ADR-0010), ordered ``VIEWER < ADMIN``.

    The string values are the wire/database form (``Role.name`` column,
    JWT-resolved ``User.role.name``); :meth:`rank` gives the comparison order
    so callers never duplicate the ranking. This is the single source of truth
    for the rank order — both the API auth deps and the agent tool wrappers
    import it, so "an agent can never do what its user cannot" (brief §7) is
    enforced against one definition, not two.
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    ENGINEER = "engineer"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        """Position in the ``viewer < operator < engineer < admin`` order."""
        return _ROLE_ORDER.index(self)

    def can_act_as(self, required: Role) -> bool:
        """Whether this role satisfies a *required* minimum role (rank >= required)."""
        return self.rank >= required.rank

    @classmethod
    def from_name(cls, name: str) -> Role | None:
        """Resolve a wire role *name* to a :class:`Role`, or ``None`` if unknown.

        Unknown names resolve to ``None`` so callers can treat them as ranking
        below every real role (deny by default), never as a privilege.
        """
        try:
            return cls(name)
        except ValueError:
            return None


#: Fixed rank order; index position is the rank consumed by :attr:`Role.rank`.
_ROLE_ORDER: tuple[Role, ...] = (Role.VIEWER, Role.OPERATOR, Role.ENGINEER, Role.ADMIN)

#: Canonical JWT signing algorithm (D10: short-lived HS256 access tokens).
ALGORITHM = "HS256"

#: bcrypt hard input limit; modern bcrypt (>=4.1) rejects longer secrets.
_BCRYPT_MAX_PASSWORD_BYTES = 72


def create_access_token(
    subject: str,
    settings: Settings,
    *,
    expires_delta: timedelta | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a signed JWT access token for *subject*.

    Args:
        subject: Token subject (``sub`` claim) — typically the user id.
        settings: Source of the signing key and the default lifetime.
        expires_delta: Optional explicit lifetime; defaults to
            ``settings.access_token_expire_minutes``.
        extra_claims: Additional claims to embed. Reserved claims
            (``sub``/``iat``/``exp``) always win over collisions.

    Returns:
        The encoded JWT string.
    """
    now = datetime.now(UTC)
    lifetime = (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload: dict[str, Any] = dict(extra_claims or {})
    payload.update({"sub": subject, "iat": now, "exp": now + lifetime})
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    """Decode and verify a JWT access token.

    Returns:
        The verified claim set.

    Raises:
        AuthError: If the token is expired, malformed, has a bad signature, or
            is missing required claims (``sub``/``exp``).
    """
    try:
        claims = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[ALGORITHM],
            options={"require": ["sub", "exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid authentication token") from exc
    return claims


def hash_password(password: str) -> str:
    """Hash *password* with bcrypt (salted, library-default work factor).

    CPU-bound — prefer :func:`hash_password_async` on the API event loop so
    concurrent requests are not stalled (perf #6 / H2).

    Raises:
        ValueError: If the UTF-8 encoding of *password* exceeds bcrypt's
            72-byte input limit — enforce a shorter maximum at the API layer.
    """
    secret = password.encode("utf-8")
    if len(secret) > _BCRYPT_MAX_PASSWORD_BYTES:
        msg = f"Password exceeds bcrypt's {_BCRYPT_MAX_PASSWORD_BYTES}-byte limit"
        raise ValueError(msg)
    return bcrypt.hashpw(secret, bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    """Constant-time verification of *password* against a stored bcrypt hash.

    CPU-bound — prefer :func:`verify_password_async` on the API event loop.
    Returns ``False`` (never raises) for over-long passwords or a malformed
    stored hash, so callers can treat any mismatch uniformly.
    """
    secret = password.encode("utf-8")
    if len(secret) > _BCRYPT_MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(secret, hashed.encode("ascii"))
    except ValueError:
        return False


async def hash_password_async(password: str) -> str:
    """Async wrapper: run :func:`hash_password` off the event loop."""
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, hashed: str) -> bool:
    """Async wrapper: run :func:`verify_password` off the event loop."""
    return await asyncio.to_thread(verify_password, password, hashed)
