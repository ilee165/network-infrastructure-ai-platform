"""Security primitives: JWT access tokens (HS256) and password hashing (bcrypt).

Functions only at M0 — the auth ROUTES (login/refresh/logout), the user store,
and the RBAC dependencies (viewer | operator | engineer | admin, D10) land in
M1. Credential-vault envelope encryption (D11) lands in ``core/crypto.py`` (M1).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import Settings
from app.core.errors import AuthError

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
