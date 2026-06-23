"""Counter key builders — one place that owns the no-secret-in-key invariant.

Every key is built from a stable, non-secret identifier (a user id, a JWT
``jti``, a username, a source IP) — never from token bytes, a password, or any
key material. Keeping the construction here means the limiter call sites read as
intent (``api_token_key(jti)``) and the secret-surface review has a single,
small surface to check.

The username and source IP are normalised (lower-cased / stripped) so the same
account+source pair maps to one counter regardless of caller casing, and hashed
into the key is avoided deliberately: a *username* is not secret (it is already
the audit ``actor``), and a source IP is an operational dimension — neither is
key material.
"""

from __future__ import annotations


def api_principal_key(user_id: str) -> str:
    """Per-user API budget key (``user:<id>``)."""
    return f"api:user:{user_id}"


def api_token_key(jti: str) -> str:
    """Per-token API budget key (``token:<jti>``) — the JWT id, never the token."""
    return f"api:token:{jti}"


def login_lockout_key(username: str, source: str) -> str:
    """Per-account + per-source failed-login counter key."""
    return f"login:fail:{_norm(username)}:{_norm(source)}"


def login_source_key(source: str) -> str:
    """Per-source failed-login counter key (source-wide brute-force blunting)."""
    return f"login:src:{_norm(source)}"


def oidc_callback_key(source: str) -> str:
    """Per-source OIDC-callback budget key (ADR-0028 §2 flood blunting)."""
    return f"oidc:cb:{_norm(source)}"


def _norm(value: str) -> str:
    """Normalise a non-secret dimension (username / IP) for stable keying."""
    return value.strip().lower()
