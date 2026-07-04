"""Authentication routes (D10, ADR-0010): session-aware login / refresh / logout,
OIDC/SSO federation, self-service account, admin user management, and system
settings — assembled onto a single ``/auth`` router.

This package is the split of the former 1,600-line ``auth.py`` module (audit
ARCH_DEBT #4). The split is **pure motion**: every route still attaches to the
one :data:`~app.api.v1.auth._shared.router`, and the submodules are imported
here in the SAME order the routes were originally declared —

    login → oidc → account → users → settings

— so the route inventory and generated OpenAPI schema are byte-identical to the
pre-split module. Submodules:

- :mod:`~app.api.v1.auth._shared`  — the shared ``/auth`` router, the refresh
  cookie contract, :func:`_issue_tokens`, and request-id extraction.
- :mod:`~app.api.v1.auth.login`    — ``POST /login`` / ``/refresh`` / ``/logout``
  plus brute-force lockout and refresh-token reuse detection.
- :mod:`~app.api.v1.auth.oidc`     — Authorization-Code + PKCE relying party.
- :mod:`~app.api.v1.auth.account`  — self-service ``/me`` + session management.
- :mod:`~app.api.v1.auth.users`    — admin-only account CRUD.
- :mod:`~app.api.v1.auth.settings` — admin-only DB-persisted LLM profile.

Server-side session model (Auth & Account UI): refresh JWTs are **stateful**.
Each carries a ``sid`` claim naming a ``refresh_sessions`` row; ``refresh`` only
rotates while that row is live (``revoked_at IS NULL``) and the user is active.
Logout / admin revoke flips ``revoked_at`` — the row is never deleted — so a
logged-out, admin-revoked, or deactivated session's refresh token is rejected
on its next use rather than staying verifiable until its natural 8 h expiry.
"""

# ruff: noqa: I001,E402,F401 -- import ORDER here is load-bearing: each submodule
# registers its routes on the shared router as an import side effect, so the
# import sequence below IS the route-declaration order and therefore the OpenAPI
# path order. isort must not alphabetize it (that would reorder the routes and
# break the byte-identical-schema guarantee), and the submodule imports are
# side-effecting rather than name-using.
from __future__ import annotations

from app.api.v1.auth._shared import router

# Import order == route-declaration order == OpenAPI path order (byte-identical
# to the pre-split module): login -> oidc -> account -> users -> settings.
from app.api.v1.auth import login
from app.api.v1.auth import oidc
from app.api.v1.auth import account
from app.api.v1.auth import users
from app.api.v1.auth import settings

__all__ = ["account", "login", "oidc", "router", "settings", "users"]
