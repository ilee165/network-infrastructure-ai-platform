"""app.api.deps: get_current_user (401 matrix) and require_role (RBAC matrix)."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import timedelta

import httpx
import pytest

from app.api import deps
from app.core.config import Settings
from app.core.security import create_access_token
from app.models import User

ROLE_ORDER = ("viewer", "operator", "engineer", "admin")
RANKS = {"viewer": 0, "operator": 1, "engineer": 2, "admin": 3}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# get_current_user: 401 on any failure
# ---------------------------------------------------------------------------


async def test_missing_authorization_header_returns_401_with_www_authenticate(
    client: httpx.AsyncClient, users: dict[str, User]
) -> None:
    resp = await client.get("/whoami")

    assert resp.status_code == 401
    assert resp.headers["content-type"] == "application/problem+json"
    assert resp.json()["type"] == "urn:netops:error:unauthorized"
    assert resp.headers["www-authenticate"] == "Bearer"


async def test_garbage_token_returns_401(client: httpx.AsyncClient, users: dict[str, User]) -> None:
    resp = await client.get("/whoami", headers=_bearer("garbage.not-a.jwt"))

    assert resp.status_code == 401


async def test_expired_token_returns_401(
    client: httpx.AsyncClient, users: dict[str, User], make_token: Callable[..., str]
) -> None:
    token = make_token(users["admin"], expires_delta=timedelta(seconds=-10))

    resp = await client.get("/whoami", headers=_bearer(token))

    assert resp.status_code == 401


async def test_refresh_token_rejected_as_access_token(
    client: httpx.AsyncClient, users: dict[str, User], make_token: Callable[..., str]
) -> None:
    """The refresh cookie JWT must never work as a Bearer access token."""
    token = make_token(users["admin"], token_type="refresh")

    resp = await client.get("/whoami", headers=_bearer(token))

    assert resp.status_code == 401


async def test_token_for_unknown_user_returns_401(
    client: httpx.AsyncClient, users: dict[str, User], settings: Settings
) -> None:
    token = create_access_token(
        str(uuid.uuid4()), settings, extra_claims={"type": "access", "roles": ["admin"]}
    )

    resp = await client.get("/whoami", headers=_bearer(token))

    assert resp.status_code == 401


async def test_token_with_non_uuid_subject_returns_401(
    client: httpx.AsyncClient, users: dict[str, User], settings: Settings
) -> None:
    token = create_access_token(
        "not-a-uuid", settings, extra_claims={"type": "access", "roles": ["admin"]}
    )

    resp = await client.get("/whoami", headers=_bearer(token))

    assert resp.status_code == 401


async def test_token_for_inactive_user_returns_401(
    client: httpx.AsyncClient, users: dict[str, User], make_token: Callable[..., str]
) -> None:
    token = make_token(users["inactive"])

    resp = await client.get("/whoami", headers=_bearer(token))

    assert resp.status_code == 401


async def test_valid_token_resolves_current_user(
    client: httpx.AsyncClient, users: dict[str, User], make_token: Callable[..., str]
) -> None:
    token = make_token(users["operator"])

    resp = await client.get("/whoami", headers=_bearer(token))

    assert resp.status_code == 200
    assert resp.json() == {"username": "operator_user", "role": "operator"}


# ---------------------------------------------------------------------------
# require_role: full rank matrix (viewer < operator < engineer < admin)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("minimum", ROLE_ORDER)
@pytest.mark.parametrize("caller_role", ROLE_ORDER)
async def test_require_role_matrix(
    client: httpx.AsyncClient,
    users: dict[str, User],
    make_token: Callable[..., str],
    caller_role: str,
    minimum: str,
) -> None:
    """Every caller-role x minimum-role pairing: 200 at/above rank, 403 below."""
    token = make_token(users[caller_role])

    resp = await client.get(f"/rbac/{minimum}", headers=_bearer(token))

    if RANKS[caller_role] >= RANKS[minimum]:
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}
    else:
        assert resp.status_code == 403
        body = resp.json()
        assert body["type"] == "urn:netops:error:forbidden"
        assert resp.headers["content-type"] == "application/problem+json"


async def test_rbac_endpoint_without_token_returns_401_not_403(
    client: httpx.AsyncClient, users: dict[str, User]
) -> None:
    resp = await client.get("/rbac/viewer")

    assert resp.status_code == 401


def test_require_role_rejects_unknown_role_name() -> None:
    with pytest.raises(ValueError, match="unknown role"):
        deps.require_role("superuser")
