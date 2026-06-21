"""ADR-0028 OIDC routes: end-to-end login, fail-closed branches, break-glass, leak.

Drives ``/auth/oidc/login`` + ``/auth/oidc/callback`` over the in-memory ASGI
app. Discovery + token exchange are stubbed (no network); the ID token is a
real RS256 token from :class:`tests.oidc_helpers.FakeIdp`, validated against a
JWKS cache primed with the IdP's real key. Covers: happy path (platform JWT
minted, federated claims present, JIT row), every fail-closed branch (replayed
state, bad signature, deny-default mapping), break-glass local-login fencing,
logout/revoke, and a leak test asserting no token/secret reaches a log or body.
"""

from __future__ import annotations

import base64
import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from fastapi import FastAPI
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.api import deps
from app.api.v1.credentials import get_key_provider
from app.core import oidc
from app.core.config import Settings
from app.core.crypto import KEY_BYTES, EnvKeyProvider
from app.core.security import hash_password
from app.main import create_app
from app.models import AuditLog, Base, CredentialKind, Role, User
from app.services.credentials import service as vault
from app.services.oidc import InMemoryPendingAuthStore
from tests.oidc_helpers import CLIENT_ID, ISSUER, FakeIdp

CLIENT_SECRET_REF = "oidc-client-secret"
CLIENT_SECRET_VALUE = "s3cr3t-confidential-client-value"
LOGIN_URL = "/api/v1/auth/oidc/login"
CALLBACK_URL = "/api/v1/auth/oidc/callback"
LOCAL_LOGIN_URL = "/api/v1/auth/login"
REFRESH_COOKIE = "netops_refresh"
TEST_PASSWORD = "local-admin-password"


@pytest.fixture()
def idp() -> FakeIdp:
    return FakeIdp()


@pytest.fixture()
def kek() -> str:
    return base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")


@pytest.fixture()
def oidc_settings(kek: str) -> Settings:
    """Settings with OIDC enabled and a deny-default-friendly group map."""
    return Settings(
        _env_file=None,
        env="dev",
        secret_key="unit-test-secret-key",
        kek=kek,
        oidc_issuer=ISSUER,
        oidc_client_id=CLIENT_ID,
        oidc_client_secret_ref=CLIENT_SECRET_REF,
        oidc_redirect_uri="https://rp/api/v1/auth/oidc/callback",
        oidc_group_role_map={"netops-engineers": "engineer", "netops-admins": "admin"},
        oidc_allow_admin=False,
    )


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _fk(dbapi_connection: Any, _record: Any) -> None:
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


@pytest.fixture()
async def seeded(session: AsyncSession) -> dict[str, Any]:
    """Roles, a local admin (break-glass), and the vault-stored client secret."""
    roles = {n: Role(name=n) for n in ("viewer", "operator", "engineer", "admin")}
    session.add_all(roles.values())
    await session.flush()
    admin = User(username="root", password_hash=hash_password(TEST_PASSWORD), role=roles["admin"])
    operator = User(
        username="op", password_hash=hash_password(TEST_PASSWORD), role=roles["operator"]
    )
    session.add_all([admin, operator])
    await session.flush()
    # Client secret lives in the vault as a credential_ref (never inlined).
    provider = EnvKeyProvider(session_settings_kek())
    await vault.create_credential(
        session,
        provider,
        name=CLIENT_SECRET_REF,
        kind=CredentialKind.OIDC,
        username=None,
        secret=CLIENT_SECRET_VALUE,
        params=None,
        actor="test",
    )
    await session.commit()
    return {"roles": roles, "admin": admin, "operator": operator}


def session_settings_kek() -> Settings:
    # Deterministic per-process KEK matched to the seeded credential + app.
    return _KEK_HOLDER["settings"]


_KEK_HOLDER: dict[str, Settings] = {}


@pytest.fixture()
def app(
    oidc_settings: Settings,
    session: AsyncSession,
    idp: FakeIdp,
    monkeypatch: pytest.MonkeyPatch,
) -> FastAPI:
    _KEK_HOLDER["settings"] = oidc_settings
    application = create_app(oidc_settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield session

    pending = InMemoryPendingAuthStore()
    cache = oidc.JwksCache()
    import time

    cache._keys[ISSUER] = idp.jwks()
    cache._fetched_at[ISSUER] = time.monotonic()

    application.dependency_overrides[deps.get_db] = _override_db
    application.dependency_overrides[deps.get_pending_auth_store] = lambda: pending
    application.dependency_overrides[deps.get_jwks_cache] = lambda: cache
    application.dependency_overrides[get_key_provider] = lambda: EnvKeyProvider(oidc_settings)

    # Stub discovery + token exchange (no network). The token endpoint returns
    # the FakeIdp-minted ID token bound to the nonce stored at /login.
    metadata = oidc.ProviderMetadata(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        jwks_uri=f"{ISSUER}/jwks",
        end_session_endpoint=f"{ISSUER}/logout",
    )

    async def _fake_discovery(issuer: str, *, verify: bool = True) -> oidc.ProviderMetadata:
        return metadata

    monkeypatch.setattr(oidc, "fetch_discovery", _fake_discovery)
    application.state._fake_idp = idp  # accessible to per-test exchange stubs
    application.state._pending = pending
    return application


@pytest.fixture()
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        yield c


def _stub_exchange(monkeypatch: pytest.MonkeyPatch, id_token: str) -> None:
    async def _fake_exchange(metadata: oidc.ProviderMetadata, **kwargs: Any) -> oidc.TokenResponse:
        # The client secret reaches here (proving vault materialization worked),
        # but is never logged/echoed.
        assert kwargs["client_secret"] == CLIENT_SECRET_VALUE
        return oidc.TokenResponse(id_token=id_token, access_token="opaque-at")

    monkeypatch.setattr(oidc, "exchange_code", _fake_exchange)


async def _begin_login(client: httpx.AsyncClient) -> str:
    """Hit /login, return the ``state`` the server stored (read from redirect)."""
    resp = await client.get(LOGIN_URL, follow_redirects=False)
    assert resp.status_code == 307
    location = resp.headers["location"]
    # Extract state from the authorize URL query.
    params = dict(httpx.QueryParams(location.split("?", 1)[1]))
    return params["state"]


def _decode_platform_jwt(token: str, settings: Settings) -> dict:
    return pyjwt.decode(token, settings.secret_key, algorithms=["HS256"])


def _stored_nonce(app: FastAPI, state: str) -> str:
    return app.state._pending._entries[state].nonce


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_login_redirects_to_idp_with_pkce(
    client: httpx.AsyncClient, seeded: dict[str, Any]
) -> None:
    resp = await client.get(LOGIN_URL, follow_redirects=False)
    assert resp.status_code == 307
    loc = resp.headers["location"]
    assert loc.startswith(f"{ISSUER}/authorize?")
    assert "code_challenge_method=S256" in loc


async def test_callback_mints_platform_jwt_and_provisions_user(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: dict[str, Any],
    idp: FakeIdp,
    oidc_settings: Settings,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = await _begin_login(client)
    nonce = _stored_nonce(app, state)
    token = idp.id_token(nonce=nonce, groups=["netops-engineers"])
    _stub_exchange(monkeypatch, token)

    resp = await client.get(f"{CALLBACK_URL}?code=abc&state={state}", follow_redirects=False)
    assert resp.status_code == 200
    body = resp.json()
    claims = _decode_platform_jwt(body["access_token"], oidc_settings)
    assert claims["roles"] == ["engineer"]
    # ADR-0028 §2: the platform JWT carries the IdP-anchored principal.
    assert claims["idp_iss"] == ISSUER
    assert claims["idp_subject"] == "idp-subject-123"
    # JIT-provisioned, anchored on (iss, sub).
    user = (
        await session.execute(select(User).where(User.idp_subject == "idp-subject-123"))
    ).scalar_one()
    assert user.idp_iss == ISSUER
    assert user.role.name == "engineer"
    # A refresh cookie was set (same session model as local login).
    assert REFRESH_COOKIE in resp.cookies


# ---------------------------------------------------------------------------
# Fail-closed branches
# ---------------------------------------------------------------------------


async def test_callback_replayed_state_is_rejected(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: dict[str, Any],
    idp: FakeIdp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = await _begin_login(client)
    nonce = _stored_nonce(app, state)
    _stub_exchange(monkeypatch, idp.id_token(nonce=nonce, groups=["netops-engineers"]))

    first = await client.get(f"{CALLBACK_URL}?code=abc&state={state}")
    assert first.status_code == 200
    # Replay the same state: pending-auth was consumed (single-use) → 401.
    replay = await client.get(f"{CALLBACK_URL}?code=abc&state={state}")
    assert replay.status_code == 401


async def test_callback_unknown_state_is_rejected(
    client: httpx.AsyncClient, seeded: dict[str, Any]
) -> None:
    resp = await client.get(f"{CALLBACK_URL}?code=abc&state=never-issued")
    assert resp.status_code == 401


async def test_callback_bad_signature_is_rejected(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: dict[str, Any],
    idp: FakeIdp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = await _begin_login(client)
    nonce = _stored_nonce(app, state)
    forged = idp.id_token(nonce=nonce, sign_with_foreign_key=True, groups=["netops-engineers"])
    _stub_exchange(monkeypatch, forged)
    resp = await client.get(f"{CALLBACK_URL}?code=abc&state={state}")
    assert resp.status_code == 401


async def test_callback_deny_default_no_mapped_group(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: dict[str, Any],
    idp: FakeIdp,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = await _begin_login(client)
    nonce = _stored_nonce(app, state)
    # Valid token, but the group maps to nothing → deny, no session minted.
    token = idp.id_token(nonce=nonce, groups=["some-unmapped-group"])
    _stub_exchange(monkeypatch, token)
    resp = await client.get(f"{CALLBACK_URL}?code=abc&state={state}")
    assert resp.status_code == 401
    # No user row was provisioned for a denied identity.
    rows = (
        (await session.execute(select(User).where(User.idp_subject.is_not(None)))).scalars().all()
    )
    assert rows == []
    # A coarse-reason failure audit was written (no token material).
    failed = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.oidc.login_failed")))
        .scalars()
        .all()
    )
    assert len(failed) == 1
    assert failed[0].detail == {"reason": "no_mapped_role"}


async def test_callback_admin_group_capped_without_opt_in(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: dict[str, Any],
    idp: FakeIdp,
    oidc_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = await _begin_login(client)
    nonce = _stored_nonce(app, state)
    _stub_exchange(monkeypatch, idp.id_token(nonce=nonce, groups=["netops-admins"]))
    resp = await client.get(f"{CALLBACK_URL}?code=abc&state={state}")
    assert resp.status_code == 200
    claims = _decode_platform_jwt(resp.json()["access_token"], oidc_settings)
    # allow_admin False ⇒ OIDC admin is capped at engineer (break-glass-only).
    assert claims["roles"] == ["engineer"]


# ---------------------------------------------------------------------------
# Break-glass local login (§5)
# ---------------------------------------------------------------------------


async def test_local_admin_breakglass_allowed_and_audited(
    client: httpx.AsyncClient, seeded: dict[str, Any], session: AsyncSession
) -> None:
    resp = await client.post(LOCAL_LOGIN_URL, json={"username": "root", "password": TEST_PASSWORD})
    assert resp.status_code == 200
    rows = (
        (
            await session.execute(
                select(AuditLog).where(AuditLog.action == "auth.local.breakglass_login")
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].actor == "user:root"


async def test_local_non_admin_denied_when_oidc_enabled(
    client: httpx.AsyncClient, seeded: dict[str, Any]
) -> None:
    resp = await client.post(LOCAL_LOGIN_URL, json={"username": "op", "password": TEST_PASSWORD})
    # OIDC enabled fences local login to admin only — the operator is denied.
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Logout / revoke (§5)
# ---------------------------------------------------------------------------


async def test_oidc_logout_revokes_and_offers_rp_logout(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: dict[str, Any],
    idp: FakeIdp,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = await _begin_login(client)
    nonce = _stored_nonce(app, state)
    _stub_exchange(monkeypatch, idp.id_token(nonce=nonce, groups=["netops-engineers"]))
    await client.get(f"{CALLBACK_URL}?code=abc&state={state}")

    resp = await client.post("/api/v1/auth/oidc/logout")
    assert resp.status_code == 200
    body = resp.json()
    assert body["revoked"] is True
    # RP-initiated logout URL points at the IdP end_session_endpoint.
    assert body["logout_url"].startswith(f"{ISSUER}/logout")


# ---------------------------------------------------------------------------
# Secret / token leak test (G-SEC, ADR-0028 §3)
# ---------------------------------------------------------------------------


async def test_no_token_or_secret_in_logs_or_response(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: dict[str, Any],
    idp: FakeIdp,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    session: AsyncSession,
) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    state = await _begin_login(client)
    nonce = _stored_nonce(app, state)
    id_token = idp.id_token(nonce=nonce, groups=["netops-engineers"])
    _stub_exchange(monkeypatch, id_token)

    resp = await client.get(f"{CALLBACK_URL}?code=secret-auth-code&state={state}")
    assert resp.status_code == 200

    # Inspect only the PLATFORM's own log records (app.* / structlog), not the
    # httpx test-transport's request-line logger which echoes the callback URL
    # (the auth code is unavoidably in the browser-supplied URL — what matters
    # is that *our* code never writes token material to a log line).
    app_logs = "\n".join(
        f"{r.getMessage()} {r.__dict__}"
        for r in caplog.records
        if not r.name.startswith(("httpx", "httpcore", "asyncio", "aiosqlite"))
    )
    # None of the sensitive materials may appear in any of our log lines.
    assert CLIENT_SECRET_VALUE not in app_logs
    assert id_token not in app_logs
    assert "secret-auth-code" not in app_logs
    assert nonce not in app_logs
    # Nor in the response body (only the platform JWT is returned).
    assert CLIENT_SECRET_VALUE not in resp.text
    assert id_token not in resp.text
    # The success audit row carries no token material.
    succeeded = (
        (
            await session.execute(
                select(AuditLog).where(AuditLog.action == "auth.oidc.login_succeeded")
            )
        )
        .scalars()
        .all()
    )
    assert len(succeeded) == 1
    assert succeeded[0].detail is None
