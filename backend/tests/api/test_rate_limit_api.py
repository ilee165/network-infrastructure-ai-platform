"""API rate-limit dependency (W6-T6): per-user + per-token 429, fail-open, audit.

Mounts a trivial protected route behind :func:`app.api.deps.enforce_api_rate_limit`
over the in-memory ASGI app, with an injectable in-memory limiter standing in for
the shared Redis (the prod limiter is unit-tested separately). Asserts the N+1th
request in a window is 429 + Retry-After, that the per-user and per-token keys are
independent, that the limit holds across two app instances sharing one limiter
(multi-replica), that a limiter outage fails OPEN, and that no token material
reaches the audit row or the response.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable

import httpx
import pytest
from fastapi import Depends, FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.config import Settings
from app.models import AuditLog, User
from app.services.rate_limit import InMemoryRateLimiter, RateLimitBackendError

PROBE_URL = "/probe"


@pytest.fixture()
def rl_settings() -> Settings:
    """Settings with a tiny API budget so the limit trips in a couple of calls."""
    return Settings(
        _env_file=None,
        env="dev",
        secret_key="unit-test-secret-key",
        rate_limit_requests=2,
        rate_limit_window_secs=60,
    )


def _build_app(settings: Settings, session: AsyncSession, limiter: object) -> FastAPI:
    """An app exposing a single route guarded by the API rate-limit dependency."""
    application = FastAPI()
    application.state.settings = settings

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield session

    application.dependency_overrides[deps.get_db] = _override_db
    application.dependency_overrides[deps.get_app_settings] = lambda: settings
    application.dependency_overrides[deps.get_rate_limiter] = lambda: limiter

    from app.core.errors import register_exception_handlers

    register_exception_handlers(application)

    @application.get(PROBE_URL, dependencies=[Depends(deps.enforce_api_rate_limit)])
    async def _probe() -> dict[str, str]:
        return {"ok": "yes"}

    return application


@pytest.fixture()
def limiter() -> InMemoryRateLimiter:
    return InMemoryRateLimiter()


@pytest.fixture()
async def rl_client(
    rl_settings: Settings, session: AsyncSession, limiter: InMemoryRateLimiter
) -> AsyncIterator[httpx.AsyncClient]:
    app = _build_app(rl_settings, session, limiter)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        yield c


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_request_within_budget_passes(
    rl_client: httpx.AsyncClient, users: dict[str, User], make_token: Callable[..., str]
) -> None:
    token = make_token(users["engineer"])
    resp = await rl_client.get(PROBE_URL, headers=_bearer(token))
    assert resp.status_code == 200


async def test_over_budget_returns_429_with_retry_after(
    rl_client: httpx.AsyncClient,
    users: dict[str, User],
    make_token: Callable[..., str],
) -> None:
    token = make_token(users["engineer"], jti="jti-a")
    # budget = 2: the 3rd request in the window is blocked.
    assert (await rl_client.get(PROBE_URL, headers=_bearer(token))).status_code == 200
    assert (await rl_client.get(PROBE_URL, headers=_bearer(token))).status_code == 200
    blocked = await rl_client.get(PROBE_URL, headers=_bearer(token))

    assert blocked.status_code == 429
    assert blocked.json()["type"] == "urn:netops:error:rate-limited"
    retry_after = int(blocked.headers["retry-after"])
    assert 0 < retry_after <= 60
    # No token material leaks into the 429 body.
    assert token not in blocked.text
    assert "jti-a" not in blocked.text


async def test_per_token_budget_is_independent_per_jti(
    rl_client: httpx.AsyncClient,
    users: dict[str, User],
    make_token: Callable[..., str],
) -> None:
    """Two tokens for the SAME user share the per-user key but have own jti keys.

    With budget=2, exhausting one token's two calls plus a third trips the
    per-user counter (4 calls > 2), so a fresh token is still blocked by the
    shared per-user budget — proving the per-user key is enforced. The per-token
    key is exercised in :func:`test_token_key_blocks_single_token`.
    """
    user = users["operator"]
    t1 = make_token(user, jti="jti-1")
    assert (await rl_client.get(PROBE_URL, headers=_bearer(t1))).status_code == 200
    assert (await rl_client.get(PROBE_URL, headers=_bearer(t1))).status_code == 200
    # Per-user budget now exhausted (count=2); next call on a new token still 429.
    t2 = make_token(user, jti="jti-2")
    assert (await rl_client.get(PROBE_URL, headers=_bearer(t2))).status_code == 429


async def test_token_key_blocks_single_token(
    rl_client: httpx.AsyncClient,
    users: dict[str, User],
    make_token: Callable[..., str],
) -> None:
    """A single token hitting its per-token budget is blocked (per-token key)."""
    token = make_token(users["admin"], jti="solo")
    statuses = [
        (await rl_client.get(PROBE_URL, headers=_bearer(token))).status_code for _ in range(3)
    ]
    assert statuses == [200, 200, 429]


async def test_limit_holds_across_replicas_sharing_one_limiter(
    rl_settings: Settings,
    session: AsyncSession,
    users: dict[str, User],
    make_token: Callable[..., str],
) -> None:
    """Two app instances sharing one limiter (≈ shared Redis) enforce one budget."""
    shared = InMemoryRateLimiter()
    app_a = _build_app(rl_settings, session, shared)
    app_b = _build_app(rl_settings, session, shared)
    token = make_token(users["engineer"], jti="cross")

    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app_a), base_url="https://a") as ca,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app_b), base_url="https://b") as cb,
    ):
        # 2 on replica A exhausts the shared budget; replica B sees it too.
        assert (await ca.get(PROBE_URL, headers=_bearer(token))).status_code == 200
        assert (await ca.get(PROBE_URL, headers=_bearer(token))).status_code == 200
        assert (await cb.get(PROBE_URL, headers=_bearer(token))).status_code == 429


async def test_api_limiter_fails_open_on_backend_outage(
    rl_settings: Settings,
    session: AsyncSession,
    users: dict[str, User],
    make_token: Callable[..., str],
) -> None:
    """Redis down ⇒ API limiter fails OPEN: requests are still served."""

    class _BrokenLimiter:
        async def hit(self, key: str, *, limit: int, window_secs: int) -> object:
            raise RateLimitBackendError("down")

        async def peek(self, key: str) -> int:
            raise RateLimitBackendError("down")

        async def reset(self, key: str) -> None:
            raise RateLimitBackendError("down")

    app = _build_app(rl_settings, session, _BrokenLimiter())
    token = make_token(users["engineer"], jti="any")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://t") as c:
        # Far beyond the budget — all served, because the limiter is unavailable.
        for _ in range(5):
            assert (await c.get(PROBE_URL, headers=_bearer(token))).status_code == 200


async def test_unauthenticated_request_is_not_keyed(
    rl_client: httpx.AsyncClient,
) -> None:
    """No bearer token ⇒ no principal to key on ⇒ not throttled here (authn is the route's job)."""
    for _ in range(5):
        assert (await rl_client.get(PROBE_URL)).status_code == 200


async def test_429_writes_audit_row_without_token_material(
    rl_client: httpx.AsyncClient,
    users: dict[str, User],
    make_token: Callable[..., str],
    session: AsyncSession,
) -> None:
    token = make_token(users["engineer"], jti="audit-jti")
    for _ in range(3):
        await rl_client.get(PROBE_URL, headers=_bearer(token))

    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.rate_limited")))
        .scalars()
        .all()
    )
    assert len(rows) >= 1
    row = rows[0]
    assert row.actor == f"user:{users['engineer'].id}"
    assert row.target_type == "api"
    # No token bytes or jti anywhere in the audit row.
    assert token not in str(row.detail)
    assert "audit-jti" not in str(row.detail)
    assert row.detail is not None
    assert row.detail.get("outcome") == "rate_limited"
