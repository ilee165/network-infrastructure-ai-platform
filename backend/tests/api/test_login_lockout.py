"""Local break-glass login throttle/lockout (W6-T6; PRODUCTION.md §5, ADR-0028 §2).

Drives ``POST /auth/login`` over the in-memory ASGI app with an injectable
in-memory limiter (≈ shared Redis) and a low threshold so the lockout trips in a
few attempts. Asserts: N failed attempts ⇒ temporary lockout (429); the locked
response leaks no account-existence oracle (unknown vs. real username look
identical); the lockout is audited (``auth.login_locked``) with no token/password
material; the lock expires after its window; a success clears the account counter;
and the lockout FAILS CLOSED (no unlimited attempts) on a limiter outage.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.config import Settings
from app.main import create_app
from app.models import AuditLog, User
from app.services.rate_limit import (
    InMemoryRateLimiter,
    RateLimitBackendError,
    login_lockout_key,
)
from tests.api.conftest import TEST_PASSWORD

LOGIN_URL = "/api/v1/auth/login"


class _AdvanceableClock:
    def __init__(self) -> None:
        self._t = 5000.0

    def now(self) -> float:
        return self._t

    def advance(self, secs: float) -> None:
        self._t += secs


@pytest.fixture()
def lockout_settings() -> Settings:
    """Low lockout threshold/window so the temporary lock trips quickly."""
    return Settings(
        _env_file=None,
        env="dev",
        secret_key="unit-test-secret-key",
        login_lockout_threshold=3,
        login_lockout_window_secs=300,
        login_lockout_duration_secs=900,
    )


@pytest.fixture()
def lockout_clock() -> _AdvanceableClock:
    return _AdvanceableClock()


@pytest.fixture()
def lockout_limiter(lockout_clock: _AdvanceableClock) -> InMemoryRateLimiter:
    return InMemoryRateLimiter(clock=lockout_clock)


@pytest.fixture()
def lockout_app(
    lockout_settings: Settings,
    session: AsyncSession,
    lockout_limiter: InMemoryRateLimiter,
) -> FastAPI:
    application = create_app(lockout_settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield session

    application.dependency_overrides[deps.get_db] = _override_db
    application.dependency_overrides[deps.get_rate_limiter] = lambda: lockout_limiter
    return application


@pytest.fixture()
async def lockout_client(lockout_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=lockout_app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        yield c


async def _login(c: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await c.post(LOGIN_URL, json={"username": username, "password": password})


async def test_failed_attempts_trip_temporary_lockout(
    lockout_client: httpx.AsyncClient, users: dict[str, User]
) -> None:
    # threshold=3: three bad attempts, then the 4th is locked out (429).
    for _ in range(3):
        resp = await _login(lockout_client, "viewer_user", "wrong")
        assert resp.status_code == 401

    locked = await _login(lockout_client, "viewer_user", "wrong")
    assert locked.status_code == 429
    assert locked.json()["type"] == "urn:netops:error:rate-limited"
    assert int(locked.headers["retry-after"]) == 900
    # Even the CORRECT password is refused while locked (it's the account+source).
    still_locked = await _login(lockout_client, "viewer_user", TEST_PASSWORD)
    assert still_locked.status_code == 429


async def test_lockout_does_not_leak_account_existence(
    lockout_client: httpx.AsyncClient, users: dict[str, User]
) -> None:
    """A locked real account and a locked unknown username look identical."""
    for _ in range(4):
        await _login(lockout_client, "operator_user", "wrong")
    real_locked = await _login(lockout_client, "operator_user", "wrong")

    for _ in range(4):
        await _login(lockout_client, "ghost_user", "wrong")
    ghost_locked = await _login(lockout_client, "ghost_user", "wrong")

    assert real_locked.status_code == ghost_locked.status_code == 429
    assert real_locked.json()["detail"] == ghost_locked.json()["detail"]
    assert real_locked.headers["retry-after"] == ghost_locked.headers["retry-after"]


async def test_lockout_is_audited_without_secret_material(
    lockout_client: httpx.AsyncClient, users: dict[str, User], session: AsyncSession
) -> None:
    for _ in range(4):
        await _login(lockout_client, "engineer_user", "wrong")

    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == "auth.login_locked")))
        .scalars()
        .all()
    )
    assert len(rows) >= 1
    row = rows[0]
    assert row.actor == "user:engineer_user"
    detail = str(row.detail)
    assert "wrong" not in detail
    assert TEST_PASSWORD not in detail
    assert row.detail is not None
    assert row.detail.get("outcome") == "locked"


async def test_lockout_expires_after_window(
    lockout_client: httpx.AsyncClient,
    users: dict[str, User],
    lockout_clock: _AdvanceableClock,
) -> None:
    for _ in range(3):
        await _login(lockout_client, "viewer_user", "wrong")
    assert (await _login(lockout_client, "viewer_user", "wrong")).status_code == 429

    # Advance past the failure window: counters expire, lock clears.
    lockout_clock.advance(301)
    ok = await _login(lockout_client, "viewer_user", TEST_PASSWORD)
    assert ok.status_code == 200


async def test_successful_login_clears_account_counter(
    lockout_client: httpx.AsyncClient,
    users: dict[str, User],
    lockout_limiter: InMemoryRateLimiter,
) -> None:
    # Two failures (below threshold), then a success clears the account counter.
    await _login(lockout_client, "viewer_user", "wrong")
    await _login(lockout_client, "viewer_user", "wrong")
    ok = await _login(lockout_client, "viewer_user", TEST_PASSWORD)
    assert ok.status_code == 200

    # The account+source counter is now cleared (source resolves to None here).
    assert await lockout_limiter.peek(login_lockout_key("viewer_user", "unknown")) == 0


async def test_lockout_fails_closed_on_backend_outage(
    lockout_settings: Settings, session: AsyncSession, users: dict[str, User]
) -> None:
    """Redis down ⇒ login lockout fails CLOSED: attempts are refused, not unlimited."""

    class _BrokenLimiter:
        async def hit(self, key: str, *, limit: int, window_secs: int) -> object:
            raise RateLimitBackendError("down")

        async def peek(self, key: str) -> int:
            raise RateLimitBackendError("down")

        async def reset(self, key: str) -> None:
            raise RateLimitBackendError("down")

    app = create_app(lockout_settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield session

    app.dependency_overrides[deps.get_db] = _override_db
    app.dependency_overrides[deps.get_rate_limiter] = lambda: _BrokenLimiter()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://t") as c:
        # Even a VALID credential is refused while the lockout backend is down
        # (fail closed): the up-front guard raises before the password is checked.
        resp = await c.post(LOGIN_URL, json={"username": "viewer_user", "password": TEST_PASSWORD})
    assert resp.status_code == 429
