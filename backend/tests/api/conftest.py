"""Fixtures for API-layer tests: ASGI app over in-memory aiosqlite (D16).

No Postgres, Docker, or network: ``app.api.deps.get_db`` is overridden to
yield the test's aiosqlite session, and httpx drives the app in-process.
The client uses an ``https`` base URL so the ``Secure`` refresh cookie is
stored and replayed by the cookie jar exactly as a browser would.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import timedelta
from typing import Annotated, Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.api import deps
from app.core.config import Settings
from app.core.security import create_access_token, hash_password
from app.main import create_app
from app.models import Base, Role, User

#: RBAC rank order under test (ADR-0010): viewer < operator < engineer < admin.
ROLE_ORDER = ("viewer", "operator", "engineer", "admin")

#: The one plaintext password shared by every seeded test user.
TEST_PASSWORD = "unit-test-password"


@pytest.fixture(scope="session")
def password_hash() -> str:
    """One bcrypt hash for the whole session (bcrypt is deliberately slow)."""
    return hash_password(TEST_PASSWORD)


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full model schema created."""
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """An :class:`AsyncSession` bound to the in-memory test engine."""
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session


@pytest.fixture()
async def users(session: AsyncSession, password_hash: str) -> dict[str, User]:
    """One active user per role plus one inactive user, keyed by role name.

    ``role`` is assigned as a relationship (not just ``role_id``) so
    ``user.role.name`` is readable without a lazy load in the async tests.
    """
    roles = {name: Role(name=name) for name in ROLE_ORDER}
    session.add_all(roles.values())
    await session.flush()

    seeded: dict[str, User] = {}
    for name in ROLE_ORDER:
        user = User(username=f"{name}_user", password_hash=password_hash, role=roles[name])
        session.add(user)
        seeded[name] = user
    inactive = User(
        username="inactive_user",
        password_hash=password_hash,
        role=roles["viewer"],
        is_active=False,
    )
    session.add(inactive)
    seeded["inactive"] = inactive
    await session.flush()
    return seeded


@pytest.fixture()
def app(settings: Settings, session: AsyncSession) -> FastAPI:
    """The app with ``get_db`` overridden plus RBAC/identity probe routes."""
    application = create_app(settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield session

    application.dependency_overrides[deps.get_db] = _override_db

    async def _ok() -> dict[str, str]:
        return {"status": "ok"}

    for role_name in ROLE_ORDER:
        application.get(
            f"/rbac/{role_name}",
            dependencies=[Depends(deps.require_role(role_name))],
        )(_ok)

    @application.get("/whoami")
    async def whoami(
        user: Annotated[User, Depends(deps.get_current_user)],
    ) -> dict[str, str]:
        return {"username": user.username, "role": user.role.name}

    return application


@pytest.fixture()
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """In-process client; https base so the Secure refresh cookie round-trips."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as test_client:
        yield test_client


@pytest.fixture()
def auth_headers(
    users: dict[str, User], make_token: Callable[..., str]
) -> Callable[[str], dict[str, str]]:
    """Bearer ``Authorization`` headers for the seeded user of a given role."""

    def _headers(role: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {make_token(users[role])}"}

    return _headers


@pytest.fixture()
def make_token(settings: Settings) -> Callable[..., str]:
    """Mint JWTs directly (bypassing /auth/login) for dependency-level tests."""

    def _make(
        user: User,
        *,
        token_type: str = "access",
        expires_delta: timedelta | None = None,
        jti: str | None = None,
    ) -> str:
        claims: dict[str, Any] = {"type": token_type, "roles": [user.role.name]}
        if jti is not None:
            claims["jti"] = jti
        return create_access_token(
            str(user.id),
            settings,
            expires_delta=expires_delta,
            extra_claims=claims,
        )

    return _make
