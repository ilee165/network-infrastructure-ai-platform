"""Optimistic-concurrency (N1) semantics re-asserted under REAL PostgreSQL.

The SQLite unit suite (``tests/api/test_applications.py``) proves the 428/400/409
contract and the app-level ``updated_at`` compare, but it cannot prove the two
behaviours the guard actually rests on, because aiosqlite mismodels both:

1. **``updated_at`` advances at flush** — the house ``onupdate=utcnow`` bumps the
   column to a strictly-greater instant on every real UPDATE, and PostgreSQL's
   ``timestamptz`` round-trips the microsecond+tz token so a legitimate save does
   NOT false-409 (GRAFT G3).
2. **``SELECT … FOR UPDATE`` serialises racing writers** — the lock is a no-op on
   SQLite (silently dropped) but real on Postgres; it closes the read-then-write
   TOCTOU so a stale full-snapshot PATCH is rejected 409 instead of clobbering a
   concurrent edit (the N1 lost-update this fix exists to prevent).

Two independent :class:`AsyncSession`s over the ``pg_engine`` (``NullPool`` → one
connection each) drive the true cross-connection race. A rejected precondition
appends no ``application.update`` entry and leaves the hash chain clean.

Secret-surface: payloads are application names / owner strings / row references
only — no fixture or assertion here contains secret material.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.api import deps
from app.core.config import Settings
from app.core.security import create_access_token
from app.models import Application, AuditLog, Role, User
from app.models.applications import ApplicationOrigin
from app.services import audit
from app.services.audit.verify import verify_chain

pytestmark = pytest.mark.integration

BASE = "/api/v1/applications"

STALE_TYPE = "urn:netops:error:stale-precondition"


@pytest.fixture()
def settings() -> Settings:
    return Settings(
        _env_file=None,
        env="dev",
        secret_key="pg-concurrency-harness-secret-key-00",
        access_token_expire_minutes=5,
    )


@pytest.fixture()
async def engineer(pg_session: AsyncSession) -> User:
    """One engineer user referencing the migration-seeded ``engineer`` role.

    Committed, so the two independent race sessions (separate connections) all
    see it.
    """
    role = (await pg_session.execute(select(Role).where(Role.name == "engineer"))).scalar_one()
    user = User(
        username=f"pg-conc-eng-{uuid.uuid4().hex[:8]}",
        password_hash="not-a-real-hash",  # never authenticated with; tokens minted directly
        role_id=role.id,
    )
    pg_session.add(user)
    await pg_session.commit()
    return user


@pytest.fixture()
async def client(settings: Settings, pg_session: AsyncSession) -> AsyncIterator[httpx.AsyncClient]:
    """The real app over the shared PG harness session (``get_db`` overridden)."""
    async with _client_ctx(settings, pg_session) as c:
        yield c


def _headers(user: User, settings: Settings, role: str = "engineer") -> dict[str, str]:
    token = create_access_token(
        str(user.id), settings, extra_claims={"type": "access", "roles": [role]}
    )
    return {"Authorization": f"Bearer {token}"}


def _if_match(headers: dict[str, str], token: str) -> dict[str, str]:
    return {**headers, "If-Match": f'"{token}"'}


@asynccontextmanager
async def _client_ctx(
    settings: Settings, session: AsyncSession
) -> AsyncIterator[httpx.AsyncClient]:
    """A real-app client whose ``get_db`` yields *session* — one client per session
    for the multi-connection race tests."""
    from app.main import create_app

    application = create_app(settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        yield session

    application.dependency_overrides[deps.get_db] = _override_db
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as c:
        yield c


async def _create(client: httpx.AsyncClient, headers: dict[str, str]) -> tuple[str, str]:
    """Create one manual application; return ``(id, updated_at_token)``."""
    resp = await client.post(
        BASE, json={"name": f"pg-conc-{uuid.uuid4().hex[:8]}", "fqdns": []}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    return body["id"], body["updated_at"]


async def test_updated_at_advances_at_flush_on_pg(
    pg_session: AsyncSession, engineer: User, settings: Settings
) -> None:
    """The house ``onupdate`` bumps ``updated_at`` to a strictly-greater instant
    across a real-PG flush — the property the whole precondition compare rests on
    (SQLite would return a coarser/naive value)."""
    application = Application(
        name=f"pg-adv-{uuid.uuid4().hex[:8]}",
        fqdns=[],
        origin=ApplicationOrigin.MANUAL,
        created_by=engineer.id,
    )
    pg_session.add(application)
    await pg_session.flush()
    before = application.updated_at

    application.name = "pg-adv-renamed"
    await pg_session.flush()
    after = application.updated_at

    assert after > before
    assert after.tzinfo is not None and before.tzinfo is not None


async def test_matching_expected_token_round_trips_on_pg(
    client: httpx.AsyncClient, engineer: User, settings: Settings
) -> None:
    """GRAFT G3: the create-response ``updated_at`` used verbatim as ``If-Match``
    PATCHes cleanly — proving the timestamptz microsecond+tz token round-trips and
    does NOT false-409 a legitimate save."""
    headers = _headers(engineer, settings)
    app_id, token = await _create(client, headers)

    resp = await client.patch(
        f"{BASE}/{app_id}", json={"owner": "team-x"}, headers=_if_match(headers, token)
    )
    assert resp.status_code == 200, resp.text
    # The 200 hands back a fresh, advanced token.
    assert resp.headers["ETag"].strip('"') != token


async def test_concurrent_edit_prevents_lost_update(
    pg_engine: AsyncEngine, engineer: User, settings: Settings
) -> None:
    """Two independent sessions both hold token v1; A commits v2, then B's PATCH
    with the now-stale v1 is rejected 409 stale-precondition and A's write
    survives — the lost update N1 describes cannot happen."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    headers = _headers(engineer, settings)

    async with (
        maker() as sa,
        maker() as sb,
        _client_ctx(settings, sa) as ca,
        _client_ctx(settings, sb) as cb,
    ):
        app_id, v1 = await _create(ca, headers)

        # Writer A saves against v1 → 200 → v2 (committed on sa).
        ra = await ca.patch(
            f"{BASE}/{app_id}", json={"name": "a-wins"}, headers=_if_match(headers, v1)
        )
        assert ra.status_code == 200, ra.text

        # Writer B is still holding v1 → its full-snapshot PATCH is refused.
        rb = await cb.patch(
            f"{BASE}/{app_id}", json={"name": "b-clobbers"}, headers=_if_match(headers, v1)
        )
        assert rb.status_code == 409, rb.text
        assert rb.json()["type"] == STALE_TYPE

    # A's write survived — B never overwrote it.
    async with maker() as verify:
        row = await verify.get(Application, uuid.UUID(app_id))
        assert row is not None and row.name == "a-wins"


async def test_for_update_serializes_racing_patches(
    pg_engine: AsyncEngine, engineer: User, settings: Settings
) -> None:
    """Lock-mechanism proof: while B holds the row ``FOR UPDATE`` and stages a v2
    write, A's own ``FOR UPDATE`` read BLOCKS (does not complete) — closing the
    read-then-write TOCTOU. After B commits, A proceeds, and A's stale v1 token
    driven through the endpoint is rejected 409."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    headers = _headers(engineer, settings)

    async with maker() as s0, _client_ctx(settings, s0) as c0:
        app_id, v1 = await _create(c0, headers)

    async with maker() as sb, maker() as sa:
        # B takes the row lock and stages an UPDATE (updated_at → v2), uncommitted.
        app_b = await sb.get(Application, uuid.UUID(app_id), with_for_update=True)
        assert app_b is not None
        app_b.owner = "team-b"
        await sb.flush()

        # A attempts the same row lock — it MUST block behind B (FOR UPDATE waits).
        task = asyncio.create_task(sa.get(Application, uuid.UUID(app_id), with_for_update=True))
        await asyncio.sleep(0.5)
        assert not task.done(), "FOR UPDATE should serialise A behind B's row lock"

        # Release B (commit v2); A's lock acquisition now completes on the new row.
        await sb.commit()
        app_a = await asyncio.wait_for(task, timeout=10)
        assert app_a is not None
        await sa.rollback()  # drop A's lock/tx before driving the endpoint

        # A's write path (stale v1) is rejected against the now-current v2.
        async with _client_ctx(settings, sa) as ca:
            resp = await ca.patch(
                f"{BASE}/{app_id}", json={"name": "a-late"}, headers=_if_match(headers, v1)
            )
            assert resp.status_code == 409, resp.text
            assert resp.json()["type"] == STALE_TYPE


async def test_conflict_writes_no_audit_and_chain_stays_clean(
    client: httpx.AsyncClient, pg_session: AsyncSession, engineer: User, settings: Settings
) -> None:
    """A rejected precondition appends NO ``application.update`` audit row and the
    hash chain still verifies — the failed attempt never enters the trail."""
    headers = _headers(engineer, settings)
    app_id, v1 = await _create(client, headers)

    # A valid edit advances the row to v2 (this one IS audited).
    ok = await client.patch(
        f"{BASE}/{app_id}", json={"owner": "team-1"}, headers=_if_match(headers, v1)
    )
    assert ok.status_code == 200, ok.text

    # A second edit still holding the stale v1 is rejected — no new audit row.
    stale = await client.patch(
        f"{BASE}/{app_id}", json={"owner": "team-2"}, headers=_if_match(headers, v1)
    )
    assert stale.status_code == 409, stale.text
    assert stale.json()["type"] == STALE_TYPE

    pg_session.expire_all()
    updates = (
        (
            await pg_session.execute(
                select(AuditLog).where(
                    AuditLog.action == audit.APPLICATION_UPDATE,
                    AuditLog.target_id == app_id,
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(updates) == 1  # only the successful edit; the 409 wrote nothing

    result = await verify_chain(pg_session)
    assert result.ok, result.break_
