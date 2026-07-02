"""Migration 0015 refresh-reuse column on REAL PostgreSQL (audit Wave 2 item 3).

The unit suite exercises the reuse-detection flow end-to-end on SQLite; what
SQLite cannot prove is the migration path itself — that ``alembic upgrade head``
(which this harness runs, conftest ``_migrated_pg``) produces a
``refresh_sessions.current_jti_hash`` column with the exact PG type/nullability
the ORM model assumes, and that the rotate/replay state machine round-trips on
a real Postgres. Tests here follow the ``tests/pg`` routing rule: PG-semantic
paths live in this package and run under the blocking ``pg-integration`` CI job
(skipping cleanly on a host with no reachable Postgres).
"""

from __future__ import annotations

import hashlib
import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.models.identity import RefreshSession, Role, User
from app.models.mixins import utcnow


async def _make_user(pg_session: AsyncSession) -> User:
    """Create a throwaway user on the migration-seeded ``viewer`` role."""
    role = (await pg_session.execute(select(Role).where(Role.name == "viewer"))).scalar_one()
    user = User(
        username=f"reuse-{uuid.uuid4().hex[:12]}",
        password_hash=hash_password("pg-harness-throwaway"),
        role_id=role.id,
    )
    pg_session.add(user)
    await pg_session.flush()
    return user


async def test_migration_0015_column_shape_on_pg(pg_session: AsyncSession) -> None:
    """``current_jti_hash`` exists, is nullable varchar(64) — the model's contract."""
    row = (
        await pg_session.execute(
            text(
                "SELECT data_type, is_nullable, character_maximum_length "
                "FROM information_schema.columns "
                "WHERE table_name = 'refresh_sessions' "
                "AND column_name = 'current_jti_hash'"
            )
        )
    ).one_or_none()
    assert row is not None, "migration 0015 did not add refresh_sessions.current_jti_hash"
    data_type, is_nullable, max_len = row
    assert data_type == "character varying"
    assert is_nullable == "YES"  # additive + nullable: pre-0015 sessions stay valid
    assert max_len == 64  # sha256 hexdigest


async def test_jti_hash_rotate_and_reuse_state_roundtrip_on_pg(
    pg_session: AsyncSession,
) -> None:
    """The rotate → replay-detect → revoke state machine persists on real PG."""
    user = await _make_user(pg_session)

    # Login: session starts with the hash of the first issued jti.
    first_jti = str(uuid.uuid4())
    session_row = RefreshSession(
        user_id=user.id,
        current_jti_hash=hashlib.sha256(first_jti.encode()).hexdigest(),
    )
    pg_session.add(session_row)
    await pg_session.commit()

    # Legitimate rotation: the stored hash advances to the new jti.
    rotated_jti = str(uuid.uuid4())
    session_row.current_jti_hash = hashlib.sha256(rotated_jti.encode()).hexdigest()
    await pg_session.commit()
    pg_session.expire_all()

    reloaded = (
        await pg_session.execute(select(RefreshSession).where(RefreshSession.id == session_row.id))
    ).scalar_one()
    # The stale (first) jti no longer matches — exactly the theft signal the
    # /auth/refresh route acts on.
    stale_hash = hashlib.sha256(first_jti.encode()).hexdigest()
    assert reloaded.current_jti_hash != stale_hash
    assert reloaded.current_jti_hash == hashlib.sha256(rotated_jti.encode()).hexdigest()

    # Reuse detected ⇒ revoke persists alongside the hash.
    reloaded.revoked_at = utcnow()
    await pg_session.commit()
    pg_session.expire_all()
    final = (
        await pg_session.execute(select(RefreshSession).where(RefreshSession.id == session_row.id))
    ).scalar_one()
    assert final.revoked_at is not None
    # No token material at rest: the column holds a 64-char hex digest only.
    assert final.current_jti_hash is not None
    assert len(final.current_jti_hash) == 64
    assert rotated_jti not in final.current_jti_hash


async def test_legacy_null_hash_row_persists_on_pg(pg_session: AsyncSession) -> None:
    """A pre-0015 session (NULL hash) inserts cleanly — the backfill-on-rotate path."""
    user = await _make_user(pg_session)
    session_row = RefreshSession(user_id=user.id)
    pg_session.add(session_row)
    await pg_session.commit()
    pg_session.expire_all()

    reloaded = (
        await pg_session.execute(select(RefreshSession).where(RefreshSession.id == session_row.id))
    ).scalar_one()
    assert reloaded.current_jti_hash is None
    assert reloaded.revoked_at is None
