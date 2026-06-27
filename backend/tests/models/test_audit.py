"""AuditLog roundtrips: composite PK semantics + JSON detail payloads."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog

# These tests construct AuditLog DIRECTLY (bypassing the writer) to exercise the
# composite-PK / JSON-detail schema semantics, so they must supply the now-required
# hash-chain columns themselves (ADR-0038 §1: prev_hash/entry_hash are NOT NULL —
# the application writer normally sets them; here a fixed genesis-shaped placeholder
# keeps the focus on the PK/detail behaviour under test).
#
# ``seq`` is also supplied explicitly: the model's ``_next_seq`` default reads
# MAX(seq)+1, which cannot disambiguate two rows added in the SAME batch flush (both
# would read MAX=0 → 1 → a duplicate seq). ``seq`` carries no UNIQUE constraint
# (round-3 #03/#04: a UNIQUE index on seq alone is invalid on the PG partitioned
# parent; uniqueness rests on the writer's MAX(seq)+1 under the append advisory lock,
# one flush per append), so these direct-construct tests pass distinct ``seq`` values
# to keep the chain order key unambiguous.
_CHAIN = {"prev_hash": b"\x00" * 32, "entry_hash": b"\x11" * 32}


async def test_audit_log_roundtrip_with_json_detail(session: AsyncSession) -> None:
    """An audit entry persists and its JSON detail dict roundtrips intact."""
    detail = {
        "before": {"status": "new"},
        "after": {"status": "reachable"},
        "reason": "discovery run 42 marked device reachable",
    }
    entry = AuditLog(
        actor="system:discovery",
        action="device.status.update",
        target_type="device",
        target_id=str(uuid.uuid4()),
        detail=detail,
        **_CHAIN,
    )
    session.add(entry)
    await session.commit()

    reloaded = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.id == entry.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.detail == detail
    assert reloaded.created_at.tzinfo == UTC
    assert reloaded.actor == "system:discovery"


async def test_audit_log_detail_is_nullable(session: AsyncSession) -> None:
    entry = AuditLog(
        actor="admin", action="auth.login", target_type="user", target_id=None, **_CHAIN
    )
    session.add(entry)
    await session.flush()
    assert entry.detail is None


async def test_composite_pk_allows_same_id_in_different_partitions(
    session: AsyncSession,
) -> None:
    """PK is (id, created_at): same id with distinct created_at is two rows."""
    shared_id = uuid.uuid4()
    session.add_all(
        [
            AuditLog(
                id=shared_id,
                created_at=datetime(2026, 5, 1, tzinfo=UTC),
                seq=1,
                actor="a",
                action="x",
                target_type="t",
                **_CHAIN,
            ),
            AuditLog(
                id=shared_id,
                created_at=datetime(2026, 6, 1, tzinfo=UTC),
                seq=2,
                actor="a",
                action="x",
                target_type="t",
                **_CHAIN,
            ),
        ]
    )
    await session.flush()


async def test_composite_pk_rejects_full_duplicate(session: AsyncSession) -> None:
    shared_id = uuid.uuid4()
    instant = datetime(2026, 6, 1, tzinfo=UTC)
    session.add(
        AuditLog(id=shared_id, created_at=instant, actor="a", action="x", target_type="t", **_CHAIN)
    )
    await session.flush()
    session.add(
        AuditLog(id=shared_id, created_at=instant, actor="b", action="y", target_type="t", **_CHAIN)
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()
