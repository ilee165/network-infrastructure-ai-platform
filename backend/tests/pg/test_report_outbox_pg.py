"""Real-PostgreSQL crash-window and locking tests for ADR-0059."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.engines.reports import deterministic_run_id
from app.models.dispatch_outbox import DispatchOutbox, DispatchOutboxState
from app.models.reports import ReportKind, ReportRun
from app.services.report_outbox import (
    claim_pending,
    enqueue_report,
    reap_stale_claims,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_report_outbox_rollback_persists_neither_transition_nor_envelope(
    pg_session: AsyncSession,
) -> None:
    await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(
            ReportKind.CHANGE,
            datetime(2026, 7, 1, tzinfo=UTC),
            datetime(2026, 7, 8, tzinfo=UTC),
        ),
        kind=ReportKind.CHANGE,
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="on_demand",
        requested_by=uuid.uuid4(),
    )
    await pg_session.rollback()
    assert await pg_session.scalar(select(func.count()).select_from(ReportRun)) == 0
    assert await pg_session.scalar(select(func.count()).select_from(DispatchOutbox)) == 0


@pytest.mark.asyncio
async def test_report_outbox_committed_row_survives_crash_before_relay(
    pg_session: AsyncSession,
) -> None:
    run = await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(
            ReportKind.CHANGE,
            datetime(2026, 7, 1, tzinfo=UTC),
            datetime(2026, 7, 8, tzinfo=UTC),
        ),
        kind=ReportKind.CHANGE,
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="scheduled",
        requested_by=None,
    )
    await pg_session.commit()
    row = await pg_session.scalar(
        select(DispatchOutbox).where(DispatchOutbox.aggregate_id == run.id)
    )
    assert row is not None
    assert row.state == DispatchOutboxState.PENDING.value


@pytest.mark.asyncio
async def test_report_outbox_stale_claim_returns_to_pending_after_lease(
    pg_session: AsyncSession,
) -> None:
    await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(
            ReportKind.CHANGE,
            datetime(2026, 7, 1, tzinfo=UTC),
            datetime(2026, 7, 8, tzinfo=UTC),
        ),
        kind=ReportKind.CHANGE,
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 8, tzinfo=UTC),
        trigger="scheduled",
        requested_by=None,
    )
    await pg_session.commit()
    claimed = await claim_pending(pg_session, owner="relay-a", batch_size=1)
    await pg_session.commit()
    assert len(claimed) == 1
    claimed[0].claimed_at = datetime.now(UTC) - timedelta(hours=1)
    await pg_session.commit()
    assert await reap_stale_claims(pg_session, lease_seconds=60) == 1
    await pg_session.commit()
    await pg_session.refresh(claimed[0])
    assert claimed[0].state == DispatchOutboxState.PENDING.value


@pytest.mark.asyncio
async def test_report_outbox_concurrent_relays_claim_each_row_once(
    pg_session: AsyncSession,
) -> None:
    start = datetime(2026, 7, 1, tzinfo=UTC)
    end = datetime(2026, 7, 8, tzinfo=UTC)
    await enqueue_report(
        pg_session,
        run_id=deterministic_run_id(ReportKind.CHANGE, start, end),
        kind=ReportKind.CHANGE,
        period_start=start,
        period_end=end,
        trigger="scheduled",
        requested_by=None,
    )
    await pg_session.commit()
    assert pg_session.bind is not None
    maker = async_sessionmaker(pg_session.bind, expire_on_commit=False)
    async with maker() as relay_a, maker() as relay_b:
        first = await claim_pending(relay_a, owner="relay-a", batch_size=1)
        await relay_a.commit()
        second = await claim_pending(relay_b, owner="relay-b", batch_size=1)
        await relay_b.commit()
    assert len(first) == 1
    assert second == []
