"""Audit→SIEM export durable cursor (ADR-0045 §2) re-asserted under REAL PostgreSQL.

The SQLite unit suite (``tests/services/test_audit_export.py``) is the fast smoke for
the export contract; THIS module re-asserts the LOAD-BEARING half — the durable
``seq`` cursor's at-least-once + cursor-resume-NO-GAP behaviour — against a real
Postgres so the W3-T1 exit criterion ("proven on real PG") does not rest on a backend
that hides cross-connection commit/visibility semantics:

  * **At-least-once under a fault-injected sink outage** — a held-down sink never
    advances the cursor (rows stay committed in ``audit_log``, nothing dropped); on
    recovery every committed ``seq`` is delivered, in order, no gap.
  * **Cursor-resume-no-gap on restart** — the watermark persisted by one PG session
    is read by a FRESH session (a true cross-connection commit, which SQLite's shared
    in-memory pool cannot model); the resumed export skips no row.
  * **NULL-``seq`` pre-chain rows excluded** — the export read carries the same
    ``seq IS NOT NULL`` filter the ADR-0038 verifier applies, on real PG ordering.
  * **Never blocks the audit write** — an audited action commits with the export sink
    fully down; the exporter only ever reads ALREADY-COMMITTED rows (ADR-0045 §3).

Secret-surface (ADR-0045 §4): audit rows are secret-free by construction; no fixture
or assertion here contains a plaintext secret. The real network sinks (TLS syslog /
HTTPS) are host-limited — their call shape is pinned by the unit-suite contract tests
and live delivery rides the W4 enforcing-CNI kind cluster (ADR-0045 §5).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.models.audit import AuditLog
from app.services.audit import chain
from app.services.audit import service as audit_service
from app.services.audit.export import (
    SinkDeliveryError,
    current_exported_seq,
    export_cycle,
    run_export_loop,
)

pytestmark = pytest.mark.integration


class _RecordingSink:
    """In-memory sink that records ACKed payloads and can fault-inject an outage."""

    def __init__(self) -> None:
        self.delivered: list[str] = []
        self.fail = False

    async def deliver(self, payloads: list[str]) -> None:
        if self.fail:
            raise SinkDeliveryError("injected outage")
        self.delivered.extend(payloads)


def _maker(pg_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """A sessionmaker over the NullPool PG engine — a fresh connection per session."""
    return async_sessionmaker(pg_engine, expire_on_commit=False)


def _settings(batch_size: int = 500) -> Settings:
    return Settings(
        audit_export_format="https-json",
        audit_export_endpoint="https://siem.example.test/c",
        audit_export_batch_size=batch_size,
        # Tiny positive interval (the config validator now rejects non-positive
        # poll/backoff — busy-spin guard, see config.py).
        audit_export_poll_seconds=0.001,
        audit_export_retry_backoff_seconds=0.001,
    )


async def _seed(maker: async_sessionmaker[AsyncSession], n: int) -> None:
    """Append *n* chained audit rows through the REAL writer (advisory-lock path)."""
    for i in range(n):
        async with maker() as session:
            await audit_service.record(
                session,
                actor=f"user:{i}",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id=str(i),
                detail={"step": i},
            )
            await session.commit()


async def test_at_least_once_under_sink_outage_on_pg(pg_engine: AsyncEngine) -> None:
    """A SIEM outage drops NO row on real PG: cursor frozen, then full drain (§2/§3)."""
    maker = _maker(pg_engine)
    await _seed(maker, 5)
    sink = _RecordingSink()

    sink.fail = True
    for _ in range(3):
        async with maker() as session:
            result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
            assert result.failed and result.delivered == 0
    async with maker() as session:
        assert await current_exported_seq(session) == 0  # never advanced over un-ACKed rows

    sink.fail = False
    await run_export_loop(sessionmaker=maker, sink=sink, settings=_settings(10), max_cycles=5)
    assert [json.loads(p)["seq"] for p in sink.delivered] == [1, 2, 3, 4, 5]


async def test_cursor_resume_no_gap_across_pg_sessions(pg_engine: AsyncEngine) -> None:
    """A watermark persisted by one PG session resumes a FRESH session with no gap (§2).

    This is the real cross-connection commit SQLite cannot model: session A advances
    the durable cursor and COMMITS; a brand-new session B (own connection, NullPool)
    reads that committed watermark and resumes strictly after it.
    """
    maker = _maker(pg_engine)
    await _seed(maker, 3)

    sink1 = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink1, fmt="https-json", batch_size=10)
    assert [json.loads(p)["seq"] for p in sink1.delivered] == [1, 2, 3]
    async with maker() as session:
        assert await current_exported_seq(session) == 3  # durable across the connection

    await _seed(maker, 2)  # seq 4, 5 appended after the cursor
    sink2 = _RecordingSink()  # "restart" — fresh exporter state
    async with maker() as session:
        await export_cycle(session, sink=sink2, fmt="https-json", batch_size=10)
    assert [json.loads(p)["seq"] for p in sink2.delivered] == [4, 5]  # no gap, no re-send


async def test_advance_cursor_is_monotonic_no_regress_on_pg(pg_engine: AsyncEngine) -> None:
    """CR[4]: the PG upsert is forward-only — a STALE write cannot regress the cursor.

    The watermark is advanced to seq=3; a concurrent stale runner then upserts an OLDER
    seq=1 (a rolling-update overlap re-ACKing a superseded batch). The DB-level
    ``ON CONFLICT ... WHERE cursor.exported_seq < EXCLUDED.exported_seq`` guard makes
    that a NO-OP, so the cursor stays at 3 — never moves backward, never PK-collides.
    """
    from datetime import UTC, datetime

    from app.services.audit.export.cursor import advance_cursor
    from app.services.audit.export.record import ExportRecord

    maker = _maker(pg_engine)
    await _seed(maker, 3)
    sink = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    async with maker() as session:
        assert await current_exported_seq(session) == 3

    stale = ExportRecord(
        seq=1,
        id=uuid.uuid4(),
        created_at=datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC),
        actor="stale-runner",
        action="legacy.write",
        target_type="device",
        target_id="1",
        request_id=None,
        reasoning_trace_id=None,
        detail=None,
    )
    async with maker() as session:
        await advance_cursor(session, last=stale)
        await session.commit()
    async with maker() as session:
        assert await current_exported_seq(session) == 3  # forward-only: no regress


async def test_null_seq_pre_chain_row_excluded_on_pg(pg_engine: AsyncEngine) -> None:
    """The export read excludes NULL-``seq`` pre-chain rows on real PG (ADR-0045 §2)."""
    maker = _maker(pg_engine)
    async with maker() as session:
        await session.execute(
            AuditLog.__table__.insert().values(
                id=uuid.uuid4(),
                created_at=datetime(2026, 6, 30, 10, 0, 0, tzinfo=UTC),
                seq=None,
                actor="old-pod",
                action="legacy.write",
                target_type="device",
                target_id="legacy",
                detail=None,
                reasoning_trace_id=None,
                request_id=None,
                prev_hash=chain.GENESIS_HASH,
                entry_hash=chain.GENESIS_HASH,
            )
        )
        await session.commit()
    await _seed(maker, 2)

    sink = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    actions = [json.loads(p)["action"] for p in sink.delivered]
    assert "legacy.write" not in actions
    assert len(sink.delivered) == 2


async def test_sink_outage_never_blocks_audit_write_on_pg(pg_engine: AsyncEngine) -> None:
    """An audited action commits on PG with the export sink fully down (decoupled, §3)."""
    maker = _maker(pg_engine)
    sink = _RecordingSink()
    sink.fail = True

    async with maker() as session:
        entry = await audit_service.record(
            session,
            actor="user:1",
            action=audit_service.DEVICE_UPDATED,
            target_type="device",
            target_id="1",
            detail={"k": "v"},
        )
        await session.commit()  # commits despite the sink being down
        assert entry.seq == 1

    async with maker() as session:
        result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert result.failed and result.delivered == 0
    async with maker() as session:
        assert await current_exported_seq(session) == 0  # row durably pending, not lost


async def test_export_lag_grows_then_drains_on_pg(pg_engine: AsyncEngine) -> None:
    """The lag SLI climbs while the sink is down and drains on recovery (ADR-0045 §3)."""
    maker = _maker(pg_engine)
    await _seed(maker, 1)
    sink = _RecordingSink()

    # Caught up after a clean delivery ⇒ lag within the SLO.
    async with maker() as session:
        ok = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert ok.delivered == 1 and ok.lag_seconds < 60.0

    # Back-date the cursor's commit ts; a held-down sink then shows a large lag.
    from app.models.audit import AuditExportCursor

    async with maker() as session:
        cur = await session.get(AuditExportCursor, AuditExportCursor.SINGLETON_ID)
        assert cur is not None
        cur.last_exported_commit_at = datetime(2026, 6, 30, 11, 0, 0, tzinfo=UTC)
        await session.commit()
    await _seed(maker, 1)
    sink.fail = True
    async with maker() as session:
        down = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert down.failed and down.lag_seconds > 60.0
