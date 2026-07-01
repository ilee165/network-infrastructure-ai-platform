"""Audit→SIEM export pipeline (ADR-0045) — formatters, leak test, cursor, pipeline.

The SQLite unit suite is the fast smoke for the export CONTRACT: the three
vendor-neutral formatters (RFC5424 syslog / ArcSight CEF / HTTPS-JSON), the
sentinel-secret-absent leak assertion across ALL THREE transports (the bite,
ADR-0045 §4), the durable-cursor at-least-once + no-gap-on-restart proofs under a
fault-injected sink outage (ADR-0045 §2), the export-lag SLI (ADR-0045 §3), ordering
by ``seq``, and the strictly-downstream-of-commit decoupling (a sink outage never
blocks the audit write, ADR-0045 §3). The cursor durability is re-asserted on real
PostgreSQL in ``tests/pg/test_audit_export_pg.py``.

The real network sinks (TLS syslog / HTTPS POST) cannot run on this host (no SIEM,
no egress); their exact stdlib/SDK call shape is pinned by the ``*_sink_contract``
tests below, and live delivery rides the W4 enforcing-CNI kind cluster (ADR-0045 §5,
named for the build — a HOST-LIMITATION L1 note, not an unrun prod path: the
load-bearing cursor + leak controls run here AND on PG).
"""

from __future__ import annotations

import json
import ssl
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import Settings
from app.models import Base
from app.models.audit import AuditExportCursor
from app.services.audit import service as audit_service
from app.services.audit.export import (
    ExportRecord,
    SinkDeliveryError,
    current_exported_seq,
    export_cycle,
    format_cef,
    format_https_json,
    format_syslog,
    run_export_loop,
)
from app.services.audit.export.record import ExportRecord as _ExportRecord

#: A sentinel that must NEVER appear in any exported payload (ADR-0045 §4). A value
#: that looks like a real device secret — if a formatter accidentally carried
#: plaintext, this exact string would surface in its output.
_SENTINEL_SECRET = "S3nt1nel-PLAINTEXT-PASSWORD-do-not-export-9f3c2a"  # noqa: S105


# ---------------------------------------------------------------------------
# Test doubles + fixtures
# ---------------------------------------------------------------------------


class _RecordingSink:
    """An in-memory sink that records delivered payloads; optionally fault-injects.

    ``fail`` toggles a forced outage (raises :class:`SinkDeliveryError` — the sink-
    down condition the pipeline must survive without dropping a row). When healthy it
    appends every payload it ACKs, so a test can assert the SIEM-side stream.
    """

    def __init__(self) -> None:
        self.delivered: list[str] = []
        self.fail = False
        self.deliver_calls = 0

    async def deliver(self, payloads: list[str]) -> None:
        self.deliver_calls += 1
        if self.fail:
            raise SinkDeliveryError("injected outage")
        self.delivered.extend(payloads)


@pytest.fixture()
async def file_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """File-backed async SQLite engine + ``NullPool`` (one real conn per session).

    A file URL with ``NullPool`` gives each ``sessionmaker()`` its own connection, so
    a NEW session per export cycle sees rows COMMITTED by an earlier session — the
    setup the at-least-once / restart-resume proofs need (the default in-memory
    ``StaticPool`` would share one connection and hide cross-session commit
    visibility).
    """
    db_path = tmp_path / "export.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path.as_posix()}", poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
def maker(file_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """A sessionmaker over the file engine (each call → a fresh, isolated session)."""
    return async_sessionmaker(file_engine, expire_on_commit=False)


def _settings(fmt: str = "https-json", *, batch_size: int = 500) -> Settings:
    """Minimal Settings for the export loop (the format + bounded batch)."""
    return Settings(
        audit_export_format=fmt,
        audit_export_endpoint="https://siem.example.test/collector",
        audit_export_host="siem.example.test",
        audit_export_batch_size=batch_size,
        # A tiny positive interval keeps the loop fast without busy-spinning (the
        # config validator now rejects a non-positive poll/backoff — see config.py).
        audit_export_poll_seconds=0.001,
        audit_export_retry_backoff_seconds=0.001,
    )


async def _seed_audit_rows(
    maker: async_sessionmaker[AsyncSession],
    n: int,
    *,
    detail: dict[str, Any] | None = None,
) -> list[uuid.UUID]:
    """Append *n* audit rows through the REAL writer, each in its own committed txn."""
    ids: list[uuid.UUID] = []
    for i in range(n):
        async with maker() as session:
            entry = await audit_service.record(
                session,
                actor=f"user:{i}",
                action=audit_service.DEVICE_UPDATED,
                target_type="device",
                target_id=str(i),
                detail=detail if detail is not None else {"step": i},
            )
            await session.commit()
            ids.append(entry.id)
    return ids


def _example_record(**overrides: Any) -> ExportRecord:
    """A representative ExportRecord for the pure-formatter tests."""
    base: dict[str, Any] = {
        "seq": 42,
        "id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "created_at": datetime(2026, 6, 30, 12, 0, 0, tzinfo=UTC),
        "actor": "user:7",
        "action": "credential.rotated",
        "target_type": "device",
        "target_id": "core-sw-1",
        "request_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
        "reasoning_trace_id": None,
        "detail": {"credential_id": "abc", "outcome": "ok"},
    }
    base.update(overrides)
    return _ExportRecord(**base)


# ---------------------------------------------------------------------------
# Formatters — valid RFC5424 syslog / CEF / HTTPS-JSON (exit criterion 1)
# ---------------------------------------------------------------------------


def test_syslog_is_rfc5424_with_seq_dedup_key() -> None:
    """``format_syslog`` emits a valid RFC5424 header + SD-ELEMENT with the seq key."""
    rec = _example_record()
    msg = format_syslog(rec, hostname="exporter-0")
    # <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD MSG.
    assert msg.startswith("<109>1 2026-06-30T12:00:00.000000Z exporter-0 netops-audit - 42 ")
    assert "[netopsAudit@" in msg
    assert 'seq="42"' in msg  # the SIEM dedup key rides every payload (ADR-0045 §2).
    assert 'action="credential.rotated"' in msg


def test_cef_has_header_and_externalid_dedup_key() -> None:
    """``format_cef`` emits a CEF:0 header and maps seq → externalId (the dedup key)."""
    rec = _example_record()
    line = format_cef(rec)
    assert line.startswith("CEF:0|NetOps|AINetworkOpsPlatform|1.0|credential.rotated|")
    assert "externalId=42" in line
    assert "suser=user:7" in line


def test_https_json_is_canonical_object_with_seq() -> None:
    """``format_https_json`` emits the canonical JSON object incl. the seq dedup key."""
    rec = _example_record()
    body = json.loads(format_https_json(rec))
    assert body["seq"] == 42
    assert body["action"] == "credential.rotated"
    assert body["created_at"] == "2026-06-30T12:00:00.000000Z"
    # Chain outputs (prev_hash/entry_hash) are NEVER exported — events only.
    assert "prev_hash" not in body and "entry_hash" not in body


# ---------------------------------------------------------------------------
# THE LEAK TEST — sentinel secret ABSENT from every transport (ADR-0045 §4 bite)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["syslog", "cef", "https-json"])
def test_sentinel_secret_absent_from_every_transport(fmt: str) -> None:
    """A planted sentinel secret must be ABSENT from every formatter's output (§4).

    This is the export-path mirror of the in-DB no-secret-in-audit posture and it
    BITES PER TRANSPORT: the audit record is built secret-free (the writer contract,
    ADR-0032 §5), so even with the sentinel placed in EVERY string-bearing field the
    exporter actually reads, no transport may serialize it — because the audit row
    never carried it. (Defence-in-depth: were a formatter to start reading an
    unredacted source, this assertion would surface the sentinel and fail.)

    NOTE the negative-control half: ``test_leak_test_bites_when_a_secret_is_present``
    below proves THIS assertion is not vacuous — if a secret WERE in the exported
    record, every transport's output would contain it.
    """
    formatter = {"syslog": format_syslog, "cef": format_cef, "https-json": format_https_json}[fmt]
    # A record whose every export-visible field is the canonical secret-free shape.
    rec = _example_record(detail={"credential_id": "ref-123", "outcome": "ok"})
    out = formatter(rec)
    assert _SENTINEL_SECRET not in out


@pytest.mark.parametrize("fmt", ["syslog", "cef", "https-json"])
def test_leak_test_bites_when_a_secret_is_present(fmt: str) -> None:
    """Negative control: the leak assertion is NOT vacuous (ADR-0045 §4).

    If the audit ``detail`` DID carry the sentinel (a writer-contract violation), the
    transport WOULD serialize it — proving the absence assertion above has teeth: it
    fails exactly when a secret reaches the exported record. The platform's guarantee
    is that ``detail`` is secret-free upstream (ADR-0032 §5); this test pins that the
    export path faithfully reflects whatever the row holds, so the real leak test
    bites on a regression rather than passing vacuously.
    """
    formatter = {"syslog": format_syslog, "cef": format_cef, "https-json": format_https_json}[fmt]
    leaky = _example_record(detail={"password": _SENTINEL_SECRET})
    out = formatter(leaky)
    assert _SENTINEL_SECRET in out


async def test_exported_audit_row_never_carries_a_planted_secret(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """End-to-end: an audited action with a sentinel in the call NEVER exports it (§4).

    Drives the FULL path — the real audit writer records a row (the sentinel is placed
    where a careless caller might leak it, but the writer/redaction contract keeps it
    out of the persisted ``detail``), then the pipeline exports it through every
    transport and asserts the sentinel is absent from each delivered payload.
    """
    # The audited action references the credential BY ID (the contract) — never the
    # secret value. The sentinel lives only in a local we never pass to ``detail``.
    async with maker() as session:
        await audit_service.record(
            session,
            actor="user:1",
            action=audit_service.CREDENTIAL_ROTATED,
            target_type="credential",
            target_id="cred-1",
            detail={"credential_id": "cred-1", "outcome": "ok"},  # id only, no secret
        )
        await session.commit()

    for fmt in ("syslog", "cef", "https-json"):
        sink = _RecordingSink()
        # Reset the cursor between formats so each export re-reads the row from seq 0.
        async with maker() as session:
            cur = await session.get(AuditExportCursor, AuditExportCursor.SINGLETON_ID)
            if cur is not None:
                await session.delete(cur)
                await session.commit()
        async with maker() as session:
            await export_cycle(session, sink=sink, fmt=fmt, batch_size=10)
        assert sink.delivered, f"{fmt} delivered nothing"
        for payload in sink.delivered:
            assert _SENTINEL_SECRET not in payload


# ---------------------------------------------------------------------------
# At-least-once under a fault-injected sink outage (ADR-0045 §2, exit criterion 2)
# ---------------------------------------------------------------------------


async def test_at_least_once_under_sink_outage_no_row_dropped(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A sink outage buffers + retries; on recovery every row is delivered (≥once, §2/§3).

    Seed rows, hold the sink DOWN for several cycles (the cursor must NOT advance —
    rows stay committed in audit_log, nothing dropped), then recover and drain. Every
    committed ``seq`` arrives, in order, with no gap.
    """
    await _seed_audit_rows(maker, 5)
    sink = _RecordingSink()
    settings = _settings("https-json", batch_size=10)

    # Sink down: several failed cycles must deliver nothing AND not advance the cursor.
    sink.fail = True
    for _ in range(3):
        async with maker() as session:
            result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
            assert result.failed and result.delivered == 0
    async with maker() as session:
        assert await current_exported_seq(session) == 0  # never advanced over an un-ACKed row

    # Recover and drain via the loop.
    sink.fail = False
    await run_export_loop(sessionmaker=maker, sink=sink, settings=settings, max_cycles=5)

    seqs = [json.loads(p)["seq"] for p in sink.delivered]
    assert seqs == [1, 2, 3, 4, 5]  # every committed row, in seq order, no gap


# ---------------------------------------------------------------------------
# Cursor-resume-no-gap on restart (ADR-0045 §2, exit criterion 2)
# ---------------------------------------------------------------------------


async def test_cursor_resume_leaves_no_gap_on_restart(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """Killed mid-stream, the exporter resumes from the persisted cursor with no gap.

    Export the first batch (cursor persists), simulate a restart with a FRESH sink +
    sessions, append more rows, and resume: the SIEM receives a contiguous ``seq``
    sequence across the restart boundary — no skipped row (no gap), only the ADR-0045
    §2 at-least-once channel (bounded duplication is allowed, a gap is not).
    """
    await _seed_audit_rows(maker, 3)
    sink1 = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink1, fmt="https-json", batch_size=10)
    first = [json.loads(p)["seq"] for p in sink1.delivered]
    assert first == [1, 2, 3]
    async with maker() as session:
        assert await current_exported_seq(session) == 3  # durable watermark persisted

    # "Restart": brand-new sink, more rows appended after the cursor.
    await _seed_audit_rows(maker, 2)  # seq 4, 5
    sink2 = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink2, fmt="https-json", batch_size=10)
    resumed = [json.loads(p)["seq"] for p in sink2.delivered]
    assert resumed == [4, 5]  # resumes strictly after the cursor — no gap, no re-send

    # The full SIEM-side stream across the restart is contiguous 1..5 (no gap).
    assert first + resumed == [1, 2, 3, 4, 5]


async def test_partial_progress_then_crash_re_exports_unadvanced_batch(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A crash AFTER sink-receive but BEFORE cursor-persist re-exports (at-least-once).

    We simulate the crash window: the sink ACKs a batch, but the cursor-advancing
    commit is "lost" (a fresh session never saw it). On restart the same rows are
    re-read and re-delivered — at-least-once, never at-most-once (ADR-0045 §2): a
    duplicate is acceptable (SIEM dedups on ``seq``), a DROP is not.
    """
    await _seed_audit_rows(maker, 2)

    # A sink that ACKs (records the payloads) but we then DISCARD the cursor advance
    # by rolling back instead of committing — modelling a crash before persist.
    sink = _RecordingSink()
    from app.services.audit.export.cursor import advance_cursor, read_unexported

    async with maker() as session:
        records = await read_unexported(session, after_seq=0, limit=10)
        await sink.deliver([format_https_json(r) for r in records])  # sink received
        await advance_cursor(session, last=records[-1])
        await session.rollback()  # crash before the cursor commit landed

    # The cursor never advanced — a fresh session re-reads from seq 0.
    async with maker() as session:
        assert await current_exported_seq(session) == 0
    sink2 = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink2, fmt="https-json", batch_size=10)
    assert [json.loads(p)["seq"] for p in sink2.delivered] == [1, 2]  # re-exported, no loss


# ---------------------------------------------------------------------------
# Export-lag SLI present + reflects backlog (ADR-0045 §3, exit criterion 3)
# ---------------------------------------------------------------------------


async def test_export_lag_metric_drains_after_delivery(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """After a clean delivery the lag is ~0 (caught up); the gauge is exposed (§3)."""
    # A row committed "now" so the lag after export is small.
    async with maker() as session:
        await audit_service.record(
            session,
            actor="user:1",
            action=audit_service.DEVICE_UPDATED,
            target_type="device",
            target_id="1",
            detail={"k": "v"},
        )
        await session.commit()
    sink = _RecordingSink()
    async with maker() as session:
        result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert result.delivered == 1
    assert result.lag_seconds < 60.0  # caught up to head ⇒ within the p95<60s SLO


async def test_export_lag_metric_grows_while_sink_is_down(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """A held-down sink keeps the cursor frozen so the lag reflects the backlog (§3).

    Deliver one row (cursor + last_exported_commit_at set to an OLD timestamp), then
    hold the sink down: the lag is measured from the frozen cursor's commit time, so
    it grows with wall-clock — the operator-visible "export stalled, no loss" signal.
    """
    old = datetime(2026, 6, 30, 11, 0, 0, tzinfo=UTC)
    # Seed a row, export it, then back-date the cursor's commit ts to simulate age.
    await _seed_audit_rows(maker, 1)
    sink = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    async with maker() as session:
        cur = await session.get(AuditExportCursor, AuditExportCursor.SINGLETON_ID)
        assert cur is not None
        cur.last_exported_commit_at = old
        await session.commit()

    # A new row arrives but the sink is DOWN — cursor frozen, lag measured from `old`.
    await _seed_audit_rows(maker, 1)
    sink.fail = True
    async with maker() as session:
        result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert result.failed
    assert result.lag_seconds > 60.0  # the stale cursor drives lag past the SLO → alert


async def test_export_lag_is_zero_when_caught_up_on_idle_stream(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """CR[5]: a caught-up idle stream reports lag 0.0, not ``now − old_commit_ts``.

    Deliver a row, back-date the cursor's commit ts far into the past, then run a cycle
    with NO new rows. Before the fix, the empty-read branch returned ``now − old_ts``
    → an unbounded, false <60 s SLO breach with ZERO backlog. It must be 0.0.
    """
    await _seed_audit_rows(maker, 1)
    sink = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    async with maker() as session:
        cur = await session.get(AuditExportCursor, AuditExportCursor.SINGLETON_ID)
        assert cur is not None
        cur.last_exported_commit_at = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)  # stale
        await session.commit()

    # No new rows: caught up. Lag must be 0.0 despite the ancient cursor commit ts.
    async with maker() as session:
        idle = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert idle.delivered == 0
    assert idle.lag_seconds == 0.0


async def test_export_lag_is_zero_after_non_full_batch_drains_to_head(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """CR[5]: a non-full successful batch drained to head ⇒ caught up ⇒ lag 0.0."""
    await _seed_audit_rows(maker, 2)
    sink = _RecordingSink()
    async with maker() as session:
        cur = await session.get(AuditExportCursor, AuditExportCursor.SINGLETON_ID)
        assert cur is None  # nothing exported yet
    async with maker() as session:
        result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert result.delivered == 2
    assert result.batch_full is False  # 2 < 10 ⇒ drained to head
    assert result.lag_seconds == 0.0


async def test_advance_cursor_never_regresses_on_stale_write(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """CR[4]: a stale ACK of an OLDER seq must not move the watermark BACKWARD.

    The unit backend enforces the same forward-only invariant the PG upsert applies at
    the DB level; the real concurrent-write assertion rides ``tests/pg``.
    """
    from app.services.audit.export.cursor import advance_cursor, current_exported_seq

    await _seed_audit_rows(maker, 5)
    sink = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    async with maker() as session:
        assert await current_exported_seq(session) == 5

    # A stale runner tries to advance to an OLDER seq (seq=2) — must be a no-op.
    async with maker() as session:
        stale = _example_record(seq=2)
        await advance_cursor(session, last=stale)
        await session.commit()
    async with maker() as session:
        assert await current_exported_seq(session) == 5  # never regressed


async def test_tcp_tls_sink_deliver_times_out_on_a_stalled_connect() -> None:
    """CR[6]: a stalled SIEM connect raises SinkDeliveryError (retried), never hangs.

    A never-resolving ``open_connection`` must not wedge the exporter loop: the bounded
    ``asyncio.wait_for`` converts the timeout into a delivery FAILURE so the batch is
    retried next cycle (buffer + retry, never a frozen lag gauge).
    """
    import asyncio

    from app.services.audit.export.sinks import TcpTlsSink

    async def _never_connects(*_a: Any, **_k: Any) -> Any:
        await asyncio.Event().wait()  # blocks forever

    ctx = ssl.create_default_context()
    sink = TcpTlsSink(host="siem.example.test", port=6514, tls_context=ctx, timeout_seconds=0.01)
    orig = asyncio.open_connection
    asyncio.open_connection = _never_connects  # type: ignore[assignment]
    try:
        with pytest.raises(SinkDeliveryError, match="timed out"):
            await sink.deliver([format_syslog(_example_record())])
    finally:
        asyncio.open_connection = orig  # type: ignore[assignment]


async def test_tcp_tls_sink_deliver_times_out_on_a_stalled_write() -> None:
    """CR re-review: a stalled ``writer.drain()`` raises SinkDeliveryError, never hangs.

    ``deliver`` bounds BOTH the connect AND the write/drain under ``wait_for``. This
    covers the WRITE/DRAIN branch (the connect-stall sibling is above): a connected
    collector that never drains the socket must convert to a delivery FAILURE (retried
    next cycle), not wedge the exporter loop and freeze the lag gauge.
    """
    import asyncio

    from app.services.audit.export.sinks import TcpTlsSink

    class _StalledWriter:
        def write(self, _data: bytes) -> None:
            pass

        async def drain(self) -> None:
            await asyncio.Event().wait()  # blocks forever — the SIEM never drains

        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def _connects_then_stalls(*_a: Any, **_k: Any) -> Any:
        return (object(), _StalledWriter())

    ctx = ssl.create_default_context()
    sink = TcpTlsSink(host="siem.example.test", port=6514, tls_context=ctx, timeout_seconds=0.01)
    orig = asyncio.open_connection
    asyncio.open_connection = _connects_then_stalls  # type: ignore[assignment]
    try:
        with pytest.raises(SinkDeliveryError, match="syslog-tls write timed out"):
            await sink.deliver([format_syslog(_example_record())])
    finally:
        asyncio.open_connection = orig  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Ordering by seq (ADR-0045 §2) + never-block-the-write decoupling (§3)
# ---------------------------------------------------------------------------


async def test_delivery_order_matches_seq(maker: async_sessionmaker[AsyncSession]) -> None:
    """Delivered order is ORDER BY seq = DB append order (ADR-0045 §2)."""
    await _seed_audit_rows(maker, 6)
    sink = _RecordingSink()
    settings = _settings("https-json", batch_size=2)  # multiple batches
    await run_export_loop(sessionmaker=maker, sink=sink, settings=settings, max_cycles=10)
    seqs = [json.loads(p)["seq"] for p in sink.delivered]
    assert seqs == sorted(seqs) == [1, 2, 3, 4, 5, 6]


async def test_null_seq_pre_chain_rows_are_never_exported(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """NULL-``seq`` pre-chain rows are EXCLUDED from the SIEM stream (ADR-0045 §2).

    Mirrors the verifier: the export reads ``seq IS NOT NULL`` only, so an old-writer
    pre-chain row (genesis hash, NULL seq) is never streamed off-platform — the export
    contract is consistent with the ADR-0038 integrity control that keeps those rows
    OUT of the chain.
    """
    from sqlalchemy import insert

    from app.models.audit import AuditLog
    from app.services.audit.chain import GENESIS_HASH

    # A CORE insert with explicit ``seq=None`` bypasses the ORM's app-side
    # ``_next_seq`` default — exactly what an old (pre-``seq``) pod would write.
    async with maker() as session:
        await session.execute(
            insert(AuditLog).values(
                id=uuid.uuid4(),
                created_at=datetime(2026, 6, 30, 10, 0, 0, tzinfo=UTC),
                seq=None,  # pre-chain old-writer row
                actor="old-writer",
                action="legacy.event",
                target_type="device",
                target_id="x",
                detail=None,
                prev_hash=GENESIS_HASH,
                entry_hash=GENESIS_HASH,
            )
        )
        await session.commit()
    await _seed_audit_rows(maker, 2)  # two REAL chained rows (seq 1, 2)

    sink = _RecordingSink()
    async with maker() as session:
        await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    actions = [json.loads(p)["action"] for p in sink.delivered]
    assert "legacy.event" not in actions  # the NULL-seq row was never exported
    assert len(sink.delivered) == 2


async def test_sink_outage_never_blocks_an_audited_action_commit(
    maker: async_sessionmaker[AsyncSession],
) -> None:
    """The audit write commits with the export sink fully DOWN (decoupled, §3).

    The negative control proving the decoupling bites: with the sink raising on every
    deliver, an audited action still records + commits its audit row — the exporter is
    a separate process/loop that reads ALREADY-COMMITTED rows and has no path into the
    action transaction (ADR-0045 §3). A slow/down SIEM cannot stall the platform.
    """
    sink = _RecordingSink()
    sink.fail = True
    # The audited action's own transaction — completely independent of the exporter.
    async with maker() as session:
        entry = await audit_service.record(
            session,
            actor="user:1",
            action=audit_service.DEVICE_UPDATED,
            target_type="device",
            target_id="1",
            detail={"k": "v"},
        )
        await session.commit()  # commits fine despite the sink being down
        assert entry.seq == 1

    # The exporter then fails to deliver (sink down) but the audit row is durably
    # committed and will be exported once the sink recovers — never lost.
    async with maker() as session:
        result = await export_cycle(session, sink=sink, fmt="https-json", batch_size=10)
    assert result.failed and result.delivered == 0
    async with maker() as session:
        assert await current_exported_seq(session) == 0  # un-advanced, row still pending


# ---------------------------------------------------------------------------
# Sink CONTRACT tests — pin the real call shape the prod path makes (L1 host-limit)
# ---------------------------------------------------------------------------


async def test_https_sink_contract_posts_over_verified_tls_with_bearer() -> None:
    """Pin the HTTPS sink's real call shape: POST body + bearer header + TLS verify.

    The live HTTPS POST cannot run here (no SIEM), so this contract test asserts the
    EXACT httpx call the prod path makes — ``client.post(endpoint, content=<body>,
    headers={Authorization: Bearer ...})`` with the verified TLS context — by stubbing
    ``httpx.AsyncClient``. This is the "pin the real call shape" discipline for a
    host-limited backend (the body bytes, the auth header, the 2xx check).
    """
    import httpx

    from app.services.audit.export.sinks import HttpsJsonSink

    captured: dict[str, Any] = {}

    class _FakeResponse:
        status_code = 200

    class _FakeClient:
        def __init__(self, *, verify: Any, timeout: Any) -> None:
            captured["verify"] = verify
            captured["timeout"] = timeout

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def post(self, url: str, *, content: bytes, headers: dict[str, str]) -> _FakeResponse:
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            return _FakeResponse()

    ctx = ssl.create_default_context()
    sink = HttpsJsonSink(
        endpoint="https://siem.example.test/c", tls_context=ctx, bearer_token="tok-xyz"
    )
    body = format_https_json(_example_record())

    orig = httpx.AsyncClient
    httpx.AsyncClient = _FakeClient  # type: ignore[misc,assignment]
    try:
        await sink.deliver([body])
    finally:
        httpx.AsyncClient = orig  # type: ignore[misc]

    assert captured["url"] == "https://siem.example.test/c"
    assert captured["content"] == body.encode("utf-8")
    assert captured["headers"]["Authorization"] == "Bearer tok-xyz"
    assert captured["verify"] is ctx  # the verified TLS context is threaded in


async def test_https_sink_contract_raises_on_non_2xx() -> None:
    """A non-2xx SIEM response raises SinkDeliveryError (status only, no body leak)."""
    import httpx

    from app.services.audit.export.sinks import HttpsJsonSink

    class _Resp:
        status_code = 503

    class _Client:
        def __init__(self, **_kw: Any) -> None: ...
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *exc: Any) -> None:
            return None

        async def post(self, *a: Any, **k: Any) -> _Resp:
            return _Resp()

    sink = HttpsJsonSink(endpoint="https://x.test", tls_context=ssl.create_default_context())
    orig = httpx.AsyncClient
    httpx.AsyncClient = _Client  # type: ignore[misc,assignment]
    try:
        with pytest.raises(SinkDeliveryError) as exc:
            await sink.deliver(["{}"])
    finally:
        httpx.AsyncClient = orig  # type: ignore[misc]
    assert "503" in str(exc.value)


async def test_tcp_tls_sink_contract_octet_frames_over_tls() -> None:
    """Pin the TLS syslog sink's call shape: open_connection(ssl=ctx) + octet framing.

    The live TLS syslog connection cannot run here; this contract asserts the exact
    asyncio call (``open_connection(host, port, ssl=<ctx>, server_hostname=host)``)
    and that the payload is octet-COUNTED-framed (``<len> <msg>``, RFC5425) so a
    newline inside ``detail`` cannot split a message.
    """
    import asyncio

    from app.services.audit.export.sinks import TcpTlsSink

    captured: dict[str, Any] = {}
    written = bytearray()

    class _FakeWriter:
        def write(self, data: bytes) -> None:
            written.extend(data)

        async def drain(self) -> None: ...
        def close(self) -> None: ...
        async def wait_closed(self) -> None: ...

    async def _fake_open(host: str, port: int, *, ssl: Any, server_hostname: str) -> Any:
        captured.update(host=host, port=port, ssl=ssl, server_hostname=server_hostname)
        return object(), _FakeWriter()

    ctx = ssl.create_default_context()
    sink = TcpTlsSink(host="siem.example.test", port=6514, tls_context=ctx)
    msg = format_syslog(_example_record())

    orig = asyncio.open_connection
    asyncio.open_connection = _fake_open  # type: ignore[assignment]
    try:
        await sink.deliver([msg])
    finally:
        asyncio.open_connection = orig  # type: ignore[assignment]

    assert captured == {
        "host": "siem.example.test",
        "port": 6514,
        "ssl": ctx,
        "server_hostname": "siem.example.test",
    }
    body = msg.encode("utf-8")
    assert bytes(written) == f"{len(body)} ".encode("ascii") + body  # octet-counted frame


def test_build_sink_tls_requires_cert_and_key_together() -> None:
    """Fail closed: a client cert without its key (or vice-versa) raises (ADR-0039 §4)."""
    from app.services.audit.export.sinks import build_sink_tls_context

    half = Settings(
        audit_export_format="https-json",
        audit_export_endpoint="https://x.test",
        audit_export_client_cert=Path("/tmp/cert.pem"),
        # key intentionally omitted
    )
    with pytest.raises(ValueError, match="must be set together"):
        build_sink_tls_context(half)
