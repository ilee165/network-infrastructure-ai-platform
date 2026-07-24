"""Report engine on REAL PostgreSQL (P4 W3-T1; ADR-0053 §1/§2/§4).

SQLite must not hide PG semantics for the report surface (P4-PLAN §0a): the
claim row's ``ON CONFLICT DO NOTHING`` under true concurrent connections, the
``bytea`` artifact round-trip with digest integrity, the retention purge, and
the RBAC-scoped listing query all re-assert here against the migrated schema
(migration 0020 ran via ``alembic upgrade head`` in the session fixture).
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from prometheus_client import REGISTRY
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import undefer

from app.engines.reports import deterministic_run_id
from app.engines.reports.payloads import ReportPayload, ReportSection
from app.models import AuditLog
from app.models.dispatch_outbox import DispatchOutbox
from app.models.reports import ReportArtifact, ReportKind, ReportRun, ReportRunStatus
from app.services.report_outbox import enqueue_report
from app.workers.tasks import reports as report_tasks

pytestmark = pytest.mark.integration

_START = datetime(2026, 7, 1, tzinfo=UTC)
_END = datetime(2026, 7, 8, tzinfo=UTC)
_RUN_ID = deterministic_run_id(ReportKind.CHANGE, _START, _END)


def _wire_session(pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the worker's per-phase session seam at the REAL-PG engine."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _pg_session() -> AsyncIterator[AsyncSession]:
        async with maker() as session:
            yield session

    monkeypatch.setattr(report_tasks, "_session", _pg_session)


async def _claim() -> str:
    return await report_tasks._claim_report_run(
        run_id=_RUN_ID,
        kind=ReportKind.CHANGE,
        trigger="scheduled",
        requested_by=None,
        period_start=_START,
        period_end=_END,
    )


async def _enqueue_generation(
    pg_engine: AsyncEngine, *, trigger: str = "on_demand"
) -> tuple[str, str]:
    """Persist the authoritative run + identifier-only dispatch envelope."""
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        await enqueue_report(
            session,
            run_id=_RUN_ID,
            kind=ReportKind.CHANGE,
            period_start=_START,
            period_end=_END,
            trigger=trigger,
            requested_by=None,
        )
        dispatch_id = (
            await session.execute(
                select(DispatchOutbox.id).where(DispatchOutbox.aggregate_id == _RUN_ID)
            )
        ).scalar_one()
        await session.commit()
    return str(dispatch_id), str(_RUN_ID)


async def test_concurrent_claims_yield_exactly_one_row(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Beat + on-demand racing the same (kind, period) cannot double-claim.

    Real PG enforcement (PR #166 F1/F2): two concurrent claim INSERTs on
    distinct connections (NullPool) leave EXACTLY ONE ``report_runs`` row.
    The loser must survive the sibling unique index
    (``uq_report_runs_kind_period``) tripping BEFORE the ``(id)`` arbiter —
    the SAVEPOINT-wrapped claim classifies ANY unique conflict instead of
    raising ``UniqueViolationError`` — and, because the winner's claim is
    YOUNG (actively owned), the loser gets the non-generating
    ``in_progress`` outcome, never ``resumed``.
    """
    _wire_session(pg_engine, monkeypatch)

    outcomes = await asyncio.gather(_claim(), _claim())

    assert sorted(outcomes) == ["claimed", "in_progress"]
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        rows = list((await session.execute(select(ReportRun))).scalars())
    assert len(rows) == 1
    assert rows[0].id == _RUN_ID
    assert rows[0].status == ReportRunStatus.RUNNING.value


async def test_concurrent_generation_yields_exactly_one_generator(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two simultaneous FULL generations for one (kind, period): exactly one
    generates (PR #166 F2).

    The winner claims and generates; the active-consumer loser is rejected
    WITHOUT generating — so there is exactly ONE
    ``report.generated`` audit entry and one csv+pdf artifact pair (no
    duplicate audit, no interleaved artifact delete+insert).
    """
    _wire_session(pg_engine, monkeypatch)
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    dispatch_id, run_id = await _enqueue_generation(pg_engine, trigger="scheduled")
    real_build_payload = report_tasks.build_payload
    winner_building = asyncio.Event()
    release_winner = asyncio.Event()

    async def _blocked_build_payload(session: AsyncSession, **kwargs: Any) -> ReportPayload:
        winner_building.set()
        await release_winner.wait()
        return await real_build_payload(session, **kwargs)

    monkeypatch.setattr(report_tasks, "build_payload", _blocked_build_payload)
    winner = asyncio.create_task(report_tasks._generate_report_core(dispatch_id, run_id))
    await asyncio.wait_for(winner_building.wait(), timeout=5)
    try:
        with pytest.raises(report_tasks.ReportConsumerActive, match="consumer_active"):
            await report_tasks._generate_report_core(dispatch_id, run_id)
    finally:
        release_winner.set()
    result = await winner

    assert result["status"] == "succeeded"
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        runs = list((await session.execute(select(ReportRun))).scalars())
        artifacts = list((await session.execute(select(ReportArtifact))).scalars())
        generated_audits = list(
            (
                await session.execute(select(AuditLog).where(AuditLog.action == "report.generated"))
            ).scalars()
        )
    assert len(runs) == 1
    assert runs[0].status == ReportRunStatus.SUCCEEDED.value
    assert sorted(a.format for a in artifacts) == ["csv", "pdf"]
    assert len(generated_audits) == 1


async def test_sibling_unique_index_conflict_is_classified_not_raised(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DETERMINISTIC bite for the SAVEPOINT claim (PR #166 F1).

    The race test above can be won by the ``(id)`` arbiter suppressing first;
    here ``uq_report_runs_kind_period`` is FORCED to raise (a pre-existing row
    with the same natural key under a DIFFERENT id — no arbiter conflict, so
    PG must error on the sibling index). The claim must classify — never leak
    ``UniqueViolationError`` — and must NOT generate on a row it cannot own.
    """
    _wire_session(pg_engine, monkeypatch)
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        session.add(
            ReportRun(
                id=deterministic_run_id(ReportKind.CHANGE, _START, _END + timedelta(days=1)),
                kind=ReportKind.CHANGE.value,
                trigger="scheduled",
                requested_by=None,
                period_start=_START,
                period_end=_END,
                status=ReportRunStatus.RUNNING.value,
                regime_tags=["soc2:CC8.1"],
            )
        )
        await session.commit()

    outcome = await _claim()  # arbiter (id) clean; sibling unique index raises

    assert outcome == "in_progress"  # non-generating: never claim a foreign row
    async with maker() as session:
        rows = list((await session.execute(select(ReportRun))).scalars())
    assert len(rows) == 1  # no second row, no error escaped


async def test_stale_claim_is_resumed_but_active_claim_is_not(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ownership by claim age on real PG (PR #166 F2): a YOUNG ``running``
    claim is actively owned (``in_progress``); only once ``updated_at`` falls
    beyond ``report_claim_timeout_seconds`` may a new request resume it."""
    _wire_session(pg_engine, monkeypatch)
    assert await _claim() == "claimed"
    # Fresh claim (updated_at = now) → actively owned, loser does not generate.
    assert await _claim() == "in_progress"

    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        run = (await session.execute(select(ReportRun))).scalar_one()
        stale = datetime.now(UTC) - timedelta(hours=2)
        run.updated_at = stale  # explicit value wins over the onupdate refresh
        await session.commit()
    assert await _claim() == "resumed"
    async with maker() as session:
        run = (await session.execute(select(ReportRun))).scalar_one()
        assert run.status == ReportRunStatus.RUNNING.value
        # The resumer refreshed the claim heartbeat (took ownership).
        assert run.updated_at > stale + timedelta(minutes=30)


async def test_claim_classifies_terminal_and_failed_rows(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire_session(pg_engine, monkeypatch)
    assert await _claim() == "claimed"

    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    # Succeeded -> a redelivery is a genuine duplicate (skipped).
    async with maker() as session:
        run = (await session.execute(select(ReportRun))).scalar_one()
        run.status = ReportRunStatus.SUCCEEDED.value
        await session.commit()
    assert await _claim() == "skipped"

    # Failed -> reclaimed for a fresh attempt (fail-closed is not forever).
    async with maker() as session:
        run = (await session.execute(select(ReportRun))).scalar_one()
        run.status = ReportRunStatus.FAILED.value
        run.error_class = "redaction_violation"
        await session.commit()
    assert await _claim() == "reclaimed"
    async with maker() as session:
        run = (await session.execute(select(ReportRun))).scalar_one()
        assert run.status == ReportRunStatus.RUNNING.value
        assert run.error_class is None


async def test_full_generation_and_artifact_bytea_round_trip(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A REAL generation persists csv+pdf artifacts whose bytea bytes survive
    PG storage bit-for-bit (sha256 recomputed on read-back matches)."""
    _wire_session(pg_engine, monkeypatch)
    from app.engines.reports import render

    # Exercise every byte value through the bytea path via the stubbed PDF leg;
    # the CSV leg + redaction choke point stay real.
    binary_blob = b"%PDF-1.7 " + bytes(range(256))
    monkeypatch.setattr(render, "_render_pdf", lambda payload: binary_blob)

    dispatch_id, run_id = await _enqueue_generation(pg_engine)
    result = await report_tasks._generate_report_core(dispatch_id, run_id)
    assert result["status"] == "succeeded"

    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        # content is deferred with raiseload (PR #166 F4) — this test verifies the
        # bytea round-trip, so it must opt in explicitly.
        artifacts = list(
            (
                await session.execute(
                    select(ReportArtifact).options(undefer(ReportArtifact.content))
                )
            ).scalars()
        )
    assert sorted(a.format for a in artifacts) == ["csv", "pdf"]
    for artifact in artifacts:
        assert hashlib.sha256(artifact.content).hexdigest() == artifact.sha256
        assert artifact.size_bytes == len(artifact.content)
        assert artifact.expires_at.tzinfo is not None
    pdf = next(a for a in artifacts if a.format == "pdf")
    assert pdf.content == binary_blob  # bytea round-trip, bit-for-bit


def _full_pem_plant() -> str:
    """Assemble a complete private-key block without a scanner-visible literal."""
    return "\n".join(
        (
            "-----BEGIN RSA " + "PRIVATE KEY-----",
            "MIIEpAIBAAKCAQEA",
            "-----END RSA " + "PRIVATE KEY-----",
        )
    )


def _contains_raw_value(node: Any, planted_value: str) -> bool:
    """Search persisted/result surfaces without escaping multiline values."""
    if isinstance(node, str):
        return planted_value in node
    if isinstance(node, bytes):
        return planted_value.encode() in node
    if isinstance(node, dict):
        return any(
            _contains_raw_value(key, planted_value) or _contains_raw_value(value, planted_value)
            for key, value in node.items()
        )
    if isinstance(node, list | tuple | set | frozenset):
        return any(_contains_raw_value(value, planted_value) for value in node)
    return planted_value in str(node)


@pytest.mark.parametrize(
    ("plant_location", "expected_field_path", "expected_rule"),
    [
        (
            "authorization_header",
            "sections[0].columns[0]",
            "deny_field_name:authorization",
        ),
        (
            "pem_cell",
            "sections[0].rows[0][1]",
            "value_pattern:pem_private_key",
        ),
    ],
    ids=("deny-header", "pem-cell"),
)
async def test_redaction_failure_is_fail_closed_on_pg(
    pg_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    plant_location: str,
    expected_field_path: str,
    expected_rule: str,
) -> None:
    """The real worker persists only bounded failure evidence on PostgreSQL."""
    _wire_session(pg_engine, monkeypatch)
    planted_value = (
        "Authorization" if plant_location == "authorization_header" else _full_pem_plant()
    )

    async def _build_planted_payload(_session: AsyncSession, **kwargs: Any) -> ReportPayload:
        columns = (
            (planted_value, "Value")
            if plant_location == "authorization_header"
            else ("Field", "Value")
        )
        rows = (
            (("Device", "core-sw-01"),)
            if plant_location == "authorization_header"
            else (("Config excerpt", planted_value),)
        )
        return ReportPayload(
            kind=kwargs["kind"].value,
            title="Change Report",
            period_start=kwargs["period_start"],
            period_end=kwargs["period_end"],
            generated_at=kwargs["generated_at"],
            sections=(ReportSection(title="Data", columns=columns, rows=rows),),
        )

    # Payload injection is the only production-behaviour patch: redaction,
    # failure persistence, audit recording, and metrics remain real. The
    # violation occurs before either renderer, so this path needs no PDF stub.
    monkeypatch.setattr(report_tasks, "build_payload", _build_planted_payload)

    failure_labels = {
        "report_kind": ReportKind.CHANGE.value,
        "error_class": report_tasks.ERROR_CLASS_REDACTION,
    }
    before = REGISTRY.get_sample_value("netops_report_failures_total", labels=failure_labels) or 0.0

    dispatch_id, run_id = await _enqueue_generation(pg_engine)
    result = await report_tasks._generate_report_core(dispatch_id, run_id)

    after = REGISTRY.get_sample_value("netops_report_failures_total", labels=failure_labels) or 0.0
    assert after - before == 1
    assert result == {
        "run_id": str(_RUN_ID),
        "status": ReportRunStatus.FAILED.value,
        "error_class": report_tasks.ERROR_CLASS_REDACTION,
    }

    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        runs = list((await session.execute(select(ReportRun))).scalars())
        artifacts = list((await session.execute(select(ReportArtifact))).scalars())
        audits = list((await session.execute(select(AuditLog))).scalars())

    assert len(runs) == 1
    run = runs[0]
    assert run.status == ReportRunStatus.FAILED.value
    assert run.error_class == report_tasks.ERROR_CLASS_REDACTION
    assert run.finished_at is not None
    assert artifacts == []

    assert len(audits) == 1
    failure_audit = audits[0]
    assert failure_audit.actor == "worker:reports"
    assert failure_audit.action == "report.generation_failed"
    assert failure_audit.target_type == "report_run"
    assert failure_audit.target_id == str(_RUN_ID)
    assert failure_audit.detail == {
        "kind": ReportKind.CHANGE.value,
        "error_class": report_tasks.ERROR_CLASS_REDACTION,
        "field_path": expected_field_path,
        "rule": expected_rule,
    }

    persisted_run_state = {
        column.key: getattr(run, column.key) for column in ReportRun.__table__.columns
    }
    persisted_audit_state = {
        column.key: getattr(failure_audit, column.key) for column in AuditLog.__table__.columns
    }
    assert not _contains_raw_value(result, planted_value)
    assert not _contains_raw_value(persisted_audit_state, planted_value)
    assert not _contains_raw_value(
        {"run": persisted_run_state, "artifacts": artifacts}, planted_value
    )


async def test_purge_deletes_only_expired_on_pg(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire_session(pg_engine, monkeypatch)
    assert await _claim() == "claimed"
    now = datetime.now(UTC)
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        session.add_all(
            [
                ReportArtifact(
                    run_id=_RUN_ID,
                    format="csv",
                    content=b"expired",
                    sha256="0" * 64,
                    size_bytes=7,
                    expires_at=now - timedelta(days=1),
                ),
                ReportArtifact(
                    run_id=_RUN_ID,
                    format="pdf",
                    content=b"live",
                    sha256="1" * 64,
                    size_bytes=4,
                    expires_at=now + timedelta(days=2557),
                ),
            ]
        )
        await session.commit()

    result = await report_tasks._purge_expired_core()

    assert result == {"deleted": 1}
    async with maker() as session:
        remaining = list((await session.execute(select(ReportArtifact))).scalars())
    assert [a.format for a in remaining] == ["pdf"]


async def test_kind_scoped_listing_query_on_pg(
    pg_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The RBAC-scoped listing predicate (kind IN visible set) works on PG."""
    _wire_session(pg_engine, monkeypatch)
    maker = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with maker() as session:
        for kind in ReportKind:
            session.add(
                ReportRun(
                    id=deterministic_run_id(kind, _START, _END),
                    kind=kind.value,
                    trigger="scheduled",
                    requested_by=None,
                    period_start=_START,
                    period_end=_END,
                    status=ReportRunStatus.SUCCEEDED.value,
                    regime_tags=["soc2:CC8.1"],
                )
            )
        await session.commit()

    engineer_kinds = ["change", "compliance_posture"]
    async with maker() as session:
        rows = list(
            (
                await session.execute(
                    select(ReportRun)
                    .where(ReportRun.kind.in_(engineer_kinds))
                    .order_by(ReportRun.created_at.desc(), ReportRun.id)
                )
            ).scalars()
        )
    assert sorted(r.kind for r in rows) == engineer_kinds
