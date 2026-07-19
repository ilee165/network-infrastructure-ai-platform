"""Change-report roll-up queries on REAL PostgreSQL (P4 W3-T2; ADR-0053 §7.1).

The change report is aggregation-heavy (DISTINCT over audit ``target_id``,
LIKE-prefix action filtering, cross-table identity joins) — SQLite must not
hide PG semantics (spec requirement 4), so every builder query re-asserts here
against the migrated schema: multi-CR periods, the empty period, agent-executor
rows, rejected/rolled-back CRs, CLOSED-OPEN period edges (start instant
included, end instant excluded), non-UTC-stored timestamps normalizing, and a
full ``reports.generate`` run driving the same queries inside the engine path.

Timestamps are anchored to the CURRENT UTC month so every ``audit_log`` insert
lands in a partition the migration chain has already created.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import undefer

from app.engines.reports.change_report import (
    NOTE_EMPTY_PERIOD,
    SECTION_APPROVALS,
    SECTION_CHANGE_REQUESTS,
    SECTION_DIFF_STATISTICS,
    SECTION_TRANSITIONS,
    build_change_sections,
)
from app.engines.reports.payloads import ReportSection
from app.models import AuditLog
from app.models.change_requests import (
    Approval,
    ApprovalDecision,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
)
from app.models.identity import Role, User
from app.models.reports import ReportArtifact
from app.services.audit import service as audit_actions
from app.workers.tasks import reports as report_tasks

pytestmark = pytest.mark.integration

#: Anchor every timestamp inside the current UTC month: the alembic chain has
#: created this month's ``audit_log`` partition (the harness migrates at session
#: start), so seeded rows always have a landing partition.
_ANCHOR = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
_START = _ANCHOR + timedelta(days=1)
_END = _ANCHOR + timedelta(days=3)

_BASELINE_HASH = "cd" * 32


def _section(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(s for s in sections if s.title == title)


def _audit(cr_id: uuid.UUID, action: str, at: datetime, actor: str) -> AuditLog:
    return AuditLog(
        actor=actor,
        action=action,
        target_type="change_request",
        target_id=str(cr_id),
        created_at=at,
    )


async def _seed_users(session: AsyncSession) -> tuple[User, User]:
    """Two throwaway users on the migration-seeded ``engineer`` role."""
    role_id = (await session.execute(select(Role.id).where(Role.name == "engineer"))).scalar_one()
    requester = User(
        username=f"t2-requester-{uuid.uuid4().hex[:8]}",
        password_hash="x",
        role_id=role_id,
        is_active=True,
    )
    approver = User(
        username=f"t2-approver-{uuid.uuid4().hex[:8]}",
        password_hash="x",
        role_id=role_id,
        is_active=True,
        idp_iss="https://idp.example.test",
        idp_subject=f"idp-sub-{uuid.uuid4().hex[:8]}",
    )
    session.add_all([requester, approver])
    await session.commit()
    return requester, approver


def _cr(
    requester: User,
    *,
    state: ChangeRequestState,
    created_at: datetime,
    after_state: dict[str, Any] | None = None,
    rollback_plan: dict[str, Any] | None = None,
) -> ChangeRequest:
    return ChangeRequest(
        state=state,
        kind=ChangeRequestKind.CONFIG,
        requester_id=requester.id,
        four_eyes_required=True,
        after_state=after_state,
        rollback_plan=rollback_plan,
        created_at=created_at,
        updated_at=created_at,
    )


async def test_multi_cr_period_rollup_on_pg(pg_session: AsyncSession) -> None:
    """Two in-period CRs (agent-executed + rejected) roll up; an out-of-period
    CR is excluded — the DISTINCT/LIKE/join stack under real PG semantics."""
    requester, approver = await _seed_users(pg_session)
    executed = _cr(
        requester,
        state=ChangeRequestState.COMPLETED,
        created_at=_START + timedelta(hours=1),
        after_state={
            "outcome": "applied",
            "verified": True,
            "applied_diff": ["+ 2 added", "- 1 removed"],
        },
        rollback_plan={"baseline_content_hash": _BASELINE_HASH},
    )
    rejected = _cr(
        requester, state=ChangeRequestState.DRAFT, created_at=_START + timedelta(hours=2)
    )
    out_of_period = _cr(
        requester, state=ChangeRequestState.DRAFT, created_at=_ANCHOR + timedelta(hours=1)
    )
    pg_session.add_all([executed, rejected, out_of_period])
    await pg_session.commit()

    pg_session.add_all(
        [
            _audit(
                executed.id,
                audit_actions.CHANGE_REQUEST_CREATED,
                _START + timedelta(hours=1),
                f"user:{requester.id}",
            ),
            _audit(
                executed.id,
                audit_actions.CHANGE_REQUEST_DRAFT_TO_PENDING,
                _START + timedelta(hours=1, minutes=5),
                f"user:{requester.id}",
            ),
            _audit(
                executed.id,
                audit_actions.CHANGE_REQUEST_PENDING_TO_APPROVED,
                _START + timedelta(hours=1, minutes=30),
                f"user:{approver.id}",
            ),
            _audit(
                executed.id,
                audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
                _START + timedelta(hours=1, minutes=45),
                "agent:automation",
            ),
            _audit(
                executed.id,
                audit_actions.CHANGE_REQUEST_EXECUTING_TO_COMPLETED,
                _START + timedelta(hours=1, minutes=50),
                "agent:automation",
            ),
            Approval(
                change_request_id=executed.id,
                actor_id=approver.id,
                decision=ApprovalDecision.APPROVE,
                created_at=_START + timedelta(hours=1, minutes=30),
            ),
            _audit(
                rejected.id,
                audit_actions.CHANGE_REQUEST_CREATED,
                _START + timedelta(hours=2),
                f"user:{requester.id}",
            ),
            _audit(
                rejected.id,
                audit_actions.CHANGE_REQUEST_DRAFT_TO_PENDING,
                _START + timedelta(hours=2, minutes=5),
                f"user:{requester.id}",
            ),
            _audit(
                rejected.id,
                audit_actions.CHANGE_REQUEST_PENDING_TO_DRAFT,
                _START + timedelta(hours=2, minutes=30),
                f"user:{approver.id}",
            ),
            Approval(
                change_request_id=rejected.id,
                actor_id=approver.id,
                decision=ApprovalDecision.REJECT,
                created_at=_START + timedelta(hours=2, minutes=30),
            ),
            # In-month but BEFORE the period start — must not appear.
            _audit(
                out_of_period.id,
                audit_actions.CHANGE_REQUEST_CREATED,
                _ANCHOR + timedelta(hours=1),
                f"user:{requester.id}",
            ),
        ]
    )
    await pg_session.commit()

    sections, notes = await build_change_sections(pg_session, period_start=_START, period_end=_END)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert [row[0] for row in crs.rows] == [str(executed.id), str(rejected.id)]
    executed_row = crs.rows[0]
    assert executed_row[4] == "agent:automation"  # agent executor attribution
    assert executed_row[3].endswith("[local]")

    approvals = _section(sections, SECTION_APPROVALS)
    assert [(row[0], row[2]) for row in approvals.rows] == [
        (str(executed.id), "approve"),
        (str(rejected.id), "reject"),
    ]
    assert all(f"[idp:{approver.idp_subject}]" in row[1] for row in approvals.rows)

    transitions = _section(sections, SECTION_TRANSITIONS)
    assert len(transitions.rows) == 8  # 5 + 3, never the out-of-period CR
    assert not any(row[0] == str(out_of_period.id) for row in transitions.rows)

    diff = _section(sections, SECTION_DIFF_STATISTICS)
    assert diff.rows[0] == (str(executed.id), "applied", "true", "2", f"sha256:{_BASELINE_HASH}")
    assert diff.rows[1] == (str(rejected.id), "none", "none", "none", "none")
    assert NOTE_EMPTY_PERIOD not in notes


async def test_empty_period_on_pg(pg_session: AsyncSession) -> None:
    sections, notes = await build_change_sections(pg_session, period_start=_START, period_end=_END)

    assert all(s.rows == () for s in sections)
    assert NOTE_EMPTY_PERIOD in notes


async def test_rolled_back_cr_full_history_on_pg(pg_session: AsyncSession) -> None:
    requester, approver = await _seed_users(pg_session)
    cr = _cr(
        requester,
        state=ChangeRequestState.ROLLED_BACK,
        created_at=_START + timedelta(hours=3),
        after_state={"outcome": "rolled_back", "verified": False, "applied_diff": ["+ 1"]},
    )
    pg_session.add(cr)
    await pg_session.commit()
    base = _START + timedelta(hours=3)
    pg_session.add_all(
        [
            _audit(cr.id, audit_actions.CHANGE_REQUEST_CREATED, base, f"user:{requester.id}"),
            _audit(
                cr.id,
                audit_actions.CHANGE_REQUEST_DRAFT_TO_PENDING,
                base + timedelta(minutes=1),
                f"user:{requester.id}",
            ),
            _audit(
                cr.id,
                audit_actions.CHANGE_REQUEST_PENDING_TO_APPROVED,
                base + timedelta(minutes=2),
                f"user:{approver.id}",
            ),
            _audit(
                cr.id,
                audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
                base + timedelta(minutes=3),
                "agent:automation",
            ),
            _audit(
                cr.id,
                audit_actions.CHANGE_REQUEST_EXECUTING_TO_FAILED,
                base + timedelta(minutes=4),
                "agent:automation",
            ),
            _audit(
                cr.id,
                audit_actions.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK,
                base + timedelta(minutes=5),
                "agent:automation",
            ),
        ]
    )
    await pg_session.commit()

    sections, _ = await build_change_sections(pg_session, period_start=_START, period_end=_END)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert crs.rows[0][2] == "rolled_back"
    transitions = _section(sections, SECTION_TRANSITIONS)
    assert [row[1] for row in transitions.rows] == [
        "created",
        "draft_to_pending_approval",
        "pending_approval_to_approved",
        "approved_to_executing",
        "executing_to_failed",
        "failed_to_rolled_back",
    ]
    diff = _section(sections, SECTION_DIFF_STATISTICS)
    assert diff.rows[0][1] == "rolled_back"


async def test_closed_open_period_edges_on_pg(pg_session: AsyncSession) -> None:
    """Start instant INCLUDED, end instant EXCLUDED — under real PG timestamptz."""
    requester, _ = await _seed_users(pg_session)
    at_start = _cr(requester, state=ChangeRequestState.DRAFT, created_at=_START)
    at_end = _cr(requester, state=ChangeRequestState.DRAFT, created_at=_END)
    pg_session.add_all([at_start, at_end])
    await pg_session.commit()
    pg_session.add_all(
        [
            _audit(at_start.id, audit_actions.CHANGE_REQUEST_CREATED, _START, "user:x"),
            _audit(at_end.id, audit_actions.CHANGE_REQUEST_CREATED, _END, "user:x"),
        ]
    )
    await pg_session.commit()

    sections, _ = await build_change_sections(pg_session, period_start=_START, period_end=_END)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert [row[0] for row in crs.rows] == [str(at_start.id)]


async def test_non_utc_stored_timestamp_normalizes_on_pg(pg_session: AsyncSession) -> None:
    """Offset-aware stamps land in the right UTC bucket (timestamptz semantics)."""
    plus5 = timezone(timedelta(hours=5))
    requester, _ = await _seed_users(pg_session)
    inside = _cr(requester, state=ChangeRequestState.DRAFT, created_at=_START)
    outside = _cr(requester, state=ChangeRequestState.DRAFT, created_at=_END)
    pg_session.add_all([inside, outside])
    await pg_session.commit()
    # The exact period-start instant, expressed as +05:00 — included.
    inside_at = _START.astimezone(plus5)
    # The exact period-end instant, expressed as +05:00 — excluded (closed-open).
    outside_at = _END.astimezone(plus5)
    pg_session.add_all(
        [
            _audit(inside.id, audit_actions.CHANGE_REQUEST_CREATED, inside_at, "user:x"),
            _audit(outside.id, audit_actions.CHANGE_REQUEST_CREATED, outside_at, "user:x"),
        ]
    )
    await pg_session.commit()

    sections, _ = await build_change_sections(pg_session, period_start=_START, period_end=_END)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert [row[0] for row in crs.rows] == [str(inside.id)]
    transitions = _section(sections, SECTION_TRANSITIONS)
    assert transitions.rows[0][3] == _START.isoformat()  # normalized UTC rendering


async def test_full_change_generation_runs_the_rollup_on_pg(
    pg_engine: AsyncEngine, pg_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``reports.generate`` for kind=change drives these queries inside the
    engine path on PG and persists artifacts (the W3-T1 harness pattern)."""
    from collections.abc import AsyncIterator
    from contextlib import asynccontextmanager

    from app.engines.reports import render

    maker = async_sessionmaker(pg_engine, expire_on_commit=False)

    @asynccontextmanager
    async def _pg_task_session() -> AsyncIterator[AsyncSession]:
        async with maker() as task_session:
            yield task_session

    monkeypatch.setattr(report_tasks, "_session", _pg_task_session)
    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")

    requester, _ = await _seed_users(pg_session)
    cr = _cr(requester, state=ChangeRequestState.DRAFT, created_at=_START + timedelta(hours=4))
    pg_session.add(cr)
    await pg_session.commit()
    pg_session.add(
        _audit(
            cr.id,
            audit_actions.CHANGE_REQUEST_CREATED,
            _START + timedelta(hours=4),
            f"user:{requester.id}",
        )
    )
    await pg_session.commit()

    result = await report_tasks._generate_report_core(
        "change", _START.isoformat(), _END.isoformat(), "on_demand", None
    )

    assert result["status"] == "succeeded"
    # content is deferred with raiseload (PR #166 F4) — this rollup test reads the
    # CSV bytes, so it must opt in explicitly.
    artifacts = list(
        (
            await pg_session.execute(
                select(ReportArtifact).options(undefer(ReportArtifact.content))
            )
        ).scalars()
    )
    assert sorted(a.format for a in artifacts) == ["csv", "pdf"]
    csv_text = next(a for a in artifacts if a.format == "csv").content.decode("utf-8")
    assert str(cr.id) in csv_text
