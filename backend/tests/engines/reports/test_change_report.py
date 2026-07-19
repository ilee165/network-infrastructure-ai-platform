"""Change-report builder (P4 W3-T2; ADR-0053 §7.1) — unit suite.

The change report is the CR lifecycle roll-up: per CR — requester, approver(s),
executor (human or agent), state transitions with timestamps, before/after as
snapshot REFERENCES + redaction-safe diff STATISTICS (line counts, the ADR-0021
``applied_diff`` posture — never config text), and reasoning-trace LINKS
(ids/URLs, never trace content).

Covered here (SQLite; the aggregation queries re-assert on real PostgreSQL in
``tests/pg/test_change_report_pg.py``):

* period selection is CLOSED-OPEN over lifecycle audit activity — the start
  instant is included, the end instant excluded, and a non-UTC-stored (aware,
  offset) timestamp normalizes into the right bucket;
* naive period inputs are pinned as UTC (the W3-T1 phantom-run-id class);
* identity labels carry the IdP subject for federated accounts (D11);
* the diff-statistics extractor is a strict ALLOWLIST — every emitted cell is a
  validated enum token, a bool literal, an integer count, or regex-validated
  hex, so planted config text in any CR JSONB field can never reach a payload;
* the payload passes the engine redaction choke point, and a planted
  deny-class field / secret-formatted value is rejected (engine-level sanity);
* the golden CSV/PDF structure fixture for W4-T3's conformance checks.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.engines.reports import build_payload, render_artifacts
from app.engines.reports.change_report import (
    APPROVAL_COLUMNS,
    CHANGE_REQUEST_COLUMNS,
    DIFF_COLUMNS,
    NOTE_EMPTY_PERIOD,
    SECTION_APPROVALS,
    SECTION_CHANGE_REQUESTS,
    SECTION_DIFF_STATISTICS,
    SECTION_TRANSITIONS,
    TRANSITION_COLUMNS,
    build_change_sections,
    diff_statistics,
)
from app.engines.reports.payloads import ReportSection
from app.engines.reports.redaction import RedactionViolationError
from app.engines.reports.regime_mapping import MAPPING_VERSION_TAG
from app.models import AuditLog, Base
from app.models.agents import AgentSession
from app.models.change_requests import (
    Approval,
    ApprovalDecision,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
)
from app.models.identity import Role, User
from app.models.reports import ReportKind
from app.services.audit import service as audit_actions

_GOLDEN = Path(__file__).resolve().parent / "golden" / "change_report_golden.json"

_PERIOD_START = datetime(2026, 7, 1, tzinfo=UTC)
_PERIOD_END = datetime(2026, 7, 8, tzinfo=UTC)
_GENERATED_AT = datetime(2026, 7, 8, 0, 5, tzinfo=UTC)

_ROLE_ID = uuid.UUID("00000000-0000-0000-0000-00000000e001")
_ALICE = uuid.UUID("00000000-0000-0000-0000-00000000a11c")
_BOB = uuid.UUID("00000000-0000-0000-0000-00000000b0b0")
_SESSION_ID = uuid.UUID("00000000-0000-0000-0000-000000005e55")
_TRACE_ID = uuid.UUID("00000000-0000-0000-0000-000000007ace")
_CR1 = uuid.UUID("00000000-0000-0000-0000-000000000c01")
_CR2 = uuid.UUID("00000000-0000-0000-0000-000000000c02")
_CR3 = uuid.UUID("00000000-0000-0000-0000-000000000c03")

_BASELINE_HASH = "ab" * 32

#: Config-text canary planted into CR JSONB fields — must NEVER reach a payload.
_CONFIG_TEXT = "interface GigabitEthernet0/1\n ip address 10.99.0.1 255.255.255.0"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    """File-backed SQLite schema + one AsyncSession (T1 harness pattern)."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'change_report.sqlite'}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db_session:
        yield db_session
    await engine.dispose()


def _ts(day: int, hour: int, minute: int = 0, second: int = 0) -> datetime:
    return datetime(2026, 7, day, hour, minute, second, tzinfo=UTC)


def _audit(cr_id: uuid.UUID, action: str, at: datetime, actor: str) -> AuditLog:
    return AuditLog(
        actor=actor,
        action=action,
        target_type="change_request",
        target_id=str(cr_id),
        created_at=at,
    )


def _identities() -> list[Any]:
    return [
        Role(id=_ROLE_ID, name="engineer"),
        User(
            id=_ALICE,
            username="alice",
            password_hash="x",
            role_id=_ROLE_ID,
            is_active=True,
        ),
        User(
            id=_BOB,
            username="bob",
            password_hash="x",
            role_id=_ROLE_ID,
            is_active=True,
            idp_iss="https://idp.example.test",
            idp_subject="idp-sub-bob",
        ),
    ]


def _scenario() -> list[Any]:
    """The deterministic three-CR scenario behind the golden fixture.

    CR1 — config, full happy path to ``completed``, agent-executed, trace-linked,
    with diff statistics + a baseline snapshot reference. CR2 — DDI, rejected
    back to ``draft`` (four-eyes reject evidence). CR3 — config, failed then
    ``rolled_back`` (agent-executed).
    """
    rows: list[Any] = _identities()
    rows.append(
        AgentSession(
            id=_SESSION_ID,
            user_id=_ALICE,
            invoking_role="engineer",
            intent="draft config change",
        )
    )
    rows.append(
        ChangeRequest(
            id=_CR1,
            state=ChangeRequestState.COMPLETED,
            kind=ChangeRequestKind.CONFIG,
            requester_id=_ALICE,
            generating_session_id=_SESSION_ID,
            reasoning_trace_id=_TRACE_ID,
            four_eyes_required=True,
            rollback_plan={"baseline_content_hash": _BASELINE_HASH},
            after_state={
                "outcome": "applied",
                "verified": True,
                "applied_diff": ["+ 3 added", "- 1 removed", "~ 2 modified"],
            },
            created_at=_ts(2, 10),
            updated_at=_ts(2, 12, 3),
        )
    )
    rows.extend(
        [
            _audit(_CR1, audit_actions.CHANGE_REQUEST_CREATED, _ts(2, 10), f"user:{_ALICE}"),
            _audit(
                _CR1, audit_actions.CHANGE_REQUEST_DRAFT_TO_PENDING, _ts(2, 10, 5), f"user:{_ALICE}"
            ),
            _audit(
                _CR1, audit_actions.CHANGE_REQUEST_PENDING_TO_APPROVED, _ts(2, 11), f"user:{_BOB}"
            ),
            _audit(
                _CR1,
                audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
                _ts(2, 12),
                "agent:automation",
            ),
            _audit(
                _CR1,
                audit_actions.CHANGE_REQUEST_EXECUTING_TO_COMPLETED,
                _ts(2, 12, 3),
                "agent:automation",
            ),
            Approval(
                change_request_id=_CR1,
                actor_id=_BOB,
                decision=ApprovalDecision.APPROVE,
                created_at=_ts(2, 11),
            ),
        ]
    )
    rows.append(
        ChangeRequest(
            id=_CR2,
            state=ChangeRequestState.DRAFT,
            kind=ChangeRequestKind.DDI_RECORD,
            requester_id=_ALICE,
            four_eyes_required=True,
            created_at=_ts(3, 9),
            updated_at=_ts(3, 9, 30),
        )
    )
    rows.extend(
        [
            _audit(_CR2, audit_actions.CHANGE_REQUEST_CREATED, _ts(3, 9), f"user:{_ALICE}"),
            _audit(
                _CR2, audit_actions.CHANGE_REQUEST_DRAFT_TO_PENDING, _ts(3, 9, 5), f"user:{_ALICE}"
            ),
            _audit(
                _CR2, audit_actions.CHANGE_REQUEST_PENDING_TO_DRAFT, _ts(3, 9, 30), f"user:{_BOB}"
            ),
            Approval(
                change_request_id=_CR2,
                actor_id=_BOB,
                decision=ApprovalDecision.REJECT,
                created_at=_ts(3, 9, 30),
            ),
        ]
    )
    rows.append(
        ChangeRequest(
            id=_CR3,
            state=ChangeRequestState.ROLLED_BACK,
            kind=ChangeRequestKind.CONFIG,
            requester_id=_ALICE,
            four_eyes_required=True,
            after_state={
                "outcome": "rolled_back",
                "verified": False,
                "applied_diff": ["+ 1 added"],
            },
            created_at=_ts(4, 8),
            updated_at=_ts(4, 9, 10),
        )
    )
    rows.extend(
        [
            _audit(_CR3, audit_actions.CHANGE_REQUEST_CREATED, _ts(4, 8), f"user:{_ALICE}"),
            _audit(
                _CR3, audit_actions.CHANGE_REQUEST_DRAFT_TO_PENDING, _ts(4, 8, 2), f"user:{_ALICE}"
            ),
            _audit(
                _CR3,
                audit_actions.CHANGE_REQUEST_PENDING_TO_APPROVED,
                _ts(4, 8, 30),
                f"user:{_BOB}",
            ),
            _audit(
                _CR3,
                audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
                _ts(4, 9),
                "agent:automation",
            ),
            _audit(
                _CR3,
                audit_actions.CHANGE_REQUEST_EXECUTING_TO_FAILED,
                _ts(4, 9, 1),
                "agent:automation",
            ),
            _audit(
                _CR3,
                audit_actions.CHANGE_REQUEST_FAILED_TO_ROLLED_BACK,
                _ts(4, 9, 10),
                "agent:automation",
            ),
            Approval(
                change_request_id=_CR3,
                actor_id=_BOB,
                decision=ApprovalDecision.APPROVE,
                created_at=_ts(4, 8, 30),
            ),
        ]
    )
    return rows


async def _seed(session: AsyncSession, rows: list[Any]) -> None:
    session.add_all(rows)
    await session.commit()


def _section(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(s for s in sections if s.title == title)


async def _build(
    session: AsyncSession,
    start: datetime = _PERIOD_START,
    end: datetime = _PERIOD_END,
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    return await build_change_sections(session, period_start=start, period_end=end)


# ---------------------------------------------------------------------------
# Roll-up content
# ---------------------------------------------------------------------------


async def test_rollup_carries_requester_approver_executor_transitions(
    session: AsyncSession,
) -> None:
    await _seed(session, _scenario())
    sections, notes = await _build(session)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert crs.columns == CHANGE_REQUEST_COLUMNS
    assert [row[0] for row in crs.rows] == [str(_CR1), str(_CR2), str(_CR3)]
    cr1 = crs.rows[0]
    assert cr1[1] == "config"
    assert cr1[2] == "completed"
    assert cr1[3] == "alice [local]"
    assert cr1[4] == "agent:automation"
    assert cr1[5] == "2026-07-02T10:00:00+00:00"
    assert cr1[6] == f"trace:{_TRACE_ID} via /api/v1/agents/{_SESSION_ID}"
    # Human-authored, never executed: no trace link, no executor.
    cr2 = crs.rows[1]
    assert cr2[4] == "none"
    assert cr2[6] == "none"

    approvals = _section(sections, SECTION_APPROVALS)
    assert approvals.columns == APPROVAL_COLUMNS
    assert list(approvals.rows) == [
        (str(_CR1), "bob [idp:idp-sub-bob]", "approve", "2026-07-02T11:00:00+00:00"),
        (str(_CR2), "bob [idp:idp-sub-bob]", "reject", "2026-07-03T09:30:00+00:00"),
        (str(_CR3), "bob [idp:idp-sub-bob]", "approve", "2026-07-04T08:30:00+00:00"),
    ]

    transitions = _section(sections, SECTION_TRANSITIONS)
    assert transitions.columns == TRANSITION_COLUMNS
    # Full histories: 5 (CR1) + 3 (CR2) + 6 (CR3) lifecycle events, chronological.
    assert len(transitions.rows) == 14
    assert transitions.rows[0] == (
        str(_CR1),
        "created",
        "alice [local]",
        "2026-07-02T10:00:00+00:00",
    )
    events_cr3 = [row[1] for row in transitions.rows if row[0] == str(_CR3)]
    assert events_cr3 == [
        "created",
        "draft_to_pending_approval",
        "pending_approval_to_approved",
        "approved_to_executing",
        "executing_to_failed",
        "failed_to_rolled_back",
    ]
    assert NOTE_EMPTY_PERIOD not in notes


async def test_diff_statistics_and_snapshot_references_only(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    diff = _section(sections, SECTION_DIFF_STATISTICS)
    assert diff.columns == DIFF_COLUMNS
    assert list(diff.rows) == [
        (str(_CR1), "applied", "true", "3", f"sha256:{_BASELINE_HASH}"),
        (str(_CR2), "none", "none", "none", "none"),
        (str(_CR3), "rolled_back", "false", "1", "none"),
    ]
    # Statistics only: the applied_diff summary ENTRIES never appear.
    dumped = json.dumps([list(row) for section in sections for row in section.rows])
    assert "+ 3 added" not in dumped
    assert "- 1 removed" not in dumped


async def test_empty_period_renders_zero_row_sections_with_note(session: AsyncSession) -> None:
    await _seed(session, _identities())
    sections, notes = await _build(session)

    assert [s.title for s in sections] == [
        SECTION_CHANGE_REQUESTS,
        SECTION_APPROVALS,
        SECTION_TRANSITIONS,
        SECTION_DIFF_STATISTICS,
    ]
    assert all(s.rows == () for s in sections)
    assert NOTE_EMPTY_PERIOD in notes


async def test_full_history_shown_for_cr_active_but_created_before_period(
    session: AsyncSession,
) -> None:
    """A pre-period CR with one in-period transition appears with its FULL history."""
    cr_id = uuid.UUID("00000000-0000-0000-0000-00000000c0de")
    rows: list[Any] = _identities()
    rows.append(
        ChangeRequest(
            id=cr_id,
            state=ChangeRequestState.PENDING_APPROVAL,
            kind=ChangeRequestKind.CONFIG,
            requester_id=_ALICE,
            four_eyes_required=True,
            created_at=datetime(2026, 6, 25, 9, 0, tzinfo=UTC),
            updated_at=_ts(2, 9),
        )
    )
    rows.append(
        _audit(
            cr_id,
            audit_actions.CHANGE_REQUEST_CREATED,
            datetime(2026, 6, 25, 9, 0, tzinfo=UTC),
            f"user:{_ALICE}",
        )
    )
    rows.append(
        _audit(cr_id, audit_actions.CHANGE_REQUEST_DRAFT_TO_PENDING, _ts(2, 9), f"user:{_ALICE}")
    )
    await _seed(session, rows)

    sections, _ = await _build(session)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert [row[0] for row in crs.rows] == [str(cr_id)]
    transitions = _section(sections, SECTION_TRANSITIONS)
    # The pre-period ``created`` event is part of the complete lifecycle evidence.
    assert [row[1] for row in transitions.rows] == ["created", "draft_to_pending_approval"]


async def test_human_executor_resolves_to_identity_label(session: AsyncSession) -> None:
    """``user:<id>`` executing actors resolve to identities (executor: human OR agent)."""
    cr_id = uuid.UUID("00000000-0000-0000-0000-00000000ec01")
    rows: list[Any] = _identities()
    rows.append(
        ChangeRequest(
            id=cr_id,
            state=ChangeRequestState.EXECUTING,
            kind=ChangeRequestKind.CONFIG,
            requester_id=_ALICE,
            four_eyes_required=True,
            created_at=_ts(2, 10),
            updated_at=_ts(2, 12),
        )
    )
    rows.append(
        _audit(
            cr_id,
            audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
            _ts(2, 12),
            f"user:{_BOB}",
        )
    )
    await _seed(session, rows)

    sections, _ = await _build(session)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert crs.rows[0][4] == "bob [idp:idp-sub-bob]"


async def test_same_timestamp_executor_claims_resolve_by_seq_not_id(
    session: AsyncSession,
) -> None:
    """Two ``approved -> executing`` claims stamped at the IDENTICAL timestamp
    must resolve the executor by append order (``AuditLog.seq``), never a
    random-UUID id tiebreak (PR #166 F2). ``app.models.audit.AuditLog``
    documents that the chain's real append order is ``seq``, not
    ``(created_at, id)`` — an id tiebreak can invert same-timestamp rows and
    poison :func:`_executors`' "last claim wins" attribution.
    """
    cr_id = uuid.UUID("00000000-0000-0000-0000-00000000ec03")
    same_ts = _ts(2, 12)
    # This id sorts LAST alphabetically (``ff...``) but is the EARLIER claim
    # by seq/append order; the other sorts FIRST (``00...``) but is the TRUE
    # later claim. An ``(created_at, id)`` tiebreak inverts the real order.
    earlier_claim_id = uuid.UUID("ffffffff-0000-0000-0000-000000000001")
    later_claim_id = uuid.UUID("00000000-0000-0000-0000-000000000002")
    rows: list[Any] = _identities()
    rows.append(
        ChangeRequest(
            id=cr_id,
            state=ChangeRequestState.EXECUTING,
            kind=ChangeRequestKind.CONFIG,
            requester_id=_ALICE,
            four_eyes_required=True,
            created_at=_ts(2, 10),
            updated_at=same_ts,
        )
    )
    rows.append(
        AuditLog(
            id=earlier_claim_id,
            actor=f"user:{_ALICE}",
            action=audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
            target_type="change_request",
            target_id=str(cr_id),
            created_at=same_ts,
            seq=1,
        )
    )
    rows.append(
        AuditLog(
            id=later_claim_id,
            actor=f"user:{_BOB}",
            action=audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
            target_type="change_request",
            target_id=str(cr_id),
            created_at=same_ts,
            seq=2,
        )
    )
    await _seed(session, rows)

    sections, _ = await _build(session)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    # seq=2 (bob) is the TRUE later claim; an (created_at, id) sort would
    # instead have picked seq=1 (alice), since earlier_claim_id sorts last.
    assert crs.rows[0][4] == "bob [idp:idp-sub-bob]"


async def test_unknown_actor_id_falls_back_to_raw_actor_string(session: AsyncSession) -> None:
    cr_id = uuid.UUID("00000000-0000-0000-0000-00000000ec02")
    ghost = uuid.UUID("00000000-0000-0000-0000-00000000dead")
    rows: list[Any] = _identities()
    rows.append(
        ChangeRequest(
            id=cr_id,
            state=ChangeRequestState.EXECUTING,
            kind=ChangeRequestKind.CONFIG,
            requester_id=_ALICE,
            four_eyes_required=True,
            created_at=_ts(2, 10),
            updated_at=_ts(2, 12),
        )
    )
    rows.append(
        _audit(
            cr_id,
            audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING,
            _ts(2, 12),
            f"user:{ghost}",
        )
    )
    await _seed(session, rows)

    sections, _ = await _build(session)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert crs.rows[0][4] == f"user:{ghost}"


# ---------------------------------------------------------------------------
# Closed-open period boundaries (the W3 sibling bug class)
# ---------------------------------------------------------------------------


async def test_start_instant_included_end_instant_excluded(session: AsyncSession) -> None:
    at_start = uuid.UUID("00000000-0000-0000-0000-00000000ed9e")
    at_end = uuid.UUID("00000000-0000-0000-0000-00000000ed9f")
    rows: list[Any] = _identities()
    for cr_id, at in ((at_start, _PERIOD_START), (at_end, _PERIOD_END)):
        rows.append(
            ChangeRequest(
                id=cr_id,
                state=ChangeRequestState.DRAFT,
                kind=ChangeRequestKind.CONFIG,
                requester_id=_ALICE,
                four_eyes_required=True,
                created_at=at,
                updated_at=at,
            )
        )
        rows.append(_audit(cr_id, audit_actions.CHANGE_REQUEST_CREATED, at, f"user:{_ALICE}"))
    await _seed(session, rows)

    sections, _ = await _build(session)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert [row[0] for row in crs.rows] == [str(at_start)]


async def test_non_utc_stored_timestamp_normalizes_into_period(session: AsyncSession) -> None:
    """Aware non-UTC stamps normalize: no double-count or omission at the edges."""
    plus5 = timezone(timedelta(hours=5))
    inside = uuid.UUID("00000000-0000-0000-0000-00000000ac01")
    outside = uuid.UUID("00000000-0000-0000-0000-00000000ac02")
    rows: list[Any] = _identities()
    # 2026-07-08T04:59:59+05:00 == 2026-07-07T23:59:59Z — inside the period.
    inside_at = datetime(2026, 7, 8, 4, 59, 59, tzinfo=plus5)
    # 2026-07-08T05:00:00+05:00 == the period end instant — excluded.
    outside_at = datetime(2026, 7, 8, 5, 0, 0, tzinfo=plus5)
    for cr_id, at in ((inside, inside_at), (outside, outside_at)):
        rows.append(
            ChangeRequest(
                id=cr_id,
                state=ChangeRequestState.DRAFT,
                kind=ChangeRequestKind.CONFIG,
                requester_id=_ALICE,
                four_eyes_required=True,
                created_at=at,
                updated_at=at,
            )
        )
        rows.append(_audit(cr_id, audit_actions.CHANGE_REQUEST_CREATED, at, f"user:{_ALICE}"))
    await _seed(session, rows)

    sections, _ = await _build(session)

    crs = _section(sections, SECTION_CHANGE_REQUESTS)
    assert [row[0] for row in crs.rows] == [str(inside)]
    # ...and the rendered timestamp is the normalized UTC instant.
    assert crs.rows[0][5] == "2026-07-07T23:59:59+00:00"


async def test_naive_period_inputs_are_pinned_utc(session: AsyncSession) -> None:
    """Naive period bounds == aware-UTC bounds (the T1 phantom-run-id class)."""
    await _seed(session, _scenario())

    aware_sections, aware_notes = await _build(session)
    naive_sections, naive_notes = await _build(
        session,
        start=_PERIOD_START.replace(tzinfo=None),
        end=_PERIOD_END.replace(tzinfo=None),
    )

    assert naive_sections == aware_sections
    assert naive_notes == aware_notes


# ---------------------------------------------------------------------------
# Diff-statistics allowlist (never config text)
# ---------------------------------------------------------------------------


def _cr_stub(
    after_state: dict[str, Any] | None = None,
    rollback_plan: dict[str, Any] | None = None,
) -> ChangeRequest:
    return ChangeRequest(
        id=uuid.uuid4(),
        state=ChangeRequestState.COMPLETED,
        kind=ChangeRequestKind.CONFIG,
        requester_id=_ALICE,
        four_eyes_required=True,
        after_state=after_state,
        rollback_plan=rollback_plan,
    )


def test_diff_statistics_extracts_valid_fields() -> None:
    cr = _cr_stub(
        after_state={"outcome": "applied", "verified": True, "applied_diff": ["a", "b"]},
        rollback_plan={"baseline_content_hash": "0" * 64},
    )
    assert diff_statistics(cr) == ("applied", "true", "2", "sha256:" + "0" * 64)


def test_diff_statistics_is_none_safe() -> None:
    assert diff_statistics(_cr_stub()) == ("none", "none", "none", "none")


def test_diff_statistics_rejects_unrecognized_outcome_token() -> None:
    cr = _cr_stub(after_state={"outcome": _CONFIG_TEXT, "verified": "yes", "applied_diff": "x"})
    outcome, verified, lines, baseline = diff_statistics(cr)
    assert outcome == "unrecognized"  # never the raw (possibly config-text) value
    assert verified == "none"  # non-bool rejected
    assert lines == "none"  # non-list rejected
    assert baseline == "none"


def test_diff_statistics_rejects_non_hex_baseline_reference() -> None:
    cr = _cr_stub(rollback_plan={"baseline_content_hash": _CONFIG_TEXT})
    assert diff_statistics(cr)[3] == "none"


async def test_planted_config_text_never_reaches_the_payload(session: AsyncSession) -> None:
    """Config text planted across EVERY CR JSONB surface stays out of the payload."""
    cr_id = uuid.UUID("00000000-0000-0000-0000-00000000feed")
    rows: list[Any] = _identities()
    rows.append(
        ChangeRequest(
            id=cr_id,
            state=ChangeRequestState.COMPLETED,
            kind=ChangeRequestKind.CONFIG,
            requester_id=_ALICE,
            four_eyes_required=True,
            payload={"config_lines": _CONFIG_TEXT},
            target_refs={"note": _CONFIG_TEXT},
            rollback_plan={"baseline_content_hash": "z-not-hex", "inverse": _CONFIG_TEXT},
            before_state={"raw": _CONFIG_TEXT},
            after_state={
                "outcome": "applied",
                "verified": True,
                "applied_diff": [_CONFIG_TEXT],
                "extra": _CONFIG_TEXT,
            },
            created_at=_ts(2, 10),
            updated_at=_ts(2, 10),
        )
    )
    rows.append(_audit(cr_id, audit_actions.CHANGE_REQUEST_CREATED, _ts(2, 10), f"user:{_ALICE}"))
    await _seed(session, rows)

    payload = await build_payload(
        session,
        kind=ReportKind.CHANGE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    dumped = json.dumps(payload.model_dump(mode="json"))
    assert "GigabitEthernet" not in dumped
    assert "10.99.0.1" not in dumped
    # The statistics DID make it (count of the planted single-entry diff).
    diff = _section(payload.sections, SECTION_DIFF_STATISTICS)
    assert diff.rows[0][3] == "1"


# ---------------------------------------------------------------------------
# Engine wiring + redaction sanity
# ---------------------------------------------------------------------------


async def test_build_payload_wires_change_kind_off_the_skeleton(session: AsyncSession) -> None:
    await _seed(session, _scenario())

    payload = await build_payload(
        session,
        kind=ReportKind.CHANGE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    assert payload.kind == "change"
    assert payload.regime_tags == ("soc2:CC8.1", MAPPING_VERSION_TAG)
    titles = [s.title for s in payload.sections]
    assert SECTION_CHANGE_REQUESTS in titles
    assert not any("skeleton" in note for note in payload.notes)


async def test_change_payload_passes_the_redaction_choke_point(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real payload renders through the SINGLE path (redaction runs first)."""
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.CHANGE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    artifacts = render_artifacts(payload)

    assert sorted(a.format.value for a in artifacts) == ["csv", "pdf"]


async def test_planted_secret_value_in_change_payload_fails_closed(
    session: AsyncSession,
) -> None:
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.CHANGE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )
    planted = payload.model_copy(
        update={
            "sections": (
                *payload.sections,
                ReportSection(
                    title="Planted",
                    columns=("Value",),
                    rows=(("-----BEGIN RSA PRIVATE KEY-----",),),
                ),
            )
        }
    )

    with pytest.raises(RedactionViolationError):
        render_artifacts(planted)


async def test_planted_deny_class_column_in_change_payload_fails_closed(
    session: AsyncSession,
) -> None:
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.CHANGE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )
    planted = payload.model_copy(
        update={
            "sections": (
                *payload.sections,
                ReportSection(title="Planted", columns=("Password",), rows=()),
            )
        }
    )

    with pytest.raises(RedactionViolationError):
        render_artifacts(planted)


def test_section_headers_clear_the_deny_class() -> None:
    """No pinned column header may trip the deny-class name filter (fail-closed)."""
    from app.engines.reports.redaction import DENY_FIELD_NAME_TOKENS

    for columns in (CHANGE_REQUEST_COLUMNS, APPROVAL_COLUMNS, TRANSITION_COLUMNS, DIFF_COLUMNS):
        for header in columns:
            lowered = header.casefold()
            assert not any(token in lowered for token in DENY_FIELD_NAME_TOKENS), header


# ---------------------------------------------------------------------------
# Pinned vocabularies stay in sync with their sources of truth
# ---------------------------------------------------------------------------


def test_outcome_allowlist_matches_change_outcome_enum() -> None:
    from app.engines.reports.change_report import ALLOWED_OUTCOME_TOKENS
    from app.plugins.base import ChangeOutcome

    assert frozenset(member.value for member in ChangeOutcome) == ALLOWED_OUTCOME_TOKENS


def test_lifecycle_action_prefix_matches_audit_vocabulary() -> None:
    from app.engines.reports.change_report import CR_LIFECYCLE_ACTION_PREFIX

    lifecycle_constants = [
        value
        for name, value in vars(audit_actions).items()
        if name.startswith("CHANGE_REQUEST_") and isinstance(value, str)
    ]
    assert lifecycle_constants, "audit vocabulary moved — update the builder"
    assert all(value.startswith(CR_LIFECYCLE_ACTION_PREFIX) for value in lifecycle_constants)
    assert audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING.startswith(CR_LIFECYCLE_ACTION_PREFIX)


# ---------------------------------------------------------------------------
# Golden CSV/PDF structure fixture (W4-T3 rides this file)
# ---------------------------------------------------------------------------


async def test_golden_csv_and_pdf_structure(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deterministic scenario renders EXACTLY the committed golden structure.

    CSV: parsed rows compare exactly (deterministic payload → deterministic
    bytes). PDF: structure-stable, not byte-golden (ADR-0053 §1) — the rendered
    HTML that WeasyPrint consumes must carry every golden section title and
    column header. W4-T3's conformance checks assert against the same fixture.
    """
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.CHANGE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))

    artifacts = render_artifacts(payload)
    csv_artifact = next(a for a in artifacts if a.format.value == "csv")
    parsed_rows = list(csv.reader(io.StringIO(csv_artifact.content.decode("utf-8"))))
    assert parsed_rows == golden["csv_rows"]

    html_source = render._jinja_env().get_template("report_base.html").render(payload=payload)
    for section in golden["pdf_structure"]["sections"]:
        assert f"<h2>{section['title']}</h2>" in html_source
        for column in section["columns"]:
            assert f"<th>{column}</th>" in html_source
    # The golden fixture itself must carry zero config text (evidence posture).
    assert "GigabitEthernet" not in _GOLDEN.read_text(encoding="utf-8")
