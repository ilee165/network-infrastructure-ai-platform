"""Change report builder (P4 W3-T2; ADR-0053 §7.1) — CR lifecycle roll-up.

Assembles the per-period change-management evidence: for every ChangeRequest
with lifecycle activity in the CLOSED-OPEN UTC period ``[start, end)`` —
requester, approver(s) with IdP subject (D11), executor (human or agent), the
COMPLETE state-transition history with timestamps, before/after as snapshot
REFERENCES plus redaction-safe diff STATISTICS (line counts, the ADR-0021
``applied_diff`` posture — never config text), and reasoning-trace LINKS
(ids/URLs into the platform, resolved under the viewer's own RBAC — never
trace content, which could quote device output).

Sources (ADR-0053 §6 layer 1 allowlist): ``change_requests`` metadata,
``approvals``, ``audit_log`` lifecycle rows, ``users`` identity columns.
Nothing here reads ``config_snapshots.content``, ``device_credentials``, or
any other deny-set surface — enforced by the import-linter contract and the
no-SELECT-deny-set runtime proof (``tests/engines/reports/test_boundary.py``).

Zero config text BY CONSTRUCTION: every cell derived from a CR JSONB column is
either a validated enum token, a bool literal, an integer count, or
regex-validated hex (:func:`diff_statistics`) — free-form JSONB strings have no
path into the payload, so a planted config line can never reach an artifact.

Period membership is defined by ``audit_log`` lifecycle activity: every CR
event writes exactly one ``change_request.*`` audit row (the creation included),
so "CRs active in the period" and "state changes evidenced in the period" are
the same set. Selected CRs show their FULL history (which may extend beyond the
period) — complete lifecycle evidence, not a windowed fragment.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.engines.reports.idempotency import coerce_utc
from app.engines.reports.payloads import ReportSection
from app.models.audit import AuditLog
from app.models.change_requests import Approval, ChangeRequest
from app.models.identity import User
from app.services.audit import service as audit_actions

__all__ = [
    "ALLOWED_OUTCOME_TOKENS",
    "APPROVAL_COLUMNS",
    "CHANGE_REQUEST_COLUMNS",
    "CR_LIFECYCLE_ACTION_PREFIX",
    "DIFF_COLUMNS",
    "NOTE_EMPTY_PERIOD",
    "SECTION_APPROVALS",
    "SECTION_CHANGE_REQUESTS",
    "SECTION_DIFF_STATISTICS",
    "SECTION_TRANSITIONS",
    "TRANSITION_COLUMNS",
    "build_change_sections",
    "diff_statistics",
]

#: The audit vocabulary this roll-up rides (single source:
#: ``app.services.audit.service`` — the sync test pins every ``CHANGE_REQUEST_*``
#: constant to this prefix, so a vocabulary drift fails the suite, not the report).
CR_LIFECYCLE_ACTION_PREFIX: Final = "change_request."
_CR_TARGET_TYPE: Final = "change_request"

#: ``ChangeOutcome`` wire values (ADR-0021 §3) — pinned here as an ALLOWLIST so
#: an ``after_state.outcome`` that is not a known token (e.g. planted free text)
#: renders as ``unrecognized``, never verbatim. Synced-by-test with
#: ``app.plugins.base.ChangeOutcome``.
ALLOWED_OUTCOME_TOKENS: Final = frozenset({"applied", "no_op", "rolled_back", "rollback_failed"})

#: A snapshot reference must be exactly SHA-256 hex (the ADR-0021
#: ``baseline_content_hash``) — anything else is not a reference and is dropped.
_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")

#: Placeholder for absent evidence dimensions (a plain token — deliberately not
#: ``-``/``—``, which the CSV formula-neutralizer would prefix).
_NONE: Final = "none"

SECTION_CHANGE_REQUESTS: Final = "Change requests"
SECTION_APPROVALS: Final = "Approvals (four-eyes evidence)"
SECTION_TRANSITIONS: Final = "Lifecycle transitions"
SECTION_DIFF_STATISTICS: Final = "Diff statistics and snapshot references"

CHANGE_REQUEST_COLUMNS: Final = (
    "CR id",
    "Kind",
    "State",
    "Requester",
    "Executor",
    "Created (UTC)",
    "Reasoning trace link",
)
APPROVAL_COLUMNS: Final = ("CR id", "Approver", "Decision", "Decided at (UTC)")
TRANSITION_COLUMNS: Final = ("CR id", "Lifecycle event", "Actor", "At (UTC)")
DIFF_COLUMNS: Final = (
    "CR id",
    "Outcome",
    "Verified",
    "Applied diff lines",
    "Baseline snapshot ref",
)

NOTE_EMPTY_PERIOD: Final = "No change-request lifecycle activity recorded in this period."
_NOTE_EVIDENCE: Final = (
    "Evidence claim (ADR-0053 §7.1): every state change in this period traversed the "
    "ChangeRequest lifecycle; transition histories and four-eyes approval decisions are "
    "shown per CR, and a selected CR's history may extend beyond the period boundaries."
)
_NOTE_POSTURE: Final = (
    "Statistics and references only (ADR-0021 posture): diffs appear as line counts and "
    "snapshot references; config text never enters this report. Reasoning-trace links are "
    "ids/URLs resolved under the viewer's own RBAC."
)

_USER_ACTOR_PREFIX: Final = "user:"


# ---------------------------------------------------------------------------
# Pure helpers (no I/O — unit-tested directly)
# ---------------------------------------------------------------------------


def diff_statistics(cr: ChangeRequest) -> tuple[str, str, str, str]:
    """ALLOWLIST extraction of ``(outcome, verified, diff lines, baseline ref)``.

    Reads exactly four known-safe facts out of the CR JSONB columns and
    validates each shape: the outcome must be a pinned :data:`ALLOWED_OUTCOME_TOKENS`
    member (else ``unrecognized``), ``verified`` a bool, ``applied_diff`` a
    sequence (only its LENGTH is emitted — the ADR-0021 line-count statistic,
    never the entries), and the baseline reference exact SHA-256 hex. Free-form
    strings therefore have no path from ``after_state``/``rollback_plan`` into
    a report cell (§7.1: never config text).
    """
    after = cr.after_state if isinstance(cr.after_state, dict) else {}
    raw_outcome = after.get("outcome")
    if raw_outcome is None:
        outcome = _NONE
    elif isinstance(raw_outcome, str) and raw_outcome in ALLOWED_OUTCOME_TOKENS:
        outcome = raw_outcome
    else:
        outcome = "unrecognized"

    raw_verified = after.get("verified")
    verified = ("true" if raw_verified else "false") if isinstance(raw_verified, bool) else _NONE

    raw_diff = after.get("applied_diff")
    lines = (
        str(len(raw_diff))
        if isinstance(raw_diff, Sequence) and not isinstance(raw_diff, str | bytes)
        else _NONE
    )

    plan = cr.rollback_plan if isinstance(cr.rollback_plan, dict) else {}
    raw_baseline = plan.get("baseline_content_hash")
    baseline = (
        f"sha256:{raw_baseline}"
        if isinstance(raw_baseline, str) and _SHA256_HEX.fullmatch(raw_baseline)
        else _NONE
    )
    return outcome, verified, lines, baseline


def _trace_link(cr: ChangeRequest) -> str:
    """Reasoning-trace LINK: the trace id + a platform URL — never content.

    The URL resolves the generating agent session (and its traces) under the
    VIEWER's own RBAC at view time (ADR-0053 §7.1); human-authored CRs carry no
    trace and render ``none``.
    """
    if cr.reasoning_trace_id is None:
        return _NONE
    link = f"trace:{cr.reasoning_trace_id}"
    if cr.generating_session_id is not None:
        link = f"{link} via /api/v1/agents/{cr.generating_session_id}"
    return link


def _identity_label(user: User | None, fallback: str) -> str:
    """D11 identity presentation: username + IdP subject (federated) or local."""
    if user is None:
        return fallback
    if user.idp_subject is not None:
        return f"{user.username} [idp:{user.idp_subject}]"
    return f"{user.username} [local]"


def _actor_user_id(actor: str) -> uuid.UUID | None:
    """Parse a ``user:<uuid>`` audit actor; ``None`` for agents/service actors."""
    if not actor.startswith(_USER_ACTOR_PREFIX):
        return None
    try:
        return uuid.UUID(actor[len(_USER_ACTOR_PREFIX) :])
    except ValueError:
        return None


def _actor_label(actor: str, users: Mapping[uuid.UUID, User]) -> str:
    """Resolve a ``user:<id>`` actor to its identity label; pass agents through."""
    user_id = _actor_user_id(actor)
    if user_id is None:
        return actor
    return _identity_label(users.get(user_id), actor)


def _parse_cr_ids(raw_ids: Iterable[str]) -> list[uuid.UUID]:
    parsed: list[uuid.UUID] = []
    for raw in raw_ids:
        try:
            parsed.append(uuid.UUID(raw))
        except ValueError:  # pragma: no cover - malformed target_id is unreachable
            continue
    return parsed


# ---------------------------------------------------------------------------
# Queries (allowlisted sources only; re-asserted on real PG in tests/pg/)
# ---------------------------------------------------------------------------


async def _active_cr_ids(session: AsyncSession, start: datetime, end: datetime) -> list[uuid.UUID]:
    """CR ids with lifecycle audit activity in the CLOSED-OPEN ``[start, end)``."""
    stmt = (
        select(AuditLog.target_id)
        .where(
            AuditLog.target_type == _CR_TARGET_TYPE,
            AuditLog.action.startswith(CR_LIFECYCLE_ACTION_PREFIX, autoescape=True),
            AuditLog.target_id.is_not(None),
            AuditLog.created_at >= start,
            AuditLog.created_at < end,
        )
        .distinct()
    )
    raw = (await session.execute(stmt)).scalars()
    return _parse_cr_ids(value for value in raw if value is not None)


async def _load_crs(session: AsyncSession, cr_ids: Sequence[uuid.UUID]) -> list[ChangeRequest]:
    stmt = (
        select(ChangeRequest)
        .where(ChangeRequest.id.in_(cr_ids))
        .order_by(ChangeRequest.created_at, ChangeRequest.id)
    )
    return list((await session.execute(stmt)).scalars())


async def _load_lifecycle_rows(
    session: AsyncSession, cr_ids: Sequence[uuid.UUID]
) -> list[AuditLog]:
    """The FULL lifecycle history of the selected CRs (not window-clipped).

    Ordered by ``created_at``, then ``seq`` (nulls last — a pre-chain/legacy
    row without a monotonic sequence sorts after every chained row), and
    ``id`` only as a final, purely-cosmetic tiebreak for genuinely identical
    ``(created_at, seq)`` pairs. ``app.models.audit.AuditLog`` documents that
    the chain's real append ORDER is ``seq``, NOT ``(created_at, id)`` — a
    random-UUID tiebreak on same-timestamp rows can invert the true order,
    which would poison :func:`_executors`' "last claim wins" attribution
    (PR #166 F2).
    """
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.target_type == _CR_TARGET_TYPE,
            AuditLog.action.startswith(CR_LIFECYCLE_ACTION_PREFIX, autoescape=True),
            AuditLog.target_id.in_([str(cr_id) for cr_id in cr_ids]),
        )
        .order_by(AuditLog.created_at, AuditLog.seq.asc().nulls_last(), AuditLog.id)
    )
    return list((await session.execute(stmt)).scalars())


async def _load_approvals(session: AsyncSession, cr_ids: Sequence[uuid.UUID]) -> list[Approval]:
    stmt = (
        select(Approval)
        .where(Approval.change_request_id.in_(cr_ids))
        .order_by(Approval.created_at, Approval.id)
    )
    return list((await session.execute(stmt)).scalars())


async def _load_identities(
    session: AsyncSession, user_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, User]:
    ids = list(set(user_ids))
    if not ids:
        return {}
    rows = (await session.execute(select(User).where(User.id.in_(ids)))).scalars()
    return {user.id: user for user in rows}


def _executors(lifecycle_rows: Sequence[AuditLog]) -> dict[str, str]:
    """Latest ``approved -> executing`` actor per CR — the executor attribution.

    The rows arrive chronologically ordered, so the last claim wins (a re-executed
    CR is attributed to its most recent executor).
    """
    executors: dict[str, str] = {}
    for row in lifecycle_rows:
        if row.action == audit_actions.CHANGE_REQUEST_APPROVED_TO_EXECUTING and row.target_id:
            executors[row.target_id] = row.actor
    return executors


# ---------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------


async def build_change_sections(
    session: AsyncSession, *, period_start: datetime, period_end: datetime
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    """Assemble the ADR-0053 §7.1 change-report sections for one period.

    Naive period bounds are pinned as UTC (:func:`coerce_utc`) — the W3 sibling
    bug class: every boundary must interpret the same wall-clock period
    identically regardless of host timezone. Selection is CLOSED-OPEN: an event
    stamped exactly at ``period_start`` is included, exactly at ``period_end``
    excluded.

    Returns the four sections (stable titles/columns — the golden fixture and
    W4-T3 assert this structure) plus the payload notes.
    """
    start = coerce_utc(period_start)
    end = coerce_utc(period_end)

    cr_ids = await _active_cr_ids(session, start, end)
    crs = await _load_crs(session, cr_ids)
    lifecycle_rows = await _load_lifecycle_rows(session, cr_ids)
    approvals = await _load_approvals(session, cr_ids)

    executor_actors = _executors(lifecycle_rows)
    referenced_user_ids = [
        user_id
        for user_id in (
            *(cr.requester_id for cr in crs),
            *(approval.actor_id for approval in approvals),
            *(_actor_user_id(row.actor) for row in lifecycle_rows),
        )
        if user_id is not None
    ]
    users = await _load_identities(session, referenced_user_ids)

    cr_rows: list[tuple[str, ...]] = []
    diff_rows: list[tuple[str, ...]] = []
    for cr in crs:
        cr_id = str(cr.id)
        executor_actor = executor_actors.get(cr_id)
        cr_rows.append(
            (
                cr_id,
                cr.kind.value,
                cr.state.value,
                _identity_label(users.get(cr.requester_id), f"user:{cr.requester_id}"),
                _actor_label(executor_actor, users) if executor_actor is not None else _NONE,
                coerce_utc(cr.created_at).isoformat(),
                _trace_link(cr),
            )
        )
        diff_rows.append((cr_id, *diff_statistics(cr)))

    approval_rows = tuple(
        (
            str(approval.change_request_id),
            _identity_label(users.get(approval.actor_id), f"user:{approval.actor_id}"),
            approval.decision.value,
            coerce_utc(approval.created_at).isoformat(),
        )
        for approval in approvals
    )
    transition_rows = tuple(
        (
            row.target_id or _NONE,
            row.action.removeprefix(CR_LIFECYCLE_ACTION_PREFIX),
            _actor_label(row.actor, users),
            coerce_utc(row.created_at).isoformat(),
        )
        for row in lifecycle_rows
    )

    sections = (
        ReportSection(
            title=SECTION_CHANGE_REQUESTS, columns=CHANGE_REQUEST_COLUMNS, rows=tuple(cr_rows)
        ),
        ReportSection(title=SECTION_APPROVALS, columns=APPROVAL_COLUMNS, rows=approval_rows),
        ReportSection(title=SECTION_TRANSITIONS, columns=TRANSITION_COLUMNS, rows=transition_rows),
        ReportSection(title=SECTION_DIFF_STATISTICS, columns=DIFF_COLUMNS, rows=tuple(diff_rows)),
    )
    notes: tuple[str, ...] = (_NOTE_EVIDENCE, _NOTE_POSTURE)
    if not crs:
        notes = (NOTE_EMPTY_PERIOD, *notes)
    return sections, notes
