"""Read-only completeness reconciliation for PRODUCTION.md §6 rows 5/6/9."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta

from sqlalchemy import and_, case, exists, func, literal, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.models.agents import (
    AgentSession,
    AgentSessionStatus,
    ReasoningTraceRow,
    ReasoningTraceStep,
)
from app.models.audit import AuditLog
from app.models.change_requests import ChangeRequest, ChangeRequestState
from app.models.config_mgmt import ConfigBackupRun

BACKUP_MISS_GRACE = timedelta(minutes=15)
# Persistence lifecycle contract: PostgresTraceRecorder awaits the commit for a
# trace header, every step, and trace completion. AgentSessionService then awaits
# the terminal session commit only after the supervisor (and therefore its trace
# recorder) returns. There is no background persistence or retry queue to settle:
# a committed row is authoritative immediately. The reconciliation job's daily
# cadence controls detection latency, not transaction settlement.
TRACE_SETTLED_GRACE = timedelta(0)


@dataclass(frozen=True)
class ReconcileResult:
    inconsistencies: int


@dataclass(frozen=True)
class TraceReconcileResult:
    sessions_without_trace: int
    traces_without_session: int
    steps_without_trace: int

    @property
    def inconsistencies(self) -> int:
        return self.sessions_without_trace + self.traces_without_session + self.steps_without_trace


def backup_slot_due(*, now: datetime, due_at: datetime, enabled: bool = True) -> bool:
    """Whether an enabled backup slot has entered its 15-minute miss window."""
    return enabled and now >= due_at + BACKUP_MISS_GRACE


def most_recent_due_backup_slot(*, now: datetime, hour: int, minute: int) -> tuple[str, datetime]:
    """Return the latest slot whose miss-grace boundary is due, including yesterday."""
    due_at = datetime.combine(now.date(), time(hour, minute), tzinfo=UTC)
    if now < due_at + BACKUP_MISS_GRACE:
        due_at -= timedelta(days=1)
    return due_at.date().isoformat(), due_at


def is_settled(*, timestamp: datetime, now: datetime) -> bool:
    """Return true at and beyond the documented trace settlement boundary."""
    return timestamp <= now - TRACE_SETTLED_GRACE


async def reconcile_config_backup(
    session: AsyncSession,
    *,
    slot: str,
    due_at: datetime,
    now: datetime | None = None,
    enabled: bool = True,
) -> ReconcileResult:
    """Count one missed scheduled slot; disabled/not-yet-due slots are excluded."""
    checked_at = now or datetime.now(UTC)
    if not backup_slot_due(now=checked_at, due_at=due_at, enabled=enabled):
        return ReconcileResult(0)
    successful = await session.scalar(
        select(
            exists().where(
                ConfigBackupRun.scheduled_slot == slot,
                ConfigBackupRun.status.in_(("succeeded", "empty")),
                ConfigBackupRun.finished_at.is_not(None),
            )
        )
    )
    return ReconcileResult(0 if successful else 1)


def change_request_audit_reconciliation_query() -> Select[tuple[int]]:
    """Build the set-wise aggregate/join used by CR audit reconciliation."""
    expected_completed = (
        "change_request.created",
        "change_request.draft_to_pending_approval",
        "change_request.pending_approval_to_approved",
        "change_request.approved_to_executing",
        "change_request.executing_to_completed",
    )
    expected_rolled_back = expected_completed[:-1] + (
        "change_request.executing_to_failed",
        "change_request.failed_to_rolled_back",
    )
    expected_actions = tuple(dict.fromkeys(expected_completed + expected_rolled_back))
    audit_counts = (
        select(
            AuditLog.target_id.label("target_id"),
            AuditLog.reasoning_trace_id.label("reasoning_trace_id"),
            func.count(
                func.distinct(case((AuditLog.action.in_(expected_completed), AuditLog.action)))
            ).label("completed_action_count"),
            func.count(
                func.distinct(case((AuditLog.action.in_(expected_rolled_back), AuditLog.action)))
            ).label("rolled_back_action_count"),
        )
        .where(
            AuditLog.target_type == "change_request",
            AuditLog.action.in_(expected_actions),
        )
        .group_by(AuditLog.target_id, AuditLog.reasoning_trace_id)
        .cte("audit_counts")
    )
    expected_count = case(
        (ChangeRequest.state == ChangeRequestState.COMPLETED, literal(len(expected_completed))),
        else_=literal(len(expected_rolled_back)),
    )
    terminal_crs = (
        select(
            ChangeRequest.id.label("id"),
            ChangeRequest.reasoning_trace_id.label("reasoning_trace_id"),
            ChangeRequest.state.label("state"),
            expected_count.label("expected_count"),
        )
        .where(
            ChangeRequest.state.in_((ChangeRequestState.COMPLETED, ChangeRequestState.ROLLED_BACK)),
        )
        .cte("terminal_crs")
    )
    action_count = case(
        (
            terminal_crs.c.state == ChangeRequestState.COMPLETED,
            audit_counts.c.completed_action_count,
        ),
        else_=audit_counts.c.rolled_back_action_count,
    )
    return (
        select(func.count())
        .select_from(
            terminal_crs.outerjoin(
                audit_counts,
                and_(
                    audit_counts.c.target_id
                    == func.cast(terminal_crs.c.id, AuditLog.target_id.type),
                    audit_counts.c.reasoning_trace_id == terminal_crs.c.reasoning_trace_id,
                ),
            )
        )
        .where(
            or_(
                terminal_crs.c.reasoning_trace_id.is_(None),
                func.coalesce(action_count, 0) < terminal_crs.c.expected_count,
            )
        )
    )


async def reconcile_change_request_audit(session: AsyncSession) -> ReconcileResult:
    """Count terminal executed CRs missing any required lifecycle audit edge."""
    count = await session.scalar(change_request_audit_reconciliation_query())
    return ReconcileResult(int(count or 0))


async def reconcile_reasoning_traces(
    session: AsyncSession, *, now: datetime | None = None
) -> TraceReconcileResult:
    """Count all three settled session/trace/step orphan shapes."""
    cutoff = (now or datetime.now(UTC)) - TRACE_SETTLED_GRACE
    sessions_without_trace = await session.scalar(
        select(func.count())
        .select_from(AgentSession)
        .where(
            AgentSession.status.in_((AgentSessionStatus.COMPLETED, AgentSessionStatus.FAILED)),
            AgentSession.completed_at <= cutoff,
            ~exists().where(ReasoningTraceRow.session_id == AgentSession.id),
        )
    )
    traces_without_session = await session.scalar(
        select(func.count())
        .select_from(ReasoningTraceRow)
        .where(
            ReasoningTraceRow.created_at <= cutoff,
            ~exists().where(AgentSession.id == ReasoningTraceRow.session_id),
        )
    )
    steps_without_trace = await session.scalar(
        select(func.count())
        .select_from(ReasoningTraceStep)
        .where(
            ReasoningTraceStep.created_at <= cutoff,
            ~exists().where(ReasoningTraceRow.id == ReasoningTraceStep.trace_id),
        )
    )
    return TraceReconcileResult(
        int(sessions_without_trace or 0),
        int(traces_without_session or 0),
        int(steps_without_trace or 0),
    )
