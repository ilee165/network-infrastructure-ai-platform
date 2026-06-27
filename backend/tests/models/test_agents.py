"""Agent-session + reasoning-trace ORM roundtrips and FK integrity (M3-01).

Mirrors ``tests/models/test_audit.py`` / ``test_inventory.py``: in-memory
aiosqlite, no Postgres/Docker/network. Partition-DDL behaviour is asserted at
the metadata level (``test_metadata.py``) and exercised for real by the
``integration``-marked migration test.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    AgentSession,
    AgentSessionStatus,
    AuditLog,
    ReasoningTraceRow,
    ReasoningTraceStep,
    Role,
    TraceStepKind,
    User,
)


async def _user(session: AsyncSession) -> User:
    """Persist a role + user so ``agent_sessions.user_id`` has a target."""
    role = Role(name=f"role-{uuid.uuid4().hex[:8]}")
    session.add(role)
    await session.flush()
    user = User(username=f"user-{uuid.uuid4().hex[:8]}", password_hash="x", role_id=role.id)
    session.add(user)
    await session.flush()
    return user


async def test_agent_session_roundtrip(session: AsyncSession) -> None:
    """An agent session persists and reloads with its enum + timestamps intact."""
    user = await _user(session)
    started = datetime(2026, 6, 13, 12, 0, tzinfo=UTC)
    agent_session = AgentSession(
        user_id=user.id,
        invoking_role="engineer",
        intent="why is bgp peer 10.0.0.1 down?",
        status=AgentSessionStatus.RUNNING,
        started_at=started,
    )
    session.add(agent_session)
    await session.commit()

    reloaded = (
        await session.execute(
            select(AgentSession)
            .where(AgentSession.id == agent_session.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.status is AgentSessionStatus.RUNNING
    assert reloaded.intent == "why is bgp peer 10.0.0.1 down?"
    assert reloaded.invoking_role == "engineer"
    assert reloaded.started_at == started
    assert reloaded.completed_at is None
    assert reloaded.user_id == user.id


async def test_agent_session_requires_user_fk(session: AsyncSession) -> None:
    """user_id references users.id — an unknown user violates the FK."""
    session.add(
        AgentSession(
            user_id=uuid.uuid4(),
            invoking_role="viewer",
            intent="orphan",
            status=AgentSessionStatus.RUNNING,
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


async def test_reasoning_trace_and_steps_roundtrip(session: AsyncSession) -> None:
    """A trace with ordered steps persists; EvidenceRef-shaped JSONB roundtrips."""
    user = await _user(session)
    agent_session = AgentSession(
        user_id=user.id,
        invoking_role="engineer",
        intent="trace me",
        status=AgentSessionStatus.RUNNING,
    )
    session.add(agent_session)
    await session.flush()

    trace = ReasoningTraceRow(session_id=agent_session.id, agent_name="troubleshooting")
    session.add(trace)
    await session.flush()

    evidence = [
        {"kind": "raw_artifact", "reference": str(uuid.uuid4()), "description": "show bgp"},
    ]
    session.add_all(
        [
            ReasoningTraceStep(
                trace_id=trace.id,
                ordinal=0,
                kind=TraceStepKind.PLAN,
                summary="route to troubleshooting specialist",
            ),
            ReasoningTraceStep(
                trace_id=trace.id,
                ordinal=1,
                kind=TraceStepKind.TOOL_CALL,
                summary="fetch bgp peers",
                detail="get_bgp_peers(device=core-01)",
                tool_name="get_bgp_peers",
                evidence=evidence,
                occurred_at=datetime(2026, 6, 13, 12, 1, tzinfo=UTC),
            ),
        ]
    )
    await session.commit()

    steps = (
        (
            await session.execute(
                select(ReasoningTraceStep)
                .where(ReasoningTraceStep.trace_id == trace.id)
                .order_by(ReasoningTraceStep.ordinal)
            )
        )
        .scalars()
        .all()
    )
    assert [step.kind for step in steps] == [TraceStepKind.PLAN, TraceStepKind.TOOL_CALL]
    assert steps[1].tool_name == "get_bgp_peers"
    assert steps[1].evidence == evidence
    assert steps[0].detail is None
    assert steps[0].tool_name is None


async def test_reasoning_trace_requires_session_fk(session: AsyncSession) -> None:
    """session_id references agent_sessions.id — an orphan trace is rejected."""
    session.add(ReasoningTraceRow(session_id=uuid.uuid4(), agent_name="ghost"))
    with pytest.raises(IntegrityError):
        await session.flush()
    await session.rollback()


def test_step_trace_id_is_plain_indexed_uuid_without_fk() -> None:
    """reasoning_trace_steps.trace_id is a bare indexed UUID, no DB-level FK.

    ``reasoning_traces`` is range-partitioned, and PostgreSQL FKs to a
    partitioned table must include the partition key — so, exactly as with
    ``raw_artifact_id`` (M1-18), there is no FK and linkage integrity is
    enforced by tests.
    """
    from app.models import Base

    table = Base.metadata.tables["reasoning_trace_steps"]
    column = table.columns["trace_id"]
    assert not column.foreign_keys
    assert not column.nullable
    indexed_columns = {c.name for index in table.indexes for c in index.columns}
    assert "trace_id" in indexed_columns


def test_audit_log_reasoning_trace_id_is_plain_indexed_uuid_without_fk() -> None:
    """audit_log.reasoning_trace_id is a nullable indexed UUID, no DB-level FK."""
    from app.models import Base

    table = Base.metadata.tables["audit_log"]
    column = table.columns["reasoning_trace_id"]
    assert not column.foreign_keys
    assert column.nullable
    indexed_columns = {c.name for index in table.indexes for c in index.columns}
    assert "reasoning_trace_id" in indexed_columns


def test_model_trace_step_kind_matches_framework_wire_values() -> None:
    """The persisted enum must not drift from the in-process trace enum."""
    from app.agents.framework.traces import TraceStepKind as FrameworkKind

    assert {kind.value for kind in TraceStepKind} == {kind.value for kind in FrameworkKind}


async def test_audit_log_links_to_reasoning_trace(session: AsyncSession) -> None:
    """audit_log.reasoning_trace_id is a nullable link to a trace (brief §6)."""
    user = await _user(session)
    agent_session = AgentSession(
        user_id=user.id,
        invoking_role="engineer",
        intent="link me",
        status=AgentSessionStatus.RUNNING,
    )
    session.add(agent_session)
    await session.flush()
    trace = ReasoningTraceRow(session_id=agent_session.id, agent_name="troubleshooting")
    session.add(trace)
    await session.flush()

    # ``seq`` is supplied explicitly (distinct values): it is UNIQUE (PR #76 round-2
    # #4) and the model's MAX(seq)+1 default cannot disambiguate two rows added in
    # the SAME batch flush (both read MAX=0 → 1 → clash). The real writer assigns it
    # under the append advisory lock, one flush per append, so it never collides.
    linked = AuditLog(
        seq=1,
        actor="agent:troubleshooting",
        action="tool.invoke",
        target_type="device",
        target_id=str(uuid.uuid4()),
        reasoning_trace_id=trace.id,
    )
    unlinked = AuditLog(
        seq=2, actor="admin", action="auth.login", target_type="user", target_id=None
    )
    session.add_all([linked, unlinked])
    await session.commit()

    reloaded = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.id == linked.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.reasoning_trace_id == trace.id
    assert unlinked.reasoning_trace_id is None
