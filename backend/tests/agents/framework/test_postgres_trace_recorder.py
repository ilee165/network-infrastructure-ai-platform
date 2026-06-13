"""DB-backed reasoning-trace recorder tests (M3-02).

Offline-first like every other unit test: an in-memory aiosqlite engine with
the full model schema, no Postgres/Docker/network. The Postgres recorder is
exercised through the same :class:`TraceRecorder` protocol as the in-memory
one; PostgreSQL-only behaviour (partition DDL) is covered by the
``integration``-marked migration test, not here.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.framework.traces import (
    EvidenceRef,
    InMemoryTraceRecorder,
    PostgresTraceRecorder,
    TraceRecorder,
    TraceStep,
    TraceStepKind,
    build_trace_recorder,
)
from app.core.errors import NotFoundError
from app.models import (
    AgentSession,
    AgentSessionStatus,
    ReasoningTraceStep,
    Role,
    User,
)
from app.models.base import Base


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full model schema created."""
    engine = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(engine.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """A sessionmaker bound to the in-memory test engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def _agent_session(maker: async_sessionmaker[AsyncSession]) -> uuid.UUID:
    """Persist a role + user + agent session and return the session id."""
    async with maker() as session:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}")
        session.add(role)
        await session.flush()
        user = User(username=f"user-{uuid.uuid4().hex[:8]}", password_hash="x", role_id=role.id)
        session.add(user)
        await session.flush()
        agent_session = AgentSession(
            user_id=user.id,
            invoking_role="engineer",
            intent="why is bgp peer 10.0.0.1 down?",
            status=AgentSessionStatus.RUNNING,
        )
        session.add(agent_session)
        await session.commit()
        return agent_session.id


def _tool_step() -> TraceStep:
    return TraceStep(
        kind=TraceStepKind.TOOL_CALL,
        summary="fetch bgp peers",
        detail="get_bgp_peers(device=core-01)",
        tool_name="get_bgp_peers",
        evidence=[
            EvidenceRef(kind="raw_artifact", reference="artifact-42", description="show bgp"),
        ],
    )


class TestPostgresTraceRecorder:
    async def test_persisted_trace_reloads_identical(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """A trace round-trips: steps stay ordered and evidence is preserved."""
        session_id = await _agent_session(sessionmaker)
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)

        trace = await recorder.start("troubleshooting")
        await recorder.record_step(
            trace.trace_id, TraceStep(kind=TraceStepKind.PLAN, summary="route to specialist")
        )
        await recorder.record_step(trace.trace_id, _tool_step())
        await recorder.record_step(
            trace.trace_id,
            TraceStep(kind=TraceStepKind.CONCLUSION, summary="peer flapping on bad MTU"),
        )

        reloaded = await recorder.get(trace.trace_id)

        assert reloaded.trace_id == trace.trace_id
        assert reloaded.agent_name == "troubleshooting"
        assert [s.kind for s in reloaded.steps] == [
            TraceStepKind.PLAN,
            TraceStepKind.TOOL_CALL,
            TraceStepKind.CONCLUSION,
        ]
        assert [s.summary for s in reloaded.steps] == [
            "route to specialist",
            "fetch bgp peers",
            "peer flapping on bad MTU",
        ]
        tool_step = reloaded.steps[1]
        assert tool_step.tool_name == "get_bgp_peers"
        assert tool_step.detail == "get_bgp_peers(device=core-01)"
        assert tool_step.evidence == [
            EvidenceRef(kind="raw_artifact", reference="artifact-42", description="show bgp"),
        ]

    async def test_steps_persist_with_dense_ascending_ordinals(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Each recorded step gets the next ordinal (0, 1, 2, ...)."""
        session_id = await _agent_session(sessionmaker)
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
        trace = await recorder.start("discovery")
        for i in range(3):
            await recorder.record_step(
                trace.trace_id, TraceStep(kind=TraceStepKind.PLAN, summary=f"step-{i}")
            )

        async with sessionmaker() as session:
            ordinals = (
                (
                    await session.execute(
                        select(ReasoningTraceStep.ordinal)
                        .where(ReasoningTraceStep.trace_id == uuid.UUID(trace.trace_id))
                        .order_by(ReasoningTraceStep.ordinal)
                    )
                )
                .scalars()
                .all()
            )
        assert ordinals == [0, 1, 2]

    async def test_complete_stamps_completed_at(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """complete() stamps completed_at and is idempotent."""
        session_id = await _agent_session(sessionmaker)
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
        trace = await recorder.start("discovery")
        assert trace.completed_at is None

        completed = await recorder.complete(trace.trace_id)
        assert completed.is_complete is True
        first_stamp = completed.completed_at

        again = await recorder.complete(trace.trace_id)
        assert again.completed_at == first_stamp

        reloaded = await recorder.get(trace.trace_id)
        assert reloaded.completed_at == first_stamp

    async def test_record_into_missing_trace_raises_not_found(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Recording into an unknown trace id raises NotFoundError."""
        session_id = await _agent_session(sessionmaker)
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
        with pytest.raises(NotFoundError):
            await recorder.record_step(
                uuid.uuid4().hex, TraceStep(kind=TraceStepKind.PLAN, summary="orphan")
            )

    async def test_complete_missing_trace_raises_not_found(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Completing an unknown trace id raises NotFoundError."""
        session_id = await _agent_session(sessionmaker)
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
        with pytest.raises(NotFoundError):
            await recorder.complete(uuid.uuid4().hex)

    async def test_get_missing_trace_raises_not_found(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Reloading an unknown trace id raises NotFoundError."""
        session_id = await _agent_session(sessionmaker)
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
        with pytest.raises(NotFoundError):
            await recorder.get(uuid.uuid4().hex)

    async def test_recorder_satisfies_the_protocol(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        recorder = PostgresTraceRecorder(sessionmaker, session_id=uuid.uuid4())
        assert isinstance(recorder, TraceRecorder)

    async def test_concurrent_record_step_yields_distinct_ordinals(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        """Two concurrent record_step calls on the same trace must both persist
        with distinct ordinals and raise no exception — regression guard for the
        SELECT FOR UPDATE fix (finding M3-02 #1)."""
        import asyncio

        session_id = await _agent_session(sessionmaker)
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
        trace = await recorder.start("troubleshooting")

        step_a = TraceStep(kind=TraceStepKind.PLAN, summary="concurrent-step-a")
        step_b = TraceStep(kind=TraceStepKind.PLAN, summary="concurrent-step-b")

        # Fire both record_step calls concurrently; neither should raise.
        results = await asyncio.gather(
            recorder.record_step(trace.trace_id, step_a),
            recorder.record_step(trace.trace_id, step_b),
        )
        assert len(results) == 2

        reloaded = await recorder.get(trace.trace_id)
        assert len(reloaded.steps) == 2
        ordinals_in_db: list[int]
        async with sessionmaker() as session:
            from sqlalchemy import select as sa_select

            ordinals_in_db = list(
                (
                    await session.execute(
                        sa_select(ReasoningTraceStep.ordinal)
                        .where(ReasoningTraceStep.trace_id == uuid.UUID(trace.trace_id))
                        .order_by(ReasoningTraceStep.ordinal)
                    )
                )
                .scalars()
                .all()
            )
        assert ordinals_in_db == [0, 1], f"expected distinct ordinals [0, 1], got {ordinals_in_db}"


class TestBuildTraceRecorder:
    def test_in_memory_selection_returns_in_memory_recorder(self) -> None:
        recorder = build_trace_recorder(None, session_id=None)
        assert isinstance(recorder, InMemoryTraceRecorder)

    def test_postgres_selection_returns_postgres_recorder(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        recorder = build_trace_recorder(sessionmaker, session_id=uuid.uuid4())
        assert isinstance(recorder, PostgresTraceRecorder)

    def test_postgres_selection_requires_session_id(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        with pytest.raises(ValueError, match="session_id"):
            build_trace_recorder(sessionmaker, session_id=None)
