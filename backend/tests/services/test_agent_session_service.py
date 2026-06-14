"""Agent-session lifecycle service tests (M3-14).

Offline-first: an in-memory aiosqlite engine with the full model schema, a
scripted fake chat model, and an :class:`InMemoryTraceRecorder`-free path where
persistence matters. Covers three exit criteria:

1. A session persists across the start -> complete lifecycle.
2. A failing run marks the session FAILED and re-raises.
3. The invoking role propagates from the session into the tool run context:
   a viewer session is denied an engineer-tier tool end-to-end (and audited),
   while an engineer session reaches it.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from typing import Any, cast

import pytest
from langchain_core.messages import AIMessage
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.framework.registry import AgentRegistry
from app.agents.framework.supervisor import build_supervisor_graph
from app.agents.framework.tools import (
    NetOpsTool,
    RbacForbiddenError,
    ToolClassification,
    netops_tool,
)
from app.core.errors import LLMUpstreamError, NotFoundError
from app.core.security import Role
from app.models import (
    AgentSession,
    AgentSessionStatus,
    ReasoningTraceStep,
    User,
)
from app.models import Role as RoleRow
from app.models.agents import ReasoningTraceRow
from app.models.base import Base
from app.services.agent_session import AgentSessionService
from tests.agents.conftest import RecordingAuditSink, SpecialistFactory, scripted_model


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full model schema + FK enforcement."""
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


async def _seed_user(maker: async_sessionmaker[AsyncSession], *, role_name: str) -> uuid.UUID:
    """Persist a role + user row and return the user id (FK target)."""
    async with maker() as session:
        role = RoleRow(name=f"{role_name}-{uuid.uuid4().hex[:8]}")
        session.add(role)
        await session.flush()
        user = User(
            username=f"user-{uuid.uuid4().hex[:8]}",
            password_hash="x",
            role_id=role.id,
        )
        session.add(user)
        await session.commit()
        return user.id


def _engineer_bgp_tool(sink: RecordingAuditSink) -> NetOpsTool:
    @netops_tool(
        classification=ToolClassification.READ_ONLY,
        audit_sink=sink,
        min_role=Role.ENGINEER,
    )
    async def get_bgp_peers(device: str) -> str:
        """Read BGP peer status from a device (engineer-tier diagnostic read)."""
        return f"{device}: peer 10.0.0.2 is Idle"

    return get_bgp_peers


def _engineer_run_script() -> list[AIMessage]:
    """Routing decision -> troubleshooting, then the tool call, then a conclusion."""
    return [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "RoutingDecision",
                    "args": {
                        "specialist": "troubleshooting",
                        "ambiguous": False,
                        "rationale": "BGP fault question",
                    },
                    "id": "route-1",
                }
            ],
        ),
        AIMessage(
            content="",
            tool_calls=[{"name": "get_bgp_peers", "args": {"device": "edge-1"}, "id": "call-1"}],
        ),
        AIMessage(content="BGP peer 10.0.0.2 on edge-1 is down (Idle)."),
    ]


def _engineer_tool_registry(
    specialist_factory: SpecialistFactory, sink: RecordingAuditSink
) -> AgentRegistry:
    """A routable registry whose troubleshooting agent exposes an engineer-tier tool."""
    registry = AgentRegistry()
    registry.register(
        specialist_factory(
            "troubleshooting",
            description="Diagnoses routing, BGP, OSPF, DNS, and DHCP problems.",
            tools=[_engineer_bgp_tool(sink)],
        )
    )
    return registry


class TestLifecyclePersistence:
    async def test_start_persists_running_session(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="engineer")
        service = AgentSessionService(sessionmaker)

        session = await service.start(
            user_id=user_id, role=Role.ENGINEER, intent="why is bgp down?"
        )

        assert session.status is AgentSessionStatus.RUNNING
        assert session.invoking_role == "engineer"
        assert session.intent == "why is bgp down?"
        assert session.completed_at is None
        # Durable: a fresh read sees the same row.
        reloaded = await service.get(session.id)
        assert reloaded.id == session.id
        assert reloaded.status is AgentSessionStatus.RUNNING

    async def test_complete_marks_session_completed(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)
        session = await service.start(user_id=user_id, role=Role.VIEWER, intent="list devices")

        completed = await service.complete(session.id)

        assert completed.status is AgentSessionStatus.COMPLETED
        assert completed.completed_at is not None
        async with sessionmaker() as db:
            row = await db.get(AgentSession, session.id)
            assert row is not None
            assert row.status is AgentSessionStatus.COMPLETED

    async def test_fail_marks_session_failed(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)
        session = await service.start(user_id=user_id, role=Role.VIEWER, intent="boom")

        failed = await service.fail(session.id)

        assert failed.status is AgentSessionStatus.FAILED
        assert failed.completed_at is not None

    async def test_finish_is_idempotent_and_does_not_revert(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)
        session = await service.start(user_id=user_id, role=Role.VIEWER, intent="x")
        await service.complete(session.id)

        # A later fail() must not flip a COMPLETED session to FAILED.
        still = await service.fail(session.id)
        assert still.status is AgentSessionStatus.COMPLETED

    async def test_get_unknown_session_raises_not_found(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        service = AgentSessionService(sessionmaker)
        with pytest.raises(NotFoundError):
            await service.get(uuid.uuid4())


class TestRunLifecycle:
    async def test_successful_run_completes_session_and_links_trace(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        specialist_factory: SpecialistFactory,
        audit_sink: RecordingAuditSink,
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="engineer")
        service = AgentSessionService(sessionmaker)
        registry = _engineer_tool_registry(specialist_factory, audit_sink)

        # Pre-start the session, bind its id to the trace recorder, and pass
        # session_id into run() so a single session row owns both lifecycle and
        # traces (the invariant asserted below).
        run_session = await service.start(
            user_id=user_id, role=Role.ENGINEER, intent="why is BGP down on edge-1?"
        )
        recorder = service.recorder_for(run_session.id)
        graph = build_supervisor_graph(
            scripted_model(_engineer_run_script()), registry, trace_recorder=recorder
        )

        result = await service.run(
            graph,
            "why is BGP down on edge-1?",
            user_id=user_id,
            role=Role.ENGINEER,
            session_id=run_session.id,
        )

        assert result["specialist"] == "troubleshooting"
        assert audit_sink.events[-1].tool_name == "get_bgp_peers"
        assert audit_sink.events[-1].outcome == "success"
        # Exactly one session exists, it is COMPLETED, and every trace links to it.
        async with sessionmaker() as db:
            sessions = (await db.execute(select(AgentSession))).scalars().all()
            assert len(sessions) == 1, "run() must not open a second session row"
            assert sessions[0].status is AgentSessionStatus.COMPLETED
            assert sessions[0].id == run_session.id
            traces = (await db.execute(select(ReasoningTraceRow))).scalars().all()
            assert traces, "the run must persist at least one reasoning trace"
            assert all(t.session_id == run_session.id for t in traces)

    async def test_failed_run_marks_session_failed_and_reraises(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        specialist_factory: SpecialistFactory,
        audit_sink: RecordingAuditSink,
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)
        registry = _engineer_tool_registry(specialist_factory, audit_sink)
        graph = build_supervisor_graph(scripted_model(_engineer_run_script()), registry)

        # A viewer driving an engineer-tier tool is denied mid-run -> the run
        # raises, so the session must be FAILED.
        with pytest.raises(RbacForbiddenError):
            await service.run(
                graph,
                "why is BGP down on edge-1?",
                user_id=user_id,
                role=Role.VIEWER,
            )

        async with sessionmaker() as db:
            sessions = (await db.execute(select(AgentSession))).scalars().all()
            assert len(sessions) == 1
            assert sessions[0].status is AgentSessionStatus.FAILED


class TestRolePropagation:
    """The invoking role flows from the session into the RBAC tool context."""

    async def test_engineer_session_reaches_engineer_tier_tool(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        specialist_factory: SpecialistFactory,
        audit_sink: RecordingAuditSink,
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="engineer")
        service = AgentSessionService(sessionmaker)
        registry = _engineer_tool_registry(specialist_factory, audit_sink)
        graph = build_supervisor_graph(scripted_model(_engineer_run_script()), registry)

        result = await service.run(
            graph,
            "why is BGP down on edge-1?",
            user_id=user_id,
            role=Role.ENGINEER,
        )

        assert "BGP peer 10.0.0.2 on edge-1 is down (Idle)." in result["messages"][-1].content
        assert audit_sink.events[-1].outcome == "success"

    async def test_viewer_session_cannot_trigger_engineer_tier_tool(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        specialist_factory: SpecialistFactory,
        audit_sink: RecordingAuditSink,
    ) -> None:
        user_id = await _seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)
        registry = _engineer_tool_registry(specialist_factory, audit_sink)
        graph = build_supervisor_graph(scripted_model(_engineer_run_script()), registry)

        with pytest.raises(RbacForbiddenError):
            await service.run(
                graph,
                "why is BGP down on edge-1?",
                user_id=user_id,
                role=Role.VIEWER,
            )

        # The denial is audited, and the session is recorded as FAILED.
        assert audit_sink.events[-1].outcome == "denied"
        async with sessionmaker() as db:
            session = (await db.execute(select(AgentSession))).scalars().one()
            assert session.status is AgentSessionStatus.FAILED
            # No reasoning step records a successful tool call for the viewer.
            steps = (await db.execute(select(ReasoningTraceStep))).scalars().all()
            assert all(s.tool_name != "get_bgp_peers" or s.kind.value != "tool_call" for s in steps)


class TestProviderErrorTranslation:
    """A provider/transport failure during a run surfaces as a typed 502, and the
    session is still marked FAILED (the raw SDK exception never reaches the API)."""

    async def test_provider_error_is_translated_and_session_failed(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import app.services.agent_session.service as svc

        # Simulate an anthropic/ollama SDK exception (recognized by its module)
        # raised mid-run, without importing or depending on the provider SDK.
        provider_exc = type("BadRequestError", (Exception,), {"__module__": "anthropic"})(
            "credit balance is too low"
        )

        async def _boom(*_args: object, **_kwargs: object) -> None:
            raise provider_exc

        monkeypatch.setattr(svc, "run_supervisor", _boom)

        user_id = await _seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)
        run_session = await service.start(user_id=user_id, role=Role.VIEWER, intent="x")

        with pytest.raises(LLMUpstreamError):
            await service.run(
                cast(Any, None),  # graph is unused: run_supervisor is monkeypatched
                "x",
                user_id=user_id,
                role=Role.VIEWER,
                session_id=run_session.id,
            )

        async with sessionmaker() as db:
            row = await db.get(AgentSession, run_session.id)
            assert row is not None
            assert row.status is AgentSessionStatus.FAILED

    async def test_genuine_bug_is_not_masked_as_provider_error(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import app.services.agent_session.service as svc

        async def _bug(*_args: object, **_kwargs: object) -> None:
            raise AttributeError("'NoneType' object has no attribute 'domain'")

        monkeypatch.setattr(svc, "run_supervisor", _bug)
        user_id = await _seed_user(sessionmaker, role_name="viewer")
        service = AgentSessionService(sessionmaker)
        run_session = await service.start(user_id=user_id, role=Role.VIEWER, intent="x")

        # A real code bug must still surface (as a 500), not be hidden as a 502.
        with pytest.raises(AttributeError):
            await service.run(
                cast(Any, None),
                "x",
                user_id=user_id,
                role=Role.VIEWER,
                session_id=run_session.id,
            )
