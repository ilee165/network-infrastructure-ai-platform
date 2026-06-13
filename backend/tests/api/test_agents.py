"""Agent session API tests (M3-15): REST + WebSocket auth, RBAC, trace, streaming.

Offline-first (D16): an in-memory aiosqlite engine carries the full schema, the
supervisor is compiled over a scripted chat model (never a real LLM provider),
and both the request-scoped session and the lifecycle-owning sessionmaker bind
to the same engine. The WebSocket cases use Starlette's synchronous
``TestClient`` because the async httpx ASGI transport does not speak WebSocket.

Covers the task's security exit criteria:

- anonymous REST start/get -> 401;
- WS rejects an unauthenticated peer with a policy-violation close (no frames);
- RBAC floor is ``viewer`` (a valid viewer token is accepted);
- ``GET`` returns the persisted session and its full reasoning trace;
- the stream yields the recorded trace steps in order, then a terminal frame;
- session start + completion + each trace are audited.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from langchain_core.messages import AIMessage
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.supervisor import build_supervisor_graph
from app.agents.framework.tools import NetOpsTool
from app.api import deps
from app.api.v1 import agents as agents_router
from app.core.config import Settings
from app.core.security import Role, create_access_token, hash_password
from app.models import AgentSessionStatus, AuditLog, Base, ReasoningTraceRow, User
from app.models import Role as RoleRow
from app.services import audit
from tests.agents.conftest import SpecialistFactory, _StubSpecialist, scripted_model

TEST_PASSWORD = "unit-test-password"
ROLE_ORDER = ("viewer", "operator", "engineer", "admin")


def _make_specialist(
    name: str,
    *,
    description: str | None = None,
    system_prompt: str = "You are a test specialist agent.",
    tools: tuple[NetOpsTool, ...] = (),
) -> BaseSpecialistAgent:
    """Build a minimal valid specialist (mirrors the agent-suite factory)."""
    return _StubSpecialist(
        name=name,
        description=description if description is not None else f"Handles {name} requests.",
        system_prompt=system_prompt,
        tools=tools,
    )


# --------------------------------------------------------------------------- #
# Engine + data fixtures (in-memory aiosqlite, full schema, FK enforcement).
# --------------------------------------------------------------------------- #
@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(eng.sync_engine, "connect")
    def _fks(dbapi_connection: Any, _record: Any) -> None:
        cur = dbapi_connection.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
async def users(sessionmaker: async_sessionmaker[AsyncSession]) -> dict[str, User]:
    """One active user per role plus one inactive viewer, keyed by role name."""
    password_hash = hash_password(TEST_PASSWORD)
    async with sessionmaker() as session:
        roles = {name: RoleRow(name=name) for name in ROLE_ORDER}
        session.add_all(roles.values())
        await session.flush()
        seeded: dict[str, User] = {}
        for name in ROLE_ORDER:
            user = User(username=f"{name}_user", password_hash=password_hash, role=roles[name])
            session.add(user)
            seeded[name] = user
        inactive = User(
            username="inactive_user",
            password_hash=password_hash,
            role=roles["viewer"],
            is_active=False,
        )
        session.add(inactive)
        seeded["inactive"] = inactive
        await session.commit()
        for user in seeded.values():
            await session.refresh(user, attribute_names=["role"])
        return seeded


@pytest.fixture()
def token_for(users: dict[str, User], settings: Settings) -> Callable[[str], str]:
    def _mint(role: str) -> str:
        user = users[role]
        return create_access_token(
            str(user.id),
            settings,
            extra_claims={"type": "access", "roles": [user.role.name]},
        )

    return _mint


# --------------------------------------------------------------------------- #
# A deterministic supervisor builder injected in place of the real LLM path.
# --------------------------------------------------------------------------- #
def _routing_script() -> list[AIMessage]:
    """Route to the troubleshooting specialist, then conclude — no tool calls."""
    return [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "RoutingDecision",
                    "args": {
                        "specialist": "troubleshooting",
                        "ambiguous": False,
                        "rationale": "diagnostic question",
                    },
                    "id": "route-1",
                }
            ],
        ),
        AIMessage(content="The link is healthy; no fault detected."),
    ]


@pytest.fixture()
def specialist_factory() -> SpecialistFactory:
    """Local copy of the agent-suite factory (conftests do not cross test dirs)."""
    return _make_specialist


@pytest.fixture()
def scripted_builder(specialist_factory: SpecialistFactory) -> Callable[..., Any]:
    """A ``get_supervisor_builder`` override compiling over a scripted model."""

    def _builder(role: Role, settings: Settings, *, trace_recorder: Any = None) -> Any:
        registry = AgentRegistry()
        registry.register(
            specialist_factory(
                "troubleshooting",
                description="Diagnoses routing, BGP, OSPF, DNS, and DHCP problems.",
            )
        )
        return build_supervisor_graph(
            scripted_model(_routing_script()), registry, trace_recorder=trace_recorder
        )

    return _builder


@pytest.fixture()
def app(
    settings: Settings,
    sessionmaker: async_sessionmaker[AsyncSession],
    scripted_builder: Callable[..., Any],
) -> Iterator[FastAPI]:
    """The app wired to the in-memory engine and the scripted supervisor."""
    from app.main import create_app

    application = create_app(settings)

    async def _override_db() -> AsyncIterator[AsyncSession]:
        async with sessionmaker() as session:
            yield session

    application.dependency_overrides[deps.get_db] = _override_db
    application.dependency_overrides[deps.get_sessionmaker] = lambda: sessionmaker
    application.dependency_overrides[agents_router.get_supervisor_builder] = lambda: (
        scripted_builder
    )
    yield application
    application.dependency_overrides.clear()


@pytest.fixture()
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="https://testserver") as test_client:
        yield test_client


# --------------------------------------------------------------------------- #
# REST: authentication + RBAC.
# --------------------------------------------------------------------------- #
class TestRestAuth:
    async def test_start_requires_authentication(self, client: httpx.AsyncClient) -> None:
        resp = await client.post("/api/v1/agents", json={"intent": "why is bgp down?"})
        assert resp.status_code == 401

    async def test_get_requires_authentication(self, client: httpx.AsyncClient) -> None:
        resp = await client.get("/api/v1/agents/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 401

    async def test_start_rejects_garbage_token(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(
            "/api/v1/agents",
            json={"intent": "hi"},
            headers={"Authorization": "Bearer not-a-jwt"},
        )
        assert resp.status_code == 401

    async def test_viewer_may_start_a_session(
        self, client: httpx.AsyncClient, token_for: Callable[[str], str]
    ) -> None:
        resp = await client.post(
            "/api/v1/agents",
            json={"intent": "is the core link healthy?"},
            headers={"Authorization": f"Bearer {token_for('viewer')}"},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["session"]["status"] == AgentSessionStatus.COMPLETED.value
        assert body["session"]["invoking_role"] == "viewer"
        assert body["answer"]


# --------------------------------------------------------------------------- #
# REST: the started session carries the invoking role and a persisted trace.
# --------------------------------------------------------------------------- #
class TestStartAndRead:
    async def test_get_returns_persisted_session_and_trace(
        self,
        client: httpx.AsyncClient,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        start = await client.post(
            "/api/v1/agents",
            json={"intent": "check ospf neighbors"},
            headers={"Authorization": f"Bearer {token_for('engineer')}"},
        )
        assert start.status_code == 201, start.text
        session_id = start.json()["session"]["id"]

        got = await client.get(
            f"/api/v1/agents/{session_id}",
            headers={"Authorization": f"Bearer {token_for('engineer')}"},
        )
        assert got.status_code == 200, got.text
        body = got.json()
        assert body["session"]["id"] == session_id
        assert body["session"]["status"] == AgentSessionStatus.COMPLETED.value
        assert body["traces"], "the run must persist at least one reasoning trace"
        steps = body["traces"][0]["steps"]
        assert [step["kind"] for step in steps][0] == "plan"
        assert steps[-1]["kind"] == "conclusion"

        # Every persisted trace links back to the session row.
        async with sessionmaker() as db:
            traces = (await db.execute(select(ReasoningTraceRow))).scalars().all()
            assert traces
            from uuid import UUID

            assert all(t.session_id == UUID(session_id) for t in traces)

    async def test_get_unknown_session_is_404(
        self, client: httpx.AsyncClient, token_for: Callable[[str], str]
    ) -> None:
        resp = await client.get(
            "/api/v1/agents/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {token_for('viewer')}"},
        )
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Auditing: start + completion + each trace.
# --------------------------------------------------------------------------- #
class TestAuditing:
    async def test_session_lifecycle_and_traces_are_audited(
        self,
        client: httpx.AsyncClient,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        start = await client.post(
            "/api/v1/agents",
            json={"intent": "audit me"},
            headers={"Authorization": f"Bearer {token_for('engineer')}"},
        )
        assert start.status_code == 201, start.text
        session_id = start.json()["session"]["id"]

        async with sessionmaker() as db:
            entries = (
                (
                    await db.execute(
                        select(AuditLog)
                        .where(AuditLog.target_id == session_id)
                        .order_by(AuditLog.created_at)
                    )
                )
                .scalars()
                .all()
            )
        actions = {entry.action for entry in entries}
        assert audit.AGENT_SESSION_STARTED in actions
        assert audit.AGENT_SESSION_COMPLETED in actions
        assert audit.AGENT_TRACE_RECORDED in actions
        # The trace audit entry links to the reasoning trace it describes.
        trace_entries = [e for e in entries if e.action == audit.AGENT_TRACE_RECORDED]
        assert trace_entries and all(e.reasoning_trace_id is not None for e in trace_entries)
        # No secret material: details carry only metadata, never the raw intent.
        for entry in entries:
            assert "audit me" not in str(entry.detail)


# --------------------------------------------------------------------------- #
# WebSocket: authentication + ordered streaming.
# --------------------------------------------------------------------------- #
class TestWebSocketStream:
    async def _start_session(
        self, client: httpx.AsyncClient, token_for: Callable[[str], str]
    ) -> str:
        resp = await client.post(
            "/api/v1/agents",
            json={"intent": "stream me"},
            headers={"Authorization": f"Bearer {token_for('viewer')}"},
        )
        assert resp.status_code == 201, resp.text
        return str(resp.json()["session"]["id"])

    async def test_unauthenticated_socket_is_rejected(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        token_for: Callable[[str], str],
    ) -> None:
        session_id = await self._start_session(client, token_for)
        sync_client = TestClient(app)
        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            sync_client.websocket_connect(f"/api/v1/agents/{session_id}/stream") as ws,
        ):
            ws.receive_json()
        assert exc_info.value.code == agents_router._WS_POLICY_VIOLATION

    async def test_bad_token_socket_is_rejected(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        token_for: Callable[[str], str],
    ) -> None:
        session_id = await self._start_session(client, token_for)
        sync_client = TestClient(app)
        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            sync_client.websocket_connect(
                f"/api/v1/agents/{session_id}/stream?token=garbage"
            ) as ws,
        ):
            ws.receive_json()
        assert exc_info.value.code == agents_router._WS_POLICY_VIOLATION

    async def test_authenticated_socket_streams_steps_in_order(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        session_id = await self._start_session(client, token_for)
        # The session ran to completion synchronously, so its full trace exists.
        async with sessionmaker() as db:
            recorded = (
                (
                    await db.execute(
                        select(ReasoningTraceRow).where(ReasoningTraceRow.session_id.is_not(None))
                    )
                )
                .scalars()
                .all()
            )
        assert recorded

        sync_client = TestClient(app)
        token = token_for("viewer")
        frames: list[dict[str, Any]] = []
        with sync_client.websocket_connect(
            f"/api/v1/agents/{session_id}/stream?token={token}"
        ) as ws:
            while True:
                frame = ws.receive_json()
                frames.append(frame)
                if frame.get("event") == "end":
                    break

        step_frames = [f for f in frames if f.get("event") != "end"]
        end_frame = frames[-1]
        assert end_frame["event"] == "end"
        assert end_frame["status"] == AgentSessionStatus.COMPLETED.value
        # Steps arrive in recorded order: plan first, conclusion last.
        kinds = [f["kind"] for f in step_frames]
        assert kinds[0] == "plan"
        assert kinds[-1] == "conclusion"
        assert "conclusion" in kinds

    async def test_socket_for_unknown_session_is_rejected(
        self,
        app: FastAPI,
        token_for: Callable[[str], str],
    ) -> None:
        sync_client = TestClient(app)
        token = token_for("viewer")
        unknown = "00000000-0000-0000-0000-000000000000"
        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            sync_client.websocket_connect(f"/api/v1/agents/{unknown}/stream?token={token}") as ws,
        ):
            ws.receive_json()
        assert exc_info.value.code == agents_router._WS_POLICY_VIOLATION
