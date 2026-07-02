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

import asyncio
import contextlib
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
from app.models import AgentSession, AgentSessionStatus, AuditLog, Base, ReasoningTraceRow, User
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

    async def test_ticket_issued_on_one_replica_redeems_on_the_socket(
        self,
        app: FastAPI,
        client: httpx.AsyncClient,
        token_for: Callable[[str], str],
    ) -> None:
        """A single-use stream ticket (shared store) authenticates the WebSocket.

        Proves the ticket path end-to-end over the shared store: the JWT never
        appears in the WebSocket URL — only the opaque ticket does.
        """
        session_id = await self._start_session(client, token_for)
        issued = await client.post(
            f"/api/v1/agents/{session_id}/stream-ticket",
            headers={"Authorization": f"Bearer {token_for('viewer')}"},
        )
        assert issued.status_code == 201, issued.text
        ticket = issued.json()["ticket"]

        sync_client = TestClient(app)
        frames: list[dict[str, Any]] = []
        with sync_client.websocket_connect(
            f"/api/v1/agents/{session_id}/stream?ticket={ticket}"
        ) as ws:
            while True:
                frame = ws.receive_json()
                frames.append(frame)
                if frame.get("event") == "end":
                    break
        assert frames[-1]["event"] == "end"
        # A single-use ticket cannot be redeemed twice (shared store, GETDEL-style).
        with (
            pytest.raises(WebSocketDisconnect) as exc_info,
            sync_client.websocket_connect(
                f"/api/v1/agents/{session_id}/stream?ticket={ticket}"
            ) as ws2,
        ):
            ws2.receive_json()
        assert exc_info.value.code == agents_router._WS_POLICY_VIOLATION


# --------------------------------------------------------------------------- #
# WebSocket fan-out: the handler subscribes to the per-session Redis pub/sub
# channel and relays live frames published by ANY replica (ADR-0044 §2). Driven
# in a single event loop against a fake WebSocket + a real shared in-memory bus,
# so cross-replica live delivery through the real ``stream_session`` handler is
# deterministic (no TestClient cross-thread loop boundary).
# --------------------------------------------------------------------------- #
class _FakeWebSocket:
    """Minimal WebSocket double recording the frames the handler relays."""

    def __init__(self, app: FastAPI, *, session_id: str, token: str) -> None:
        self.app = app
        self.path_params = {"session_id": session_id}
        self.query_params = {"token": token}
        self.sent: list[dict[str, Any]] = []
        self.accepted = False
        self.close_code: int | None = None

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(self, data: dict[str, Any]) -> None:
        self.sent.append(data)

    async def close(self, code: int = 1000) -> None:
        self.close_code = code


async def _await_subscriber(bus: Any, channel: str, *, timeout: float = 3.0) -> None:
    """Block until at least one subscriber is attached to *channel* on *bus*.

    The handler subscribes (attaches to the bus) before it accepts and before any
    real DB I/O completes; the producer must not publish until that attach has
    happened, or the at-most-once bus correctly drops the frame. Polling the bus
    directly is deterministic regardless of how many event-loop turns the handler's
    aiosqlite awaits take.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if bus._subscribers.get(channel):
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"no subscriber attached to {channel} within {timeout}s")


async def _await_handler_terminal(handler: asyncio.Task[None]) -> None:
    """Await the streaming handler's return once its session has reached a terminal state.

    The caller has already set the session's status to a terminal value (COMPLETED)
    in the DB, so the handler's poll loop *will* observe it and return; this waits
    for that real terminal condition — the handler task finishing — rather than
    betting a fixed wall clock that it happens within N seconds. A prior version
    used ``asyncio.wait_for(handler, timeout=5.0)``; that 5s bet lost whenever CI
    CPU contention dilated the handler's per-poll aiosqlite I/O past the budget,
    surfacing as a spurious ``TimeoutError`` (the flake this replaces).

    Determinism comes from bounding the wait by the handler's OWN termination
    contract — ``_STREAM_MAX_POLLS`` iterations, each at most ``_STREAM_POLL_SECONDS``
    plus real DB I/O — not by a magic constant. We scale the ceiling to that
    contract with slack for I/O so it tracks the code, and a genuine wedged handler
    (never returning) still fails fast rather than hanging the suite. On timeout the
    handler is cancelled so it cannot leak into teardown.
    """
    # The handler's worst case is _STREAM_MAX_POLLS iterations; give each generous
    # slack for per-poll DB I/O under load. This is a safety ceiling for a truly
    # wedged handler, NOT a bet on normal completion time (which returns as soon as
    # the terminal status is polled). Bounded so a real hang fails fast.
    per_poll_ceiling = max(agents_router._STREAM_POLL_SECONDS, 0.05) + 0.05
    ceiling = agents_router._STREAM_MAX_POLLS * per_poll_ceiling
    try:
        await asyncio.wait_for(asyncio.shield(handler), timeout=ceiling)
    except TimeoutError:  # pragma: no cover - only a genuinely wedged handler
        handler.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await handler
        raise AssertionError(
            "streaming handler did not return after its session reached a terminal "
            f"status within its own poll-budget ceiling ({ceiling:.1f}s); the handler "
            "is wedged, not merely slow"
        ) from None


class TestWebSocketFanout:
    async def test_production_run_path_fans_recorded_steps_onto_the_channel(
        self,
        app: FastAPI,
        scripted_builder: Callable[..., Any],
        settings: Settings,
        sessionmaker: async_sessionmaker[AsyncSession],
        users: dict[str, User],
    ) -> None:
        """The REAL run path is the producer — not a test-only ``replica_a.publish``.

        ``AgentSessionService(stream_fanout=...)`` is exactly what ``POST /agents``
        constructs in production. Driving its ``run`` over the scripted supervisor
        records reasoning steps through the ``PublishingTraceRecorder`` (the wired
        producer), which fans each persisted step onto the session channel. A
        subscriber on a SEPARATE fan-out instance (a second replica over the same
        bus) receives those frames — proving the ADR-0044 §6 exit criterion end to
        end through the production producer, with no manual publish.
        """
        from app.agents.framework.traces import PublishingTraceRecorder
        from app.services.agent_session import AgentSessionService
        from app.services.agent_stream import (
            AgentStreamFrame,
            InMemoryAgentStreamFanout,
            channel_for,
        )
        from app.services.agent_stream.fanout import _InMemoryBus

        # One shared bus = one Redis. replica A runs the session (producer);
        # replica B subscribes (consumer). Different fan-out instances => no
        # in-process affinity, just like two ``api`` pods.
        bus = _InMemoryBus()
        replica_a = InMemoryAgentStreamFanout(bus)  # producer side of the run
        replica_b = InMemoryAgentStreamFanout(bus)  # subscribing replica

        viewer = users["viewer"]
        service = AgentSessionService(sessionmaker, stream_fanout=replica_a)
        run_session = await service.start(
            user_id=viewer.id, role=Role.VIEWER, intent="why is bgp down?"
        )

        # The producer is the wired run path: recorder_for returns the publishing
        # recorder because the service was built with a fan-out (the production wiring).
        recorder = service.recorder_for(run_session.id)
        assert isinstance(recorder, PublishingTraceRecorder)
        graph = scripted_builder(Role.VIEWER, settings, trace_recorder=recorder)

        received: list[AgentStreamFrame] = []

        async def _consume() -> None:
            async with replica_b.subscribe(str(run_session.id)) as frames:
                await _await_subscriber(bus, channel_for(str(run_session.id)))
                while True:
                    received.append(await asyncio.wait_for(frames.__anext__(), timeout=5.0))

        consumer = asyncio.create_task(_consume())
        # Let the consumer attach before the producing run records any step, or the
        # at-most-once bus would (correctly) drop frames sent into the gap.
        await _await_subscriber(bus, channel_for(str(run_session.id)))

        await service.run(
            graph,
            "why is bgp down?",
            user_id=viewer.id,
            role=Role.VIEWER,
            session_id=run_session.id,
        )
        # Give the consumer a moment to drain the frames the run produced.
        await asyncio.sleep(0.05)
        consumer.cancel()
        with pytest.raises((asyncio.CancelledError, TimeoutError)):
            await consumer

        # The production producer fanned real session content onto the channel.
        assert received, "the production run path published no frames onto the channel"
        kinds = [f.data["kind"] for f in received]
        assert kinds[0] == "plan", f"first fanned frame should be the routing plan; got {kinds}"
        assert "conclusion" in kinds, f"the terminal reasoning step was not fanned; got {kinds}"
        # Every fanned frame is scoped to this session and rides its trace id.
        for frame in received:
            assert frame.session_id == str(run_session.id)
            assert frame.trace_id
            # No credential rides a fanned frame (re-serialization re-checks).
            assert "token" not in frame.to_payload().lower()

    async def test_live_frame_published_by_another_replica_is_relayed(
        self,
        app: FastAPI,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
        users: dict[str, User],
    ) -> None:
        """A frame published for session X by "replica A" is relayed to a peer on "replica B".

        The serving handler (replica B) subscribes to the session channel; a
        separate fan-out instance (replica A) publishes a live frame; the peer
        receives it — proving any-replica-serves-any-session, plus that the
        trace/audit-join id rides the frame and no token is on the channel.
        """
        from app.services.agent_stream import (
            AgentStreamFrame,
            InMemoryAgentStreamFanout,
        )
        from app.services.agent_stream.fanout import _InMemoryBus

        # One shared bus = one Redis: replica A (producer) and replica B (the
        # serving handler) attach to the same bus.
        bus = _InMemoryBus()
        replica_a = InMemoryAgentStreamFanout(bus)
        app.state.stream_fanout = InMemoryAgentStreamFanout(bus)  # replica B (handler)

        # A RUNNING session (no persisted steps) so the handler enters live relay.
        viewer = users["viewer"]
        async with sessionmaker() as db:
            session_row = AgentSession(
                user_id=viewer.id,
                invoking_role="viewer",
                intent="stream",
                status=AgentSessionStatus.RUNNING,
            )
            db.add(session_row)
            await db.commit()
            session_id = session_row.id

        fake_ws = _FakeWebSocket(app, session_id=str(session_id), token=token_for("viewer"))
        trace_id = "abcd1234abcd1234abcd1234abcd1234"
        live = AgentStreamFrame(
            session_id=str(session_id),
            trace_id=trace_id,
            data={"kind": "tool_call", "summary": "ping", "trace_id": trace_id},
        )

        async def _drive_handler() -> None:
            await agents_router.stream_session(fake_ws, session_id, sessionmaker)  # type: ignore[arg-type]

        from app.services.agent_stream import channel_for

        handler = asyncio.create_task(_drive_handler())
        # Wait until the handler has actually subscribed before publishing, or the
        # at-most-once bus would (correctly) drop a frame sent into the gap.
        await _await_subscriber(bus, channel_for(str(session_id)))
        await replica_a.publish(live)
        # Then terminate the session so the handler's poll loop exits cleanly.
        async with sessionmaker() as db:
            row = await db.get(AgentSession, session_id)
            assert row is not None
            row.status = AgentSessionStatus.COMPLETED
            await db.commit()
        await _await_handler_terminal(handler)

        # The live frame's content (data) was relayed to the peer.
        relayed = [f for f in fake_ws.sent if f.get("kind") == "tool_call"]
        assert relayed, f"the live frame was not relayed; got {fake_ws.sent}"
        assert relayed[0]["summary"] == "ping"
        # The trace/audit-join id rode the frame to the peer (G-OBS).
        assert relayed[0]["trace_id"] == trace_id
        # The terminal frame closed the stream.
        assert fake_ws.sent[-1]["event"] == "end"
        # The bearer token never appears in any relayed frame.
        token = token_for("viewer")
        for frame in fake_ws.sent:
            assert token not in str(frame)

    async def test_live_relay_survives_idle_drains_before_the_frame_arrives(
        self,
        app: FastAPI,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
        users: dict[str, User],
    ) -> None:
        """A frame published AFTER several idle relay cycles is still relayed.

        Regression pin for the recurring relay flake (2026-07-01 audit, W1): the
        old drain used ``asyncio.wait_for`` around the subscription's
        ``__anext__``, and its timeout CANCELLED the generator — closing it for
        good, so the live relay silently died after its first idle drain. Any
        frame published later was never relayed (the flake fired whenever the
        publish lost the race with the first 20 ms drain window). Publishing
        only after the handler has demonstrably sat through many idle cycles
        makes the old behaviour fail deterministically.
        """
        from app.services.agent_stream import (
            AgentStreamFrame,
            InMemoryAgentStreamFanout,
            channel_for,
        )
        from app.services.agent_stream.fanout import _InMemoryBus

        bus = _InMemoryBus()
        replica_a = InMemoryAgentStreamFanout(bus)
        app.state.stream_fanout = InMemoryAgentStreamFanout(bus)

        viewer = users["viewer"]
        async with sessionmaker() as db:
            session_row = AgentSession(
                user_id=viewer.id,
                invoking_role="viewer",
                intent="stream",
                status=AgentSessionStatus.RUNNING,
            )
            db.add(session_row)
            await db.commit()
            session_id = session_row.id

        fake_ws = _FakeWebSocket(app, session_id=str(session_id), token=token_for("viewer"))
        trace_id = "abcd1234abcd1234abcd1234abcd1234"
        live = AgentStreamFrame(
            session_id=str(session_id),
            trace_id=trace_id,
            data={"kind": "tool_call", "summary": "late ping", "trace_id": trace_id},
        )

        async def _drive_handler() -> None:
            await agents_router.stream_session(fake_ws, session_id, sessionmaker)  # type: ignore[arg-type]

        handler = asyncio.create_task(_drive_handler())
        await _await_subscriber(bus, channel_for(str(session_id)))
        # Let the handler run MANY idle relay cycles first — long enough that the
        # 20 ms drain window has elapsed repeatedly before anything is published.
        await asyncio.sleep(0.2)
        await replica_a.publish(live)
        async with sessionmaker() as db:
            row = await db.get(AgentSession, session_id)
            assert row is not None
            row.status = AgentSessionStatus.COMPLETED
            await db.commit()
        await _await_handler_terminal(handler)

        relayed = [f for f in fake_ws.sent if f.get("kind") == "tool_call"]
        assert relayed, (
            "the live relay died after an idle drain; a frame published later "
            f"was never relayed — got {fake_ws.sent}"
        )
        assert relayed[0]["summary"] == "late ping"
        assert fake_ws.sent[-1]["event"] == "end"

    async def test_token_is_never_published_to_the_channel(
        self,
        app: FastAPI,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
        users: dict[str, User],
    ) -> None:
        """The serving edge authenticates with the token but never puts it on the bus.

        We capture every payload published to the shared bus while a socket is
        served and assert the token/JWT is absent (the secret-surface bite). A
        negative control: a frame that tried to carry the token would be refused
        by ``AgentStreamFrame.to_payload`` (see test_agent_stream_fanout).
        """
        from app.services.agent_stream import (
            AgentStreamFrame,
            InMemoryAgentStreamFanout,
        )
        from app.services.agent_stream.fanout import _InMemoryBus

        published: list[str] = []
        bus = _InMemoryBus()
        original_publish = bus.publish

        async def _spy_publish(channel: str, frame: AgentStreamFrame) -> None:
            published.append(frame.to_payload())
            await original_publish(channel, frame)

        bus.publish = _spy_publish  # type: ignore[method-assign]
        replica_a = InMemoryAgentStreamFanout(bus)
        app.state.stream_fanout = InMemoryAgentStreamFanout(bus)

        viewer = users["viewer"]
        async with sessionmaker() as db:
            session_row = AgentSession(
                user_id=viewer.id,
                invoking_role="viewer",
                intent="stream",
                status=AgentSessionStatus.RUNNING,
            )
            db.add(session_row)
            await db.commit()
            session_id = session_row.id

        token = token_for("viewer")
        fake_ws = _FakeWebSocket(app, session_id=str(session_id), token=token)

        async def _drive_handler() -> None:
            await agents_router.stream_session(fake_ws, session_id, sessionmaker)  # type: ignore[arg-type]

        from app.services.agent_stream import channel_for

        handler = asyncio.create_task(_drive_handler())
        await _await_subscriber(bus, channel_for(str(session_id)))
        await replica_a.publish(
            AgentStreamFrame(
                session_id=str(session_id),
                trace_id="0" * 32,
                data={"kind": "plan", "summary": "go"},
            )
        )
        async with sessionmaker() as db:
            row = await db.get(AgentSession, session_id)
            assert row is not None
            row.status = AgentSessionStatus.COMPLETED
            await db.commit()
        await _await_handler_terminal(handler)

        assert published, "the producer published at least one frame onto the channel"
        for payload in published:
            assert token not in payload, "the bearer token must never reach the shared channel"

    async def test_persisted_step_replayed_and_relayed_is_sent_at_most_once(
        self,
        app: FastAPI,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
        users: dict[str, User],
    ) -> None:
        """A step seen from BOTH the DB replay and the live relay is sent exactly once.

        The production producer persists a step THEN publishes a live frame whose
        ``data`` is byte-identical to the step's DB read model. The handler replays
        the persisted step from the DB and also drains the buffered live frame — so
        without cross-source dedup the SAME step lands on the wire twice. We persist
        one step and publish its exact read model as a live frame, then assert the
        peer receives that step's content exactly once (F-agents-582 / F-agents-609).
        """
        from app.agents.framework.traces import PostgresTraceRecorder, TraceStep, TraceStepKind
        from app.services.agent_stream import (
            AgentStreamFrame,
            InMemoryAgentStreamFanout,
            channel_for,
        )
        from app.services.agent_stream.fanout import _InMemoryBus

        bus = _InMemoryBus()
        replica_a = InMemoryAgentStreamFanout(bus)
        app.state.stream_fanout = InMemoryAgentStreamFanout(bus)  # serving replica

        viewer = users["viewer"]
        async with sessionmaker() as db:
            session_row = AgentSession(
                user_id=viewer.id,
                invoking_role="viewer",
                intent="stream",
                status=AgentSessionStatus.RUNNING,
            )
            db.add(session_row)
            await db.commit()
            session_id = session_row.id

        # Persist one step through the real recorder so the handler replays it from
        # the DB; the recorder links the trace to THIS session (so _load_traces finds it).
        recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
        trace = await recorder.start("discovery")
        step = TraceStep(kind=TraceStepKind.PLAN, summary="route", detail="pick discovery")
        await recorder.record_step(trace.trace_id, step)

        # The live frame's data is the EXACT read model of the persisted step — what
        # PublishingTraceRecorder fans onto the channel in production.
        live_data = agents_router._step_read(step).model_dump(mode="json")

        fake_ws = _FakeWebSocket(app, session_id=str(session_id), token=token_for("viewer"))

        async def _drive_handler() -> None:
            await agents_router.stream_session(fake_ws, session_id, sessionmaker)  # type: ignore[arg-type]

        handler = asyncio.create_task(_drive_handler())
        await _await_subscriber(bus, channel_for(str(session_id)))

        # Prove the DB-replay source contributed FIRST: the persisted step must reach
        # the wire before any live frame is published. Without this the final
        # ``len == 1`` could be satisfied by live-relay-only (a broken DB replay) or
        # DB-replay-only (a dropped live relay); asserting the pre-publish state pins
        # that BOTH sources observe the step and the dedup is what keeps it single.
        for _ in range(500):
            if any(f.get("kind") == "plan" and f.get("summary") == "route" for f in fake_ws.sent):
                break
            await asyncio.sleep(0.01)
        pre_publish = [
            f for f in fake_ws.sent if f.get("kind") == "plan" and f.get("summary") == "route"
        ]
        assert len(pre_publish) == 1, (
            f"DB replay must deliver the persisted step before the live frame; got {pre_publish}"
        )

        # Now publish the IDENTICAL live frame — the relay must recognise it as the
        # already-replayed step (shared emitted_keys) and NOT re-send it.
        await replica_a.publish(
            AgentStreamFrame(session_id=str(session_id), trace_id=trace.trace_id, data=live_data)
        )
        async with sessionmaker() as db:
            row = await db.get(AgentSession, session_id)
            assert row is not None
            row.status = AgentSessionStatus.COMPLETED
            await db.commit()
        await _await_handler_terminal(handler)

        # The step's content is on the wire exactly ONCE despite both sources seeing it.
        step_frames = [
            f for f in fake_ws.sent if f.get("kind") == "plan" and f.get("summary") == "route"
        ]
        assert len(step_frames) == 1, (
            f"a step seen from both DB replay and live relay must be sent once; got {step_frames}"
        )

    async def test_running_session_past_poll_budget_sends_no_terminal_end(
        self,
        app: FastAPI,
        token_for: Callable[[str], str],
        sessionmaker: async_sessionmaker[AsyncSession],
        users: dict[str, User],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the poll budget is exhausted with the run still RUNNING, no end frame.

        Emitting ``AgentStreamEnd(status=running)`` would tell the client the stream
        is terminal while the run has not finished (empty answer) — a contradictory,
        misleading frame. The handler must close WITHOUT a terminal end so the client
        knows to reconnect; the terminal end is reserved for a real terminal status
        (F-agents-588).
        """
        from app.services.agent_stream import InMemoryAgentStreamFanout
        from app.services.agent_stream.fanout import _InMemoryBus

        app.state.stream_fanout = InMemoryAgentStreamFanout(_InMemoryBus())
        # Tiny budget so the loop exhausts immediately while the session stays RUNNING.
        monkeypatch.setattr(agents_router, "_STREAM_MAX_POLLS", 2)
        monkeypatch.setattr(agents_router, "_STREAM_POLL_SECONDS", 0.0)

        viewer = users["viewer"]
        async with sessionmaker() as db:
            session_row = AgentSession(
                user_id=viewer.id,
                invoking_role="viewer",
                intent="stream",
                status=AgentSessionStatus.RUNNING,  # never transitions — budget exhausts first
            )
            db.add(session_row)
            await db.commit()
            session_id = session_row.id

        fake_ws = _FakeWebSocket(app, session_id=str(session_id), token=token_for("viewer"))
        await agents_router.stream_session(fake_ws, session_id, sessionmaker)  # type: ignore[arg-type]

        end_frames = [f for f in fake_ws.sent if f.get("event") == "end"]
        assert not end_frames, (
            "a still-RUNNING run past its poll budget must not send a terminal end; "
            f"got {end_frames}"
        )
        # Assert the GRACEFUL close (bare websocket.close() -> 1000), not merely "any
        # close": an early auth/policy/not-found rejection would close with
        # _WS_POLICY_VIOLATION (1008) before ever reaching the poll-budget path, and
        # `is not None` would pass on that wrong reason too.
        assert fake_ws.close_code == 1000, (
            "a budget-exhausted still-RUNNING socket must close gracefully (1000), not "
            f"via an early {agents_router._WS_POLICY_VIOLATION} rejection; got {fake_ws.close_code}"
        )


# --------------------------------------------------------------------------- #
# W3-T0: agent first-token latency observed after a started run.
# --------------------------------------------------------------------------- #
class TestFirstTokenMetric:
    @staticmethod
    def _first_token_count() -> float:
        """Read the per-``local``-profile histogram sample count off the registry."""
        from prometheus_client import generate_latest

        target = 'netops_agent_first_token_seconds_count{profile="local"}'
        for line in generate_latest().decode().splitlines():
            if line.startswith(target):
                return float(line.rsplit(" ", 1)[1])
        return 0.0

    async def test_start_observes_first_token_latency(
        self, client: httpx.AsyncClient, token_for: Callable[[str], str]
    ) -> None:
        """A run that persists a reasoning step records ONE first-token sample.

        The profile label resolves from the reasoning-role profile (default
        ``local`` in the unit settings). The histogram's per-profile sample COUNT
        must advance by exactly one across the request (ADR-0046 §1).
        """
        before = self._first_token_count()
        resp = await client.post(
            "/api/v1/agents",
            json={"intent": "why is bgp down?"},
            headers={"Authorization": f"Bearer {token_for('viewer')}"},
        )
        assert resp.status_code == 201, resp.text
        assert self._first_token_count() == before + 1
