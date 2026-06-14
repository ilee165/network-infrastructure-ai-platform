"""Shared fixtures and fakes for the M3 agent eval suite (M3-17).

The eval suite drives the *real* Master Architect supervisor + specialist
subgraphs against a :class:`ScriptedChatModel` (deterministic, offline) with
fixture-grounded tool output, an in-memory SQLite database for the durable
session/trace/audit linkage, and the production redaction wiring. Nothing here
touches the network or a real LLM provider.

Key seams reused (not redefined):

* ``ScriptedChatModel`` / ``scripted_model`` / ``RecordingAuditSink`` from the
  agent-test conftest (``tests/agents/conftest.py``).
* ``AgentSessionService`` + ``PostgresTraceRecorder`` for durable persistence.
* ``TroubleshootingAgent`` with its fixture-patchable ``TROUBLESHOOTING_TOOLS``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from typing import Annotated, Any

import pytest
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.consultant.agent import ConsultantAgent
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.tools import (
    AuditSink,
    NetOpsTool,
    ToolAuditEvent,
    ToolClassification,
    netops_tool,
)
from app.agents.troubleshooting.agent import TroubleshootingAgent
from app.models import Role as RoleRow
from app.models import User
from app.models.base import Base

# ---------------------------------------------------------------------------
# Stable identifiers used across the eval cases ("device Y", "peer X").
# ---------------------------------------------------------------------------

#: The device under test in the canonical "why is BGP peer X down on Y" case.
DEVICE_Y = "11111111-1111-1111-1111-111111111111"
#: The specific BGP peer the user asks about.
PEER_X = "10.0.0.2"

#: Fixture BGP read: peer 10.0.0.2 is Idle (the fault), 10.0.0.3 Established.
BGP_PEER_DOWN_PAYLOAD = json.dumps(
    {
        "device_id": DEVICE_Y,
        "peers": [
            {
                "peer_address": PEER_X,
                "remote_as": 65002,
                "local_as": 65001,
                "state": "idle",
                "vrf": None,
                "address_family": "ipv4_unicast",
                "prefixes_received": 0,
                "uptime_seconds": None,
            },
            {
                "peer_address": "10.0.0.3",
                "remote_as": 65003,
                "local_as": 65001,
                "state": "established",
                "vrf": None,
                "address_family": "ipv4_unicast",
                "prefixes_received": 12,
                "uptime_seconds": 4200,
            },
        ],
    }
)


# ---------------------------------------------------------------------------
# Seeded vendor secret patterns (one per profile/redaction class). Every entry
# is (kind_token, secret_substring, config_line); the secret_substring is the
# raw material that must NEVER reach a provider call.
# ---------------------------------------------------------------------------

#: (redaction_kind, raw_secret, config_line). The raw secret is the exact
#: substring that must be absent from any prompt that reaches a provider.
SEEDED_SECRETS: list[tuple[str, str, str]] = [
    ("snmp_community", "S3cr3tCommunityRO", "snmp-server community S3cr3tCommunityRO RO"),
    (
        "snmpv3_auth",
        "AuthPass789",
        "snmp-server user admin GRP v3 auth sha AuthPass789 priv aes 128 PrivPass012",
    ),
    ("cisco_type7", "070C285F4D06", "username bob password 7 070C285F4D06"),
    ("enable_secret", "MyEnablePass!", "enable secret MyEnablePass!"),
    ("routing_auth_key", "BgpPeerSecret", "neighbor 10.0.0.1 password BgpPeerSecret"),
    ("aaa_shared_key", "MyTacacsSharedSecret", "tacacs-server key MyTacacsSharedSecret"),
]


# ---------------------------------------------------------------------------
# In-memory database (sessions / traces / audit linkage) + seeded users.
# ---------------------------------------------------------------------------


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full schema + FK enforcement."""
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
    """A sessionmaker bound to the in-memory eval engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


async def seed_user(maker: async_sessionmaker[AsyncSession], *, role_name: str) -> uuid.UUID:
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


# ---------------------------------------------------------------------------
# Audit sink that also persists an AuditLog row carrying the reasoning-trace id
# — so an audited tool action is durably linked to the trace that produced it
# (brief §6: traces linked from the audit log). Mirrors the M5 wiring contract
# while staying offline.
# ---------------------------------------------------------------------------


class TraceLinkingAuditSink:
    """An :class:`AuditSink` that records events *and* links them to a trace.

    Each recorded :class:`ToolAuditEvent` is retained in memory (for direct
    assertions) and written as an append-only
    :class:`~app.models.audit.AuditLog` row. When constructed with a
    ``session_id``, the row's ``reasoning_trace_id`` is resolved *at record time*
    to the latest reasoning trace persisted under that agent session — so an
    audited tool action is durably linked back to the trace that produced it
    (brief §6: traces linked from the audit log). This is the offline stand-in
    for the M5 ``audit_log`` writer and lets the eval assert the "linked from the
    audit log" half of exit criterion 1.

    By the time a tool fires inside a specialist subgraph, that subgraph has
    already opened (and persisted) its reasoning trace, so the lookup is
    deterministic — there is always a trace to link to.
    """

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        session_id: uuid.UUID | None = None,
    ) -> None:
        self._sessionmaker = sessionmaker
        self._session_id = session_id
        self.events: list[ToolAuditEvent] = []

    async def _latest_trace_id(self, session: AsyncSession) -> uuid.UUID | None:
        """Resolve the most recent reasoning trace for the bound session, if any."""
        if self._session_id is None:
            return None
        from sqlalchemy import select

        from app.models.agents import ReasoningTraceRow

        rows = (
            (
                await session.execute(
                    select(ReasoningTraceRow)
                    .where(ReasoningTraceRow.session_id == self._session_id)
                    .order_by(ReasoningTraceRow.started_at.desc())
                )
            )
            .scalars()
            .all()
        )
        return rows[0].id if rows else None

    async def record(self, event: ToolAuditEvent) -> None:
        """Retain *event* and persist a linked, append-only audit row."""
        self.events.append(event)
        from app.models.audit import AuditLog

        async with self._sessionmaker() as session:
            trace_id = await self._latest_trace_id(session)
            session.add(
                AuditLog(
                    actor="agent:troubleshooting",
                    action=f"tool.invoke:{event.outcome}",
                    target_type="tool",
                    target_id=event.tool_name,
                    detail={"classification": event.classification.value},
                    reasoning_trace_id=trace_id,
                )
            )
            await session.commit()


class InMemoryAuditSink:
    """A minimal in-memory :class:`AuditSink` (no DB) for offline portability runs."""

    def __init__(self) -> None:
        self.events: list[ToolAuditEvent] = []

    async def record(self, event: ToolAuditEvent) -> None:
        self.events.append(event)


# ---------------------------------------------------------------------------
# Fixture-grounded fake tools (module scope so Pydantic annotation eval sees
# Annotated/Field — the established troubleshooting-test constraint).
# ---------------------------------------------------------------------------


def make_fake_bgp_tool(sink: AuditSink) -> NetOpsTool:
    """Build a fixture-backed ``read_live_bgp_peers`` wired to *sink*."""

    @netops_tool(
        classification=ToolClassification.READ_ONLY,
        name="read_live_bgp_peers",
        audit_sink=sink,
    )
    async def read_live_bgp_peers(
        device_id: Annotated[str, Field(description="device UUID")],
    ) -> str:
        """Fixture-backed BGP read: peer 10.0.0.2 is Idle, 10.0.0.3 Established."""
        return BGP_PEER_DOWN_PAYLOAD

    return read_live_bgp_peers


@contextmanager
def bgp_tool_patched(fake_tool: NetOpsTool) -> Iterator[None]:
    """Swap the real BGP tool for *fake_tool* in the shared tool list, in place.

    The agent holds ``TROUBLESHOOTING_TOOLS`` by reference, so the swap mutates
    the list contents (``list[:] = ...``) and is always restored — the
    offline-execution pattern established by the M3-13 tests.
    """
    import app.agents.troubleshooting.tools as _tools_mod

    original = _tools_mod.TROUBLESHOOTING_TOOLS[:]
    _tools_mod.TROUBLESHOOTING_TOOLS[:] = [
        fake_tool if t.name == fake_tool.name else t for t in original
    ]
    try:
        yield
    finally:
        _tools_mod.TROUBLESHOOTING_TOOLS[:] = original


# ---------------------------------------------------------------------------
# Scripted-routing helpers (structured RoutingDecision + SymptomClassification).
# ---------------------------------------------------------------------------


def routing_reply(
    *, specialist: str | None, ambiguous: bool = False, rationale: str = "eval route"
) -> AIMessage:
    """A scripted structured ``RoutingDecision`` tool call for the supervisor."""
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "RoutingDecision",
                "args": {
                    "specialist": specialist,
                    "ambiguous": ambiguous,
                    "rationale": rationale,
                },
                "id": "route-1",
            }
        ],
    )


def symptom_reply(*, domain: str, device_id: str | None, target: str | None = None) -> AIMessage:
    """A scripted structured ``SymptomClassification`` tool call (troubleshooting)."""
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "SymptomClassification",
                "args": {
                    "domain": domain,
                    "device_id": device_id,
                    "target": target,
                    "rationale": "eval classification",
                },
                "id": "sym-1",
            }
        ],
    )


def bgp_down_script() -> list[AIMessage]:
    """The full scripted reply stream for the canonical BGP-down eval run.

    Order: supervisor RoutingDecision -> troubleshooting SymptomClassification.
    (The troubleshooting subgraph composes its grounded answer from evidence;
    it does not consult the model again after classification.)
    """
    return [
        routing_reply(specialist="troubleshooting", rationale="BGP peer fault question"),
        symptom_reply(domain="bgp", device_id=DEVICE_Y, target=PEER_X),
    ]


# ---------------------------------------------------------------------------
# Registry builder: the real consultant + a trace-recorder-bound troubleshooting
# agent, routable under the supervisor.
# ---------------------------------------------------------------------------


def build_eval_registry(troubleshooting: TroubleshootingAgent) -> AgentRegistry:
    """A routable registry: the real consultant + the supplied troubleshooting agent."""
    registry = AgentRegistry()
    registry.register(ConsultantAgent())
    registry.register(troubleshooting)
    return registry


# ---------------------------------------------------------------------------
# A capturing chat model for the redaction parity check (criterion 5): it
# records every message that reaches it AFTER the production redaction wrapper.
# ---------------------------------------------------------------------------


class CapturingChatModel(BaseChatModel):
    """Records the messages it is asked to generate (post-redaction) and replies "ok".

    Used to prove the central redaction wrapping strips seeded secrets on every
    provider profile: the wrapper feeds redacted prompts here, and the eval
    inspects what was actually captured.
    """

    captured: list[BaseMessage] = []

    @property
    def _llm_type(self) -> str:
        return "eval-capturing-fake"

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: object = None,
        **kwargs: object,
    ) -> ChatResult:
        type(self).captured = list(messages)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])


__all__ = [
    "BGP_PEER_DOWN_PAYLOAD",
    "DEVICE_Y",
    "PEER_X",
    "SEEDED_SECRETS",
    "CapturingChatModel",
    "InMemoryAuditSink",
    "TraceLinkingAuditSink",
    "bgp_down_script",
    "bgp_tool_patched",
    "build_eval_registry",
    "make_fake_bgp_tool",
    "routing_reply",
    "seed_user",
    "symptom_reply",
]
