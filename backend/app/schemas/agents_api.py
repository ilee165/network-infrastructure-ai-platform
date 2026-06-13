"""Agent session API contracts (M3-15): request/response models for ``/api/v1/agents``.

Pure data (D2): validation only, no I/O — these models import nothing from the
agent framework or engines. They mirror the persisted
:class:`~app.models.agents.AgentSession` row and the reasoning-trace shapes
(``ReasoningTrace`` / ``TraceStep`` / ``EvidenceRef`` in
:mod:`app.agents.framework.traces`) so the API surfaces the durable
"explain every AI decision" artifact (brief §5/§6); the router owns the
conversion from the in-process trace models into these read models.

The same step shape is reused by the WebSocket stream: every frame the
``/agents/{id}/stream`` socket emits is one :class:`AgentTraceStepRead` (a
recorded reasoning step) or the terminal :class:`AgentStreamEnd` marker.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.agents import AgentSessionStatus

__all__ = [
    "AgentEvidenceRead",
    "AgentSessionRead",
    "AgentStreamEnd",
    "AgentTraceRead",
    "AgentTraceStepRead",
    "StartSessionRequest",
    "StartSessionResponse",
    "StreamTicketResponse",
]


class StartSessionRequest(BaseModel):
    """Body of ``POST /agents``.

    The caller supplies only the natural-language intent; the invoking user and
    their RBAC role are taken from the authenticated principal (never from the
    body), so "an agent can never do what its user cannot" (brief §7) cannot be
    spoofed by the request.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    intent: str = Field(
        min_length=1,
        max_length=8192,
        description="The user's network-operations question for the agent team.",
    )


class AgentEvidenceRead(BaseModel):
    """A pointer to evidence supporting a reasoning step (mirrors ``EvidenceRef``)."""

    model_config = ConfigDict(from_attributes=True)

    kind: str
    reference: str
    description: str | None = None


class AgentTraceStepRead(BaseModel):
    """One ordered reasoning step (mirrors ``traces.TraceStep``)."""

    model_config = ConfigDict(from_attributes=True)

    kind: str
    summary: str
    detail: str | None = None
    tool_name: str | None = None
    evidence: list[AgentEvidenceRead] = Field(default_factory=list)
    occurred_at: datetime


class AgentTraceRead(BaseModel):
    """The full reasoning record of one agent run (mirrors ``ReasoningTrace``)."""

    trace_id: str
    agent_name: str
    started_at: datetime
    completed_at: datetime | None = None
    steps: list[AgentTraceStepRead] = Field(default_factory=list)


class AgentSessionRead(BaseModel):
    """One agent session as returned by the session endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    invoking_role: str
    intent: str
    status: AgentSessionStatus
    started_at: datetime
    completed_at: datetime | None = None


class StartSessionResponse(BaseModel):
    """Result of ``POST /agents``: the persisted session, its answer, and its trace."""

    session: AgentSessionRead
    answer: str
    traces: list[AgentTraceRead] = Field(default_factory=list)


class StreamTicketResponse(BaseModel):
    """Response body of ``POST /agents/{id}/stream-ticket``.

    ``ticket`` is a short-lived (30-second TTL) opaque single-use token.
    The WebSocket upgrade handler exchanges it for the session and discards it;
    the bearer JWT therefore never appears in a WebSocket URL.
    """

    ticket: str


class AgentStreamEnd(BaseModel):
    """Terminal WebSocket frame: signals the stream is complete.

    ``event`` is the literal ``"end"`` so a client can switch on the frame type
    (every other frame is a reasoning step). ``status`` carries the session's
    terminal lifecycle value and ``answer`` the final synthesized message.
    """

    event: str = "end"
    status: AgentSessionStatus
    answer: str
