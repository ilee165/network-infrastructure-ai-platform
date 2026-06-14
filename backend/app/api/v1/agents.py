"""Agent session routes (M3-15, brief §5/§7): start a run, read it, stream it.

The Master Architect supervisor (ADR-0003) is reachable to any authenticated
user from ``viewer`` up — agents are *read-only* (no state-changing tool is
reachable through the supervisor), so the floor is ``viewer`` and the invoking
user's real role is carried into the :class:`~app.models.agents.AgentSession`
and bound into every tool's RBAC context for the run ("an agent can never do
what its user cannot", brief §7).

Three surfaces:

- ``POST /agents`` starts a session, drives the supervisor to completion, and
  returns the session, its synthesized answer, and its full reasoning trace.
- ``GET /agents/{session_id}`` returns the persisted session and trace.
- ``WS /agents/{session_id}/stream`` streams the recorded reasoning steps in
  order, then a terminal frame. The socket authenticates with the *same* JWT as
  the REST surface (a ``token`` query parameter); an unauthenticated or
  unauthorized peer is closed with a policy-violation code and never receives a
  trace.

Every session start and completion is audited, and each reasoning trace the run
produces is linked back to the session by a dedicated audit entry whose
``reasoning_trace_id`` is set (brief §6/§7).
"""

from __future__ import annotations

import asyncio
import inspect
import secrets
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, WebSocket
from langchain_core.language_models import BaseChatModel
from langgraph.graph.state import CompiledStateGraph
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import db
from app.agents import build_default_supervisor
from app.agents.framework.supervisor import SupervisorState
from app.agents.framework.traces import ReasoningTrace, TraceStep
from app.api.deps import (
    TOKEN_TYPE_ACCESS,
    get_app_settings,
    get_sessionmaker,
    require_role,
)
from app.core.config import Settings
from app.core.errors import AuthError, NotFoundError
from app.core.security import Role, decode_access_token
from app.llm.providers import get_chat_model
from app.llm.runtime_settings import effective_profile_for_role
from app.models import AgentSession, AgentSessionStatus, ReasoningTraceRow, User
from app.schemas.agents_api import (
    AgentSessionRead,
    AgentStreamEnd,
    AgentTraceRead,
    AgentTraceStepRead,
    StartSessionRequest,
    StartSessionResponse,
    StreamTicketResponse,
)
from app.services import audit
from app.services.agent_session import AgentSessionService

router = APIRouter(prefix="/agents", tags=["agents"])

Viewer = Annotated[User, Depends(require_role("viewer"))]
SessionMaker = Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)]

#: Target type used for every agent-session audit entry.
_TARGET_TYPE = "agent_session"

#: WebSocket close code for an authenticated/authorization failure (RFC 6455
#: 1008 "policy violation"): the peer is closed without receiving any trace.
_WS_POLICY_VIOLATION = 1008

#: How long the stream socket waits between polls of an in-progress session
#: before re-checking for newly recorded steps / a terminal status.
_STREAM_POLL_SECONDS = 0.02

#: Upper bound on stream poll iterations so a stuck run can never wedge the
#: socket open forever (defence in depth — runs complete synchronously today).
_STREAM_MAX_POLLS = 1500

#: Lifetime of a single-use stream ticket in seconds.  The client must open
#: the WebSocket within this window after calling ``stream-ticket``; the ticket
#: is destroyed on first use so it cannot be replayed.
_TICKET_TTL_SECONDS = 30

# ---------------------------------------------------------------------------
# In-process single-use stream-ticket store.
#
# Maps opaque ticket string -> (user_id, session_id, expiry_epoch_float).
# Tickets are created by ``POST /agents/{id}/stream-ticket`` (authenticated
# via the normal Authorization header) and consumed once by the WebSocket
# upgrade handler, so the bearer JWT never appears in a URL.
#
# This implementation is intentionally process-local and therefore correct for
# single-replica deployments; a multi-replica deployment should replace this
# dict with a shared Redis SET EX / GETDEL pair without changing any of the
# API contracts.
# ---------------------------------------------------------------------------
_ticket_store: dict[str, tuple[uuid.UUID, uuid.UUID, float]] = {}


SupervisorGraph = CompiledStateGraph[SupervisorState, None, SupervisorState, SupervisorState]


async def build_supervisor_for_role(
    role: Role,
    settings: Settings,
    *,
    trace_recorder: object | None = None,
) -> SupervisorGraph:
    """Compile the default supervisor graph for an invoking *role* (DI seam).

    Selects the reasoning-tier chat model via the multi-LLM provider registry
    (ADR-0009 — never instantiates a provider class directly). The reasoning
    *profile* is resolved at runtime from the single ``system_settings`` row
    (DB over env, env fallback when the row is absent or the field is null);
    provider API keys and the Ollama endpoint stay env-only. Tests override
    :func:`get_supervisor_builder` to inject a scripted model instead.
    """
    async with db.get_sessionmaker()() as session:
        profile = await effective_profile_for_role(session, "reasoning", settings)
    llm: BaseChatModel = get_chat_model(profile, settings, _role="reasoning")
    return build_default_supervisor(llm, trace_recorder=trace_recorder)  # type: ignore[arg-type]


def get_supervisor_builder() -> object:
    """Return the supervisor-graph factory (overridable DI seam).

    Production returns :func:`build_supervisor_for_role`; tests override this
    dependency to return a builder that compiles the graph over a scripted chat
    model and a fixed registry, so the route never reaches a real LLM provider.
    """
    return build_supervisor_for_role


async def _load_session_or_404(
    sessionmaker: async_sessionmaker[AsyncSession], session_id: uuid.UUID
) -> AgentSession:
    """Reload one :class:`AgentSession` row or raise :class:`NotFoundError`."""
    async with sessionmaker() as session:
        row = await session.get(AgentSession, session_id)
        if row is None:
            raise NotFoundError(f"agent session '{session_id}' does not exist")
        return row


async def _load_traces(
    sessionmaker: async_sessionmaker[AsyncSession], session_id: uuid.UUID
) -> list[ReasoningTrace]:
    """Reload every reasoning trace linked to *session_id*, oldest first."""
    service = AgentSessionService(sessionmaker)
    async with sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(ReasoningTraceRow.id)
                    .where(ReasoningTraceRow.session_id == session_id)
                    .order_by(ReasoningTraceRow.started_at, ReasoningTraceRow.id)
                )
            )
            .scalars()
            .all()
        )
    recorder = service.recorder_for(session_id)
    return [await recorder.get(row_id.hex) for row_id in rows]


def _trace_read(trace: ReasoningTrace) -> AgentTraceRead:
    """Project an in-process :class:`ReasoningTrace` to its read model."""
    return AgentTraceRead(
        trace_id=trace.trace_id,
        agent_name=trace.agent_name,
        started_at=trace.started_at,
        completed_at=trace.completed_at,
        steps=[_step_read(step) for step in trace.steps],
    )


def _step_read(step: TraceStep) -> AgentTraceStepRead:
    """Project one :class:`TraceStep` to its read model."""
    return AgentTraceStepRead(
        kind=step.kind.value,
        summary=step.summary,
        detail=step.detail,
        tool_name=step.tool_name,
        evidence=[ref.model_dump() for ref in step.evidence],  # type: ignore[misc]
        occurred_at=step.occurred_at,
    )


def _answer_of(state: SupervisorState) -> str:
    """Extract the final synthesized answer text from a finished run state."""
    messages = state.get("messages") or []
    if not messages:
        return ""
    content = messages[-1].content
    return content if isinstance(content, str) else str(content)


def _issue_ticket(user_id: uuid.UUID, session_id: uuid.UUID) -> str:
    """Mint an opaque single-use ticket and store it with a TTL.

    Purges expired entries on each call so the dict cannot grow unboundedly in
    long-running processes — the bounded rate of ticket issuance keeps this O(n)
    purge cheap in practice.
    """
    now = time.monotonic()
    expired = [k for k, (_, _, exp) in _ticket_store.items() if exp <= now]
    for k in expired:
        del _ticket_store[k]

    ticket = secrets.token_urlsafe(32)
    _ticket_store[ticket] = (user_id, session_id, now + _TICKET_TTL_SECONDS)
    return ticket


def _consume_ticket(ticket: str, session_id: uuid.UUID) -> uuid.UUID | None:
    """Exchange *ticket* for the issuing user_id, or return ``None``.

    The ticket is removed on first call (single-use); expired tickets are also
    rejected.  Returns ``None`` for unknown, expired, or session-mismatched
    tickets — callers must not distinguish these cases to the client.
    """
    entry = _ticket_store.pop(ticket, None)
    if entry is None:
        return None
    user_id, stored_session_id, expiry = entry
    if time.monotonic() > expiry:
        return None
    if stored_session_id != session_id:
        return None
    return user_id


@router.post("/{session_id}/stream-ticket", response_model=StreamTicketResponse, status_code=201)
async def create_stream_ticket(
    session_id: uuid.UUID,
    user: Viewer,
    sessionmaker: SessionMaker,
) -> StreamTicketResponse:
    """Issue a short-lived single-use ticket for the trace-stream WebSocket.

    The WebSocket handshake cannot carry an ``Authorization`` header, so the
    client would otherwise have to embed the JWT in the URL — leaking it into
    server access logs, browser history, and ``Referer`` headers.  This
    endpoint issues an opaque 30-second ticket instead; the WebSocket upgrade
    handler calls :func:`_consume_ticket` to redeem it (single use, TTL-bound)
    and the JWT never appears in a URL.

    Returns 404 when the session does not exist (consistent with the REST
    ``GET`` surface) so the caller cannot probe for session ids via ticket
    issuance.
    """
    await _load_session_or_404(sessionmaker, session_id)
    ticket = _issue_ticket(user.id, session_id)
    return StreamTicketResponse(ticket=ticket)


@router.post("", response_model=StartSessionResponse, status_code=201)
async def start_session(
    body: StartSessionRequest,
    user: Viewer,
    sessionmaker: SessionMaker,
    settings: Annotated[Settings, Depends(get_app_settings)],
    builder: Annotated[object, Depends(get_supervisor_builder)],
) -> StartSessionResponse:
    """Start an agent session and drive the supervisor to completion.

    The invoking user's role is resolved from the authenticated principal and
    carried into the session + every tool's RBAC context (brief §7); a viewer
    can therefore never reach a tool above its rank through the agent. The
    session start and completion are both audited, and each reasoning trace the
    run produces is linked back to the session with its own audit entry.
    """
    role = Role.from_name(user.role.name) or Role.VIEWER
    service = AgentSessionService(sessionmaker)

    run_session = await service.start(user_id=user.id, role=role, intent=body.intent)
    await _audit(
        sessionmaker,
        user=user,
        action=audit.AGENT_SESSION_STARTED,
        session_id=run_session.id,
        detail={"intent_length": len(body.intent), "invoking_role": role.value},
    )

    recorder = service.recorder_for(run_session.id)
    graph = builder(role, settings, trace_recorder=recorder)  # type: ignore[operator]
    # The production builder is async (it consults the DB-backed LLM settings at
    # runtime); the test DI seam stays a plain sync function. Await only when the
    # builder actually returned a coroutine so both shapes work unchanged.
    if inspect.isawaitable(graph):
        graph = await graph
    state = await service.run(
        graph,
        body.intent,
        user_id=user.id,
        role=role,
        session_id=run_session.id,
    )

    finished = await service.get(run_session.id)
    traces = await _load_traces(sessionmaker, run_session.id)
    for trace in traces:
        await _audit(
            sessionmaker,
            user=user,
            action=audit.AGENT_TRACE_RECORDED,
            session_id=run_session.id,
            detail={"agent_name": trace.agent_name, "step_count": len(trace.steps)},
            reasoning_trace_id=uuid.UUID(hex=trace.trace_id),
        )
    await _audit(
        sessionmaker,
        user=user,
        action=audit.AGENT_SESSION_COMPLETED,
        session_id=run_session.id,
        detail={"status": finished.status.value, "trace_count": len(traces)},
    )

    return StartSessionResponse(
        session=AgentSessionRead.model_validate(finished),
        answer=_answer_of(state),
        traces=[_trace_read(trace) for trace in traces],
    )


@router.get("/{session_id}", response_model=StartSessionResponse)
async def get_session(
    session_id: uuid.UUID,
    _user: Viewer,
    sessionmaker: SessionMaker,
) -> StartSessionResponse:
    """Return one persisted session and its full reasoning trace (404 if unknown)."""
    row = await _load_session_or_404(sessionmaker, session_id)
    traces = await _load_traces(sessionmaker, session_id)
    answer = _final_answer_from_traces(traces)
    return StartSessionResponse(
        session=AgentSessionRead.model_validate(row),
        answer=answer,
        traces=[_trace_read(trace) for trace in traces],
    )


@router.websocket("/{session_id}/stream")
async def stream_session(
    websocket: WebSocket,
    session_id: uuid.UUID,
    sessionmaker: SessionMaker,
) -> None:
    """Stream a session's recorded reasoning steps in order, then a terminal frame.

    Authentication mirrors the REST surface: the peer presents the same JWT
    access token as a ``token`` query parameter. An unauthenticated or
    unauthorized peer is closed with :data:`_WS_POLICY_VIOLATION` *before* any
    trace frame is sent, so the socket never leaks a reasoning trace to a
    caller who could not read it over REST.

    Settings are read from ``websocket.app.state`` (a WebSocket scope has no
    HTTP :class:`~fastapi.Request`, so the REST ``get_app_settings`` dependency
    cannot resolve here).
    """
    settings: Settings = websocket.app.state.settings
    user = await _authenticate_socket(websocket, sessionmaker, settings)
    if user is None:
        return  # _authenticate_socket already closed the socket.

    try:
        await _load_session_or_404(sessionmaker, session_id)
    except NotFoundError:
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return

    await websocket.accept()
    emitted = 0
    answer = ""
    status = AgentSessionStatus.RUNNING
    for _ in range(_STREAM_MAX_POLLS):
        row = await _load_session_or_404(sessionmaker, session_id)
        status = row.status
        traces = await _load_traces(sessionmaker, session_id)
        steps = [step for trace in traces for step in trace.steps]
        while emitted < len(steps):
            await websocket.send_json(_step_read(steps[emitted]).model_dump(mode="json"))
            emitted += 1
        if status is not AgentSessionStatus.RUNNING:
            answer = _final_answer_from_traces(traces)
            break
        await asyncio.sleep(_STREAM_POLL_SECONDS)

    await websocket.send_json(AgentStreamEnd(status=status, answer=answer).model_dump(mode="json"))
    await websocket.close()


def _final_answer_from_traces(traces: list[ReasoningTrace]) -> str:
    """The synthesized answer is the last ``conclusion`` step's summary, if any."""
    for trace in reversed(traces):
        for step in reversed(trace.steps):
            if step.kind.value == "conclusion":
                return step.summary
    return ""


async def _authenticate_socket(
    websocket: WebSocket,
    sessionmaker: async_sessionmaker[AsyncSession],
    settings: Settings,
) -> User | None:
    """Resolve either a ``ticket`` or ``token`` query param to a ``viewer+`` user.

    Preferred path — ``ticket``: the client obtained a short-lived single-use
    opaque ticket via ``POST /agents/{id}/stream-ticket`` (authenticated with
    the normal ``Authorization`` header).  :func:`_consume_ticket` redeems the
    ticket (single-use, TTL-enforced) so the bearer JWT never appears in a URL.

    Fallback path — ``token``: a raw JWT access token passed directly.  This
    path exists so internal tooling and existing tests can reach the stream
    without the ticket round-trip; the fallback is not used by the browser SPA.

    On any failure the socket is closed with :data:`_WS_POLICY_VIOLATION` and
    ``None`` is returned; the caller must not proceed.
    """
    session_id_str = websocket.path_params.get("session_id", "")

    ticket = websocket.query_params.get("ticket")
    if ticket is not None:
        try:
            session_id = uuid.UUID(str(session_id_str))
        except ValueError:
            await websocket.close(code=_WS_POLICY_VIOLATION)
            return None
        user_id = _consume_ticket(ticket, session_id)
        if user_id is None:
            await websocket.close(code=_WS_POLICY_VIOLATION)
            return None
        async with sessionmaker() as session:
            user = (
                await session.execute(select(User).where(User.id == user_id))
            ).scalar_one_or_none()
        if user is None or not user.is_active:
            await websocket.close(code=_WS_POLICY_VIOLATION)
            return None
        return user

    # Fallback: raw JWT token query param (internal tooling / test path).
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return None
    try:
        claims = decode_access_token(token, settings)
    except AuthError:
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return None
    if claims.get("type") != TOKEN_TYPE_ACCESS:
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return None
    try:
        user_id = uuid.UUID(str(claims["sub"]))
    except (ValueError, KeyError):
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return None
    async with sessionmaker() as session:
        user = (await session.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return None
    if (Role.from_name(user.role.name) or Role.VIEWER).rank < Role.VIEWER.rank:  # pragma: no cover
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return None
    return user


async def _audit(
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    user: User,
    action: str,
    session_id: uuid.UUID,
    detail: dict[str, object],
    reasoning_trace_id: uuid.UUID | None = None,
) -> None:
    """Append one agent-session audit entry on its own committed transaction.

    The service owns its lifecycle commits independently of the request, so the
    audit trail does too: each entry commits immediately and never carries
    secret material (only intent length and lifecycle metadata).
    """
    async with sessionmaker() as session:
        entry = await audit.record(
            session,
            actor=f"user:{user.username}",
            action=action,
            target_type=_TARGET_TYPE,
            target_id=str(session_id),
            detail=detail,
        )
        if reasoning_trace_id is not None:
            entry.reasoning_trace_id = reasoning_trace_id
        await session.commit()
