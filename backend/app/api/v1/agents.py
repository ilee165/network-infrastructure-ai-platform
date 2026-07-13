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
import contextlib
import inspect
import uuid
from collections.abc import AsyncIterator, Callable
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Query, Request, WebSocket
from langchain_core.language_models import BaseChatModel
from langgraph.graph.state import CompiledStateGraph
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app import db
from app.agents import build_default_supervisor
from app.agents.framework.supervisor import SupervisorState
from app.agents.framework.traces import PostgresTraceRecorder, ReasoningTrace, TraceStep
from app.api.deps import (
    TOKEN_TYPE_ACCESS,
    enforce_api_rate_limit,
    get_app_settings,
    get_db,
    get_sessionmaker,
    require_role,
)
from app.core import metrics
from app.core.config import Settings
from app.core.errors import (
    AuthError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    UnprocessableEntityError,
)
from app.core.logging import get_logger
from app.core.security import Role, decode_access_token
from app.engines.packet import (
    PacketFindings,
    analyze_pcap,
    pcap_path_for,
    validate_capture_filter,
)
from app.engines.packet.filters import FilterValidationError
from app.llm.providers import get_chat_model
from app.llm.runtime_settings import effective_profile_for_role
from app.models import (
    AgentSession,
    AgentSessionStatus,
    PcapMetadata,
    ReasoningTraceRow,
    ReasoningTraceStep,
    User,
)
from app.schemas.agents_api import (
    AgentSessionRead,
    AgentStreamEnd,
    AgentTraceRead,
    AgentTraceStepRead,
    StartSessionRequest,
    StartSessionResponse,
    StreamTicketResponse,
)
from app.schemas.changes_api import (
    ChangeDecisionRequest,
    ChangeRequestListResponse,
    ChangeRequestRead,
)
from app.schemas.packet_api import (
    CaptureLaunchRequest,
    CaptureLaunchResponse,
    CaptureStatus,
    CaptureStatusResponse,
)
from app.services import audit
from app.services.agent_session import AgentSessionService
from app.services.agent_stream import (
    AgentStreamFanout,
    AgentStreamFrame,
    InMemoryAgentStreamFanout,
    InMemoryStreamTicketStore,
    StreamTicketStore,
)
from app.services.change_requests import ChangeRequestService
from app.workers.celery_app import QUEUE_PACKET_CAPTURE, celery_app

router = APIRouter(prefix="/agents", tags=["agents"])

_logger = get_logger(__name__)

#: W6-T6 per-principal/per-token API budget (PRODUCTION.md §5). Applied PER HTTP
#: ROUTE here rather than as a router-level dependency, because this router also
#: exposes the ``/{session_id}/stream`` WebSocket — and ``enforce_api_rate_limit``
#: depends on an ``HTTPBearer`` scheme that cannot resolve on a WebSocket scope.
#: A router-level dependency would attach to the WS route too and break it, so
#: every HTTP ``@router.{get,post}`` below carries this explicitly while the
#: ``@router.websocket`` route (its own single-use stream-ticket auth) is left
#: unbound.
_API_RATE_LIMIT: Final = [Depends(enforce_api_rate_limit)]

Viewer = Annotated[User, Depends(require_role("viewer"))]
Engineer = Annotated[User, Depends(require_role("engineer"))]
DbSession = Annotated[AsyncSession, Depends(get_db)]
SessionMaker = Annotated[async_sessionmaker[AsyncSession], Depends(get_sessionmaker)]

#: Celery task name of the worker-side segment capture (app/workers/tasks/packet.py).
SEGMENT_CAPTURE_TASK: Final = "packet.capture_segment"
#: Celery task name of the device-side ``eos`` monitor-session capture.
DEVICE_CAPTURE_TASK: Final = "packet.capture_device"

#: Target type for the capture-request audit entry.
_CAPTURE_TARGET_TYPE: Final = "pcap_capture"

#: Target type used for every agent-session audit entry.
_TARGET_TYPE = "agent_session"

#: WebSocket close code for an authenticated/authorization failure (RFC 6455
#: 1008 "policy violation"): the peer is closed without receiving any trace.
_WS_POLICY_VIOLATION = 1008

#: How long the stream socket waits between polls of an in-progress session
#: before re-checking for newly recorded steps / a terminal status.
#: ≥500 ms — the previous 20 ms (50 Hz) N+1 poll path generated ~400 q/s per
#: open socket; Redis pub/sub carries liveness, DB poll is durability only (H4).
_STREAM_POLL_SECONDS = 0.5

#: Upper bound on stream poll iterations so a stuck run can never wedge the
#: socket open forever (~30 s at 0.5 s/poll; defence in depth).
_STREAM_MAX_POLLS = 60

#: Lifetime of a single-use stream ticket in seconds.  The client must open
#: the WebSocket within this window after calling ``stream-ticket``; the ticket
#: is destroyed on first use so it cannot be replayed.
_TICKET_TTL_SECONDS = 30


# ---------------------------------------------------------------------------
# Shared single-use stream-ticket store + per-session pub/sub fan-out (W2-T2,
# ADR-0044 §2). Both are externalized to Redis so the WebSocket stream is
# STATELESS — a ticket issued on replica A is redeemable on replica B, and a
# session opened on replica A is served (its live frames relayed) from replica B.
# Production binds the Redis-backed implementations onto ``app.state`` at startup
# over the Sentinel-aware client; tests override the two DI seams below with the
# in-memory implementations (no Redis, no network).
# ---------------------------------------------------------------------------
def get_stream_ticket_store(websocket: WebSocket) -> StreamTicketStore:
    """Return the shared single-use stream-ticket store (overridable DI seam).

    Production reads the Redis-backed store bound on ``app.state`` at startup (a
    ticket issued on any replica redeems on any replica, ADR-0044 §2). When none
    is bound (a bare dev run) a process-local store is used. Tests override this
    seam with an :class:`InMemoryStreamTicketStore`.
    """
    store = getattr(websocket.app.state, "stream_ticket_store", None)
    if store is None:
        store = InMemoryStreamTicketStore()
        websocket.app.state.stream_ticket_store = store
    return store


def get_stream_ticket_store_http(request: Request) -> StreamTicketStore:
    """HTTP-scope variant of :func:`get_stream_ticket_store` for the ticket-issue route.

    The ``POST /stream-ticket`` route runs in an HTTP scope (no WebSocket), so it
    resolves the same ``app.state`` store via the request. Tests override
    :func:`get_stream_ticket_store` and this both bind to the same instance.
    """
    store = getattr(request.app.state, "stream_ticket_store", None)
    if store is None:
        store = InMemoryStreamTicketStore()
        request.app.state.stream_ticket_store = store
    return store


def get_stream_fanout(websocket: WebSocket) -> AgentStreamFanout:
    """Return the per-session pub/sub fan-out (overridable DI seam, ADR-0044 §2).

    Production reads the Redis pub/sub fan-out bound on ``app.state`` at startup
    over the Sentinel-aware client; the serving replica subscribes to the session
    channel and relays live frames. When none is bound (a bare dev run) an
    in-memory fan-out is used. Tests override this seam so two "replicas" can share
    one in-memory bus and prove cross-replica delivery without a real Redis.
    """
    fanout = getattr(websocket.app.state, "stream_fanout", None)
    if fanout is None:
        fanout = InMemoryAgentStreamFanout()
        websocket.app.state.stream_fanout = fanout
    return fanout


def get_stream_fanout_http(request: Request) -> AgentStreamFanout:
    """HTTP-scope variant of :func:`get_stream_fanout` for the run producer.

    ``POST /agents`` drives the supervisor in an HTTP scope (no WebSocket), and it
    is the PRODUCER side of the fan-out: the trace recorder it builds publishes
    each persisted step as a live frame (ADR-0044 §2/§6). It must resolve the SAME
    ``app.state.stream_fanout`` instance the WebSocket subscriber reads — so a step
    fanned out by a run on this replica is relayed by whichever replica serves the
    socket. Binding the lazily-created in-memory fan-out back onto ``app.state``
    (as the WS seam also does) keeps the producer and subscriber on one bus in a
    bare dev run; tests override :func:`get_stream_fanout` to share an explicit bus.
    """
    fanout = getattr(request.app.state, "stream_fanout", None)
    if fanout is None:
        fanout = InMemoryAgentStreamFanout()
        request.app.state.stream_fanout = fanout
    return fanout


def get_change_request_service(sessionmaker: SessionMaker) -> ChangeRequestService:
    """Build the :class:`ChangeRequestService` over the process sessionmaker (DI seam).

    The service owns its own commit boundary (one short transaction + audit row
    per transition), so it takes the :class:`async_sessionmaker`, not a
    request-scoped session — mirroring the agent-session lifecycle service. Tests
    override :func:`get_sessionmaker` (the underlying seam) to bind an isolated
    in-memory engine; nothing here reaches a real Postgres.
    """
    return ChangeRequestService(sessionmaker)


ChangeService = Annotated[ChangeRequestService, Depends(get_change_request_service)]


#: A pcap analyzer is ``(capture_id, display_filter) -> PacketFindings``. The
#: default resolves the on-disk pcap path and runs the sandboxed tshark analysis;
#: tests override :func:`get_pcap_analyzer` so no real pcap/subprocess is touched.
PcapAnalyzer = Callable[[uuid.UUID, str | None], PacketFindings]


def get_pcap_analyzer(
    settings: Annotated[Settings, Depends(get_app_settings)],
) -> PcapAnalyzer:
    """Return the pcap analyzer for the synchronous API path (overridable DI seam).

    **Fail-closed by design (ADR-0049 residual):** when
    ``packet_sandbox_posture_enforced`` is on (the secure default), this seam
    NEVER parses pcap bytes in-process — it raises :class:`ConflictError` (409)
    instead. The API/web pod holds DB/JWT/KEK credentials + egress and none of
    the executor-split sandbox controls, and the shared api/worker image ships
    no tshark (a guard test pins the Dockerfile stage split), so synchronous
    in-pod analysis is disabled; analysis runs only in the executor-confined
    ``packet_analysis`` worker (ADR-0049). Routing this endpoint through that
    tier (enqueue → executor → stored findings) is a scoped follow-up.

    Only with enforcement OFF (the eager unit-test / dev runner) does the seam
    run :func:`app.engines.packet.analyze_pcap` in-process — argv-only,
    ``shell=False``, ``-n``, whitelisted display filter, hard timeout
    (ADR-0023 §1) — returning only normalized :class:`PacketFindings`, never raw
    packet bytes. Tests override this seam so the API contract is exercised
    without a real capture file.
    """

    def _analyze(capture_id: uuid.UUID, display_filter: str | None) -> PacketFindings:
        if settings.packet_sandbox_posture_enforced:
            # Fail closed (ADR-0049 residual): never dissect untrusted pcap
            # bytes inside the credential-bearing API pod. The message names
            # the supported path only — no path/credential detail leaks.
            raise ConflictError(
                "synchronous in-pod packet analysis is disabled; analysis runs "
                "only in the executor-confined packet_analysis worker (ADR-0049)"
            )
        path = pcap_path_for(capture_id, pcap_dir=settings.pcap_dir)
        return analyze_pcap(
            path,
            display_filter=display_filter,
            tshark_bin=settings.tshark_bin,
            timeout_seconds=settings.packet_analysis_timeout_seconds,
        )

    return _analyze


SupervisorGraph = CompiledStateGraph[SupervisorState, None, SupervisorState, SupervisorState]

#: Process-wide supervisor graphs keyed by (profile, model_name). The compiled
#: graph closes over a :class:`ContextVarTraceRecorder`; each request binds the
#: real per-session recorder before invoke (Wave 5 / agents H1).
_SUPERVISOR_GRAPH_CACHE: dict[tuple[str, str], SupervisorGraph] = {}


def clear_supervisor_cache() -> None:
    """Drop cached supervisor graphs (LLM settings change / tests)."""
    _SUPERVISOR_GRAPH_CACHE.clear()


def invalidate_llm_runtime_caches() -> None:
    """Clear supervisor + chat-model + embedder caches after an LLM settings mutation."""
    from app.knowledge.embedding import clear_embedder_caches
    from app.llm.providers import clear_chat_model_cache

    clear_supervisor_cache()
    clear_chat_model_cache()
    clear_embedder_caches()


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

    Graphs are process-cached by ``(profile, model)``; *trace_recorder* is
    bound into a task-local ContextVar so a cached graph still records into the
    correct session.
    """
    from app.agents.framework.traces import (
        ContextVarTraceRecorder,
        TraceRecorder,
        bind_trace_recorder,
    )

    async with db.get_sessionmaker()() as session:
        profile = await effective_profile_for_role(session, "reasoning", settings)
    llm: BaseChatModel = get_chat_model(profile, settings, _role="reasoning")
    # Cache key: resolved profile + the model name the factory selected
    # (effective_profile_for_role always returns a concrete profile string).
    if profile == "local":
        model_name = settings.llm_local_model
    else:
        from app.llm.providers import DEFAULT_MODELS

        model_name = DEFAULT_MODELS.get(profile, settings.llm_local_model)
    cache_key = (profile, model_name)

    graph = _SUPERVISOR_GRAPH_CACHE.get(cache_key)
    if graph is None:
        graph = build_default_supervisor(
            llm,
            trace_recorder=ContextVarTraceRecorder(),
        )
        _SUPERVISOR_GRAPH_CACHE[cache_key] = graph

    if trace_recorder is not None and isinstance(trace_recorder, TraceRecorder):
        bind_trace_recorder(trace_recorder)
    return graph


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
    """Reload every reasoning trace linked to *session_id*, oldest first.

    This is a pure DB read (the durable replay path), so it uses the
    :class:`PostgresTraceRecorder` directly — never the publishing producer
    wrapper, which only the *run* path needs to fan live frames onto the channel.
    """
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
    recorder = PostgresTraceRecorder(sessionmaker, session_id=session_id)
    return [await recorder.get(row_id.hex) for row_id in rows]


async def _load_session_steps(
    sessionmaker: async_sessionmaker[AsyncSession],
    session_id: uuid.UUID,
) -> list[TraceStep]:
    """Load every durable step for *session_id* in a single query.

    Avoids the prior N+1 full-trace reload (one ``recorder.get`` per trace).
    Offset-based cursors are **not** used: concurrent specialist traces can
    insert steps that reorder under ``(started_at, id, ordinal)``, and a
    global offset would skip mid-list inserts. Dedup is the caller's
    ``emitted_keys`` set (same as live Redis frames).
    """
    from app.agents.framework.traces import EvidenceRef
    from app.agents.framework.traces import TraceStepKind as FrameworkStepKind

    async with sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(ReasoningTraceStep)
                    .join(
                        ReasoningTraceRow,
                        ReasoningTraceStep.trace_id == ReasoningTraceRow.id,
                    )
                    .where(ReasoningTraceRow.session_id == session_id)
                    .order_by(
                        ReasoningTraceRow.started_at,
                        ReasoningTraceRow.id,
                        ReasoningTraceStep.ordinal,
                    )
                )
            )
            .scalars()
            .all()
        )
        # Build while session is open (no DetachedInstanceError).
        return [
            TraceStep(
                kind=FrameworkStepKind(row.kind.value),
                summary=row.summary,
                detail=row.detail,
                tool_name=row.tool_name,
                evidence=[EvidenceRef.model_validate(item) for item in (row.evidence or [])],
                occurred_at=row.occurred_at,
            )
            for row in rows
        ]


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


def _first_token_seconds(traces: list[ReasoningTrace]) -> float | None:
    """Seconds from the first trace's start to its first persisted step, or None.

    The agent run is step-granular (no per-token stream at this layer), so the
    first persisted reasoning step is the earliest user-visible output — the
    operational first-token signal for the §6 first-token-latency SLI
    (ADR-0046 §1). Both timestamps are UTC wall-clock; a run with no recorded step
    yields ``None`` (nothing to observe). Clamped at ``0.0`` so clock skew between
    the trace-start stamp and a step stamp can never record a negative latency.
    """
    if not traces:
        return None
    first = traces[0]
    if not first.steps:
        return None
    delta = (first.steps[0].occurred_at - first.started_at).total_seconds()
    return max(delta, 0.0)


def _answer_of(state: SupervisorState) -> str:
    """Extract the final synthesized answer text from a finished run state."""
    messages = state.get("messages") or []
    if not messages:
        return ""
    content = messages[-1].content
    return content if isinstance(content, str) else str(content)


@router.post(
    "/{session_id}/stream-ticket",
    response_model=StreamTicketResponse,
    status_code=201,
    dependencies=_API_RATE_LIMIT,
)
async def create_stream_ticket(
    session_id: uuid.UUID,
    user: Viewer,
    sessionmaker: SessionMaker,
    ticket_store: Annotated[StreamTicketStore, Depends(get_stream_ticket_store_http)],
) -> StreamTicketResponse:
    """Issue a short-lived single-use ticket for the trace-stream WebSocket.

    The WebSocket handshake cannot carry an ``Authorization`` header, so the
    client would otherwise have to embed the JWT in the URL — leaking it into
    server access logs, browser history, and ``Referer`` headers.  This
    endpoint issues an opaque 30-second ticket instead; the WebSocket upgrade
    handler redeems it (single use, TTL-bound) and the JWT never appears in a URL.

    The ticket is stored in the **shared** store (Redis in prod, ADR-0044 §2) so
    a ticket issued on this replica is redeemable on any replica — the WebSocket
    stream is stateless and not pinned to the issuing replica.

    Returns 404 when the session does not exist (consistent with the REST
    ``GET`` surface) so the caller cannot probe for session ids via ticket
    issuance.
    """
    await _load_session_or_404(sessionmaker, session_id)
    ticket = await ticket_store.issue(
        user_id=user.id, session_id=session_id, ttl_seconds=_TICKET_TTL_SECONDS
    )
    return StreamTicketResponse(ticket=ticket)


@router.post("", response_model=StartSessionResponse, status_code=201, dependencies=_API_RATE_LIMIT)
async def start_session(
    body: StartSessionRequest,
    user: Viewer,
    sessionmaker: SessionMaker,
    settings: Annotated[Settings, Depends(get_app_settings)],
    builder: Annotated[object, Depends(get_supervisor_builder)],
    stream_fanout: Annotated[AgentStreamFanout, Depends(get_stream_fanout_http)],
) -> StartSessionResponse:
    """Start an agent session and drive the supervisor to completion.

    The invoking user's role is resolved from the authenticated principal and
    carried into the session + every tool's RBAC context (brief §7); a viewer
    can therefore never reach a tool above its rank through the agent. The
    session start and completion are both audited, and each reasoning trace the
    run produces is linked back to the session with its own audit entry.
    """
    role = Role.from_name(user.role.name) or Role.VIEWER
    # Pass the per-session fan-out so ``recorder_for`` returns the production
    # PRODUCER (ADR-0044 §2/§6): every persisted reasoning step is fanned out as a
    # live frame on the session channel, served by any subscribing replica.
    service = AgentSessionService(sessionmaker, stream_fanout=stream_fanout)

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
    # Agent first-token latency SLI (ADR-0046 §1): observe time-to-first-persisted
    # step, labelled by the resolved reasoning profile. Post-hoc over the loaded
    # traces — no cost on the run hot path; skipped when the run produced no step.
    first_token = _first_token_seconds(traces)
    if first_token is not None:
        # BEST-EFFORT: an observability metric must NEVER break the audit path. This
        # block opens its OWN DB session (effective_profile_for_role) BEFORE the
        # AGENT_TRACE_RECORDED / AGENT_SESSION_COMPLETED audit writes below; a
        # transient DB error here must not abort the request and drop the completed
        # run's audit trail. Swallow + log so the metric is skipped, not fatal.
        try:
            async with sessionmaker() as profile_session:
                profile = await effective_profile_for_role(profile_session, "reasoning", settings)
            metrics.observe_agent_first_token(profile=profile, seconds=first_token)
        except Exception:  # noqa: BLE001 — metric is best-effort; audit path must proceed
            _logger.warning(
                "agent.first_token_metric_failed", session_id=str(run_session.id), exc_info=True
            )
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


@router.get("/{session_id:uuid}", response_model=StartSessionResponse, dependencies=_API_RATE_LIMIT)
async def get_session(
    session_id: uuid.UUID,
    _user: Viewer,
    sessionmaker: SessionMaker,
) -> StartSessionResponse:
    """Return one persisted session and its full reasoning trace (404 if unknown).

    The ``:uuid`` path convertor constrains this single-segment route to valid
    UUIDs only, so the sibling static sub-resources on this router (``/changes``,
    ``/captures``) fall through to their own handlers instead of being parsed as
    a session id.
    """
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
    """Stream a session's reasoning steps, then a terminal frame — statelessly.

    Authentication mirrors the REST surface and happens **at the edge, per
    connection** (ADR-0044 §3): the peer presents a single-use stream ticket
    (preferred) or the same JWT access token as a ``token`` query parameter. An
    unauthenticated or unauthorized peer is closed with :data:`_WS_POLICY_VIOLATION`
    *before* any frame is sent, so the socket never leaks a trace to a caller who
    could not read it over REST. The bearer token is verified here and is **never**
    published onto the shared pub/sub channel.

    Statelessness (ADR-0044 §2/§5): this replica **subscribes to the session's
    Redis pub/sub channel** (keyed by the opaque session id) and relays live frames
    to its peer — so a session opened on another replica is served here without
    affinity. Postgres remains the durable record: persisted steps are replayed
    from the DB first (completeness / reconnect backfill), then live frames are
    relayed best-effort (at-most-once on the wire) until the run reaches a terminal
    status. A frame missed on the live wire is recovered by the DB replay, never
    lost session state.

    Settings/fan-out/ticket-store are read from ``websocket.app.state`` (a
    WebSocket scope has no HTTP :class:`~fastapi.Request`, so the REST
    ``get_app_settings`` dependency cannot resolve here).
    """
    settings: Settings = websocket.app.state.settings
    fanout = get_stream_fanout(websocket)
    ticket_store = get_stream_ticket_store(websocket)
    user = await _authenticate_socket(websocket, sessionmaker, settings, ticket_store)
    if user is None:
        return  # _authenticate_socket already closed the socket.

    try:
        await _load_session_or_404(sessionmaker, session_id)
    except NotFoundError:
        await websocket.close(code=_WS_POLICY_VIOLATION)
        return

    answer = ""
    status = AgentSessionStatus.RUNNING
    # A step can be observed from TWO sources — the durable DB replay and the live
    # pub/sub relay — and the producer makes a live frame byte-identical to its
    # replayed read model (traces._step_read_model). Track a stable per-step key so
    # a step already sent from one source is not re-sent from the other (at-most-once
    # on the wire). The key is derived from the read-model fields the producer also
    # fills, so it matches across both sources.
    emitted_keys: set[str] = set()
    # Subscribe BEFORE accepting the socket (and before the DB replay): once we
    # are attached to the channel, a frame published by any replica is buffered on
    # our subscription rather than lost in the accept/replay gap.
    # One in-flight ``__anext__`` on the live subscription, kept across relay
    # cycles. It is NEVER cancelled between cycles: cancelling an async
    # generator's ``__anext__`` throws CancelledError into the generator and
    # permanently closes it — the pre-W1-audit bug that silently killed the
    # live relay after its first idle drain (and could eat a frame consumed
    # but not yet yielded). Cancelled exactly once, at teardown below.
    pending_live: asyncio.Task[AgentStreamFrame] | None = None
    async with fanout.subscribe(str(session_id)) as live_frames:
        await websocket.accept()
        try:
            for _ in range(_STREAM_MAX_POLLS):
                row = await _load_session_or_404(sessionmaker, session_id)
                status = row.status
                # Durable replay: one query for all steps (no N+1); skip via keys.
                steps = await _load_session_steps(sessionmaker, session_id)
                for step in steps:
                    data = _step_read(step).model_dump(mode="json")
                    key = _step_frame_key(data)
                    if key not in emitted_keys:
                        emitted_keys.add(key)
                        await websocket.send_json(data)
                # Liveness: relay any live frames already fanned out for this session
                # (ADR-0044 §2). Done on EVERY iteration — including the terminal one —
                # so a frame that arrived on the wire just before the run finished is
                # still delivered before the end frame rather than needlessly dropped.
                # Cross-source dedup: a frame whose step was already replayed from the DB
                # (or vice-versa) is skipped via the shared ``emitted_keys`` set.
                pending_live = await _relay_pending_live_frames(
                    websocket, live_frames, emitted_keys, pending_live
                )
                if status is not AgentSessionStatus.RUNNING:
                    traces = await _load_traces(sessionmaker, session_id)
                    answer = _final_answer_from_traces(traces)
                    break
                await asyncio.sleep(_STREAM_POLL_SECONDS)
        finally:
            # Teardown is the ONE place the in-flight __anext__ is cancelled —
            # the generator is closed by the subscription context exit anyway.
            if pending_live is not None:
                pending_live.cancel()
                with contextlib.suppress(asyncio.CancelledError, StopAsyncIteration):
                    await pending_live

    # Only emit the terminal ``end`` frame when the run actually REACHED a terminal
    # status. If the poll budget was exhausted while the run is still RUNNING,
    # sending AgentStreamEnd(status=running) would be a contradictory, misleading
    # terminal frame (event=end yet not finished, empty answer) — instead close
    # without claiming termination so the client knows to reconnect (F-agents-588).
    if status is not AgentSessionStatus.RUNNING:
        await websocket.send_json(
            AgentStreamEnd(status=status, answer=answer).model_dump(mode="json")
        )
    await websocket.close()


def _step_frame_key(data: dict[str, object]) -> str:
    """Stable cross-source identity of a streamed step read model.

    Both the DB-replay read model (``_step_read(step).model_dump``) and the live
    fanned-out frame (``traces._step_read_model``) carry the same fields, so a key
    built from them matches a step regardless of which source observed it first.
    ``occurred_at`` is monotonic per run and the ``(kind, summary, tool_name)``
    triple disambiguates same-instant steps.
    """
    return "\x1f".join(
        (
            str(data.get("kind")),
            str(data.get("occurred_at")),
            str(data.get("summary")),
            str(data.get("tool_name")),
        )
    )


async def _relay_pending_live_frames(
    websocket: WebSocket,
    live_frames: AsyncIterator[AgentStreamFrame],
    emitted_keys: set[str],
    pending: asyncio.Task[AgentStreamFrame] | None,
) -> asyncio.Task[AgentStreamFrame] | None:
    """Relay any live pub/sub frames currently available, without blocking.

    Drains the subscription with a short timeout so the relay loop keeps its
    terminal-status poll cadence: a frame that has arrived on the channel is sent
    to the peer immediately; if none has arrived this returns at once. Best-effort
    (ADR-0044 §5) — no buffering beyond what the subscription already holds.

    The in-flight ``__anext__`` task is threaded through *pending* across calls
    and is **never cancelled here**. ``asyncio.wait_for`` was the pre-W1-audit
    implementation and its timeout CANCELLED the ``__anext__`` — which throws
    CancelledError into the async generator and closes it for good, so the live
    relay silently died after its first idle drain (every later drain saw an
    instant ``StopAsyncIteration``; the DB replay masked the loss). It could
    also eat a frame the generator had consumed but not yet yielded. Instead an
    unfinished ``__anext__`` is simply left running and handed back to the next
    cycle; the caller cancels it exactly once at socket teardown.

    Cross-source dedup: a frame whose step was already emitted from the DB replay
    (or an earlier live frame) is skipped via the shared ``emitted_keys`` set so a
    persisted step — published as a frame byte-identical to its replay — is sent at
    most once on the wire (F-agents-582 / F-agents-609).
    """
    while True:
        if pending is None:
            pending = asyncio.ensure_future(anext(live_frames))
        done, _ = await asyncio.wait({pending}, timeout=_STREAM_POLL_SECONDS)
        if not done:
            return pending  # still in flight — hand it to the next cycle intact
        task, pending = pending, None
        try:
            frame = task.result()
        except StopAsyncIteration:
            return None  # subscription ended; nothing further to relay
        key = _step_frame_key(frame.data)
        if key in emitted_keys:
            continue
        emitted_keys.add(key)
        await websocket.send_json(frame.data)


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
    ticket_store: StreamTicketStore,
) -> User | None:
    """Resolve either a ``ticket`` or ``token`` query param to a ``viewer+`` user.

    Preferred path — ``ticket``: the client obtained a short-lived single-use
    opaque ticket via ``POST /agents/{id}/stream-ticket`` (authenticated with
    the normal ``Authorization`` header). The ticket is redeemed once against the
    **shared** store (Redis in prod, ADR-0044 §2) so a ticket issued on any replica
    is redeemable here and the bearer JWT never appears in a URL.

    Fallback path — ``token``: a raw JWT access token passed directly.  This
    path exists so internal tooling and existing tests can reach the stream
    without the ticket round-trip; the fallback is not used by the browser SPA.

    Either way auth happens **at this serving edge** and the bearer token is never
    placed on the shared pub/sub channel (ADR-0044 §3). On any failure the socket
    is closed with :data:`_WS_POLICY_VIOLATION` and ``None`` is returned; the
    caller must not proceed.
    """
    session_id_str = websocket.path_params.get("session_id", "")

    ticket = websocket.query_params.get("ticket")
    if ticket is not None:
        try:
            session_id = uuid.UUID(str(session_id_str))
        except ValueError:
            await websocket.close(code=_WS_POLICY_VIOLATION)
            return None
        user_id = await ticket_store.consume(ticket=ticket, session_id=session_id)
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


# ===========================================================================
# ChangeRequest + approvals surface (M5-T15; ADR-0020).
#
# The CR lifecycle (draft -> pending_approval -> approved -> ... ) is owned by
# the ChangeRequestService (T3) — the *only* mutator of ``change_requests``.
# These endpoints are thin: they authenticate, enforce engineer+ RBAC, apply the
# server-side four-eyes guard a SECOND time at the endpoint layer (defence in
# depth, in addition to the service's PRIMARY guard), and delegate every
# transition to the service. There is deliberately **no** execute/mark-* edge on
# this surface: the ``approved -> executing`` handoff requires the verified
# Automation Agent service principal (ADR-0020 §2), never a holder of an HTTP
# token, so a non-approved CR can never be driven to execute through the API.
# ===========================================================================


@router.get("/changes", response_model=ChangeRequestListResponse, dependencies=_API_RATE_LIMIT)
async def list_change_requests(
    session: DbSession,
    _user: Engineer,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ChangeRequestListResponse:
    """List ChangeRequests, newest first, paginated (engineer+; ADR-0020 §5).

    The CR lifecycle is an engineer+ capability (operator/viewer are not on the
    change surface). ``payload`` is never surfaced — only lifecycle metadata and
    the id-only ``target_refs`` (ADR-0020 §4 data minimization).
    """
    from app.models import ChangeRequest  # local import: avoid widening module surface

    total = (await session.execute(select(func.count()).select_from(ChangeRequest))).scalar_one()
    rows = (
        (
            await session.execute(
                select(ChangeRequest)
                .order_by(ChangeRequest.created_at.desc(), ChangeRequest.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ChangeRequestListResponse(
        items=[ChangeRequestRead.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/changes/{cr_id}", response_model=ChangeRequestRead, dependencies=_API_RATE_LIMIT)
async def get_change_request(
    cr_id: uuid.UUID,
    _user: Engineer,
    service: ChangeService,
) -> ChangeRequestRead:
    """One ChangeRequest by id (engineer+; 404 problem when unknown)."""
    cr = await service.get(cr_id)
    return ChangeRequestRead.model_validate(cr)


@router.post(
    "/changes/{cr_id}/submit", response_model=ChangeRequestRead, dependencies=_API_RATE_LIMIT
)
async def submit_change_request(
    cr_id: uuid.UUID,
    body: ChangeDecisionRequest,
    user: Engineer,
    service: ChangeService,
) -> ChangeRequestRead:
    """``draft -> pending_approval`` (engineer+; ADR-0020 §1)."""
    cr = await service.submit(cr_id, actor_id=user.id, actor_role=_role_of(user))
    return ChangeRequestRead.model_validate(cr)


@router.post(
    "/changes/{cr_id}/approve", response_model=ChangeRequestRead, dependencies=_API_RATE_LIMIT
)
async def approve_change_request(
    cr_id: uuid.UUID,
    body: ChangeDecisionRequest,
    user: Engineer,
    service: ChangeService,
) -> ChangeRequestRead:
    """``pending_approval -> approved`` — engineer+ with an endpoint four-eyes guard.

    Defence in depth (ADR-0020 §3): the four-eyes predicate (``approver !=
    requester`` when ``four_eyes_required``) is re-checked **here at the endpoint**
    before delegating, in addition to the PRIMARY guard inside the
    ChangeRequestService. A self-approval is rejected with 403 and no transition
    is attempted — the CR never leaves ``pending_approval`` and no ``approved``
    audit row is written.
    """
    cr = await service.get(cr_id)
    if cr.four_eyes_required and cr.requester_id == user.id:
        raise ForbiddenError(
            "four-eyes violation: the approver must differ from the requester "
            f"for change request '{cr_id}'"
        )
    approved = await service.approve(
        cr_id, actor_id=user.id, actor_role=_role_of(user), comment=body.comment
    )
    return ChangeRequestRead.model_validate(approved)


@router.post(
    "/changes/{cr_id}/reject", response_model=ChangeRequestRead, dependencies=_API_RATE_LIMIT
)
async def reject_change_request(
    cr_id: uuid.UUID,
    body: ChangeDecisionRequest,
    user: Engineer,
    service: ChangeService,
) -> ChangeRequestRead:
    """``pending_approval -> draft`` (engineer+; ADR-0020 §1).

    Four-eyes constrains *approve*, not *reject* — the requester may withdraw
    their own CR, so there is no four-eyes guard on this edge.
    """
    cr = await service.reject(
        cr_id, actor_id=user.id, actor_role=_role_of(user), comment=body.comment
    )
    return ChangeRequestRead.model_validate(cr)


def _role_of(user: User) -> Role:
    """The verified principal's RBAC role (never spoofed from the request body)."""
    return Role.from_name(user.role.name) or Role.VIEWER


# ===========================================================================
# Packet capture / analysis surface (M5-T15; ADR-0023).
#
# A capture LAUNCH is asynchronous and never inline-blocking: the route validates
# + whitelist-checks the BPF filter, then enqueues the worker-side capture task on
# the ``packet`` queue and returns the capture id + ``queued`` status (mirrors the
# discovery run surface). The status endpoint reads the persisted pcap metadata,
# and the analysis endpoint returns the NORMALIZED findings (top talkers, protocol
# hierarchy, TCP anomalies) — never raw packet bytes (ADR-0023 §1).
# ===========================================================================


@router.post(
    "/captures",
    response_model=CaptureLaunchResponse,
    status_code=202,
    dependencies=_API_RATE_LIMIT,
)
async def launch_capture(
    body: CaptureLaunchRequest,
    session: DbSession,
    user: Engineer,
) -> CaptureLaunchResponse:
    """Launch a packet capture asynchronously (engineer+; ADR-0023 §2/§3).

    The BPF filter is whitelist-validated **before** anything is enqueued (a
    dash-prefixed/injection token is rejected 422, nothing queued). The capture
    request is audited, committed, and only then is the worker task enqueued — so
    the worker never races the audit. 202: the capture runs on the ``packet``
    queue; poll ``GET /captures/{capture_id}`` for completion.
    """
    try:
        validate_capture_filter(body.capture_filter)
    except FilterValidationError as exc:
        raise UnprocessableEntityError(str(exc)) from exc

    capture_id = uuid.uuid4()
    await audit.record(
        session,
        actor=f"user:{user.username}",
        action=audit.PACKET_CAPTURE_REQUESTED,
        target_type=_CAPTURE_TARGET_TYPE,
        target_id=str(capture_id),
        detail={
            "interface": body.interface,
            "device_id": str(body.device_id) if body.device_id is not None else None,
            # The filter is whitelist-validated, never secret; recording only its
            # presence keeps the trail terse and avoids echoing attacker input.
            "has_filter": body.capture_filter is not None,
        },
    )
    await session.commit()

    if body.device_id is not None:
        celery_app.send_task(
            DEVICE_CAPTURE_TASK,
            args=[
                str(user.id),
                str(body.device_id),
                body.interface,
                body.capture_filter,
                body.duration_seconds,
                body.size_bytes,
                str(capture_id),
            ],
            queue=QUEUE_PACKET_CAPTURE,
        )
    else:
        celery_app.send_task(
            SEGMENT_CAPTURE_TASK,
            args=[
                str(user.id),
                body.interface,
                body.capture_filter,
                body.duration_seconds,
                body.size_bytes,
                str(capture_id),
            ],
            queue=QUEUE_PACKET_CAPTURE,
        )
    return CaptureLaunchResponse(
        capture_id=capture_id,
        status=CaptureStatus.QUEUED,
        interface=body.interface,
        device_id=body.device_id,
    )


async def _get_capture_or_404(session: AsyncSession, capture_id: uuid.UUID) -> PcapMetadata:
    """Reload one capture's metadata row or raise :class:`NotFoundError`."""
    row = (
        await session.execute(select(PcapMetadata).where(PcapMetadata.capture_id == capture_id))
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"capture {capture_id} does not exist")
    return row


def _capture_status(row: PcapMetadata) -> CaptureStatus:
    """Lifecycle of a persisted capture row (tombstoned > completed)."""
    if row.tombstoned_at is not None:
        return CaptureStatus.TOMBSTONED
    return CaptureStatus.COMPLETED


@router.get(
    "/captures/{capture_id}", response_model=CaptureStatusResponse, dependencies=_API_RATE_LIMIT
)
async def get_capture(
    capture_id: uuid.UUID,
    session: DbSession,
    _user: Engineer,
) -> CaptureStatusResponse:
    """One capture's metadata + lifecycle status (engineer+; no raw pcap content)."""
    row = await _get_capture_or_404(session, capture_id)
    return CaptureStatusResponse(
        capture_id=row.capture_id,
        status=_capture_status(row),
        interface=row.interface,
        device_id=row.device_id,
        byte_count=row.byte_count,
        packet_count=row.packet_count,
        sha256=row.sha256,
        started_at=row.started_at,
        ended_at=row.ended_at,
        retention_expires_at=row.retention_expires_at,
        tombstoned_at=row.tombstoned_at,
    )


@router.get(
    "/captures/{capture_id}/analysis", response_model=PacketFindings, dependencies=_API_RATE_LIMIT
)
async def get_capture_analysis(
    capture_id: uuid.UUID,
    session: DbSession,
    _user: Engineer,
    analyzer: Annotated[PcapAnalyzer, Depends(get_pcap_analyzer)],
    display_filter: Annotated[str | None, Query(max_length=1024)] = None,
) -> PacketFindings:
    """Return the normalized analysis findings for a stored capture (engineer+).

    **409 when the sandbox posture is enforced** (the secure default): the
    synchronous in-pod analysis path is disabled by design — this pod holds
    credentials and none of the executor-split controls, so it never parses
    untrusted pcap bytes; analysis runs only in the executor-confined
    ``packet_analysis`` worker (ADR-0049 residual, see :func:`get_pcap_analyzer`).

    With enforcement off (dev/eager runner) it runs the sandboxed tshark
    analysis (argv-only, ``-n``, whitelisted filter, hard timeout — ADR-0023 §1)
    over the capture's pcap and returns only the normalized
    :class:`PacketFindings` (top talkers, protocol hierarchy, TCP anomalies).
    Raw packet bytes never leave the sandbox (ADR-0023 §1). 404 when the capture
    is unknown or its pcap has been tombstoned by retention.
    """
    row = await _get_capture_or_404(session, capture_id)
    if row.tombstoned_at is not None:
        raise NotFoundError(
            f"capture {capture_id} has been purged by retention; its pcap no longer exists"
        )
    try:
        validate_capture_filter(display_filter)
    except FilterValidationError as exc:
        raise UnprocessableEntityError(str(exc)) from exc
    return analyzer(capture_id, display_filter)
