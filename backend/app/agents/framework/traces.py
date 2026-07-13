"""Reasoning-trace models and recorders (ADR-0003 Decision 3, ADR-0011 §4).

Every agent run must yield an inspectable reasoning trace — steps, tool calls,
evidence — so "Explain all AI decisions" is a stored artifact, not a UI
nicety. M0 ships the models plus an in-memory recorder behind the
:class:`TraceRecorder` seam; M3 adds the database-backed recorder that
persists to the ``reasoning_traces`` table and links entries from
``audit_log`` (brief §6).
"""

from __future__ import annotations

import asyncio
import uuid
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.models.agents import ReasoningTraceRow, ReasoningTraceStep
from app.models.agents import TraceStepKind as OrmTraceStepKind

if TYPE_CHECKING:
    from app.services.agent_stream import AgentStreamFanout

_logger = get_logger(__name__)


def _utcnow() -> datetime:
    """Return the current UTC instant (single seam for freezing in tests)."""
    return datetime.now(tz=UTC)


class TraceStepKind(StrEnum):
    """What a single reasoning step represents.

    Values are wire-stable strings: they persist to ``reasoning_traces`` (M3)
    and render in the UI trace viewer.
    """

    #: The agent decided what to do next (supervisor routing, planning).
    PLAN = "plan"
    #: The agent invoked a tool (links to the tool's audit event).
    TOOL_CALL = "tool_call"
    #: The agent ingested evidence (tool output, retrieved context).
    OBSERVATION = "observation"
    #: The agent produced a result or final answer.
    CONCLUSION = "conclusion"


class EvidenceRef(BaseModel):
    """A pointer to evidence supporting a reasoning step.

    M0 references are opaque strings; M3 resolves them against real rows
    (``raw_artifacts``, ``audit_log``, ``documents``) so the UI can deep-link.
    """

    model_config = ConfigDict(frozen=True)

    #: Evidence category, e.g. ``"raw_artifact"``, ``"audit_event"``,
    #: ``"document"``, ``"message"``.
    kind: str = Field(min_length=1)
    #: Opaque identifier or URI of the evidence.
    reference: str = Field(min_length=1)
    #: Optional human-readable label for the trace viewer.
    description: str | None = None


class TraceStep(BaseModel):
    """One ordered step inside a :class:`ReasoningTrace`."""

    model_config = ConfigDict(frozen=True)

    #: What this step represents.
    kind: TraceStepKind
    #: One-line human-readable summary of the step.
    summary: str = Field(min_length=1)
    #: Optional longer detail (model output excerpt, tool result digest).
    detail: str | None = None
    #: Tool name — required when (and only meaningful when) ``kind`` is
    #: :attr:`TraceStepKind.TOOL_CALL`.
    tool_name: str | None = None
    #: Evidence cited by this step.
    evidence: list[EvidenceRef] = Field(default_factory=list)
    #: UTC instant the step occurred.
    occurred_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _tool_call_names_its_tool(self) -> TraceStep:
        """A tool_call step without a tool name is unexplainable — reject it."""
        if self.kind is TraceStepKind.TOOL_CALL and not self.tool_name:
            raise ValueError("tool_call steps must set tool_name")
        return self


class ReasoningTrace(BaseModel):
    """The full reasoning record of one agent run.

    Mutable by design: recorders append steps while the run progresses and
    stamp ``completed_at`` when it ends. M3 persists each trace to the
    ``reasoning_traces`` table and links it from ``audit_log`` entries.
    """

    #: Opaque trace identifier (hex UUID4).
    trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    #: Agent that produced the trace (string id, e.g. ``"master_architect"``).
    agent_name: str = Field(min_length=1)
    #: UTC instant the run started.
    started_at: datetime = Field(default_factory=_utcnow)
    #: UTC instant the run ended; ``None`` while in progress.
    completed_at: datetime | None = None
    #: Ordered reasoning steps.
    steps: list[TraceStep] = Field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """Whether the trace has been completed by its recorder."""
        return self.completed_at is not None


@runtime_checkable
class TraceRecorder(Protocol):
    """Records reasoning traces for agent runs (pluggable seam).

    M0: :class:`InMemoryTraceRecorder`. M3: a database-backed recorder that
    persists to ``reasoning_traces`` and links from ``audit_log``
    (ADR-0011 §4) implements this same protocol.
    """

    async def start(self, agent_name: str) -> ReasoningTrace:
        """Open a new trace for *agent_name* and return it."""
        ...

    async def record_step(self, trace_id: str, step: TraceStep) -> ReasoningTrace:
        """Append *step* to the trace and return the updated trace."""
        ...

    async def complete(self, trace_id: str) -> ReasoningTrace:
        """Mark the trace finished and return it."""
        ...


#: Per-task active recorder so a process-cached supervisor graph can still
#: write traces for the current agent session (Wave 5 / agents H1).
_active_trace_recorder: ContextVar[TraceRecorder | None] = ContextVar(
    "netops_active_trace_recorder", default=None
)


def bind_trace_recorder(recorder: TraceRecorder) -> Token[TraceRecorder | None]:
    """Bind *recorder* for the current asyncio task (supervisor cache path)."""
    return _active_trace_recorder.set(recorder)


def reset_trace_recorder(token: Token[TraceRecorder | None]) -> None:
    """Restore the previous active recorder after a request finishes."""
    _active_trace_recorder.reset(token)


class ContextVarTraceRecorder:
    """Delegates every call to the task-local recorder set via :func:`bind_trace_recorder`.

    A single instance is safe to close over in a process-cached supervisor graph:
    each request binds its real :class:`PostgresTraceRecorder` (or test double)
    before invoke, so traces still land on the correct session.
    """

    def _inner(self) -> TraceRecorder:
        recorder = _active_trace_recorder.get()
        if recorder is None:
            raise RuntimeError(
                "no active TraceRecorder bound; call bind_trace_recorder() before invoke"
            )
        return recorder

    async def start(self, agent_name: str) -> ReasoningTrace:
        return await self._inner().start(agent_name)

    async def record_step(self, trace_id: str, step: TraceStep) -> ReasoningTrace:
        return await self._inner().record_step(trace_id, step)

    async def complete(self, trace_id: str) -> ReasoningTrace:
        return await self._inner().complete(trace_id)


class InMemoryTraceRecorder:
    """Process-local trace recorder — the M0 implementation.

    Traces live only for the lifetime of this instance; durable persistence
    to the ``reasoning_traces`` table is M3. Suitable for unit tests and for
    attaching traces to in-process supervisor runs.
    """

    def __init__(self) -> None:
        self._traces: dict[str, ReasoningTrace] = {}

    async def start(self, agent_name: str) -> ReasoningTrace:
        """Open and retain a new trace for *agent_name*."""
        trace = ReasoningTrace(agent_name=agent_name)
        self._traces[trace.trace_id] = trace
        return trace

    async def record_step(self, trace_id: str, step: TraceStep) -> ReasoningTrace:
        """Append *step* to the identified trace."""
        trace = self.get(trace_id)
        trace.steps.append(step)
        return trace

    async def complete(self, trace_id: str) -> ReasoningTrace:
        """Stamp ``completed_at`` on the identified trace."""
        trace = self.get(trace_id)
        if trace.completed_at is None:
            trace.completed_at = _utcnow()
        return trace

    def get(self, trace_id: str) -> ReasoningTrace:
        """Return the trace for *trace_id* or raise :class:`NotFoundError`."""
        try:
            return self._traces[trace_id]
        except KeyError:
            raise NotFoundError(f"reasoning trace '{trace_id}' does not exist") from None

    def list_traces(self) -> list[ReasoningTrace]:
        """Return all retained traces in insertion order."""
        return list(self._traces.values())


def _trace_uuid(trace_id: str) -> uuid.UUID:
    """Parse a hex ``trace_id`` into a :class:`uuid.UUID`.

    ``ReasoningTrace.trace_id`` is a 32-char hex string (``uuid4().hex``); the
    persistence layer keys on a real ``uuid.UUID``. A malformed id can never
    name an existing row, so it is surfaced as :class:`NotFoundError` rather
    than a raw ``ValueError``.
    """
    try:
        return uuid.UUID(hex=trace_id)
    except ValueError:
        raise NotFoundError(f"reasoning trace '{trace_id}' does not exist") from None


class PostgresTraceRecorder:
    """Database-backed trace recorder — the M3 implementation (brief §5/§6).

    Persists each agent run to the ``reasoning_traces`` / ``reasoning_trace_steps``
    tables created in M3-01 and reloads them losslessly, so "explain every AI
    decision" is a durable artifact. Implements the same :class:`TraceRecorder`
    protocol as :class:`InMemoryTraceRecorder`; the two are interchangeable at
    runtime via :func:`build_trace_recorder`.

    One recorder serves one :class:`~app.models.agents.AgentSession` (supervisor
    run): ``session_id`` is the FK every persisted trace carries. Each method
    runs in its own short transaction obtained from the injected sessionmaker,
    so the recorder owns no long-lived session and is safe to share across the
    concurrent specialist subgraphs of a single run.
    """

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        session_id: uuid.UUID,
    ) -> None:
        self._sessionmaker = sessionmaker
        self._session_id = session_id
        # Per-trace asyncio locks guard the COUNT-then-INSERT ordinal assignment
        # against in-process concurrent callers (asyncio.gather across specialist
        # subgraphs).  Combined with SELECT … FOR UPDATE these cover both
        # in-process and cross-process (multi-worker) concurrency.
        self._ordinal_locks: dict[str, asyncio.Lock] = {}

    async def start(self, agent_name: str) -> ReasoningTrace:
        """Open and persist a new trace for *agent_name*."""
        trace = ReasoningTrace(agent_name=agent_name)
        async with self._sessionmaker() as session:
            session.add(
                ReasoningTraceRow(
                    id=_trace_uuid(trace.trace_id),
                    session_id=self._session_id,
                    agent_name=agent_name,
                    started_at=trace.started_at,
                )
            )
            await session.commit()
        return trace

    async def record_step(self, trace_id: str, step: TraceStep) -> ReasoningTrace:
        """Append *step* to the persisted trace and return the reloaded trace.

        Ordinal assignment is made safe against concurrent callers in two layers:

        1. An ``asyncio.Lock`` per trace_id serialises in-process callers
           (e.g. concurrent specialist subgraphs joined via ``asyncio.gather``).
        2. ``SELECT … FOR UPDATE`` on the parent trace row serialises
           cross-process callers on Postgres (multiple uvicorn workers / Celery
           tasks sharing the same DB).  SQLite ignores the hint, which is fine
           because layer 1 covers all in-process concurrency.
        """
        row_id = _trace_uuid(trace_id)
        # ``setdefault`` is atomic w.r.t. the event loop (no await between the
        # lookup and the insert), so two concurrent callers for the same trace
        # always observe and share the SAME lock — closing the check-then-create
        # window of the prior ``if not in`` form.
        lock = self._ordinal_locks.setdefault(trace_id, asyncio.Lock())
        async with lock, self._sessionmaker() as session:
            # Cross-process lock: hold the parent row until commit so that
            # another DB connection cannot race past the COUNT query.
            row = (
                await session.execute(
                    select(ReasoningTraceRow)
                    .where(ReasoningTraceRow.id == row_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if row is None:
                raise NotFoundError(f"reasoning trace '{trace_id}' does not exist")
            next_ordinal = (
                await session.execute(
                    select(func.count())
                    .select_from(ReasoningTraceStep)
                    .where(ReasoningTraceStep.trace_id == row_id)
                )
            ).scalar_one()
            session.add(
                ReasoningTraceStep(
                    trace_id=row_id,
                    ordinal=next_ordinal,
                    kind=OrmTraceStepKind(step.kind.value),
                    summary=step.summary,
                    detail=step.detail,
                    tool_name=step.tool_name,
                    evidence=[ref.model_dump() for ref in step.evidence],
                    occurred_at=step.occurred_at,
                )
            )
            await session.commit()
        return await self.get(trace_id)

    async def complete(self, trace_id: str) -> ReasoningTrace:
        """Stamp ``completed_at`` on the persisted trace (idempotent)."""
        row_id = _trace_uuid(trace_id)
        async with self._sessionmaker() as session:
            row = await self._require_trace(session, trace_id, row_id)
            if row.completed_at is None:
                row.completed_at = _utcnow()
                await session.commit()
        return await self.get(trace_id)

    async def get(self, trace_id: str) -> ReasoningTrace:
        """Reload the persisted trace and its ordered steps as Pydantic models."""
        row_id = _trace_uuid(trace_id)
        async with self._sessionmaker() as session:
            row = await self._require_trace(session, trace_id, row_id)
            step_rows = (
                (
                    await session.execute(
                        select(ReasoningTraceStep)
                        .where(ReasoningTraceStep.trace_id == row_id)
                        .order_by(ReasoningTraceStep.ordinal)
                    )
                )
                .scalars()
                .all()
            )
            # Construct the Pydantic model while the session is still open so
            # that ORM attribute access never raises DetachedInstanceError on a
            # sessionmaker that does not set expire_on_commit=False.
            return ReasoningTrace(
                trace_id=row.id.hex,
                agent_name=row.agent_name,
                started_at=row.started_at,
                completed_at=row.completed_at,
                steps=[_step_from_row(step) for step in step_rows],
            )

    async def _require_trace(
        self, session: AsyncSession, trace_id: str, row_id: uuid.UUID
    ) -> ReasoningTraceRow:
        """Load the trace row or raise :class:`NotFoundError`."""
        row = (
            await session.execute(select(ReasoningTraceRow).where(ReasoningTraceRow.id == row_id))
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError(f"reasoning trace '{trace_id}' does not exist")
        return row


def _step_read_model(step: TraceStep) -> dict[str, Any]:
    """Project a :class:`TraceStep` to the JSON read model the stream emits.

    This is the SAME shape the WebSocket relays for a DB-replayed step
    (``app.api.v1.agents._step_read(step).model_dump(mode="json")``): ``kind`` /
    ``summary`` / ``detail`` / ``tool_name`` / ``evidence`` / ISO ``occurred_at``.
    Producing it here lets a live fanned-out frame be byte-identical to its
    durable replay, so a client cannot tell a live frame from a replayed one.
    """
    return {
        "kind": step.kind.value,
        "summary": step.summary,
        "detail": step.detail,
        "tool_name": step.tool_name,
        "evidence": [ref.model_dump(mode="json") for ref in step.evidence],
        "occurred_at": step.occurred_at.isoformat(),
    }


class PublishingTraceRecorder:
    """A :class:`TraceRecorder` that ALSO fans each recorded step onto the bus.

    This is the **production producer** for the stateless agent-session fan-out
    (ADR-0044 §2/§6, W2-T2). It wraps any inner recorder (the
    :class:`PostgresTraceRecorder` in production) and, once a step is durably
    persisted, publishes an :class:`~app.services.agent_stream.AgentStreamFrame`
    carrying the step read model + the trace/audit-join id onto the session's
    Redis pub/sub channel. A session running on any ``api`` replica therefore fans
    its live reasoning frames to a peer subscribing on any other replica — the
    "session opened on replica A served from replica B" exit criterion — instead of
    the channel carrying no real session content (the dead-producer defect).

    Ordering of the two effects is deliberate: **persist first, publish second.**
    Postgres is the durable replay source (ADR-0044 §5); the live publish is
    best-effort (at-most-once on the wire), so a publish failure (Redis blip,
    Sentinel failover, no subscriber) is swallowed — the step is already durable
    and a reconnecting client backfills it from the DB. A publish failure must
    never fail the run or lose a persisted step.

    The terminal ``end`` frame is intentionally NOT produced here: the WebSocket
    handler synthesizes it from the session's terminal DB status, so the producer
    only ever fans the per-step session content.
    """

    def __init__(
        self,
        inner: TraceRecorder,
        *,
        fanout: AgentStreamFanout,
        session_id: str,
    ) -> None:
        self._inner = inner
        self._fanout = fanout
        self._session_id = session_id

    async def start(self, agent_name: str) -> ReasoningTrace:
        """Delegate trace creation to the inner recorder."""
        return await self._inner.start(agent_name)

    async def record_step(self, trace_id: str, step: TraceStep) -> ReasoningTrace:
        """Persist *step* via the inner recorder, then fan it onto the channel.

        Persist-then-publish: the durable write happens first (Postgres is the
        replay source); the live frame is published best-effort afterwards and any
        publish error is logged and swallowed so it can never break the run.
        """
        trace = await self._inner.record_step(trace_id, step)
        await self._publish_step(trace_id, step)
        return trace

    async def complete(self, trace_id: str) -> ReasoningTrace:
        """Delegate completion to the inner recorder (no terminal frame here)."""
        return await self._inner.complete(trace_id)

    async def _publish_step(self, trace_id: str, step: TraceStep) -> None:
        """Best-effort publish of one recorded step as a live frame (never raises)."""
        # Imported lazily so this low-level framework module does not depend on the
        # service layer at import time (and to keep the dependency one-directional).
        from app.services.agent_stream import AgentStreamFrame

        try:
            frame = AgentStreamFrame(
                session_id=self._session_id,
                trace_id=trace_id,
                data=_step_read_model(step),
            )
            await self._fanout.publish(frame)
        except Exception:  # noqa: BLE001 - best-effort live fan-out; DB is durable.
            # At-most-once on the wire (ADR-0044 §5): the step is already persisted,
            # so a failed live publish is recovered by the client's DB replay. Never
            # propagate — a fan-out hiccup must not fail an agent run.
            _logger.warning(
                "agent_stream.publish_failed",
                session_id=self._session_id,
                trace_id=trace_id,
            )


def _step_from_row(row: ReasoningTraceStep) -> TraceStep:
    """Rebuild a :class:`TraceStep` from its persisted row."""
    evidence_payload: list[dict[str, Any]] = row.evidence
    return TraceStep(
        kind=TraceStepKind(row.kind.value),
        summary=row.summary,
        detail=row.detail,
        tool_name=row.tool_name,
        evidence=[EvidenceRef.model_validate(ref) for ref in evidence_payload],
        occurred_at=row.occurred_at,
    )


def build_trace_recorder(
    sessionmaker: async_sessionmaker[AsyncSession] | None,
    *,
    session_id: uuid.UUID | None,
) -> TraceRecorder:
    """Select the trace recorder for the current execution context (DI hook).

    Runtime passes a sessionmaker and the active ``AgentSession`` id to get a
    :class:`PostgresTraceRecorder`; tests pass ``None`` to get the in-memory
    recorder. Requiring ``session_id`` whenever a sessionmaker is supplied keeps
    the FK to ``agent_sessions`` non-optional at the boundary rather than
    failing later at flush time.
    """
    if sessionmaker is None:
        return InMemoryTraceRecorder()
    if session_id is None:
        raise ValueError("session_id is required for the Postgres trace recorder")
    return PostgresTraceRecorder(sessionmaker, session_id=session_id)
