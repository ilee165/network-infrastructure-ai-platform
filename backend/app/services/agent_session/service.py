"""Agent-session lifecycle service (M3-14, brief §5/§7, ADR-0003/0011).

One :class:`~app.models.agents.AgentSession` records a single supervisor run:
who invoked it, with which role, the intent, and the outcome. This service owns
that row's lifecycle and the RBAC + trace wiring around a run:

- :meth:`AgentSessionService.start` opens a ``RUNNING`` session for the
  invoking user + role.
- :meth:`AgentSessionService.complete` / :meth:`AgentSessionService.fail` close
  it (terminal status + ``completed_at``).
- :meth:`AgentSessionService.run` is the orchestration entrypoint: it starts a
  session, builds a :class:`~app.agents.framework.traces.PostgresTraceRecorder`
  bound to that session id (so every reasoning trace links to the session,
  brief §6), drives the supervisor graph as the invoking role via
  :func:`~app.agents.framework.supervisor.run_supervisor` (binding the role into
  the tool run context that RBAC reads — "an agent can never do what its user
  cannot", brief §7), and marks the session complete or failed.

The service takes an :class:`async_sessionmaker` explicitly (not a request-scoped
session): lifecycle transitions commit independently of the run so a crashed run
still leaves a durable ``FAILED`` record, and the trace recorder owns its own
short transactions per step (it is shared across concurrent specialist
subgraphs).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph.state import CompiledStateGraph
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.framework.approval import ApprovalGate, ChangeRequestGate
from app.agents.framework.supervisor import SupervisorState, run_supervisor
from app.agents.framework.tools import AgentRunIdentity, GateFactory
from app.agents.framework.traces import (
    PostgresTraceRecorder,
    PublishingTraceRecorder,
    TraceRecorder,
)
from app.core.errors import NotFoundError, translate_llm_error
from app.core.logging import get_logger
from app.core.security import Role
from app.models.agents import AgentSession, AgentSessionStatus
from app.models.mixins import utcnow
from app.services.agent_stream import AgentStreamFanout
from app.services.change_requests import ChangeRequestService

_logger = get_logger(__name__)


class AgentSessionService:
    """Owns the lifecycle of one :class:`AgentSession` per supervisor run."""

    def __init__(
        self,
        sessionmaker: async_sessionmaker[AsyncSession],
        *,
        stream_fanout: AgentStreamFanout | None = None,
    ) -> None:
        self._sessionmaker = sessionmaker
        # The per-session pub/sub fan-out (ADR-0044 §2). When supplied, the trace
        # recorder this service builds becomes the PRODUCTION PRODUCER: each
        # persisted reasoning step is fanned out as a live frame so a session
        # running on any ``api`` replica is served live from any other. When
        # ``None`` (CLI/tests that do not stream), the recorder stays Postgres-only.
        self._stream_fanout = stream_fanout

    async def start(self, *, user_id: uuid.UUID, role: Role, intent: str) -> AgentSession:
        """Open and persist a ``RUNNING`` session for *user_id* / *role*.

        ``invoking_role`` is stored as the wire role value so the RBAC role that
        later flows into the tool run context is the one durably recorded against
        the session (auditability, brief §7).
        """
        async with self._sessionmaker() as session:
            row = AgentSession(
                user_id=user_id,
                invoking_role=role.value,
                intent=intent,
                status=AgentSessionStatus.RUNNING,
            )
            session.add(row)
            await session.commit()
            session_id = row.id
        _logger.info(
            "agent_session.started",
            session_id=str(session_id),
            user_id=str(user_id),
            invoking_role=role.value,
        )
        return await self.get(session_id)

    async def complete(self, session_id: uuid.UUID) -> AgentSession:
        """Mark the session ``COMPLETED`` (idempotent once terminal)."""
        return await self._finish(session_id, AgentSessionStatus.COMPLETED)

    async def fail(self, session_id: uuid.UUID) -> AgentSession:
        """Mark the session ``FAILED`` (idempotent once terminal)."""
        return await self._finish(session_id, AgentSessionStatus.FAILED)

    async def get(self, session_id: uuid.UUID) -> AgentSession:
        """Reload the session row or raise :class:`NotFoundError`."""
        async with self._sessionmaker() as session:
            row = await session.get(AgentSession, session_id)
            if row is None:
                raise NotFoundError(f"agent session '{session_id}' does not exist")
            return row

    async def run(
        self,
        graph: CompiledStateGraph[SupervisorState, None, SupervisorState, SupervisorState],
        intent: str,
        *,
        user_id: uuid.UUID,
        role: Role,
        messages: Sequence[BaseMessage] | None = None,
        session_id: uuid.UUID | None = None,
    ) -> SupervisorState:
        """Run *graph* inside a lifecycle-managed, role-bound session.

        When *session_id* is ``None`` (default), a fresh ``RUNNING`` session is
        started internally and its id is used for the entire lifecycle.

        When *session_id* is supplied the caller is responsible for having already
        opened that session via :meth:`start` (and typically for having built
        *graph* with a trace recorder bound to the same id via
        :meth:`recorder_for`).  In that case :meth:`run` skips the internal
        :meth:`start` call and manages only the terminal transition
        (``COMPLETED`` / ``FAILED``) on the caller-supplied session.  This is the
        pattern that keeps a single session row owning both its lifecycle and all
        of its reasoning traces:

        .. code-block:: python

            session = await service.start(user_id=uid, role=role, intent=intent)
            recorder = service.recorder_for(session.id)
            graph = build_supervisor_graph(model, registry, trace_recorder=recorder)
            result = await service.run(graph, intent, user_id=uid, role=role,
                                       session_id=session.id)

        Drives the supervisor as *role* (so every
        :class:`~app.agents.framework.tools.NetOpsTool` inside the run sees the
        real caller role) and binds the ChangeRequest gate factory
        (:meth:`_change_request_gate_factory`) plus the run identity (``user_id`` /
        ``session_id``) into :func:`~app.agents.framework.supervisor.run_supervisor`
        — so a state-changing tool CREATES a CR draft as the real user (ADR-0020
        §4, M5 task #4) instead of falling back to the hard-reject gate. Then marks
        the session ``COMPLETED`` — or ``FAILED`` and re-raises if the run raises
        (e.g. an RBAC denial when *role* is below a tool's ``min_role``).
        *messages* defaults to a single user turn carrying *intent*.
        """
        if session_id is None:
            run_session = await self.start(user_id=user_id, role=role, intent=intent)
            active_session_id = run_session.id
        else:
            active_session_id = session_id

        conversation: Sequence[BaseMessage] = (
            messages if messages is not None else [HumanMessage(content=intent)]
        )
        try:
            result = await run_supervisor(
                graph,
                conversation,
                role=role,
                user_id=user_id,
                session_id=active_session_id,
                gate_factory=self._change_request_gate_factory(),
            )
        except Exception as exc:
            await self.fail(active_session_id)
            # An upstream LLM/transport failure (provider rejected/unavailable)
            # becomes a typed 502 so the API never returns an opaque 500; a real
            # code bug is left untranslated and still surfaces as a 500.
            translated = translate_llm_error(exc)
            if translated is not None:
                _logger.warning(
                    "agent_session.run_failed_upstream",
                    session_id=str(active_session_id),
                    error_type=type(exc).__name__,
                )
                raise translated from exc
            raise
        await self.complete(active_session_id)
        return result

    def _change_request_gate_factory(self) -> GateFactory:
        """Build the per-run ChangeRequest gate factory (ADR-0020 §4, M5 task #4).

        Closes over a :class:`~app.services.change_requests.ChangeRequestService`
        bound to this service's sessionmaker and, for each state-changing tool
        call, builds a :class:`~app.agents.framework.approval.ChangeRequestGate`
        from the bound :class:`~app.agents.framework.tools.AgentRunIdentity` — so a
        state-changing tool now CREATES a CR *draft* as the real user instead of
        falling back to the hard-reject :class:`DenyAllGate`. Wiring this here is
        what makes CR creation reachable end-to-end in production (the API route
        drives the supervisor through :meth:`run`), not only in tests.

        Returns ``None`` for any identity without a real ``user_id`` (the CR
        ``requester_id`` is a NOT NULL FK to ``users``): such a run cannot author a
        CR, so the framework keeps the secure hard-reject fallback rather than
        minting an unattributable CR.
        """
        service = ChangeRequestService(self._sessionmaker)

        def factory(identity: AgentRunIdentity) -> ApprovalGate | None:
            if identity.user_id is None:
                return None
            return ChangeRequestGate(
                service,
                requester_id=identity.user_id,
                actor_role=identity.role,
                generating_session_id=identity.session_id,
                reasoning_trace_id=identity.reasoning_trace_id,
            )

        return factory

    def recorder_for(self, session_id: uuid.UUID) -> TraceRecorder:
        """Build a trace recorder whose persisted traces link to *session_id*.

        Callers build the supervisor graph with this recorder so that every
        reasoning trace recorded during the run carries the session FK (brief §6:
        traces are linked to the session and the audit log).

        When this service was constructed with a ``stream_fanout`` (the API does so
        from ``app.state.stream_fanout``), the Postgres recorder is wrapped in a
        :class:`~app.agents.framework.traces.PublishingTraceRecorder` — the
        production producer (ADR-0044 §2/§6): every persisted step is fanned out as
        a live :class:`AgentStreamFrame` on the session channel (keyed by the opaque
        session id), so a session running on this replica is served live from any
        replica subscribing for it. Without a fan-out the recorder is Postgres-only
        (durable replay still works), so non-streaming callers are unchanged.
        """
        recorder: TraceRecorder = PostgresTraceRecorder(self._sessionmaker, session_id=session_id)
        if self._stream_fanout is not None:
            recorder = PublishingTraceRecorder(
                recorder, fanout=self._stream_fanout, session_id=str(session_id)
            )
        return recorder

    async def _finish(self, session_id: uuid.UUID, status: AgentSessionStatus) -> AgentSession:
        """Apply a terminal *status* + ``completed_at`` once (idempotent)."""
        async with self._sessionmaker() as session:
            row = await session.get(AgentSession, session_id)
            if row is None:
                raise NotFoundError(f"agent session '{session_id}' does not exist")
            if row.status is AgentSessionStatus.RUNNING:
                row.status = status
                row.completed_at = utcnow()
                await session.commit()
            final_status = row.status
        _logger.info(
            "agent_session.finished",
            session_id=str(session_id),
            status=final_status.value,
        )
        return await self.get(session_id)
