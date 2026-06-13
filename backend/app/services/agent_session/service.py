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

from app.agents.framework.supervisor import SupervisorState, run_supervisor
from app.agents.framework.traces import PostgresTraceRecorder
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.core.security import Role
from app.models.agents import AgentSession, AgentSessionStatus
from app.models.mixins import utcnow

_logger = get_logger(__name__)


class AgentSessionService:
    """Owns the lifecycle of one :class:`AgentSession` per supervisor run."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

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
    ) -> SupervisorState:
        """Run *graph* inside a lifecycle-managed, role-bound session.

        Starts a ``RUNNING`` session, drives the supervisor as *role* (so every
        :class:`~app.agents.framework.tools.NetOpsTool` inside the run sees the
        real caller role), then marks the session ``COMPLETED`` — or ``FAILED``
        and re-raises if the run raises (e.g. an RBAC denial when *role* is below
        a tool's ``min_role``). *messages* defaults to a single user turn carrying
        *intent*.

        The graph passed here must already carry a trace recorder bound to the
        session id (see :meth:`recorder_for`) so the run's reasoning traces link
        to this session.
        """
        run_session = await self.start(user_id=user_id, role=role, intent=intent)
        conversation: Sequence[BaseMessage] = (
            messages if messages is not None else [HumanMessage(content=intent)]
        )
        try:
            result = await run_supervisor(graph, conversation, role=role)
        except Exception:
            await self.fail(run_session.id)
            raise
        await self.complete(run_session.id)
        return result

    def recorder_for(self, session_id: uuid.UUID) -> PostgresTraceRecorder:
        """Build a trace recorder whose persisted traces link to *session_id*.

        Callers build the supervisor graph with this recorder so that every
        reasoning trace recorded during the run carries the session FK (brief §6:
        traces are linked to the session and the audit log).
        """
        return PostgresTraceRecorder(self._sessionmaker, session_id=session_id)

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
