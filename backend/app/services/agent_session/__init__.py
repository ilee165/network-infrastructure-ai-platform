"""Agent-session lifecycle service package (M3-14).

Exposes :class:`AgentSessionService`, which owns the lifecycle of one
:class:`~app.models.agents.AgentSession` per supervisor run and wires the
invoking role into the tool run context (RBAC) plus the session-linked trace
recorder.

    from app.services.agent_session import AgentSessionService
"""

from app.services.agent_session.service import AgentSessionService

__all__ = ["AgentSessionService"]
