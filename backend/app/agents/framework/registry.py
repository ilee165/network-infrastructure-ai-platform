"""Specialist registry (ADR-0003: agents register; the supervisor routes by name).

One :class:`AgentRegistry` instance is the composition seam between the
specialist packages and the Master Architect supervisor
(:func:`~app.agents.framework.supervisor.build_supervisor_graph`). M3 wires a
process-wide registry populated by the specialist packages at import time;
M0 ships the container so the supervisor and tests can compose against it.
"""

from __future__ import annotations

import builtins

from app.agents.framework.base import BaseSpecialistAgent
from app.core.errors import ConflictError, NotFoundError


class AgentRegistry:
    """Holds the registered specialist agents, keyed by their string id."""

    def __init__(self) -> None:
        self._agents: dict[str, BaseSpecialistAgent] = {}

    def register(self, agent: BaseSpecialistAgent) -> BaseSpecialistAgent:
        """Validate and add *agent*; return it for decorator-style chaining.

        Raises
        ------
        AgentDefinitionError
            If the agent declaration violates the framework contract
            (delegated to ``agent.validate_definition()``).
        ConflictError
            If an agent with the same name is already registered.
        """
        agent.validate_definition()
        if agent.name in self._agents:
            raise ConflictError(f"agent '{agent.name}' is already registered")
        self._agents[agent.name] = agent
        return agent

    def get(self, name: str) -> BaseSpecialistAgent:
        """Return the agent registered under *name*.

        Raises :class:`~app.core.errors.NotFoundError` for unknown names.
        """
        try:
            return self._agents[name]
        except KeyError:
            raise NotFoundError(f"agent '{name}' is not registered") from None

    # builtins.list: the method name shadows the builtin in class scope.
    def list(self) -> builtins.list[BaseSpecialistAgent]:
        """Return all registered agents, sorted by name (stable routing order)."""
        return sorted(self._agents.values(), key=lambda agent: agent.name)

    def names(self) -> builtins.list[str]:
        """Return the sorted registered agent names."""
        return sorted(self._agents)

    def __contains__(self, name: object) -> bool:
        return name in self._agents

    def __len__(self) -> int:
        return len(self._agents)
