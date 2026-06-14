"""Master Architect Agent — the supervisor as a first-class registry citizen.

CLAUDE.md Core Agent #1 / ADR-0003 Decision 1: the Master Architect is the
LangGraph *supervisor* (``app.agents.framework.supervisor``) — it plans, routes
to specialists, and synthesizes. It is not a routable specialist subgraph.

This thin :class:`~app.agents.framework.base.BaseSpecialistAgent` exists so the
supervisor is a named, validated entry in the process-wide
:class:`~app.agents.framework.registry.AgentRegistry` alongside the specialists
it supervises (the default registry therefore lists all four core M3 agents).
The composition root (:func:`app.agents.build_default_supervisor`) deliberately
excludes this agent from the *routable* sub-registry it hands to
:func:`~app.agents.framework.supervisor.build_supervisor_graph`, so the
supervisor never routes to itself.

The agent declares no tools: routing/planning/synthesis run in the supervisor
graph's own nodes, not in a ReAct subgraph, so it never crosses the
``agents -> framework typed tools -> engines`` boundary.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.agents.framework.base import BaseSpecialistAgent
from app.agents.framework.supervisor import SUPERVISOR_NAME
from app.agents.framework.tools import NetOpsTool


class MasterArchitectAgent(BaseSpecialistAgent):
    """The supervisor's registry identity (name/description/system prompt).

    Pure-reasoning, tool-less. The real orchestration lives in
    :func:`~app.agents.framework.supervisor.build_supervisor_graph`; this class
    only gives the supervisor a validated registry entry so it can be listed,
    described, and addressed by :data:`~app.agents.framework.supervisor.SUPERVISOR_NAME`.
    """

    @property
    def name(self) -> str:
        return SUPERVISOR_NAME

    @property
    def description(self) -> str:
        return (
            "The Master Architect supervisor. Receives the user's network-operations "
            "intent, plans, routes it to exactly one specialist agent, and synthesizes "
            "the final answer. Not a routable target itself."
        )

    @property
    def system_prompt(self) -> str:
        return (
            "You are the Master Architect Agent, the supervisor of a team of specialist "
            "network-operations agents. You analyze the user's request, route it to the "
            "single best-fit specialist, and compose the final answer from that "
            "specialist's findings, keeping every decision explainable."
        )

    @property
    def tools(self) -> Sequence[NetOpsTool]:
        return ()
