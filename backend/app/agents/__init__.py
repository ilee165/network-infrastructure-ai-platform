"""LangGraph supervisor + specialist agents (ADR-0003, brief section 5).

Layout (REPO-STRUCTURE section 2): ``framework/`` holds the shared layers
(tool wrappers, approval gate, reasoning traces, registry, supervisor) used by
all ten core agents. Specialist packages (``master_architect/``,
``troubleshooting/``, ...) land with M3 and may import *only*
``agents.framework`` plus ``core``/``schemas``/``llm`` (REPO-STRUCTURE
section 3.2, row 11).

Composition root (M3-14)
    :func:`build_default_registry` assembles the process-wide
    :class:`~app.agents.framework.registry.AgentRegistry` for the M3 core set —
    the Master Architect supervisor plus the consultant, discovery, and
    troubleshooting specialists. :func:`build_default_supervisor` compiles the
    runnable supervisor graph over the *routable* subset of that registry
    (everything except the Master Architect itself, which is the supervisor and
    must never route to itself). Both take their inputs explicitly so a fresh,
    isolated set can be built per process or per test.
"""

from __future__ import annotations

from langchain_core.language_models import BaseChatModel
from langgraph.graph.state import CompiledStateGraph

from app.agents.consultant.agent import ConsultantAgent
from app.agents.discovery.agent import DiscoveryAgent
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.supervisor import (
    SUPERVISOR_NAME,
    SupervisorState,
    build_supervisor_graph,
)
from app.agents.framework.traces import TraceRecorder
from app.agents.master_architect.agent import MasterArchitectAgent
from app.agents.troubleshooting.agent import TroubleshootingAgent

__all__ = [
    "build_default_registry",
    "build_default_supervisor",
]


def build_default_registry() -> AgentRegistry:
    """Build the M3 default :class:`AgentRegistry` (the composition root).

    Registers the four M3 core agents — the Master Architect supervisor
    (CLAUDE.md Core Agent #1) and the consultant, discovery, and troubleshooting
    specialists — each as a fresh instance so the registry owns no shared mutable
    state across processes or tests. Registration validates every agent's
    declaration (:meth:`~app.agents.framework.base.BaseSpecialistAgent.validate_definition`).

    The Master Architect is included so the supervisor is a named, addressable
    citizen of the registry; :func:`build_default_supervisor` excludes it from
    the routable specialist set it hands to the graph builder.
    """
    registry = AgentRegistry()
    registry.register(MasterArchitectAgent())
    registry.register(ConsultantAgent())
    registry.register(DiscoveryAgent())
    registry.register(TroubleshootingAgent())
    return registry


def _routable_registry(registry: AgentRegistry) -> AgentRegistry:
    """Return a copy of *registry* without the supervisor (its routable subset).

    The supervisor (:data:`~app.agents.framework.supervisor.SUPERVISOR_NAME`)
    drives routing; it is never itself a routing target. Building a separate
    registry keeps :func:`~app.agents.framework.supervisor.build_supervisor_graph`
    unchanged (it routes to every agent it is given).
    """
    routable = AgentRegistry()
    for agent in registry.list():
        if agent.name != SUPERVISOR_NAME:
            routable.register(agent)
    return routable


def build_default_supervisor(
    llm: BaseChatModel,
    registry: AgentRegistry | None = None,
    *,
    trace_recorder: TraceRecorder | None = None,
) -> CompiledStateGraph[SupervisorState, None, SupervisorState, SupervisorState]:
    """Compile the runnable Master Architect supervisor graph (composition root).

    Builds (or accepts) the default registry, strips the Master Architect from
    the routable set, and compiles the supervisor graph over the remaining
    specialists via
    :func:`~app.agents.framework.supervisor.build_supervisor_graph`. *llm* must
    come from the ``llm`` provider registry (ADR-0009) — callers never
    instantiate provider classes directly. *trace_recorder* is the persistence
    seam (runtime ``PostgresTraceRecorder`` linked to the active
    :class:`~app.models.agents.AgentSession`; tests pass an in-memory recorder).
    """
    base = registry if registry is not None else build_default_registry()
    return build_supervisor_graph(llm, _routable_registry(base), trace_recorder=trace_recorder)
