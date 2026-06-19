"""LangGraph supervisor + specialist agents (ADR-0003, brief section 5).

Layout (REPO-STRUCTURE section 2): ``framework/`` holds the shared layers
(tool wrappers, approval gate, reasoning traces, registry, supervisor) used by
all ten core agents. Specialist packages (``master_architect/``,
``troubleshooting/``, ...) land with M3 and may import *only*
``agents.framework`` plus ``core``/``schemas``/``llm`` (REPO-STRUCTURE
section 3.2, row 11).

Composition root (M3-14, extended in M4 T13 and M5 T14)
    :func:`build_default_registry` assembles the process-wide
    :class:`~app.agents.framework.registry.AgentRegistry` for the core set — the
    Master Architect supervisor plus the EIGHT routable specialists (consultant,
    discovery, troubleshooting, configuration, documentation added M3/M4;
    automation, ddi, packet_analysis added in M5 T14). :func:`build_default_supervisor`
    compiles the runnable supervisor graph over the *routable* subset of that
    registry (everything except the Master Architect itself, which is the
    supervisor and must never route to itself). Both take their inputs explicitly
    so a fresh, isolated set can be built per process or per test.

    The Automation Agent is registered for ROUTING only — its
    name/description/system_prompt and read-only narration tools — built without a
    :class:`~app.services.change_requests.ChangeRequestService`, so the
    DB-free composition root stays pure. Its execution write path
    (:meth:`~app.agents.automation.agent.AutomationAgent.execute`) is driven
    separately by the Wave-5 API/worker with a real service; a routing-only
    instance cannot execute a change (M5-PLAN risk #4).
"""

from __future__ import annotations

from langchain_core.language_models import BaseChatModel
from langgraph.graph.state import CompiledStateGraph

from app.agents.automation.agent import AutomationAgent
from app.agents.configuration.agent import ConfigurationAgent
from app.agents.consultant.agent import ConsultantAgent
from app.agents.ddi.agent import DdiAgent
from app.agents.discovery.agent import DiscoveryAgent
from app.agents.documentation.agent import DocumentationAgent
from app.agents.framework.registry import AgentRegistry
from app.agents.framework.supervisor import (
    SUPERVISOR_NAME,
    SupervisorState,
    build_supervisor_graph,
)
from app.agents.framework.traces import TraceRecorder
from app.agents.master_architect.agent import MasterArchitectAgent
from app.agents.packet_analysis.agent import PacketAnalysisAgent
from app.agents.troubleshooting.agent import TroubleshootingAgent

__all__ = [
    "build_default_registry",
    "build_default_supervisor",
]


def build_default_registry() -> AgentRegistry:
    """Build the default :class:`AgentRegistry` (the composition root).

    Registers the nine core agents — the Master Architect supervisor (CLAUDE.md
    Core Agent #1) and the eight routable specialists: consultant, discovery,
    troubleshooting, configuration, documentation (M3/M4) plus automation, ddi,
    and packet_analysis (M5 T14) — each as a fresh instance so the registry owns
    no shared mutable state across processes or tests. Registration validates
    every agent's declaration
    (:meth:`~app.agents.framework.base.BaseSpecialistAgent.validate_definition`).

    The Automation Agent is built routing-only (no
    :class:`~app.services.change_requests.ChangeRequestService`): its supervisor
    surface is its read-only narration tools, and execution is wired separately
    with a real service, so the composition root needs no DB.

    The Master Architect is included so the supervisor is a named, addressable
    citizen of the registry; :func:`build_default_supervisor` excludes it from
    the routable specialist set it hands to the graph builder.
    """
    registry = AgentRegistry()
    registry.register(MasterArchitectAgent())
    registry.register(ConsultantAgent())
    registry.register(DiscoveryAgent())
    registry.register(TroubleshootingAgent())
    registry.register(ConfigurationAgent())
    registry.register(DocumentationAgent())
    registry.register(AutomationAgent())
    registry.register(DdiAgent())
    registry.register(PacketAnalysisAgent())
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
