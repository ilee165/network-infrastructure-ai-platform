"""Packet Analysis Agent package (M5 task #11, ADR-0003 Decision 3, ADR-0023).

The packet-analysis specialist: read-only summarization of, and filter-style
Q&A over, a finished capture's normalized analysis findings (top talkers,
protocol breakdown, TCP resets/retransmissions). It operates exclusively on the
LLM-safe :class:`~app.engines.packet.PacketFindings` boundary — never raw packet
bytes — and never launches a capture itself (that is the ``diagnostic`` capture
tier, T8). Findings attach to a troubleshooting session through the injected
:class:`~app.agents.framework.traces.TraceRecorder`, the same session/trace model
M3 introduced.

The agent reaches the analysis engine only through its classified ``NetOpsTool``
set, so the agents -> engines module boundary is never crossed directly.

A process-wide singleton and its registry are available for direct import::

    from app.agents.packet_analysis import PacketAnalysisAgent, packet_analysis_agent, registry

Construct a fresh instance for tests (and to attach findings to a specific
session via its recorder), to avoid shared-state pollution::

    from app.agents.packet_analysis import PacketAnalysisAgent
    agent = PacketAnalysisAgent()

Routing/registration with the Master Architect supervisor is T14 (Wave 5) and is
intentionally not wired in this package.
"""

from app.agents.framework.registry import AgentRegistry
from app.agents.packet_analysis.agent import PacketAnalysisAgent

#: Process-wide registry for the packet_analysis package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
packet_analysis_agent: PacketAnalysisAgent = PacketAnalysisAgent()
registry.register(packet_analysis_agent)

__all__ = ["PacketAnalysisAgent", "packet_analysis_agent", "registry"]
