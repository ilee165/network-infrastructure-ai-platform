"""Discovery Agent package (M3-12, ADR-0003 Decision 3).

Wraps the M1 discovery engine through READ_ONLY typed tools so the
Master Architect supervisor can route discovery requests to a specialist
agent without violating the agents -> engines module boundary.

A process-wide singleton and its registry are available for direct import::

    from app.agents.discovery import DiscoveryAgent, discovery_agent, registry

Construct a fresh instance for tests to avoid shared-state pollution::

    from app.agents.discovery import DiscoveryAgent
    agent = DiscoveryAgent()
"""

from app.agents.discovery.agent import DiscoveryAgent
from app.agents.framework.registry import AgentRegistry

#: Process-wide registry for the discovery package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
discovery_agent: DiscoveryAgent = DiscoveryAgent()
registry.register(discovery_agent)

__all__ = ["DiscoveryAgent", "discovery_agent", "registry"]
