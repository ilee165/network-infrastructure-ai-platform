"""Troubleshooting Agent package (M3-13, ADR-0003 Decision 3).

The first analytic specialist: read-only routing / BGP / OSPF / ACL analysis
over collected normalized data plus on-demand live reads, exposed to the
Master Architect supervisor through READ_ONLY typed tools so the
agents -> engines module boundary is never crossed directly.

A process-wide singleton and its registry are available for direct import::

    from app.agents.troubleshooting import (
        TroubleshootingAgent,
        troubleshooting_agent,
        registry,
    )

Construct a fresh instance for tests (and to inspect a run's evidence-grounded
trace) to avoid shared-state pollution::

    from app.agents.troubleshooting import TroubleshootingAgent
    agent = TroubleshootingAgent()
"""

from app.agents.framework.registry import AgentRegistry
from app.agents.troubleshooting.agent import TroubleshootingAgent

#: Process-wide registry for the troubleshooting package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
troubleshooting_agent: TroubleshootingAgent = TroubleshootingAgent()
registry.register(troubleshooting_agent)

__all__ = ["TroubleshootingAgent", "registry", "troubleshooting_agent"]
