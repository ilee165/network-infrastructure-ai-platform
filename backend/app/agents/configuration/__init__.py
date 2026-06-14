"""Configuration Agent package (M4 task 9, ADR-0003 Decision 3, ADR-0017 §3).

A read-only specialist that *explains* configuration drift and compliance
posture. Drift diffs and compliance findings are computed server-side over the
raw, unredacted config by ``engines/config_mgmt``; this agent narrates only the
A9-redacted results, so no secret value ever reaches a model prompt. Exposed to
the Master Architect supervisor through READ_ONLY typed tools — the
agents -> engines module boundary is never crossed directly, and no
state-changing tool is ever declared (config push is gated to M5).

A process-wide singleton and its registry are available for direct import::

    from app.agents.configuration import (
        ConfigurationAgent,
        configuration_agent,
        registry,
    )

Construct a fresh instance for tests (and to inject the server-computed drift /
compliance inputs and inspect a run's redacted reasoning trace)::

    from app.agents.configuration import ConfigurationAgent
    agent = ConfigurationAgent(drift_diff=diff, has_drift=True)
"""

from app.agents.configuration.agent import ConfigurationAgent
from app.agents.framework.registry import AgentRegistry

#: Process-wide registry for the configuration package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
configuration_agent: ConfigurationAgent = ConfigurationAgent()
registry.register(configuration_agent)

__all__ = ["ConfigurationAgent", "configuration_agent", "registry"]
