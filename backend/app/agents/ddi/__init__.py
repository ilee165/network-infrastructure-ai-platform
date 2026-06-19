"""DDI Agent package (M5 task #10, ADR-0003 Decision 3, ADR-0022).

The DNS/DHCP (DDI) specialist: read-only DNS/DHCP troubleshooting over collected
normalized DDI data plus approval-gated DDI record/range changes. Read-only tools
narrate only A9-redacted content, so no secret value reaches a model prompt;
mutating tools never apply inline — each creates a ``ddi_record`` ChangeRequest
for human approval, executed later by the Automation Agent. The agent reaches
services/plugins exclusively through its classified ``NetOpsTool`` set, so the
agents -> services/plugins module boundary is never crossed directly.

A process-wide singleton and its registry are available for direct import::

    from app.agents.ddi import DdiAgent, ddi_agent, registry

Construct a fresh instance for tests (and to avoid shared-state pollution)::

    from app.agents.ddi import DdiAgent
    agent = DdiAgent()

Routing/registration with the Master Architect supervisor is T14 (Wave 5) and is
intentionally not wired in this package.
"""

from app.agents.ddi.agent import DdiAgent
from app.agents.framework.registry import AgentRegistry

#: Process-wide registry for the ddi package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
ddi_agent: DdiAgent = DdiAgent()
registry.register(ddi_agent)

__all__ = ["DdiAgent", "ddi_agent", "registry"]
