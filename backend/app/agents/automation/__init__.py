"""Automation Agent package (M5 task #9, ADR-0020/0021/0022).

The sole executor of approved ChangeRequests — the single component that turns an
``approved`` change into a real device (``CONFIG_RESTORE``/``CONFIG_DEPLOY``) or
DDI (Infoblox WAPI) write, verifies it, and rolls back on failure. It executes
**only** ``approved`` CRs (refusing every other lifecycle state, audited), drives
the lifecycle through the ChangeRequest service (never self-approving, never
bypassing four-eyes), and surfaces only A9-redacted content to any LLM. The write
path is the deterministic, server-gated :meth:`AutomationAgent.execute`; the
supervisor-facing tool surface is READ_ONLY narration only.

A process-wide singleton and its registry are available for direct import. The
singleton is constructed without wired executor ports / service — those are
injected by the worker/API composition root (Wave 5); a fresh instance is built
for tests::

    from app.agents.automation import AutomationAgent
    agent = AutomationAgent(
        change_request_service=service,
        config_executor=config_executor,
    )
    result = await agent.execute(cr_id)
"""

from app.agents.automation.agent import AutomationAgent
from app.agents.framework.registry import AgentRegistry

#: Process-wide registry for the automation package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time. The service
#: and executor ports are wired by the composition root before :meth:`execute` is
#: called (Wave 5); the singleton exists so the registry/supervisor can compose
#: against the declaration (name/description/tools), which needs no live wiring.
automation_agent: AutomationAgent = AutomationAgent(change_request_service=None)  # type: ignore[arg-type]
registry.register(automation_agent)

__all__ = ["AutomationAgent", "automation_agent", "registry"]
