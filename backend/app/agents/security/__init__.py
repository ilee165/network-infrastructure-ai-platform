"""Security Agent package (P2 W3, ADR-0003 Decision 3, ADR-0037).

CLAUDE.md Core Agent #9 (Security): read-only firewall-policy + posture audit over
already-collected normalized ``FIREWALL_POLICY`` / ``ACL`` data, plus
approval-gated remediation proposals. The analysis is deterministic in the security
engine (the agent narrates, it does not judge — ADR-0037 §2); read-only tools
narrate only A9-redacted content, so no secret value reaches a model prompt; the
remediation tool never applies inline — it creates a ``security_remediation``
ChangeRequest for human approval, executed later by the Automation Agent. The agent
reaches the analysis engine exclusively through its classified ``NetOpsTool`` set,
so the agents -> engines module boundary is never crossed directly.

A process-wide singleton and its registry are available for direct import::

    from app.agents.security import SecurityAgent, security_agent, registry

Construct a fresh instance for tests (and to avoid shared-state pollution)::

    from app.agents.security import SecurityAgent
    agent = SecurityAgent()

Supervisor routing / RBAC scoping / ADR-0033 allow-list registration are W3-T2.
"""

from app.agents.framework.registry import AgentRegistry
from app.agents.security.agent import SECURITY_NAME, SecurityAgent

#: Process-wide registry for the security package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
security_agent: SecurityAgent = SecurityAgent()
registry.register(security_agent)

__all__ = ["SECURITY_NAME", "SecurityAgent", "registry", "security_agent"]
