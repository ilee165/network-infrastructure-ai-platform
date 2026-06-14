"""Documentation Agent package (M4 task 10, ADR-0003, ADR-0019).

A read-only specialist that *generates* documentation artifacts from live
platform data: network inventories (deterministic Markdown + CSV from
normalized tables), topology diagrams (Mermaid from the Neo4j projection,
added in T11), and runbooks (template + grounded LLM narrative, added in T12).

Inventories are generated without any LLM (ADR-0019 §2): all values are
rendered verbatim from the caller-supplied normalized-table rows, so the M4
exit criterion "generated inventory matches normalized-table content exactly"
is satisfied by construction (round-trip equality).

A process-wide singleton and its registry are available for direct import::

    from app.agents.documentation import (
        DocumentationAgent,
        documentation_agent,
        registry,
    )

Construct a fresh instance for tests::

    from app.agents.documentation import DocumentationAgent
    agent = DocumentationAgent()
"""

from app.agents.documentation.agent import DocumentationAgent
from app.agents.framework.registry import AgentRegistry

#: Process-wide registry for the documentation package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
documentation_agent: DocumentationAgent = DocumentationAgent()
registry.register(documentation_agent)

__all__ = ["DocumentationAgent", "documentation_agent", "registry"]
