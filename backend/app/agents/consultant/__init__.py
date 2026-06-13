"""Consultant Agent package (M3-11, ADR-0003 Decision 2).

When intent is ambiguous the Consultant Agent asks a clarifying question
rather than acting. In autonomous runs it records the question plus a
recommended default in ``docs/consultant/QUESTIONS.md`` and proceeds on the
default.

A process-wide singleton and its registry are available for direct import::

    from app.agents.consultant import ConsultantAgent, consultant_agent, registry

Pass a custom ``questions_path`` when constructing your own instance for tests::

    from app.agents.consultant import ConsultantAgent
    agent = ConsultantAgent(questions_path=tmp_path / "QUESTIONS.md")
"""

from app.agents.consultant.agent import ConsultantAgent
from app.agents.framework.registry import AgentRegistry

#: Process-wide registry for the consultant package.
registry: AgentRegistry = AgentRegistry()

#: Process-wide singleton — registered in *registry* at import time.
consultant_agent: ConsultantAgent = ConsultantAgent()
registry.register(consultant_agent)

__all__ = ["ConsultantAgent", "consultant_agent", "registry"]
