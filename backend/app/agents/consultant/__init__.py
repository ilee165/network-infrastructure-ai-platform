"""Consultant Agent package (M3-11, ADR-0003 Decision 2).

When intent is ambiguous the Consultant Agent asks a clarifying question
rather than acting. In autonomous runs it records the question plus a
recommended default in ``docs/consultant/QUESTIONS.md`` and proceeds on the
default.

Register via the framework registry:

    from app.agents.consultant import consultant_agent, registry
    registry.register(consultant_agent)

or import :class:`~app.agents.consultant.agent.ConsultantAgent` directly and
pass a custom ``questions_path`` for tests.
"""

from app.agents.consultant.agent import ConsultantAgent

__all__ = ["ConsultantAgent"]
