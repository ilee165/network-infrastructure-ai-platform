"""Master Architect Agent package (M3-14, ADR-0003 Decision 1).

The Master Architect is the LangGraph supervisor; :class:`MasterArchitectAgent`
is its thin registry identity so it can be registered alongside the specialists
it supervises. The runtime supervisor graph is built by the composition root
:func:`app.agents.build_default_supervisor`, which excludes this agent from the
routable specialist set (the supervisor never routes to itself).

    from app.agents.master_architect import MasterArchitectAgent
"""

from app.agents.master_architect.agent import MasterArchitectAgent

__all__ = ["MasterArchitectAgent"]
